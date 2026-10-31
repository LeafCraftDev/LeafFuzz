package net.leaf.sleuth.paper.fuzz;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.ArgumentType;
import com.mojang.brigadier.arguments.DoubleArgumentType;
import com.mojang.brigadier.arguments.FloatArgumentType;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.arguments.LongArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.tree.ArgumentCommandNode;
import com.mojang.brigadier.tree.CommandNode;
import com.mojang.brigadier.tree.RootCommandNode;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import net.kyori.adventure.text.Component;
import net.leaf.fuzz.common.BrigadierDispatcherInspector.BrigadierPermissionRequirement;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Server;
import org.bukkit.command.Command;
import org.bukkit.command.CommandMap;
import org.bukkit.command.CommandSender;
import org.bukkit.command.PluginIdentifiableCommand;
import org.bukkit.entity.Entity;
import org.bukkit.permissions.PermissibleBase;
import org.bukkit.permissions.Permission;
import org.bukkit.permissions.PermissionAttachment;
import org.bukkit.permissions.PermissionAttachmentInfo;
import org.bukkit.permissions.PermissionDefault;
import org.bukkit.permissions.ServerOperator;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.PluginManager;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts the live Bukkit {@link CommandMap} and Brigadier command graph per permission tier
 * ({@code default} vs {@code op}) in-JVM without requiring external bot logins or reflection
 * ({@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Evaluates each tier using a synthetic {@link CommandSender} / {@link PermissibleBase}
 * ({@code isOp=false} for {@code default}, {@code isOp=true} for {@code op}) via
 * {@link Command#testPermissionSilent(CommandSender)} and Brigadier {@link CommandNode#canUse(Object)},
 * building distinct per-tier subtrees and honoring {@link Permission#DEFAULT_PERMISSION}
 * ({@link PermissionDefault#OP}) for unregistered permissions as well as {@link PermissionDefault#FALSE}.
 *
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace S-005
 */
@SuppressWarnings("deprecation")
public final class PaperCommandTreeInspector {

    /**
     * Typed carrier interface for supplying a live {@link CommandDispatcher} without reflection.
     */
    public interface BrigadierDispatcherCarrier {
        CommandDispatcher<?> getCommandsDispatcher();
    }

    /**
     * Typed bridge interface for server mocks or wrappers that expose a backing server object.
     */
    public interface BrigadierServerBridge extends Server {
        Object getServer();
    }

    /** Marker permission assigned when a Brigadier node has a non-default {@code requires} predicate that throws on synthetic sources. */
    public static final String UNKNOWN_BRIGADIER_REQUIRES = "<unknown-brigadier-requires>";

    private static final int MAX_BRIGADIER_DEPTH = 12;
    private static final Pattern USAGE_SUBCOMMANDS = Pattern.compile("<([a-zA-Z0-9_|:-]{2,120})>");
    private static final Predicate<?> DEFAULT_BRIGADIER_REQUIREMENT = resolveDefaultBrigadierRequirement();

    private PaperCommandTreeInspector() {
    }

    /**
     * Inspects the live server's command surface across {@code default} and {@code op} tiers and
     * runs {@link CommandSurfaceAuditor#auditCommandSurface(Map, Collection, JarClassOwnershipIndex)}.
     *
     * @param server         Bukkit/Paper server instance (falls back to {@link Bukkit#getServer()} if null)
     * @param extraDeny      optional additional denylist entries
     * @param ownershipIndex optional JAR class ownership index
     * @return command surface audit report
     */
    public static CommandAuditReport auditLiveServer(
            Server server,
            Collection<String> extraDeny,
            JarClassOwnershipIndex ownershipIndex
    ) {
        Server targetServer = server != null ? server : safeBukkitServer();
        Map<String, List<RawCommandNode>> tierGraphs = inspectTierCommandGraphs(targetServer);
        return CommandSurfaceAuditor.auditCommandSurface(tierGraphs, extraDeny, ownershipIndex);
    }

    /**
     * Extracts the per-tier ({@code "default"} and {@code "op"}) raw command node trees from the given
     * {@link Server}'s {@link CommandMap} and Brigadier dispatcher.
     *
     * @param server Bukkit/Paper server instance
     * @return map containing {@code "default"} and {@code "op"} command root lists with tier-filtered subtrees
     */
    public static Map<String, List<RawCommandNode>> inspectTierCommandGraphs(Server server) {
        return inspectTierCommandGraphs(server, null);
    }

    /**
     * Extracts the per-tier ({@code "default"} and {@code "op"}) raw command node trees from the given
     * {@link Server}'s {@link CommandMap} and an optional explicit {@link CommandDispatcher}.
     *
     * @param server              Bukkit/Paper server instance
     * @param explicitDispatcher  optional Brigadier dispatcher
     * @return map containing {@code "default"} and {@code "op"} command root lists with tier-filtered subtrees
     */
    public static Map<String, List<RawCommandNode>> inspectTierCommandGraphs(
            Server server,
            CommandDispatcher<?> explicitDispatcher
    ) {
        if (server == null && explicitDispatcher == null) {
            return Map.of("default", List.of(), "op", List.of());
        }
        Map<String, Command> knownCommands = extractKnownCommands(server);
        Map<String, CommandNode<?>> brigadierRoots = extractBrigadierRootChildren(server, explicitDispatcher);
        PluginManager pm = safePluginManager(server);

        TierCommandSender defaultSender = new TierCommandSender(server, pm, false);
        TierCommandSender opSender = new TierCommandSender(server, pm, true);

        List<RawCommandNode> defaultRoots = new ArrayList<>();
        List<RawCommandNode> opRoots = new ArrayList<>();

        try {
            Set<String> allLabels = new LinkedHashSet<>();
            allLabels.addAll(knownCommands.keySet());
            allLabels.addAll(brigadierRoots.keySet());

            Map<Command, String> canonicalLabelByCmd = new IdentityHashMap<>();
            for (Map.Entry<String, Command> e : knownCommands.entrySet()) {
                Command c = e.getValue();
                if (c != null && c.getName() != null && !c.getName().isBlank()) {
                    canonicalLabelByCmd.putIfAbsent(c, c.getName().toLowerCase(Locale.ROOT));
                }
            }

            for (String rawLabel : allLabels) {
                if (rawLabel == null || rawLabel.isBlank()) {
                    continue;
                }
                String label = rawLabel.trim();
                Command bukkitCmd = knownCommands.get(rawLabel);
                CommandNode<?> brigNode = brigadierRoots.get(rawLabel);

                String declaredPerm = extractCommandPermission(bukkitCmd);
                String owningPlugin = extractOwningPlugin(bukkitCmd, label);
                String redirectTarget = extractBrigadierRedirectName(brigNode);
                if (redirectTarget == null && bukkitCmd != null) {
                    String canon = canonicalLabelByCmd.get(bukkitCmd);
                    String[] nsBare = CommandSurfaceAuditor.splitNamespace(label.toLowerCase(Locale.ROOT));
                    if (canon != null && !nsBare[0].isEmpty() && nsBare[1].equals(canon) && !label.equalsIgnoreCase(canon)) {
                        redirectTarget = canon;
                    }
                }

                RawCommandNode defaultRoot = buildRootForTier(
                        label,
                        bukkitCmd,
                        brigNode,
                        declaredPerm,
                        owningPlugin,
                        redirectTarget,
                        defaultSender
                );
                if (defaultRoot != null) {
                    defaultRoots.add(defaultRoot);
                }

                RawCommandNode opRoot = buildRootForTier(
                        label,
                        bukkitCmd,
                        brigNode,
                        declaredPerm,
                        owningPlugin,
                        redirectTarget,
                        opSender
                );
                if (opRoot != null) {
                    opRoots.add(opRoot);
                }
            }
        } finally {
            defaultSender.close();
            opSender.close();
        }

        Map<String, List<RawCommandNode>> out = new LinkedHashMap<>();
        out.put("default", Collections.unmodifiableList(defaultRoots));
        out.put("op", Collections.unmodifiableList(opRoots));
        return Collections.unmodifiableMap(out);
    }

    private static RawCommandNode buildRootForTier(
            String label,
            Command bukkitCmd,
            CommandNode<?> brigNode,
            String declaredPerm,
            String owningPlugin,
            String redirectTarget,
            TierCommandSender tierSender
    ) {
        boolean bukkitAllowed = true;
        if (bukkitCmd != null) {
            bukkitAllowed = testBukkitCommandPermission(bukkitCmd, tierSender);
        }
        if (!bukkitAllowed) {
            return null;
        }

        String effectivePerm = declaredPerm;
        if (brigNode != null) {
            BrigadierEval rootEval = evaluateBrigadierRequirement(brigNode, tierSender);
            if (rootEval.status == EvalStatus.DENIED) {
                return null;
            }
            if (rootEval.status == EvalStatus.UNKNOWN) {
                if (bukkitCmd == null && !tierSender.isOp()) {
                    return null;
                }
                if (bukkitCmd == null && effectivePerm == null) {
                    effectivePerm = UNKNOWN_BRIGADIER_REQUIRES;
                }
            } else if (effectivePerm == null && rootEval.queriedPermission != null) {
                effectivePerm = rootEval.queriedPermission;
            }
        }

        List<RawCommandNode> children = extractChildrenForTier(
                label,
                bukkitCmd,
                brigNode,
                effectivePerm,
                owningPlugin,
                tierSender
        );
        boolean executable = isExecutable(bukkitCmd, brigNode, children);
        return new RawCommandNode(
                label,
                "literal",
                null,
                Map.of(),
                executable,
                redirectTarget,
                effectivePerm,
                owningPlugin,
                children
        );
    }

    public static boolean isPermittedForDefaultTier(
            String permission,
            String commandLabel,
            PluginManager pluginManager
    ) {
        return isPermittedForTier(permission, false, pluginManager);
    }

    public static boolean isPermittedForTier(
            String permission,
            boolean isOp,
            PluginManager pluginManager
    ) {
        if (permission == null || permission.isBlank()) {
            return true;
        }
        TierCommandSender sender = new TierCommandSender(null, pluginManager, isOp);
        try {
            return evaluatePermissionExpression(permission, sender);
        } finally {
            sender.close();
        }
    }

    public static CommandSender createTierSender(Server server, PluginManager pluginManager, boolean isOp) {
        return new TierCommandSender(server, pluginManager, isOp);
    }

    private static boolean testBukkitCommandPermission(Command bukkitCmd, TierCommandSender tierSender) {
        if (bukkitCmd == null) {
            return true;
        }
        String declaredPerm = extractCommandPermission(bukkitCmd);
        try {
            return bukkitCmd.testPermissionSilent(tierSender);
        } catch (Throwable ignored) {
            return evaluatePermissionExpression(declaredPerm, tierSender);
        }
    }

    private static boolean evaluatePermissionExpression(String permission, TierCommandSender tierSender) {
        if (permission == null || permission.isBlank()) {
            return true;
        }
        for (String part : permission.split(";")) {
            String p = part.trim();
            if (!p.isEmpty() && tierSender.hasPermission(p)) {
                return true;
            }
        }
        return false;
    }

    static Map<String, Command> extractKnownCommands(Server server) {
        Map<String, Command> result = new LinkedHashMap<>();
        if (server == null) {
            return result;
        }
        try {
            CommandMap commandMap = server.getCommandMap();
            if (commandMap == null) {
                return result;
            }
            Map<String, Command> rawMap = commandMap.getKnownCommands();
            if (rawMap != null) {
                for (Map.Entry<String, Command> e : rawMap.entrySet()) {
                    if (e.getKey() != null && e.getValue() != null) {
                        result.put(e.getKey(), e.getValue());
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return result;
    }

    private static Map<String, CommandNode<?>> extractBrigadierRootChildren(
            Server server,
            CommandDispatcher<?> explicitDispatcher
    ) {
        Map<String, CommandNode<?>> out = new LinkedHashMap<>();
        try {
            CommandDispatcher<?> dispatcher = explicitDispatcher;
            if (dispatcher == null && server instanceof BrigadierDispatcherCarrier carrier) {
                dispatcher = carrier.getCommandsDispatcher();
            }
            if (dispatcher == null && server instanceof BrigadierServerBridge bridge) {
                Object mcServer = bridge.getServer();
                if (mcServer instanceof BrigadierDispatcherCarrier carrier) {
                    dispatcher = carrier.getCommandsDispatcher();
                } else if (mcServer instanceof CommandDispatcher<?> direct) {
                    dispatcher = direct;
                }
            }
            if (dispatcher == null) {
                return out;
            }
            RootCommandNode<?> root = dispatcher.getRoot();
            if (root == null) {
                return out;
            }
            Collection<? extends CommandNode<?>> children = root.getChildren();
            if (children != null) {
                for (CommandNode<?> ch : children) {
                    if (ch == null) {
                        continue;
                    }
                    String name = ch.getName();
                    if (name != null && !name.isBlank()) {
                        out.put(name, ch);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private static List<RawCommandNode> extractChildrenForTier(
            String label,
            Command bukkitCmd,
            CommandNode<?> brigNode,
            String rootPerm,
            String owningPlugin,
            TierCommandSender tierSender
    ) {
        List<RawCommandNode> brigChildren = extractBrigadierChildrenForTier(
                brigNode,
                rootPerm,
                owningPlugin,
                tierSender,
                new IdentityHashMap<>(),
                1
        );
        if (!brigChildren.isEmpty()) {
            boolean onlyGenericArgsWrapper = brigChildren.size() == 1
                    && "argument".equals(brigChildren.get(0).kind())
                    && "args".equals(brigChildren.get(0).name())
                    && brigChildren.get(0).children().isEmpty();
            if (!onlyGenericArgsWrapper) {
                return brigChildren;
            }
            List<RawCommandNode> tabSubNodes = extractTabCompleteSubcommands(
                    bukkitCmd, label, rootPerm, owningPlugin, tierSender
            );
            if (!tabSubNodes.isEmpty()) {
                return tabSubNodes;
            }
            List<RawCommandNode> usageSubNodes = extractUsageSubcommands(bukkitCmd, rootPerm, owningPlugin);
            if (!usageSubNodes.isEmpty()) {
                return usageSubNodes;
            }
            RawCommandNode argsNode = brigChildren.get(0);
            if (bukkitCmd != null && UNKNOWN_BRIGADIER_REQUIRES.equals(argsNode.permission())) {
                return List.of(new RawCommandNode(
                        argsNode.name(),
                        argsNode.kind(),
                        argsNode.parser(),
                        argsNode.properties(),
                        argsNode.executable(),
                        argsNode.redirectTarget(),
                        rootPerm,
                        argsNode.owningPlugin(),
                        argsNode.children()
                ));
            }
            return brigChildren;
        }
        List<RawCommandNode> tabSubNodes = extractTabCompleteSubcommands(
                bukkitCmd, label, rootPerm, owningPlugin, tierSender
        );
        if (!tabSubNodes.isEmpty()) {
            return tabSubNodes;
        }
        return extractUsageSubcommands(bukkitCmd, rootPerm, owningPlugin);
    }

    private static List<RawCommandNode> extractTabCompleteSubcommands(
            Command bukkitCmd,
            String label,
            String rootPerm,
            String owner,
            TierCommandSender tierSender
    ) {
        if (bukkitCmd == null || tierSender == null) {
            return List.of();
        }
        Set<String> onlinePlayerNames = new LinkedHashSet<>();
        try {
            Server srv = tierSender.getServer();
            if (srv != null && srv.getOnlinePlayers() != null) {
                for (org.bukkit.entity.Player p : srv.getOnlinePlayers()) {
                    if (p != null && p.getName() != null) {
                        onlinePlayerNames.add(p.getName().toLowerCase(Locale.ROOT));
                    }
                }
            }
        } catch (Throwable ignored) {
        }

        CommandSender tabSender = tierSender.toPlayerProxy();
        List<String> topCompletions;
        try {
            String effectiveLabel = (label != null && !label.isBlank()) ? label : bukkitCmd.getName();
            topCompletions = bukkitCmd.tabComplete(tabSender, effectiveLabel, new String[]{""});
        } catch (Throwable t) {
            return List.of();
        }
        if (topCompletions == null || topCompletions.isEmpty()) {
            return List.of();
        }

        List<RawCommandNode> out = new ArrayList<>();
        Set<String> seenNames = new LinkedHashSet<>();
        String effectiveLabel = (label != null && !label.isBlank()) ? label : bukkitCmd.getName();
        int paramNodesAdded = 0;

        for (String raw : topCompletions) {
            if (raw == null) {
                continue;
            }
            String token = raw.trim();
            if (token.isEmpty()
                    || token.contains(" ")
                    || token.startsWith("<")
                    || token.startsWith("[")
                    || onlinePlayerNames.contains(token.toLowerCase(Locale.ROOT))) {
                continue;
            }
            if (token.endsWith("=")) {
                if (paramNodesAdded < 6) {
                    List<RawCommandNode> paramNodes = expandParameterCompletions(
                            bukkitCmd,
                            effectiveLabel,
                            new String[]{token},
                            token,
                            rootPerm,
                            owner,
                            tierSender,
                            tabSender,
                            onlinePlayerNames,
                            seenNames,
                            1
                    );
                    out.addAll(paramNodes);
                    paramNodesAdded += paramNodes.size();
                }
                continue;
            }
            if (!seenNames.add(token.toLowerCase(Locale.ROOT))) {
                continue;
            }
            List<RawCommandNode> secondLevel = new ArrayList<>();
            try {
                List<String> subCompletions = bukkitCmd.tabComplete(tabSender, effectiveLabel, new String[]{token, ""});
                if (subCompletions != null) {
                    Set<String> seenSub = new LinkedHashSet<>();
                    for (String subRaw : subCompletions) {
                        if (subRaw == null) {
                            continue;
                        }
                        String subTok = subRaw.trim();
                        if (subTok.isEmpty()
                                || subTok.contains(" ")
                                || subTok.startsWith("<")
                                || subTok.startsWith("[")
                                || subTok.endsWith("=")
                                || onlinePlayerNames.contains(subTok.toLowerCase(Locale.ROOT))) {
                            continue;
                        }
                        if (seenSub.add(subTok.toLowerCase(Locale.ROOT)) && secondLevel.size() < 4) {
                            secondLevel.add(new RawCommandNode(
                                    subTok,
                                    "literal",
                                    null,
                                    Map.of(),
                                    true,
                                    null,
                                    tierSender.isOp() ? (rootPerm != null ? rootPerm : "minecraft.op") : rootPerm,
                                    owner,
                                    List.of()
                            ));
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
            out.add(new RawCommandNode(
                    token,
                    "literal",
                    null,
                    Map.of(),
                    true,
                    null,
                    tierSender.isOp() ? (rootPerm != null ? rootPerm : "minecraft.op") : rootPerm,
                    owner,
                    secondLevel
            ));
        }
        return out;
    }

    private static List<RawCommandNode> expandParameterCompletions(
            Command bukkitCmd,
            String effectiveLabel,
            String[] argsWithPrefix,
            String paramPrefix,
            String rootPerm,
            String owner,
            TierCommandSender tierSender,
            CommandSender tabSender,
            Set<String> onlinePlayerNames,
            Set<String> seenNames,
            int maxPerParam
    ) {
        List<RawCommandNode> nodes = new ArrayList<>();
        try {
            List<String> values = bukkitCmd.tabComplete(tabSender, effectiveLabel, argsWithPrefix);
            int added = 0;
            if (values != null) {
                for (String vRaw : values) {
                    if (vRaw == null) {
                        continue;
                    }
                    String v = vRaw.trim();
                    if (v.isEmpty() || v.contains(" ") || v.endsWith("=")) {
                        continue;
                    }
                    String fullToken = v.startsWith(paramPrefix) ? v : (paramPrefix + v);
                    String valPart = fullToken.substring(paramPrefix.length());
                    if (valPart.isEmpty() || onlinePlayerNames.contains(valPart.toLowerCase(Locale.ROOT))) {
                        continue;
                    }
                    if (seenNames.add(fullToken.toLowerCase(Locale.ROOT))) {
                        nodes.add(new RawCommandNode(
                                fullToken,
                                "literal",
                                null,
                                Map.of(),
                                true,
                                null,
                                tierSender.isOp() ? (rootPerm != null ? rootPerm : "minecraft.op") : rootPerm,
                                owner,
                                List.of()
                        ));
                        added++;
                        if (added >= maxPerParam) {
                            break;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return nodes;
    }

    private static List<RawCommandNode> extractUsageSubcommands(
            Command bukkitCmd,
            String perm,
            String owner
    ) {
        if (bukkitCmd == null) {
            return List.of();
        }
        String usage = bukkitCmd.getUsage();
        if (usage == null || usage.isBlank()) {
            return List.of();
        }
        Matcher m = USAGE_SUBCOMMANDS.matcher(usage);
        if (m.find()) {
            String group = m.group(1);
            if (group != null && group.contains("|")) {
                String[] parts = group.split("\\|");
                List<RawCommandNode> subNodes = new ArrayList<>(parts.length);
                for (String p : parts) {
                    String clean = p.trim();
                    if (!clean.isEmpty() && !clean.contains(" ") && !clean.contains("=")) {
                        subNodes.add(new RawCommandNode(
                                clean,
                                "literal",
                                null,
                                Map.of(),
                                true,
                                null,
                                perm,
                                owner,
                                List.of()
                        ));
                    }
                }
                return subNodes;
            }
        }
        return List.of();
    }

    private static List<RawCommandNode> extractBrigadierChildrenForTier(
            CommandNode<?> brigNode,
            String parentPerm,
            String owningPlugin,
            TierCommandSender tierSender,
            Map<Object, Boolean> visited,
            int depth
    ) {
        if (brigNode == null || depth > MAX_BRIGADIER_DEPTH || visited.containsKey(brigNode)) {
            return List.of();
        }
        visited.put(brigNode, Boolean.TRUE);
        List<RawCommandNode> out = new ArrayList<>();
        try {
            Collection<? extends CommandNode<?>> children = brigNode.getChildren();
            if (children == null || children.isEmpty()) {
                return List.of();
            }
            for (CommandNode<?> ch : children) {
                if (ch == null) {
                    continue;
                }
                String name = ch.getName();
                if (name == null || name.isBlank()) {
                    continue;
                }
                BrigadierEval childEval = evaluateBrigadierRequirement(ch, tierSender);
                if (childEval.status == EvalStatus.DENIED) {
                    continue;
                }
                String childPerm = childEval.queriedPermission;
                if (childPerm == null && childEval.status == EvalStatus.UNKNOWN) {
                    childPerm = UNKNOWN_BRIGADIER_REQUIRES;
                }
                if (childPerm == null) {
                    childPerm = parentPerm;
                }
                boolean isArg = ch instanceof ArgumentCommandNode<?, ?>;
                String kind = isArg ? "argument" : "literal";
                String parser = isArg ? extractBrigadierParser((ArgumentCommandNode<?, ?>) ch) : null;
                Map<String, Object> props = isArg ? extractBrigadierProperties((ArgumentCommandNode<?, ?>) ch) : Map.of();
                Object cmdObj = ch.getCommand();
                String redir = extractBrigadierRedirectName(ch);
                List<RawCommandNode> grandChildren = extractBrigadierChildrenForTier(
                        ch,
                        childPerm,
                        owningPlugin,
                        tierSender,
                        new IdentityHashMap<>(visited),
                        depth + 1
                );
                boolean exec = cmdObj != null || grandChildren.isEmpty();
                out.add(new RawCommandNode(
                        name,
                        kind,
                        parser,
                        props,
                        exec,
                        redir,
                        childPerm,
                        owningPlugin,
                        grandChildren
                ));
            }
        } catch (Throwable ignored) {
        }
        return out;
    }

    private enum EvalStatus {
        ALLOWED,
        DENIED,
        UNKNOWN
    }

    private record BrigadierEval(EvalStatus status, String queriedPermission) {}

    @SuppressWarnings("unchecked")
    private static BrigadierEval evaluateBrigadierRequirement(
            CommandNode<?> brigNode,
            TierCommandSender tierSender
    ) {
        if (brigNode == null) {
            return new BrigadierEval(EvalStatus.ALLOWED, null);
        }
        try {
            Predicate<?> reqObj = brigNode.getRequirement();
            if (reqObj == null || isDefaultBrigadierRequirement(reqObj)) {
                return new BrigadierEval(EvalStatus.ALLOWED, null);
            }
            if (reqObj instanceof BrigadierPermissionRequirement<?> typedReq) {
                String perm = typedReq.requiredPermission();
                if (perm != null && !perm.isBlank()) {
                    boolean allowed = evaluatePermissionExpression(perm, tierSender);
                    return new BrigadierEval(allowed ? EvalStatus.ALLOWED : EvalStatus.DENIED, perm);
                }
                Integer lvl = typedReq.requiredPermissionLevel();
                if (lvl != null) {
                    boolean allowed = tierSender.isOp() || lvl <= 0;
                    return new BrigadierEval(
                            allowed ? EvalStatus.ALLOWED : EvalStatus.DENIED,
                            lvl > 0 ? "minecraft.op.level." + lvl : null
                    );
                }
            }
            tierSender.clearQueriedPermissions();
            try {
                boolean res = ((CommandNode<Object>) brigNode).canUse(tierSender);
                String queried = tierSender.joinedQueriedPermissions();
                return new BrigadierEval(res ? EvalStatus.ALLOWED : EvalStatus.DENIED, queried);
            } catch (Throwable t) {
                return new BrigadierEval(EvalStatus.UNKNOWN, null);
            }
        } catch (Throwable ignored) {
        }
        return new BrigadierEval(EvalStatus.ALLOWED, null);
    }

    private static Predicate<?> resolveDefaultBrigadierRequirement() {
        try {
            return LiteralArgumentBuilder.literal("_sleuth_probe_").getRequirement();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean isDefaultBrigadierRequirement(Predicate<?> reqObj) {
        if (reqObj == null) {
            return true;
        }
        if (DEFAULT_BRIGADIER_REQUIREMENT != null) {
            return reqObj == DEFAULT_BRIGADIER_REQUIREMENT
                    || reqObj.getClass() == DEFAULT_BRIGADIER_REQUIREMENT.getClass();
        }
        return false;
    }

    private static String extractBrigadierRedirectName(CommandNode<?> brigNode) {
        if (brigNode == null) {
            return null;
        }
        try {
            CommandNode<?> redir = brigNode.getRedirect();
            if (redir != null) {
                String name = redir.getName();
                if (name != null && !name.isBlank()) {
                    return name;
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static String extractBrigadierParser(ArgumentCommandNode<?, ?> argNode) {
        try {
            ArgumentType<?> typeObj = argNode.getType();
            if (typeObj == null) {
                return "brigadier:string";
            }
            if (typeObj instanceof IntegerArgumentType) {
                return "brigadier:integer";
            }
            if (typeObj instanceof LongArgumentType) {
                return "brigadier:long";
            }
            if (typeObj instanceof FloatArgumentType) {
                return "brigadier:float";
            }
            if (typeObj instanceof DoubleArgumentType) {
                return "brigadier:double";
            }
            String simple = typeObj.getClass().getSimpleName().toLowerCase(Locale.ROOT);
            if (simple.contains("bool")) {
                return "brigadier:bool";
            }
            if (simple.contains("entity") || simple.contains("player")) {
                return "minecraft:entity";
            }
            return "brigadier:string";
        } catch (Throwable ignored) {
            return "brigadier:string";
        }
    }

    private static Map<String, Object> extractBrigadierProperties(ArgumentCommandNode<?, ?> argNode) {
        Map<String, Object> props = new LinkedHashMap<>();
        try {
            ArgumentType<?> typeObj = argNode.getType();
            if (typeObj instanceof IntegerArgumentType intType) {
                props.put("min", intType.getMinimum());
                props.put("max", intType.getMaximum());
            } else if (typeObj instanceof LongArgumentType longType) {
                props.put("min", longType.getMinimum());
                props.put("max", longType.getMaximum());
            } else if (typeObj instanceof FloatArgumentType floatType) {
                props.put("min", floatType.getMinimum());
                props.put("max", floatType.getMaximum());
            } else if (typeObj instanceof DoubleArgumentType doubleType) {
                props.put("min", doubleType.getMinimum());
                props.put("max", doubleType.getMaximum());
            }
        } catch (Throwable ignored) {
        }
        return props;
    }

    private static boolean isExecutable(Command bukkitCmd, CommandNode<?> brigNode, List<RawCommandNode> children) {
        if (brigNode != null && brigNode.getCommand() != null) {
            return true;
        }
        return bukkitCmd != null || children.isEmpty();
    }

    private static String extractCommandPermission(Command cmd) {
        if (cmd == null) {
            return null;
        }
        try {
            String p = cmd.getPermission();
            return (p == null || p.isBlank()) ? null : p.trim();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String extractOwningPlugin(Command cmd, String label) {
        if (cmd instanceof PluginIdentifiableCommand pic) {
            try {
                Plugin plugin = pic.getPlugin();
                if (plugin != null && plugin.getName() != null && !plugin.getName().isBlank()) {
                    return plugin.getName();
                }
            } catch (Throwable ignored) {
            }
        }
        if (cmd != null) {
            String clsName = cmd.getClass().getName();
            if (!LogAndStallSignatureOracle.isPlatformOrJdkClass(clsName)) {
                return clsName;
            }
        }
        String[] nsBare = CommandSurfaceAuditor.splitNamespace(label == null ? "" : label);
        String ns = nsBare[0];
        if (!ns.isEmpty()
                && !"minecraft".equalsIgnoreCase(ns)
                && !"bukkit".equalsIgnoreCase(ns)
                && !"spigot".equalsIgnoreCase(ns)
                && !"paper".equalsIgnoreCase(ns)) {
            return ns;
        }
        return null;
    }

    private static Server safeBukkitServer() {
        try {
            return Bukkit.getServer();
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static PluginManager safePluginManager(Server server) {
        if (server == null) {
            return null;
        }
        try {
            return server.getPluginManager();
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Direct compile-time {@link CommandSender} and {@link CommandSourceStack} implementation
     * for {@code default} ({@code isOp = false}) and {@code op} ({@code isOp = true}) evaluation
     * with zero reflection or dynamic proxies.
     */
    static final class TierCommandSender implements CommandSender, CommandSourceStack, ServerOperator {
        private final Server server;
        private final PluginManager pluginManager;
        private final boolean op;
        private final PermissibleBase permissibleBase;
        private final Map<String, Boolean> computedDefaultPermissions;
        private final Set<String> queriedPermissions = new LinkedHashSet<>();
        private final Spigot spigotDelegate = new Spigot();

        TierCommandSender(Server server, PluginManager pluginManager, boolean op) {
            this.server = server;
            this.pluginManager = pluginManager;
            this.op = op;
            PermissibleBase base = null;
            try {
                Server globalServer = safeBukkitServer();
                if (globalServer != null
                        && globalServer.getPluginManager() != null
                        && (pluginManager == null || globalServer.getPluginManager() == pluginManager)) {
                    base = new PermissibleBase(new ServerOperator() {
                        @Override
                        public boolean isOp() {
                            return op;
                        }

                        @Override
                        public void setOp(boolean value) {
                        }
                    });
                }
            } catch (Throwable ignored) {
                base = null;
            }
            this.permissibleBase = base;
            this.computedDefaultPermissions = computeRecursiveDefaultPermissions(pluginManager, op);
        }

        void close() {
            if (permissibleBase != null) {
                try {
                    permissibleBase.clearPermissions();
                } catch (Throwable ignored) {
                }
            }
        }

        void clearQueriedPermissions() {
            queriedPermissions.clear();
        }

        String joinedQueriedPermissions() {
            if (queriedPermissions.isEmpty()) {
                return null;
            }
            return String.join(";", queriedPermissions);
        }

        @Override
        public void sendMessage(String message) {
        }

        @Override
        public void sendMessage(String... messages) {
        }

        @Override
        public void sendMessage(UUID sender, String message) {
        }

        @Override
        public void sendMessage(UUID sender, String... messages) {
        }

        @Override
        public Server getServer() {
            return server;
        }

        @Override
        public String getName() {
            return op ? "LeafFuzzTierOp" : "LeafFuzzTierDefault";
        }

        @Override
        public Spigot spigot() {
            return spigotDelegate;
        }

        @Override
        public Component name() {
            return Component.text(getName());
        }

        @Override
        public Location getLocation() {
            return null;
        }

        @Override
        public CommandSender getSender() {
            return this;
        }

        @Override
        public Entity getExecutor() {
            return null;
        }

        @Override
        public CommandSourceStack withLocation(Location location) {
            return this;
        }

        @Override
        public CommandSourceStack withExecutor(Entity executor) {
            return this;
        }

        @Override
        public boolean isOp() {
            return op;
        }

        @Override
        public void setOp(boolean value) {
        }

        @Override
        public boolean isPermissionSet(String name) {
            if (name == null || name.isBlank()) {
                return false;
            }
            String trimmed = name.trim();
            if (permissibleBase != null) {
                try {
                    if (permissibleBase.isPermissionSet(trimmed)) {
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
            if (computedDefaultPermissions.containsKey(trimmed.toLowerCase(Locale.ROOT))) {
                return true;
            }
            return findRegisteredPermission(pluginManager, trimmed) != null;
        }

        @Override
        public boolean isPermissionSet(Permission perm) {
            if (perm == null) {
                return false;
            }
            return isPermissionSet(perm.getName());
        }

        @Override
        public boolean hasPermission(String inName) {
            if (inName == null || inName.isBlank()) {
                return true;
            }
            String name = inName.trim();
            String lower = name.toLowerCase(Locale.ROOT);
            queriedPermissions.add(name);
            if (permissibleBase != null) {
                try {
                    if (permissibleBase.isPermissionSet(name)) {
                        return permissibleBase.hasPermission(name);
                    }
                    if (permissibleBase.isPermissionSet(lower)) {
                        return permissibleBase.hasPermission(lower);
                    }
                } catch (Throwable ignored) {
                }
            }
            Boolean recursiveGrant = computedDefaultPermissions.get(lower);
            if (recursiveGrant != null) {
                return recursiveGrant;
            }
            Permission registered = findRegisteredPermission(pluginManager, name);
            if (registered != null) {
                PermissionDefault def = registered.getDefault() != null
                        ? registered.getDefault()
                        : Permission.DEFAULT_PERMISSION;
                return def.getValue(op);
            }
            return Permission.DEFAULT_PERMISSION.getValue(op);
        }

        @Override
        public boolean hasPermission(Permission perm) {
            if (perm == null) {
                return true;
            }
            String name = perm.getName();
            if (name != null && !name.isBlank()) {
                queriedPermissions.add(name.trim());
                String lower = name.trim().toLowerCase(Locale.ROOT);
                if (permissibleBase != null) {
                    try {
                        if (permissibleBase.isPermissionSet(name)) {
                            return permissibleBase.hasPermission(perm);
                        }
                        if (permissibleBase.isPermissionSet(lower)) {
                            return permissibleBase.hasPermission(lower);
                        }
                    } catch (Throwable ignored) {
                    }
                }
                Boolean recursiveGrant = computedDefaultPermissions.get(lower);
                if (recursiveGrant != null) {
                    return recursiveGrant;
                }
                Permission registered = findRegisteredPermission(pluginManager, name);
                if (registered != null && registered.getDefault() != null) {
                    return registered.getDefault().getValue(op);
                }
            }
            PermissionDefault def = perm.getDefault() != null ? perm.getDefault() : Permission.DEFAULT_PERMISSION;
            return def.getValue(op);
        }

        @Override
        public PermissionAttachment addAttachment(Plugin plugin, String name, boolean value) {
            return null;
        }

        @Override
        public PermissionAttachment addAttachment(Plugin plugin) {
            return null;
        }

        @Override
        public PermissionAttachment addAttachment(Plugin plugin, String name, boolean value, int ticks) {
            return null;
        }

        @Override
        public PermissionAttachment addAttachment(Plugin plugin, int ticks) {
            return null;
        }

        @Override
        public void removeAttachment(PermissionAttachment attachment) {
        }

        @Override
        public void recalculatePermissions() {
            if (permissibleBase != null) {
                try {
                    permissibleBase.recalculatePermissions();
                } catch (Throwable ignored) {
                }
            }
        }

        CommandSender toPlayerProxy() {
            final UUID probeUuid = op
                    ? UUID.fromString("00000000-0000-0000-0000-00000000f001")
                    : UUID.fromString("00000000-0000-0000-0000-00000000f000");
            return (CommandSender) java.lang.reflect.Proxy.newProxyInstance(
                    org.bukkit.entity.Player.class.getClassLoader(),
                    new Class<?>[]{org.bukkit.entity.Player.class},
                    (proxy, method, args) -> {
                        String m = method.getName();
                        switch (m) {
                            case "getUniqueId" -> {
                                return probeUuid;
                            }
                            case "getName", "getDisplayName", "getPlayerListName" -> {
                                return getName();
                            }
                            case "isOp" -> {
                                return isOp();
                            }
                            case "hasPermission" -> {
                                if (args != null && args.length == 1) {
                                    if (args[0] instanceof String s) {
                                        return hasPermission(s);
                                    }
                                    if (args[0] instanceof Permission p) {
                                        return hasPermission(p);
                                    }
                                }
                                return isOp();
                            }
                            case "isPermissionSet" -> {
                                if (args != null && args.length == 1) {
                                    if (args[0] instanceof String s) {
                                        return isPermissionSet(s);
                                    }
                                    if (args[0] instanceof Permission p) {
                                        return isPermissionSet(p);
                                    }
                                }
                                return false;
                            }
                            case "getServer" -> {
                                return getServer();
                            }
                            case "isOnline", "isValid" -> {
                                return true;
                            }
                            case "equals" -> {
                                return args != null && args.length == 1 && proxy == args[0];
                            }
                            case "hashCode" -> {
                                return System.identityHashCode(proxy);
                            }
                            case "toString" -> {
                                return "TierPlayerProbe[" + getName() + "]";
                            }
                            default -> {
                                Class<?> ret = method.getReturnType();
                                if (ret == boolean.class) return false;
                                if (ret == int.class) return 0;
                                if (ret == long.class) return 0L;
                                if (ret == float.class) return 0.0f;
                                if (ret == double.class) return 0.0d;
                                if (ret == String.class) return "";
                                if (List.class.isAssignableFrom(ret)) return List.of();
                                if (Set.class.isAssignableFrom(ret)) return Set.of();
                                if (Map.class.isAssignableFrom(ret)) return Map.of();
                                return null;
                            }
                        }
                    }
            );
        }

        @Override
        public Set<PermissionAttachmentInfo> getEffectivePermissions() {
            if (permissibleBase != null) {
                try {
                    return permissibleBase.getEffectivePermissions();
                } catch (Throwable ignored) {
                }
            }
            return Set.of();
        }

        private static Permission findRegisteredPermission(PluginManager pm, String name) {
            if (pm == null || name == null || name.isBlank()) {
                return null;
            }
            try {
                Permission exact = pm.getPermission(name);
                if (exact != null) {
                    return exact;
                }
                String lower = name.toLowerCase(Locale.ROOT);
                if (!lower.equals(name)) {
                    Permission lowPerm = pm.getPermission(lower);
                    if (lowPerm != null) {
                        return lowPerm;
                    }
                }
                Set<Permission> all = pm.getPermissions();
                if (all != null) {
                    for (Permission p : all) {
                        if (p != null && p.getName() != null && p.getName().equalsIgnoreCase(name)) {
                            return p;
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
            return null;
        }

        private static Map<String, Boolean> computeRecursiveDefaultPermissions(PluginManager pm, boolean op) {
            if (pm == null) {
                return Map.of();
            }
            Map<String, Boolean> effective = new LinkedHashMap<>();
            try {
                Set<Permission> rootDefaults = new LinkedHashSet<>();
                Set<Permission> fromGetDefault = pm.getDefaultPermissions(op);
                if (fromGetDefault != null) {
                    rootDefaults.addAll(fromGetDefault);
                }
                Set<Permission> allPerms = pm.getPermissions();
                if (allPerms != null) {
                    for (Permission p : allPerms) {
                        if (p != null) {
                            PermissionDefault def = p.getDefault() != null ? p.getDefault() : Permission.DEFAULT_PERMISSION;
                            if (def.getValue(op)) {
                                rootDefaults.add(p);
                            }
                        }
                    }
                }
                Set<String> visited = new LinkedHashSet<>();
                for (Permission parent : rootDefaults) {
                    if (parent == null || parent.getName() == null || parent.getName().isBlank()) {
                        continue;
                    }
                    String lower = parent.getName().toLowerCase(Locale.ROOT);
                    effective.put(lower, Boolean.TRUE);
                    if (parent.getChildren() != null && !parent.getChildren().isEmpty()) {
                        calculateChildPermissionsRecursive(parent.getChildren(), false, effective, pm, visited);
                    }
                }
            } catch (Throwable ignored) {
            }
            return Collections.unmodifiableMap(effective);
        }

        private static void calculateChildPermissionsRecursive(
                Map<String, Boolean> children,
                boolean invert,
                Map<String, Boolean> effective,
                PluginManager pm,
                Set<String> visited
        ) {
            if (children == null || children.isEmpty()) {
                return;
            }
            for (Map.Entry<String, Boolean> entry : children.entrySet()) {
                String childName = entry.getKey();
                if (childName == null || childName.isBlank()) {
                    continue;
                }
                boolean value = Boolean.TRUE.equals(entry.getValue()) ^ invert;
                String lower = childName.trim().toLowerCase(Locale.ROOT);
                effective.put(lower, value);
                if (visited.add(lower + ":" + value)) {
                    Permission childPerm = findRegisteredPermission(pm, lower);
                    if (childPerm != null && childPerm.getChildren() != null && !childPerm.getChildren().isEmpty()) {
                        calculateChildPermissionsRecursive(childPerm.getChildren(), !value, effective, pm, visited);
                    }
                }
            }
        }
    }
}
