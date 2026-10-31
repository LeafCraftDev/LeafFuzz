package net.leaf.fuzz.common;

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
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;

/**
 * Platform-neutral Brigadier {@link CommandDispatcher} inspector and target-plugin/mod
 * command-tree filter for Paper, Folia, Fabric, and NeoForge ({@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Extracts {@link RawCommandNode} trees across {@code default} (permission level {@code 0}) and
 * {@code op} (permission level {@code 4}) tiers from any live Brigadier {@code CommandDispatcher}
 * instance using compile-time Brigadier types and {@link JarClassOwnershipIndex} class-to-JAR
 * attribution, with zero reflection and zero Minecraft, Bukkit, Fabric, or NeoForge bytecode imports.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace S-005
 */
public final class BrigadierDispatcherInspector {

    /**
     * Optional typed predicate interface for Brigadier {@code requires} predicates that declare an
     * explicit permission node or permission level.
     */
    public interface BrigadierPermissionRequirement<S> extends Predicate<S> {
        default String requiredPermission() {
            return null;
        }

        default Integer requiredPermissionLevel() {
            return null;
        }
    }

    private static final int MAX_BRIGADIER_DEPTH = 12;
    private static final Predicate<?> DEFAULT_BRIGADIER_REQUIREMENT = resolveDefaultBrigadierRequirement();

    private BrigadierDispatcherInspector() {
    }

    /**
     * Extracts per-tier ({@code "default"} and {@code "op"}) {@link RawCommandNode} graphs from a
     * live Brigadier {@code CommandDispatcher} object.
     *
     * @param dispatcher     Brigadier {@code CommandDispatcher<?>} instance (nullable)
     * @param ownershipIndex optional JAR class ownership index for attributing command executor classes
     * @return immutable map with {@code "default"} and {@code "op"} root node lists
     */
    public static Map<String, List<RawCommandNode>> inspectDispatcher(
            Object dispatcher,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (!(dispatcher instanceof CommandDispatcher<?> brigDispatcher)) {
            return Map.of("default", List.of(), "op", List.of());
        }
        JarClassOwnershipIndex idx = ownershipIndex != null ? ownershipIndex : JarClassOwnershipIndex.empty();
        List<RawCommandNode> defaultRoots = new ArrayList<>();
        List<RawCommandNode> opRoots = new ArrayList<>();

        try {
            RootCommandNode<?> root = brigDispatcher.getRoot();
            if (root != null) {
                Collection<? extends CommandNode<?>> children = root.getChildren();
                if (children != null) {
                    for (CommandNode<?> ch : children) {
                        if (ch == null) {
                            continue;
                        }
                        RawCommandNode defNode = extractNodeForTier(ch, null, null, false, idx, new IdentityHashMap<>(), 1);
                        if (defNode != null) {
                            defaultRoots.add(defNode);
                        }
                        RawCommandNode opNode = extractNodeForTier(ch, null, null, true, idx, new IdentityHashMap<>(), 1);
                        if (opNode != null) {
                            opRoots.add(opNode);
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
            // Safe fallback when dispatcher inspection fails
        }

        Map<String, List<RawCommandNode>> out = new LinkedHashMap<>();
        out.put("default", Collections.unmodifiableList(defaultRoots));
        out.put("op", Collections.unmodifiableList(opRoots));
        return Collections.unmodifiableMap(out);
    }

    /**
     * Parses a target filter expression (e.g. {@code "all"}, {@code "PluginA"}, or
     * comma-separated {@code "PluginA,PluginB"}) into normalized lowercase target selectors.
     * Returns an empty list when {@code targetFilter} is {@code null}, blank, or contains {@code "all"}.
     *
     * @param targetFilter raw target filter string
     * @return immutable list of normalized target selectors, or empty list for whole-server ({@code "all"})
     */
    public static List<String> parseTargetSelectors(String targetFilter) {
        if (targetFilter == null || targetFilter.isBlank()) {
            return List.of();
        }
        String[] parts = targetFilter.split(",");
        List<String> selectors = new ArrayList<>(parts.length);
        for (String raw : parts) {
            if (raw == null) {
                continue;
            }
            String trimmed = raw.trim().toLowerCase(Locale.ROOT);
            if (trimmed.isEmpty()) {
                continue;
            }
            if ("all".equals(trimmed) || "*".equals(trimmed)) {
                return List.of();
            }
            selectors.add(trimmed);
        }
        return Collections.unmodifiableList(selectors);
    }

    /**
     * Resolves the set of canonical target tokens (plugin/mod IDs, JAR names, and selector stems)
     * matching one or more target selectors against {@code ownershipIndex}.
     *
     * @param targetFilter   single target, comma-separated target list, or {@code "all"}
     * @param ownershipIndex JAR ownership index for resolving plugin/mod IDs to JAR names
     * @return immutable list of matched lowercase tokens, or empty list when {@code targetFilter} is {@code "all"}
     */
    public static List<String> resolveMatchedTargetTokens(
            String targetFilter,
            JarClassOwnershipIndex ownershipIndex
    ) {
        List<String> selectors = parseTargetSelectors(targetFilter);
        if (selectors.isEmpty()) {
            return List.of();
        }
        List<String> matchedTokens = new ArrayList<>();
        for (String query : selectors) {
            String queryNoJar = stripJarSuffix(query);
            addUniqueToken(matchedTokens, query);
            addUniqueToken(matchedTokens, queryNoJar);
            if (ownershipIndex != null) {
                for (JarClassOwnershipIndex.JarDescriptor desc : ownershipIndex.descriptors().values()) {
                    String jarLow = desc.jarName().toLowerCase(Locale.ROOT);
                    String jarStem = stripVersionAndJarSuffix(jarLow);
                    String idLow = desc.pluginId().toLowerCase(Locale.ROOT);
                    if (jarLow.equals(query)
                            || jarLow.equals(queryNoJar + ".jar")
                            || jarStem.equals(queryNoJar)
                            || jarLow.startsWith(queryNoJar + "-")
                            || jarLow.startsWith(queryNoJar + "_")
                            || jarLow.startsWith(queryNoJar + ".")
                            || idLow.equals(queryNoJar)) {
                        addUniqueToken(matchedTokens, jarLow);
                        addUniqueToken(matchedTokens, jarStem);
                        addUniqueToken(matchedTokens, idLow);
                    }
                }
            }
        }
        return Collections.unmodifiableList(matchedTokens);
    }

    private static void addUniqueToken(List<String> tokens, String token) {
        if (token != null && !token.isBlank() && !tokens.contains(token)) {
            tokens.add(token);
        }
    }

    private static String stripJarSuffix(String s) {
        if (s != null && s.endsWith(".jar") && s.length() > 4) {
            return s.substring(0, s.length() - 4);
        }
        return s != null ? s : "";
    }

    private static String stripVersionAndJarSuffix(String jarNameLower) {
        String noJar = stripJarSuffix(jarNameLower);
        int dashIdx = noJar.indexOf('-');
        if (dashIdx > 0 && dashIdx + 1 < noJar.length() && Character.isDigit(noJar.charAt(dashIdx + 1))) {
            return noJar.substring(0, dashIdx);
        }
        return noJar;
    }

    /**
     * Filters a per-tier {@link RawCommandNode} map to commands owned by one or more targets in
     * {@code targetFilter} (matching plugin/mod ID, JAR file name, comma-separated target list,
     * or command namespace). Returns {@code tierGraphs} unchanged when {@code targetFilter} is
     * {@code null}, blank, or {@code "all"}.
     *
     * @param tierGraphs     per-tier raw command trees
     * @param targetFilter   one or more comma-separated plugin/mod names, JAR names, or {@code "all"}
     * @param ownershipIndex JAR ownership index for resolving plugin/mod IDs to JAR names
     * @return filtered per-tier raw command trees
     */
    public static Map<String, List<RawCommandNode>> filterTierGraphsForTarget(
            Map<String, List<RawCommandNode>> tierGraphs,
            String targetFilter,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (tierGraphs == null || tierGraphs.isEmpty()) {
            return Map.of("default", List.of(), "op", List.of());
        }
        List<String> matchedTokens = resolveMatchedTargetTokens(targetFilter, ownershipIndex);
        if (matchedTokens.isEmpty()) {
            return tierGraphs;
        }

        Map<String, List<RawCommandNode>> filtered = new LinkedHashMap<>();
        for (Map.Entry<String, List<RawCommandNode>> entry : tierGraphs.entrySet()) {
            List<RawCommandNode> kept = new ArrayList<>();
            if (entry.getValue() != null) {
                for (RawCommandNode root : entry.getValue()) {
                    if (matchesTargetNode(root, matchedTokens, ownershipIndex)) {
                        kept.add(root);
                    }
                }
            }
            filtered.put(entry.getKey(), Collections.unmodifiableList(kept));
        }
        return Collections.unmodifiableMap(filtered);
    }

    /**
     * Checks whether an owning JAR name, plugin/mod identifier, or class/frame name belongs to
     * any target in {@code targetFilter}. Returns {@code true} for all inputs when
     * {@code targetFilter} is {@code null}, blank, or {@code "all"}.
     *
     * @param candidateOwnerOrJar owning JAR or plugin/mod identifier
     * @param candidateClassOrFrame class name or stack frame
     * @param targetFilter single target, comma-separated targets, or {@code "all"}
     * @param ownershipIndex JAR ownership index
     * @return {@code true} if the candidate matches any requested target
     */
    public static boolean matchesTargetIdentifier(
            String candidateOwnerOrJar,
            String candidateClassOrFrame,
            String targetFilter,
            JarClassOwnershipIndex ownershipIndex
    ) {
        List<String> matchedTokens = resolveMatchedTargetTokens(targetFilter, ownershipIndex);
        if (matchedTokens.isEmpty()) {
            return true;
        }
        if (candidateOwnerOrJar != null && !candidateOwnerOrJar.isBlank()) {
            if (tokenMatchesIdentifier(candidateOwnerOrJar.trim().toLowerCase(Locale.ROOT), matchedTokens)) {
                return true;
            }
        }
        if (candidateClassOrFrame != null && !candidateClassOrFrame.isBlank()) {
            String cleanClass = candidateClassOrFrame.trim();
            int hashIdx = cleanClass.indexOf('#');
            if (hashIdx > 0) {
                cleanClass = cleanClass.substring(0, hashIdx);
            }
            if (ownershipIndex != null) {
                Optional<String> jarOpt = ownershipIndex.ownerJarForClass(cleanClass);
                if (jarOpt.isPresent()
                        && tokenMatchesIdentifier(jarOpt.get().toLowerCase(Locale.ROOT), matchedTokens)) {
                    return true;
                }
            }
            String clsLow = cleanClass.toLowerCase(Locale.ROOT);
            for (String tok : matchedTokens) {
                String tokNoJar = stripJarSuffix(tok);
                if (!tokNoJar.isEmpty()
                        && (clsLow.equals(tokNoJar)
                        || clsLow.contains("." + tokNoJar + ".")
                        || clsLow.startsWith(tokNoJar + "."))) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean tokenMatchesIdentifier(String idLow, List<String> matchedTokens) {
        String idStem = stripVersionAndJarSuffix(idLow);
        String idNoJar = stripJarSuffix(idLow);
        for (String tok : matchedTokens) {
            String tokStem = stripVersionAndJarSuffix(tok);
            String tokNoJar = stripJarSuffix(tok);
            if (idLow.equals(tok)
                    || idNoJar.equals(tokNoJar)
                    || idStem.equals(tokStem)
                    || idLow.startsWith(tokNoJar + "-")
                    || idLow.startsWith(tokNoJar + "_")
                    || idLow.startsWith(tokNoJar + ".")) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesTargetNode(
            RawCommandNode node,
            List<String> matchedTokens,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (node == null) {
            return false;
        }
        String[] nsBare = CommandSurfaceAuditor.splitNamespace(node.name().toLowerCase(Locale.ROOT));
        String ns = nsBare[0];
        String bare = nsBare[1];
        for (String tok : matchedTokens) {
            String tokNoJar = stripJarSuffix(tok);
            if (!ns.isEmpty() && (ns.equals(tokNoJar) || ns.equals(tok) || tokNoJar.startsWith(ns + "-"))) {
                return true;
            }
            if (bare.equals(tokNoJar) || bare.equals(tok)) {
                return true;
            }
        }
        String owner = node.owningPlugin();
        if (owner != null && !owner.isBlank()) {
            String ownerLow = owner.trim().toLowerCase(Locale.ROOT);
            if (tokenMatchesIdentifier(ownerLow, matchedTokens)) {
                return true;
            }
            if (ownershipIndex != null) {
                Optional<String> jarOpt = ownershipIndex.ownerJarForClass(owner);
                if (jarOpt.isPresent()
                        && tokenMatchesIdentifier(jarOpt.get().toLowerCase(Locale.ROOT), matchedTokens)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static RawCommandNode extractNodeForTier(
            CommandNode<?> brigNode,
            String inheritedPerm,
            String inheritedOwner,
            boolean isOp,
            JarClassOwnershipIndex ownershipIndex,
            Map<Object, Boolean> visited,
            int depth
    ) {
        if (brigNode == null || depth > MAX_BRIGADIER_DEPTH || visited.containsKey(brigNode)) {
            return null;
        }
        visited.put(brigNode, Boolean.TRUE);
        try {
            String name = brigNode.getName();
            if (name == null || name.isBlank()) {
                return null;
            }

            RequirementEval eval = evaluateRequirement(brigNode, isOp);
            if (!eval.allowed) {
                return null;
            }
            String effectivePerm = eval.permission != null ? eval.permission : inheritedPerm;

            Object cmdObj = brigNode.getCommand();
            String owner = resolveNodeOwner(name, cmdObj, inheritedOwner, ownershipIndex);

            boolean isArg = brigNode instanceof ArgumentCommandNode<?, ?>;
            String kind = isArg ? "argument" : "literal";
            String parser = isArg ? extractBrigadierParser((ArgumentCommandNode<?, ?>) brigNode) : null;
            Map<String, Object> props = isArg ? extractBrigadierProperties((ArgumentCommandNode<?, ?>) brigNode) : Map.of();
            String redirect = extractRedirectName(brigNode);

            List<RawCommandNode> children = new ArrayList<>();
            Collection<? extends CommandNode<?>> rawChildren = brigNode.getChildren();
            if (rawChildren != null) {
                for (CommandNode<?> ch : rawChildren) {
                    RawCommandNode childNode = extractNodeForTier(
                            ch,
                            effectivePerm,
                            owner,
                            isOp,
                            ownershipIndex,
                            new IdentityHashMap<>(visited),
                            depth + 1
                    );
                    if (childNode != null) {
                        children.add(childNode);
                    }
                }
            }

            boolean executable = cmdObj != null || children.isEmpty();
            return new RawCommandNode(
                    name,
                    kind,
                    parser,
                    props,
                    executable,
                    redirect,
                    effectivePerm,
                    owner,
                    children
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    private record RequirementEval(boolean allowed, String permission) {
    }

    @SuppressWarnings("unchecked")
    private static RequirementEval evaluateRequirement(CommandNode<?> brigNode, boolean isOp) {
        try {
            Predicate<?> reqObj = brigNode.getRequirement();
            if (reqObj == null || isDefaultBrigadierRequirement(reqObj)) {
                return new RequirementEval(true, null);
            }
            if (reqObj instanceof BrigadierPermissionRequirement<?> typedReq) {
                Integer capturedLevel = typedReq.requiredPermissionLevel();
                String capturedPerm = typedReq.requiredPermission();
                if (capturedLevel != null) {
                    boolean allowed = isOp || capturedLevel <= 0;
                    String perm = capturedLevel > 0 ? "minecraft.op.level." + capturedLevel : capturedPerm;
                    return new RequirementEval(allowed, perm);
                }
                if (capturedPerm != null && !capturedPerm.isBlank()) {
                    return new RequirementEval(isOp, capturedPerm);
                }
            }
            try {
                Object tierSource = BrigadierSyntheticSourceFactory.createSource(
                        Object.class,
                        new UUID(0L, isOp ? 4L : 0L),
                        isOp ? "LeafFuzzOp" : "LeafFuzzDefault",
                        isOp,
                        0,
                        64,
                        0
                );
                boolean tierResult = ((Predicate<Object>) reqObj).test(tierSource);
                return new RequirementEval(tierResult, tierResult && !isOp ? null : "<brigadier-requires>");
            } catch (Throwable ignored) {
                try {
                    boolean nullResult = ((Predicate<Object>) reqObj).test(null);
                    return new RequirementEval(isOp || nullResult, nullResult ? null : "<brigadier-requires>");
                } catch (Throwable ignored2) {
                    return new RequirementEval(isOp, "<brigadier-requires>");
                }
            }
        } catch (Throwable ignored) {
        }
        return new RequirementEval(true, null);
    }

    private static String resolveNodeOwner(
            String nodeName,
            Object cmdObj,
            String inheritedOwner,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (cmdObj != null) {
            String cmdClass = cmdObj.getClass().getName();
            if (ownershipIndex != null) {
                Optional<String> jar = ownershipIndex.ownerJarForClass(cmdClass);
                if (jar.isPresent()) {
                    return jar.get();
                }
            }
            if (!LogAndStallSignatureOracle.isPlatformOrJdkClass(cmdClass)) {
                return cmdClass;
            }
        }
        if (inheritedOwner != null && !inheritedOwner.isBlank()) {
            return inheritedOwner;
        }
        String[] nsBare = CommandSurfaceAuditor.splitNamespace(nodeName.toLowerCase(Locale.ROOT));
        String ns = nsBare[0];
        if (!ns.isEmpty()
                && !"minecraft".equalsIgnoreCase(ns)
                && !"brigadier".equalsIgnoreCase(ns)
                && !"bukkit".equalsIgnoreCase(ns)
                && !"paper".equalsIgnoreCase(ns)
                && !"spigot".equalsIgnoreCase(ns)
                && !"fabric".equalsIgnoreCase(ns)
                && !"neoforge".equalsIgnoreCase(ns)) {
            return ns;
        }
        return null;
    }

    private static Predicate<?> resolveDefaultBrigadierRequirement() {
        try {
            return LiteralArgumentBuilder.literal("_leaffuzz_probe_").getRequirement();
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

    private static String extractRedirectName(CommandNode<?> brigNode) {
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
}
