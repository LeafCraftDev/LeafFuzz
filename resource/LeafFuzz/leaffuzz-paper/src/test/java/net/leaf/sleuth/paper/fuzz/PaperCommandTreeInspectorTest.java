package net.leaf.sleuth.paper.fuzz;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.IntegerArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.builder.RequiredArgumentBuilder;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.LeastPrivilegeFinding;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import org.bukkit.Server;
import org.bukkit.command.Command;
import org.bukkit.command.CommandMap;
import org.bukkit.command.CommandSender;
import org.bukkit.permissions.Permission;
import org.bukkit.permissions.PermissionDefault;
import org.bukkit.plugin.PluginManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PaperCommandTreeInspector} verifying Bukkit {@link PermissionDefault}
 * semantics ({@code OP}, {@code TRUE}, {@code NOT_OP}, {@code FALSE}, and unregistered permissions),
 * {@link Command#testPermissionSilent(CommandSender)} evaluation, and Brigadier per-tier subtree
 * extraction ({@code REQ-SLEUTH-FUZZ-003}, {@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace S-005
 */
class PaperCommandTreeInspectorTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: PaperCommandTreeInspector honors PermissionDefault OP/TRUE/NOT_OP/FALSE and denies unregistered permissions to default tier without suffix guessing")
    void honorsRegisteredPermissionDefaultsAndDeniesUnregisteredPermissionsToDefaultTier() {
        PluginManager pm = mock(PluginManager.class);
        Permission permOp = new Permission("myplugin.admin", PermissionDefault.OP);
        Permission permTrue = new Permission("myplugin.public", PermissionDefault.TRUE);
        Permission permNotOp = new Permission("myplugin.nonop", PermissionDefault.NOT_OP);
        Permission permFalse = new Permission("myplugin.disabled", PermissionDefault.FALSE);

        when(pm.getPermission("myplugin.admin")).thenReturn(permOp);
        when(pm.getPermission("myplugin.public")).thenReturn(permTrue);
        when(pm.getPermission("myplugin.nonop")).thenReturn(permNotOp);
        when(pm.getPermission("myplugin.disabled")).thenReturn(permFalse);
        when(pm.getPermissions()).thenReturn(Set.of(permOp, permTrue, permNotOp, permFalse));

        // 1. Registered PermissionDefault checks
        assertFalse(PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.admin", "admincmd", pm));
        assertTrue(PaperCommandTreeInspector.isPermittedForTier("myplugin.admin", true, pm));

        assertTrue(PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.public", "pubcmd", pm));
        assertTrue(PaperCommandTreeInspector.isPermittedForTier("myplugin.public", true, pm));

        assertTrue(PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.nonop", "nonopcmd", pm));
        assertFalse(PaperCommandTreeInspector.isPermittedForTier("myplugin.nonop", true, pm),
                "PermissionDefault.NOT_OP must be granted to default and denied to op");

        assertFalse(PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.disabled", "discmd", pm));
        assertFalse(PaperCommandTreeInspector.isPermittedForTier("myplugin.disabled", true, pm),
                "PermissionDefault.FALSE must be denied to both default and op tiers");

        // 2. Unregistered permission nodes must default to Permission.DEFAULT_PERMISSION (OP) -> denied to default even with .use/.default/.user suffix
        assertFalse(PaperCommandTreeInspector.isPermittedForDefaultTier("unregistered.plugin.use", "unreg", pm));
        assertFalse(PaperCommandTreeInspector.isPermittedForDefaultTier("unregistered.plugin.default", "unreg", pm));
        assertFalse(PaperCommandTreeInspector.isPermittedForDefaultTier("unregistered.plugin.user", "unreg", pm));
        assertTrue(PaperCommandTreeInspector.isPermittedForTier("unregistered.plugin.use", true, pm));

        // 3. Full inspectTierCommandGraphs with Bukkit Command#testPermissionSilent
        Map<String, Command> known = new LinkedHashMap<>();
        known.put("admincmd", simpleBukkitCommand("admincmd", "myplugin.admin"));
        known.put("pubcmd", simpleBukkitCommand("pubcmd", "myplugin.public"));
        known.put("nonopcmd", simpleBukkitCommand("nonopcmd", "myplugin.nonop"));
        known.put("discmd", simpleBukkitCommand("discmd", "myplugin.disabled"));
        known.put("unreguse", simpleBukkitCommand("unreguse", "unregistered.plugin.use"));

        CommandMap commandMap = mock(CommandMap.class);
        when(commandMap.getKnownCommands()).thenReturn(known);
        Server server = mock(Server.class);
        when(server.getCommandMap()).thenReturn(commandMap);
        when(server.getPluginManager()).thenReturn(pm);

        Map<String, List<RawCommandNode>> tierGraphs = PaperCommandTreeInspector.inspectTierCommandGraphs(server);
        Set<String> defaultNames = tierGraphs.get("default").stream().map(RawCommandNode::name).collect(Collectors.toSet());
        Set<String> opNames = tierGraphs.get("op").stream().map(RawCommandNode::name).collect(Collectors.toSet());

        assertEquals(Set.of("pubcmd", "nonopcmd"), defaultNames);
        assertEquals(Set.of("admincmd", "pubcmd", "unreguse"), opNames);
        assertFalse(opNames.contains("discmd"), "PermissionDefault.FALSE command must be excluded from op tier");
        assertFalse(opNames.contains("nonopcmd"), "PermissionDefault.NOT_OP command must be excluded from op tier");
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: PaperCommandTreeInspector honors PermissibleBase recursive default parent/child/grandchild precedence over child PermissionDefault.OP")
    void honorsPermissibleBaseRecursiveParentChildPrecedenceAndAuthoritativeBukkitRoot() {
        PluginManager pm = mock(PluginManager.class);
        // Child and grandchild are registered with PermissionDefault.OP (or default OP),
        // while parent `myplugin.user` has PermissionDefault.TRUE and grants `myplugin.child -> myplugin.home`
        Permission homePerm = new Permission("myplugin.home", PermissionDefault.OP);
        Permission childPerm = new Permission(
                "myplugin.child",
                PermissionDefault.OP,
                Map.of("myplugin.home", true)
        );
        Permission userParentPerm = new Permission(
                "myplugin.user",
                PermissionDefault.TRUE,
                Map.of("myplugin.child", true)
        );
        when(pm.getPermission("myplugin.home")).thenReturn(homePerm);
        when(pm.getPermission("myplugin.child")).thenReturn(childPerm);
        when(pm.getPermission("myplugin.user")).thenReturn(userParentPerm);
        when(pm.getDefaultPermissions(false)).thenReturn(Set.of(userParentPerm));
        when(pm.getDefaultPermissions(true)).thenReturn(Set.of(userParentPerm, childPerm, homePerm));
        when(pm.getPermissions()).thenReturn(Set.of(userParentPerm, childPerm, homePerm));

        // Both direct child and grandchild must be granted to default tier via recursive parent grant
        assertTrue(
                PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.child", "childcmd", pm),
                "Child permission with PermissionDefault.OP granted by a default:true parent must be allowed on default tier"
        );
        assertTrue(
                PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.home", "home", pm),
                "Grandchild permission with PermissionDefault.OP granted recursively by a default:true parent must be allowed on default tier"
        );

        // Also verify with a Bukkit-wrapped Brigadier root whose requirement casts to an opaque NMS class
        CommandDispatcher<Object> dispatcher = new CommandDispatcher<>();
        dispatcher.register(
                LiteralArgumentBuilder.literal("home")
                        .requires(s -> ((OpaqueInternalSource) s).isDeveloper()) // throws ClassCastException -> UNKNOWN
                        .executes(ctx -> 1)
                        .then(LiteralArgumentBuilder.literal("delete")
                                .executes(ctx -> 1))
        );
        dispatcher.register(
                LiteralArgumentBuilder.literal("unguarded")
                        .requires(s -> ((OpaqueInternalSource) s).isDeveloper()) // throws ClassCastException -> UNKNOWN on Bukkit-wrapped root
                        .executes(ctx -> 1)
                        .then(LiteralArgumentBuilder.literal("reload")
                                .executes(ctx -> 1))
        );

        Command homeCmd = simpleBukkitCommand("home", "myplugin.home");
        Command unguardedCmd = simpleBukkitCommand("unguarded", null);
        Map<String, Command> known = new LinkedHashMap<>();
        known.put("home", homeCmd);
        known.put("unguarded", unguardedCmd);

        CommandMap commandMap = mock(CommandMap.class);
        when(commandMap.getKnownCommands()).thenReturn(known);
        BrigadierHostServer server = mock(BrigadierHostServer.class);
        when(server.getCommandMap()).thenReturn(commandMap);
        when(server.getPluginManager()).thenReturn(pm);
        when(server.getServer()).thenReturn(new FakeMcServer(dispatcher));

        CommandAuditReport report = PaperCommandTreeInspector.auditLiveServer(
                server,
                List.of(),
                JarClassOwnershipIndex.empty()
        );

        // 1. `/home delete` is exposed to default tier because `myplugin.user` (default:true) recursively grants `myplugin.home`
        LeastPrivilegeFinding homeDeleteFinding = report.findings().stream()
                .filter(f -> "home delete".equals(f.nodeId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected /home delete to be flagged as exposed via parent permission grant"));
        assertEquals("STATE_MUTATING_DEFAULT_EXPOSURE", homeDeleteFinding.findingKind());
        assertEquals("HIGH", homeDeleteFinding.severity());
        assertEquals("myplugin.home", homeDeleteFinding.declaredPermission());

        // 2. `/unguarded reload` has an authoritative Bukkit Command (`permission == null`);
        //    the Brigadier root's UNKNOWN NMS cast must NOT downgrade it from CRITICAL to MEDIUM!
        LeastPrivilegeFinding unguardedReloadFinding = report.findings().stream()
                .filter(f -> "unguarded reload".equals(f.nodeId()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected /unguarded reload to be flagged as CRITICAL"));
        assertEquals("MISSING_PERMISSION_GUARD", unguardedReloadFinding.findingKind());
        assertEquals("CRITICAL", unguardedReloadFinding.severity());

        // 3. Verify recursive parent/child/grandchild default grant evaluation directly via auditLiveServer
        assertTrue(
                PaperCommandTreeInspector.isPermittedForDefaultTier("myplugin.home", "home", pm),
                "Recursive default permission computation must grant grandchild permission myplugin.home via default:true parent"
        );
        CommandAuditReport liveReport = PaperCommandTreeInspector.auditLiveServer(
                server,
                List.of(),
                JarClassOwnershipIndex.empty()
        );
        assertTrue(liveReport.findings().stream().anyMatch(f -> "home delete".equals(f.nodeId())
                && "STATE_MUTATING_DEFAULT_EXPOSURE".equals(f.findingKind())));
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: PaperCommandTreeInspector evaluates Brigadier canUse/requires per child node, builds distinct per-tier subtrees, and avoids false CRITICAL alerts")
    void evaluatesBrigadierRequiresPerChildAndBuildsDistinctTierSubtrees() {
        PluginManager pm = mock(PluginManager.class);
        Permission rtpUse = new Permission("betterrtp.use", PermissionDefault.TRUE);
        Permission rtpAdmin = new Permission("betterrtp.admin", PermissionDefault.OP);
        Permission warpsDefault = new Permission("warps.default", PermissionDefault.TRUE);
        when(pm.getPermission("betterrtp.use")).thenReturn(rtpUse);
        when(pm.getPermission("betterrtp.admin")).thenReturn(rtpAdmin);
        when(pm.getPermission("warps.default")).thenReturn(warpsDefault);
        when(pm.getPermissions()).thenReturn(Set.of(rtpUse, rtpAdmin, warpsDefault));

        CommandDispatcher<Object> dispatcher = new CommandDispatcher<>();

        // 1. `/rtp` (default-visible root) with:
        //    - `world <radius>` (allowed for default)
        //    - `reload` (guarded by `s -> ((CommandSender) s).hasPermission("betterrtp.admin")` -> OP only!)
        //    - `debug` (guarded by an opaque predicate that casts to CustomInternalSource -> throws ClassCastException)
        dispatcher.register(
                LiteralArgumentBuilder.literal("rtp")
                        .requires(s -> ((CommandSender) s).hasPermission("betterrtp.use"))
                        .executes(ctx -> 1)
                        .then(LiteralArgumentBuilder.literal("world")
                                .then(RequiredArgumentBuilder.argument("radius", IntegerArgumentType.integer(1, 512))
                                        .executes(ctx -> 1)))
                        .then(LiteralArgumentBuilder.literal("reload")
                                .requires(s -> ((CommandSender) s).hasPermission("betterrtp.admin"))
                                .executes(ctx -> 1))
                        .then(LiteralArgumentBuilder.literal("debug")
                                .requires(s -> ((OpaqueInternalSource) s).isDeveloper())
                                .executes(ctx -> 1))
        );

        // 2. `/warps` (default-visible root) with:
        //    - `delete` (NO requires guard -> CRITICAL MISSING_PERMISSION_GUARD)
        //    - `set` (guarded by `warps.default` which is PermissionDefault.TRUE -> HIGH STATE_MUTATING_DEFAULT_EXPOSURE)
        dispatcher.register(
                LiteralArgumentBuilder.literal("warps")
                        .executes(ctx -> 1)
                        .then(LiteralArgumentBuilder.literal("delete")
                                .executes(ctx -> 1))
                        .then(LiteralArgumentBuilder.literal("set")
                                .requires(s -> ((CommandSender) s).hasPermission("warps.default"))
                                .executes(ctx -> 1))
        );

        // 3. Brigadier-only `/stop` guarded by `CommandSender::isOp`
        dispatcher.register(
                LiteralArgumentBuilder.literal("stop")
                        .requires(s -> ((CommandSender) s).isOp())
                        .executes(ctx -> 1)
        );

        Map<String, Command> known = new LinkedHashMap<>();
        known.put("rtp", simpleBukkitCommand("rtp", "betterrtp.use"));
        known.put("warps", simpleBukkitCommand("warps", null));

        CommandMap commandMap = mock(CommandMap.class);
        when(commandMap.getKnownCommands()).thenReturn(known);

        BrigadierHostServer server = mock(BrigadierHostServer.class);
        when(server.getCommandMap()).thenReturn(commandMap);
        when(server.getPluginManager()).thenReturn(pm);
        when(server.getServer()).thenReturn(new FakeMcServer(dispatcher));

        Map<String, List<RawCommandNode>> tierGraphs = PaperCommandTreeInspector.inspectTierCommandGraphs(server);
        RawCommandNode rtpDefault = tierGraphs.get("default").stream()
                .filter(n -> "rtp".equals(n.name()))
                .findFirst()
                .orElseThrow();
        RawCommandNode rtpOp = tierGraphs.get("op").stream()
                .filter(n -> "rtp".equals(n.name()))
                .findFirst()
                .orElseThrow();

        Set<String> rtpDefaultChildren = rtpDefault.children().stream().map(RawCommandNode::name).collect(Collectors.toSet());
        Set<String> rtpOpChildren = rtpOp.children().stream().map(RawCommandNode::name).collect(Collectors.toSet());

        assertFalse(rtpDefaultChildren.contains("reload"),
                "Op-guarded Brigadier subcommand /rtp reload must be excluded from default tier subtree");
        assertTrue(rtpOpChildren.contains("reload"),
                "Op-guarded Brigadier subcommand /rtp reload must be present in op tier subtree");
        assertTrue(rtpDefaultChildren.contains("world"));

        // Brigadier-only `/stop` with `isOp` requirement is excluded from default tier and present in op tier
        assertFalse(tierGraphs.get("default").stream().anyMatch(n -> "stop".equals(n.name())));
        assertTrue(tierGraphs.get("op").stream().anyMatch(n -> "stop".equals(n.name())));

        // Run full audit and verify findings
        JarClassOwnershipIndex ownershipIndex = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "BetterRTP-3.6.13.jar", Set.of("me.SuperRonanCraft.BetterRTP.BetterRTP"),
                "LeakyWarps-1.0.jar", Set.of("com.example.warps.WarpCommand")
        ));
        CommandAuditReport report = PaperCommandTreeInspector.auditLiveServer(server, List.of(), ownershipIndex);

        CommandNode reloadNode = report.commandTree().nodes().get("rtp reload");
        assertNotNull(reloadNode);
        assertEquals(List.of("op"), reloadNode.tiers());
        assertEquals("op", reloadNode.minTier());
        assertEquals("betterrtp.admin", reloadNode.permission());

        CommandNode radiusNode = report.commandTree().nodes().get("rtp world <radius>");
        assertNotNull(radiusNode);
        assertEquals("brigadier:integer", radiusNode.parser());
        assertEquals(1, radiusNode.properties().get("min"));
        assertEquals(512, radiusNode.properties().get("max"));

        // Verify `/rtp reload` is NOT flagged as a finding and is NOT a default-tier fuzz candidate
        assertFalse(report.findings().stream().anyMatch(f -> "rtp reload".equals(f.nodeId())),
                "Guarded /rtp reload must never be flagged as a least-privilege violation");
        assertFalse(report.commandTree().executableAllowedNodes().stream()
                .filter(CommandNode::isDefaultVisible)
                .anyMatch(n -> "rtp reload".equals(n.nodeId())));

        // Verify `/rtp debug` (opaque Brigadier requirement) is labeled UNKNOWN_PERMISSION_GUARD (MEDIUM), never CRITICAL
        LeastPrivilegeFinding debugFinding = report.findings().stream()
                .filter(f -> "rtp debug".equals(f.nodeId()))
                .findFirst()
                .orElseThrow();
        assertEquals("UNKNOWN_PERMISSION_GUARD", debugFinding.findingKind());
        assertEquals("MEDIUM", debugFinding.severity());
        assertEquals(PaperCommandTreeInspector.UNKNOWN_BRIGADIER_REQUIRES, debugFinding.declaredPermission());

        // Verify `/warps delete` (truly unguarded) -> CRITICAL MISSING_PERMISSION_GUARD
        LeastPrivilegeFinding deleteFinding = report.findings().stream()
                .filter(f -> "warps delete".equals(f.nodeId()))
                .findFirst()
                .orElseThrow();
        assertEquals("MISSING_PERMISSION_GUARD", deleteFinding.findingKind());
        assertEquals("CRITICAL", deleteFinding.severity());

        // Verify `/warps set` (guarded by default-granted permission) -> HIGH STATE_MUTATING_DEFAULT_EXPOSURE
        LeastPrivilegeFinding setFinding = report.findings().stream()
                .filter(f -> "warps set".equals(f.nodeId()))
                .findFirst()
                .orElseThrow();
        assertEquals("STATE_MUTATING_DEFAULT_EXPOSURE", setFinding.findingKind());
        assertEquals("HIGH", setFinding.severity());
        assertEquals("warps.default", setFinding.declaredPermission());
    }

    private static Command simpleBukkitCommand(String name, String permission) {
        Command cmd = new Command(name) {
            @Override
            public boolean execute(CommandSender sender, String commandLabel, String[] args) {
                return true;
            }
        };
        cmd.setPermission(permission);
        return cmd;
    }

    public interface BrigadierHostServer extends PaperCommandTreeInspector.BrigadierServerBridge {
    }

    public static final class FakeMcServer implements PaperCommandTreeInspector.BrigadierDispatcherCarrier {
        private final CommandDispatcher<?> dispatcher;

        public FakeMcServer(CommandDispatcher<?> dispatcher) {
            this.dispatcher = dispatcher;
        }

        @Override
        public CommandDispatcher<?> getCommandsDispatcher() {
            return dispatcher;
        }
    }

    private static final class OpaqueInternalSource {
        boolean isDeveloper() {
            return false;
        }
    }
}
