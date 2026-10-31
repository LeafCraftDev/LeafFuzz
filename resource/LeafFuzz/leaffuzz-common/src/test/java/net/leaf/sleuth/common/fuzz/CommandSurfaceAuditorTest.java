package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.Denylist;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.LeastPrivilegeFinding;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link CommandSurfaceAuditor} verifying {@code namespace:cmd} alias folding,
 * {@link CommandSurfaceAuditor#DEFAULT_DENYLIST} path and {@code <argkind>} filtering, redirect
 * cycle cutting, and {@link CommandSurfaceAuditor.LeastPrivilegeOracle} privilege exposure checks
 * ({@code REQ-SLEUTH-FUZZ-003}, {@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace S-004
 * @trace S-005
 */
class CommandSurfaceAuditorTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: CommandSurfaceAuditor folds structurally equal namespace:cmd aliases, preserves conflicting namespaces, and cuts redirect cycles")
    void foldsStructurallyEqualNamespaceAliasesAndCutsRedirectCycles() {
        RawCommandNode radiusArg = RawCommandNode.argument(
                "radius",
                "brigadier:integer",
                Map.of("min", 1, "max", 1024),
                true,
                List.of()
        );
        // `betterrtp:rtp` and `rtp` have identical subtrees -> must fold into canonical `rtp`
        RawCommandNode bareRtp = new RawCommandNode(
                "rtp",
                "literal",
                null,
                Map.of(),
                true,
                null,
                "betterrtp.use",
                "BetterRTP",
                List.of(radiusArg)
        );
        RawCommandNode namespacedRtp = new RawCommandNode(
                "betterrtp:rtp",
                "literal",
                null,
                Map.of(),
                true,
                "rtp",
                "betterrtp.use",
                "BetterRTP",
                List.of()
        );

        // `plugin_a:home` vs `home` have DIFFERENT subtrees -> must NOT fold together
        RawCommandNode bareHome = RawCommandNode.literal("home", true, List.of());
        RawCommandNode pluginHomeWithArg = RawCommandNode.literal(
                "plugin_a:home",
                false,
                List.of(RawCommandNode.argument("target", "brigadier:string", Map.of(), true, List.of()))
        );

        // Mutual redirect cycle: `execute -> run -> execute`
        RawCommandNode runRedirect = new RawCommandNode(
                "run",
                "literal",
                null,
                Map.of(),
                false,
                "execute",
                "minecraft.command.execute",
                "minecraft",
                List.of()
        );
        RawCommandNode executeRoot = new RawCommandNode(
                "execute",
                "literal",
                null,
                Map.of(),
                false,
                null,
                "minecraft.command.execute",
                "minecraft",
                List.of(runRedirect)
        );

        CommandTree tree = CommandSurfaceAuditor.mergeCommandTrees(
                Map.of(
                        "default", List.of(bareRtp, namespacedRtp, bareHome, pluginHomeWithArg),
                        "op", List.of(bareRtp, namespacedRtp, bareHome, pluginHomeWithArg, executeRoot)
                ),
                List.of()
        );

        // 1. Structurally equal `betterrtp:rtp` folded into `rtp`
        assertEquals("rtp", tree.aliasMap().get("rtp"));
        assertEquals("rtp", tree.aliasMap().get("betterrtp:rtp"));
        assertFalse(tree.nodes().containsKey("betterrtp:rtp"));

        CommandNode rtpRoot = tree.nodes().get("rtp");
        assertNotNull(rtpRoot);
        assertEquals(List.of("rtp", "betterrtp:rtp"), rtpRoot.aliases());
        assertEquals("default", rtpRoot.minTier());
        assertEquals(List.of("default", "op"), rtpRoot.tiers());

        CommandNode rtpRadius = tree.nodes().get("rtp <radius>");
        assertNotNull(rtpRadius);
        assertEquals(List.of("rtp <radius>", "betterrtp:rtp <radius>"), rtpRadius.aliases());
        assertEquals("brigadier:integer", rtpRadius.parser());

        // 2. Conflicting `plugin_a:home` stays separate from `home`
        assertTrue(tree.nodes().containsKey("home"));
        assertTrue(tree.nodes().containsKey("plugin_a:home"));

        // 3. Mutual redirect cycle `execute -> run -> execute` terminates with cycleCut=true and is denylisted
        CommandNode execRun = tree.nodes().get("execute run");
        assertNotNull(execRun);
        assertTrue(execRun.cycleCut(), "Expected mutual redirect loop execute -> run -> execute to set cycleCut=true");
        assertTrue(tree.nodes().get("execute").denied());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: Denylist enforces DEFAULT_DENYLIST root globs, subpaths, and <argkind> rules while leaving safe siblings allowed")
    void denylistEnforcesRootGlobsSubpathsAndArgKinds() {
        RawCommandNode stopCmd = RawCommandNode.literal("minecraft:stop", true, List.of());
        RawCommandNode banIpCmd = RawCommandNode.literal("ban-ip", true, List.of());
        // `reload` and `reload confirm`
        RawCommandNode reloadConfirm = RawCommandNode.literal("confirm", true, List.of());
        RawCommandNode reloadRoot = RawCommandNode.literal("reload", true, List.of(reloadConfirm));

        // `kill` (bare self-kill allowed) vs `kill <targets>` (entity selector denied by `kill <entity>`)
        RawCommandNode killTargets = RawCommandNode.argument("targets", "minecraft:entity", Map.of(), true, List.of());
        RawCommandNode killRoot = RawCommandNode.literal("kill", true, List.of(killTargets));

        // `tick query` (allowed) vs `tick freeze` and `tick sprint` (denied)
        RawCommandNode tickQuery = RawCommandNode.literal("query", true, List.of());
        RawCommandNode tickFreeze = RawCommandNode.literal("freeze", true, List.of());
        RawCommandNode tickSprint = RawCommandNode.literal("sprint", true, List.of());
        RawCommandNode tickRoot = RawCommandNode.literal("tick", false, List.of(tickQuery, tickFreeze, tickSprint));

        CommandTree tree = CommandSurfaceAuditor.mergeCommandTrees(
                Map.of("op", List.of(stopCmd, banIpCmd, reloadRoot, killRoot, tickRoot)),
                List.of("customadmin wipe")
        );

        assertTrue(tree.nodes().get("minecraft:stop").denied());
        assertEquals("stop", tree.nodes().get("minecraft:stop").deniedBy());

        assertTrue(tree.nodes().get("ban-ip").denied());
        assertEquals("ban*", tree.nodes().get("ban-ip").deniedBy());

        assertTrue(tree.nodes().get("reload").denied());
        assertTrue(tree.nodes().get("reload confirm").denied());

        // Bare `kill` is allowed; `kill <targets>` (minecraft:entity) is denied by `kill <entity>`
        assertFalse(tree.nodes().get("kill").denied(), "Bare /kill without entity selector should remain allowed");
        assertTrue(tree.nodes().get("kill <targets>").denied(), "/kill <targets> with entity parser must be denied");
        assertEquals("kill <entity>", tree.nodes().get("kill <targets>").deniedBy());

        // `tick query` is allowed; `tick freeze` and `tick sprint` are denied
        assertFalse(tree.nodes().get("tick query").denied());
        assertTrue(tree.nodes().get("tick freeze").denied());
        assertEquals("tick freeze", tree.nodes().get("tick freeze").deniedBy());
        assertTrue(tree.nodes().get("tick sprint").denied());

        Denylist deny = new Denylist(List.of("customadmin wipe"));
        assertEquals(Optional.of("stop"), deny.matchCommandLine("/minecraft:stop", tree));
        assertEquals(Optional.of("kill <entity>"), deny.matchCommandLine("/kill @e", tree));
        assertEquals(Optional.empty(), deny.matchCommandLine("/kill", tree));
        assertEquals(Optional.of("customadmin wipe"), deny.matchCommandLine("/customadmin wipe world", tree));
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: LeastPrivilegeOracle flags state-mutating and denylisted commands exposed on the default permission tier and attributes owning JAR")
    void leastPrivilegeOracleFlagsUnguardedStateMutatingAndDenylistedCommandsOnDefaultTier() {
        JarClassOwnershipIndex ownershipIndex = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "BetterRTP-3.6.13.jar", Set.of("me.SuperRonanCraft.BetterRTP.BetterRTP"),
                "LeakyWarps-1.0.jar", Set.of("com.example.warps.WarpCommand")
        ));

        // 1. Safe player command `/rtp` + op-only `/rtp reload` (properly restricted to op tier)
        RawCommandNode rtpDefault = RawCommandNode.literal(
                "rtp",
                true,
                "betterrtp.use",
                "BetterRTP-3.6.13.jar",
                List.of()
        );
        RawCommandNode rtpReloadOpOnly = RawCommandNode.literal(
                "reload",
                true,
                "betterrtp.admin",
                "BetterRTP-3.6.13.jar",
                List.of()
        );
        RawCommandNode rtpOp = RawCommandNode.literal(
                "rtp",
                true,
                "betterrtp.use",
                "BetterRTP-3.6.13.jar",
                List.of(rtpReloadOpOnly)
        );

        // 2. Vulnerable plugin command `/warps reload` and `/warps delete` exposed on the `default` tier without permission guard!
        RawCommandNode warpsReloadExposed = RawCommandNode.literal(
                "reload",
                true,
                null,
                "com.example.warps.WarpCommand",
                List.of()
        );
        RawCommandNode warpsDeleteExposed = RawCommandNode.literal(
                "delete",
                true,
                "warps.default",
                "com.example.warps.WarpCommand",
                List.of()
        );
        RawCommandNode warpsDefault = RawCommandNode.literal(
                "warps",
                true,
                null,
                "com.example.warps.WarpCommand",
                List.of(warpsReloadExposed, warpsDeleteExposed)
        );

        // 3. Denylisted `/op` accidentally exposed to `default` tier
        RawCommandNode opExposed = RawCommandNode.literal("op", true, "minecraft.command.op", "server", List.of());

        CommandAuditReport report = CommandSurfaceAuditor.auditCommandSurface(
                Map.of(
                        "default", List.of(rtpDefault, warpsDefault, opExposed),
                        "op", List.of(rtpOp, warpsDefault, opExposed)
                ),
                List.of(),
                ownershipIndex
        );

        List<LeastPrivilegeFinding> findings = report.findings();
        assertFalse(findings.isEmpty());

        // `/rtp reload` is ONLY in the `op` tier, so it must NOT be flagged
        assertFalse(
                findings.stream().anyMatch(f -> "rtp reload".equals(f.nodeId())),
                "Op-only /rtp reload must not be flagged as a default-tier exposure"
        );

        // `/op` exposed on default tier -> CRITICAL DENYLIST_EXPOSED_TO_DEFAULT
        assertTrue(findings.stream().anyMatch(f ->
                "op".equals(f.nodeId())
                        && "DENYLIST_EXPOSED_TO_DEFAULT".equals(f.findingKind())
                        && "CRITICAL".equals(f.severity())
        ));

        // `/warps reload` exposed on default tier with no permission -> CRITICAL MISSING_PERMISSION_GUARD attributed to LeakyWarps-1.0.jar
        LeastPrivilegeFinding warpsReloadFinding = findings.stream()
                .filter(f -> "warps reload".equals(f.nodeId()))
                .findFirst()
                .orElseThrow();
        assertEquals("MISSING_PERMISSION_GUARD", warpsReloadFinding.findingKind());
        assertEquals("CRITICAL", warpsReloadFinding.severity());
        assertEquals("LeakyWarps-1.0.jar", warpsReloadFinding.suspectPluginOrJar());
        assertTrue(warpsReloadFinding.remediationCommand().contains("lp group default permission set warps.reload false"));

        // `/warps delete` exposed on default tier with default permission -> HIGH STATE_MUTATING_DEFAULT_EXPOSURE
        LeastPrivilegeFinding warpsDeleteFinding = findings.stream()
                .filter(f -> "warps delete".equals(f.nodeId()))
                .findFirst()
                .orElseThrow();
        assertEquals("STATE_MUTATING_DEFAULT_EXPOSURE", warpsDeleteFinding.findingKind());
        assertEquals("HIGH", warpsDeleteFinding.severity());
        assertEquals("LeakyWarps-1.0.jar", warpsDeleteFinding.suspectPluginOrJar());
    }
}
