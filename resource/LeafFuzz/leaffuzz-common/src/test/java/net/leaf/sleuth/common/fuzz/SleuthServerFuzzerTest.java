package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.NodeBandit.ArmKey;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit and calibration tests for {@link SleuthServerFuzzer}, {@link NodeBandit},
 * {@link NumericBoundaryLadder}, {@link FuzzActionShrinker}, and {@link DualAudienceMitigationReport}
 * ({@code REQ-SLEUTH-FUZZ-004}, {@code leafsleuth-ADR-006}).
 */
class SleuthServerFuzzerTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: NumericBoundaryLadder generates sorted deduplicated boundary points within bounds")
    void numericBoundaryLadderClampsAndSortsPoints() {
        List<Integer> ladder = NumericBoundaryLadder.integerLadder(0, 512, 4096);
        assertEquals(List.of(0, 1, 16, 64, 256, 512), ladder);

        List<Integer> full = NumericBoundaryLadder.integerLadder(-10, 2000, 1024);
        assertEquals(List.of(-10, -1, 0, 1, 16, 64, 256, 1024, 2000), full);

        List<Double> floatLadder = NumericBoundaryLadder.doubleLadder(-2.5, 100.0, 50.0);
        assertTrue(floatLadder.contains(-2.5));
        assertTrue(floatLadder.contains(-1.0));
        assertTrue(floatLadder.contains(0.0));
        assertTrue(floatLadder.contains(16.0));
        assertTrue(floatLadder.contains(50.0));
        assertTrue(floatLadder.contains(100.0));
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: NodeBandit stratifies default vs op budget and rewards novelty and faults")
    void nodeBanditStratifiesTiersAndRewardsNovelty() {
        RawCommandNode rtpDefault = RawCommandNode.literal("rtp", true, "betterrtp.use", "BetterRTP.jar", List.of());
        RawCommandNode adminOp = RawCommandNode.literal("rtpadmin", true, "betterrtp.admin", "BetterRTP.jar", List.of());

        Map<String, List<RawCommandNode>> tierGraphs = Map.of(
                "default", List.of(rtpDefault),
                "op", List.of(rtpDefault, adminOp)
        );
        CommandTree tree = CommandSurfaceAuditor.mergeCommandTrees(tierGraphs, List.of());
        NodeBandit bandit = new NodeBandit(
                tree,
                List.of("default", "op"),
                0.75,
                1.414,
                List.of("repeat", "quit_lt1s"),
                new Random(42L)
        );

        for (int i = 0; i < 40; i++) {
            ArmKey arm = bandit.selectArm();
            if ("rtp".equals(arm.nodeId()) && "quit_lt1s".equals(arm.followUpShape())) {
                bandit.update(
                        arm.nodeId(),
                        arm.followUpShape(),
                        NodeBandit.EpisodeFeedback.of(
                                10.0,
                                15.0,
                                1,
                                List.of("me.SuperRonanCraft.BetterRTP.player.rtp.RTPPlayer"),
                                false
                        )
                );
            } else {
                bandit.update(
                        arm.nodeId(),
                        arm.followUpShape(),
                        NodeBandit.EpisodeFeedback.of(0.0, 0.0, 0, List.of(), false)
                );
            }
        }

        assertEquals(40, bandit.totalPulls());
        assertTrue(bandit.defaultPulls() > bandit.opPulls(), "Default stratum should receive ~75% of pulls");
        NodeBandit.BanditArmStats hotStats = bandit.armStats("rtp", "quit_lt1s");
        assertTrue(hotStats.meanReward() > 2.0);
        assertTrue(hotStats.noveltyHits() >= 1);
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: SleuthServerFuzzer discovers fault, shrinks 8-step noisy trace via ddmin to 1 step, and bisects n >= 256")
    void sleuthServerFuzzerDiscoversShrinksAndBisectsExactThreshold() {
        RawCommandNode radiusArg = RawCommandNode.argument(
                "n",
                "brigadier:integer",
                Map.of("min", 1, "max", 1024),
                true,
                List.of()
        );
        RawCommandNode radiusLit = RawCommandNode.literal("radius", false, List.of(radiusArg));
        RawCommandNode rtpRoot = new RawCommandNode(
                "rtp",
                "literal",
                null,
                Map.of(),
                true,
                null,
                "betterrtp.use",
                "BetterRTP.jar",
                List.of(radiusLit)
        );
        RawCommandNode spawnRoot = RawCommandNode.literal("spawn", true, "essentials.spawn", "EssentialsX.jar", List.of());
        RawCommandNode helpRoot = RawCommandNode.literal("help", true, null, "Bukkit", List.of());

        CommandTree tree = CommandSurfaceAuditor.mergeCommandTrees(
                Map.of("default", List.of(rtpRoot, spawnRoot, helpRoot)),
                List.of()
        );
        JarClassOwnershipIndex ownershipIndex = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "BetterRTP.jar", Set.of("me.SuperRonanCraft.BetterRTP.player.rtp.RTPPlayer"),
                "EssentialsX.jar", Set.of("com.earth2me.essentials.spawn.Commandspawn")
        ));

        SleuthServerFuzzer fuzzer = new SleuthServerFuzzer(
                tree,
                ownershipIndex,
                List.of("default"),
                List.of("repeat", "quit_lt1s"),
                new Random(7L)
        );

        SleuthServerFuzzer.EpisodeRunner mockOracle = actions -> {
            for (EpisodeAction act : actions) {
                if ("quit_lt1s".equals(act.followUpShape()) && act.commandLine().startsWith("/rtp radius ")) {
                    String numPart = act.commandLine().substring("/rtp radius ".length()).trim();
                    try {
                        int n = Integer.parseInt(numPart);
                        if (n >= 256) {
                            return EpisodeOutcome.fault(
                                    "leak:me.SuperRonanCraft.BetterRTP.player.rtp.RTPPlayer",
                                    "BetterRTP.jar",
                                    1.0,
                                    18.5,
                                    List.of("me.SuperRonanCraft.BetterRTP.player.rtp.RTPPlayer")
                            );
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
            return EpisodeOutcome.clean();
        };

        // 1. Verify UCB1 bandit + NumericBoundaryLadder discovers the fault autonomously
        List<DualAudienceMitigationReport> campaignReports = fuzzer.runCampaign(30, mockOracle);
        assertFalse(campaignReports.isEmpty(), "UCB1 campaign should discover the /rtp radius >= 256 + quit_lt1s fault");

        // 2. Verify 8-step noisy trace shrinks to the exact 1-step minimal reproducer and bisects n >= 256
        List<EpisodeAction> noisyTrace = List.of(
                EpisodeAction.of("/help", "repeat", "help"),
                EpisodeAction.of("/spawn", "repeat", "spawn"),
                EpisodeAction.of("/rtp", "repeat", "rtp"),
                EpisodeAction.of("/rtp radius 16", "repeat", "rtp radius <n>"),
                EpisodeAction.of("/spawn", "quit_lt1s", "spawn"),
                EpisodeAction.of("/rtp radius 1024", "quit_lt1s", "rtp radius <n>"),
                EpisodeAction.of("/help", "repeat", "help"),
                EpisodeAction.of("/rtp radius 64", "repeat", "rtp radius <n>")
        );

        EpisodeOutcome initialOutcome = mockOracle.runEpisode(noisyTrace);
        assertTrue(initialOutcome.reproduced());

        DualAudienceMitigationReport report = fuzzer.minimizeAndRecordFinding(noisyTrace, initialOutcome, mockOracle);
        assertEquals("leak:me.SuperRonanCraft.BetterRTP.player.rtp.RTPPlayer", report.signatureId());
        assertEquals("BetterRTP.jar", report.suspectJar());
        assertEquals(List.of("/rtp radius 256"), report.minimalCommandSequence());
        assertEquals("quit_lt1s", report.followUpShape());
        assertEquals("n >= 256", report.bisectedNumericThreshold().orElse(""));
        assertTrue(report.commandsYmlOverrideSnippet().contains("rtp: []"));
        assertTrue(report.permissionRevokeCommand().contains("lp group default permission set betterrtp.use false"));
        assertTrue(report.authorReproducerSummary().contains("BetterRTP.jar"));
        assertTrue(report.authorReproducerSummary().contains("n >= 256"));
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: FuzzActionShrinker preserves multi-step causal dependencies when 2 steps are jointly required")
    void ddminPreservesTwoStepJointDependency() {
        List<String> trace = List.of("noise1", "setup_A", "noise2", "noise3", "trigger_B", "noise4");
        List<String> shrunk = FuzzActionShrinker.ddmin(
                new ArrayList<>(trace),
                candidate -> candidate.contains("setup_A") && candidate.contains("trigger_B")
        );
        assertEquals(List.of("setup_A", "trigger_B"), shrunk);
    }
}
