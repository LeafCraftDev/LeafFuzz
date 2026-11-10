package net.leaf.sleuth.common.resource;

import io.github.dailystruggle.helpers.stresstestrtp.LeakProbe;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
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
 * Unit and statistical calibration tests for {@link ClassRetentionScreener} and
 * {@link ClassRetentionFinding} ({@code REQ-SLEUTH-FUZZ-002}, {@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-122
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leaffuzz-ADR-001
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-001
 * @trace REQ-SLEUTH-FUZZ-002
 */
class ClassRetentionScreenerTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-002: Bonferroni OLS class retention screener isolates 1 leaking class (+1.0/departure) among 49 noisy stable classes and attributes owning JAR")
    void isolatesSingleLeakingClassAmongFortyNineNoisyStableClasses() {
        String leakingClass = "com.example.leakyrtp.PendingTeleportSession";
        String sharedClass = "com.google.gson.internal.LinkedTreeMap";

        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "LeakyRTP-3.6.13.jar", Set.of(leakingClass, sharedClass),
                "OtherPlugin-1.0.jar", Set.of("com.example.other.StableService", sharedClass)
        ));

        ClassRetentionScreener screener = new ClassRetentionScreener(index);
        Random rng = new Random(20261029L);

        // 8 checkpoints with 10 player departures per step (departures = 0, 10, 20, ..., 70)
        int checkpoints = 8;
        for (int step = 0; step < checkpoints; step++) {
            long departures = step * 10L;
            long commands = step * 15L;
            StringBuilder rawHisto = new StringBuilder();
            rawHisto.append(" num     #instances         #bytes  class name (module)\n");
            rawHisto.append("-------------------------------------------------------\n");

            // 1. Leaking plugin class growing linearly at +1.0 instance per player departure
            long leakedInstances = 5L + departures;
            long leakedBytes = leakedInstances * 512L;
            rawHisto.append(String.format("   1: %14d %14d  %s%n", leakedInstances, leakedBytes, leakingClass));

            // 2. 49 noisy stable classes (oscillating around baseline without monotonic drift)
            for (int c = 0; c < 49; c++) {
                String clsName = (c == 0) ? sharedClass : ("net.minecraft.server.StableClass_" + c);
                long base = 200L + c * 10L;
                long jitter = rng.nextInt(5) - 2L;
                long inst = Math.max(1L, base + jitter);
                long bytes = inst * 64L;
                rawHisto.append(String.format("%4d: %14d %14d  %s%n", c + 2, inst, bytes, clsName));
            }
            rawHisto.append("Total          10000         640000\n");

            screener.recordHistogramText(
                    "chk-" + step,
                    1_000L + step * 5_000L,
                    departures,
                    commands,
                    rawHisto.toString()
            );
        }

        List<ClassRetentionFinding> findings = screener.screenDepartureRetention();
        assertEquals(1, findings.size(), "Expected exactly the 1 leaking class to pass Bonferroni alpha=0.05/50");

        ClassRetentionFinding top = findings.get(0);
        assertEquals(leakingClass, top.className());
        assertEquals("LeakyRTP-3.6.13.jar", top.owningJar());
        assertTrue(top.isPluginOwned());
        assertEquals("departure", top.eventBasis());
        assertEquals(1.0, top.slopePerEvent(), 1e-4);
        assertTrue(top.rSquared() > 0.999, "Expected R^2 > 0.999, got " + top.rSquared());
        assertTrue(top.pValue() < (0.05 / 50.0), "Expected pValue below Bonferroni threshold, got " + top.pValue());
        assertEquals(5L, top.baselineInstances());
        assertEquals(75L, top.peakInstances());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-002: ClassRetentionScreener attributes retained ticket holder class to owning plugin JAR")
    void attributesRetainedTicketHolderClassToOwningPluginJar() {
        String leakingTicketClass = "com.example.chunkloader.LeakedTicketHolder";
        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "BadChunkLoader.jar", Set.of(leakingTicketClass)
        ));
        ClassRetentionScreener screener = new ClassRetentionScreener(index);

        for (int i = 0; i < 5; i++) {
            long deps = i * 4L;
            screener.recordCheckpoint(new ClassRetentionScreener.HistogramCheckpoint(
                    "cp-" + i,
                    1_000L + i * 1_000L,
                    deps,
                    deps,
                    400.0 + i * 12.0,
                    List.of(new LeakProbe.ClassCount(leakingTicketClass, 10L + deps * 2L, (10L + deps * 2L) * 1024L))
            ));
        }

        List<ClassRetentionFinding> findings = screener.latestFindings();
        assertFalse(findings.isEmpty());
        assertEquals(leakingTicketClass, findings.get(0).className());
        assertEquals("BadChunkLoader.jar", findings.get(0).owningJar());
        assertTrue(findings.get(0).isPluginOwned());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-002: LeakProbe and ClassRetentionScreener track +/-500ms diagnostic GC pause exclusion window")
    void tracksDiagnosticGcPauseExclusionWindow() {
        LeakProbe.clearGcPauseWindow();
        ClassRetentionScreener screener = new ClassRetentionScreener();
        long baseNanos = 10_000_000_000L;
        assertFalse(screener.inGcPauseWindow(baseNanos));

        LeakProbe.recordGcPauseWindow(baseNanos, baseNanos + 80_000_000L);
        assertTrue(screener.inGcPauseWindow(baseNanos - 400_000_000L), "Within -500ms buffer should be excluded");
        assertTrue(screener.inGcPauseWindow(baseNanos + 40_000_000L), "During GC window should be excluded");
        assertTrue(screener.inGcPauseWindow(baseNanos + 550_000_000L), "Within +500ms buffer should be excluded");
        assertFalse(screener.inGcPauseWindow(baseNanos + 700_000_000L), "Beyond +500ms buffer should not be excluded");

        screener.reset();
        assertFalse(screener.inGcPauseWindow(baseNanos));
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-002: oneSidedStudentTPValue matches Abramowitz & Stegun reference critical values")
    void studentTPValueMatchesReferenceCriticalValues() {
        // dof=1 (Cauchy): t=6.3137515 -> p=0.05
        assertEquals(0.05, ClassRetentionScreener.oneSidedStudentTPValue(6.3137515, 1), 1e-4);
        // dof=5 (odd): t=2.015048 -> p=0.05, t=3.364930 -> p=0.01
        assertEquals(0.05, ClassRetentionScreener.oneSidedStudentTPValue(2.015048, 5), 1e-4);
        assertEquals(0.01, ClassRetentionScreener.oneSidedStudentTPValue(3.364930, 5), 1e-4);
        // dof=6 (even): t=1.943180 -> p=0.05, t=3.142668 -> p=0.01
        assertEquals(0.05, ClassRetentionScreener.oneSidedStudentTPValue(1.943180, 6), 1e-4);
        assertEquals(0.01, ClassRetentionScreener.oneSidedStudentTPValue(3.142668, 6), 1e-4);
        // Non-positive t returns 0.5
        assertEquals(0.5, ClassRetentionScreener.oneSidedStudentTPValue(0.0, 5), 1e-9);
        assertEquals(0.5, ClassRetentionScreener.oneSidedStudentTPValue(-2.5, 5), 1e-9);
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-002: Null-model Monte Carlo calibration holds family-wise false-positive rate <= 0.05 across 200 noisy trials")
    void nullModelMonteCarloCalibrationHoldsFamilyWiseErrorRateBelowAlpha() {
        int trials = 200;
        int classesPerTrial = 40;
        int checkpoints = 8;
        int trialsWithAnyFalsePositive = 0;

        for (int trial = 0; trial < trials; trial++) {
            ClassRetentionScreener screener = new ClassRetentionScreener();
            Random rng = new Random(900_000L + trial * 1_009L);
            for (int step = 0; step < checkpoints; step++) {
                long departures = step * 10L;
                // Sawtooth GC phase oscillation (zero secular slope) + Gaussian noise
                double sawtooth = (step % 2 == 0) ? 4.0 : -4.0;
                List<LeakProbe.ClassCount> counts = new ArrayList<>(classesPerTrial);
                for (int c = 0; c < classesPerTrial; c++) {
                    double noise = rng.nextGaussian() * 6.0;
                    long inst = Math.max(10L, Math.round(500.0 + c * 20.0 + sawtooth + noise));
                    counts.add(new LeakProbe.ClassCount("net.minecraft.NullModelClass_" + c, inst, inst * 64L));
                }
                screener.recordCheckpoint(new ClassRetentionScreener.HistogramCheckpoint(
                        "null-" + step,
                        1_000L + step * 1_000L,
                        departures,
                        0L,
                        256.0,
                        counts
                ));
            }
            if (!screener.screenClassGrowth().isEmpty()) {
                trialsWithAnyFalsePositive++;
            }
        }

        int totalFp = trialsWithAnyFalsePositive;
        double empiricalFwer = (double) totalFp / trials;
        assertTrue(
                empiricalFwer <= 0.05,
                () -> String.format("Expected null-model FWER <= 0.05 across %d trials, got %.4f (%d/200)",
                        trials, empiricalFwer, totalFp)
        );
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-001 & REQ-SLEUTH-FUZZ-002: Leaking multi-JAR shared class is reported as 'shared' and never blamed as plugin-owned")
    void leakingSharedClassIsMarkedSharedAndNeverFalselyBlamedOnSinglePlugin() {
        String sharedLeakingClass = "com.google.gson.internal.LinkedTreeMap$Node";
        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "PluginA.jar", Set.of(sharedLeakingClass, "com.example.a.CleanA"),
                "PluginB.jar", Set.of(sharedLeakingClass, "com.example.b.CleanB")
        ));
        ClassRetentionScreener screener = new ClassRetentionScreener(index);

        for (int i = 0; i < 6; i++) {
            long deps = i * 5L;
            long inst = 20L + deps * 3L;
            screener.recordCheckpoint(new ClassRetentionScreener.HistogramCheckpoint(
                    "cp-" + i,
                    1_000L + i * 1_000L,
                    deps,
                    0L,
                    300.0,
                    List.of(new LeakProbe.ClassCount(sharedLeakingClass, inst, inst * 128L))
            ));
        }

        List<ClassRetentionFinding> findings = screener.screenClassGrowth();
        assertEquals(1, findings.size());
        ClassRetentionFinding sharedFinding = findings.get(0);
        assertEquals(sharedLeakingClass, sharedFinding.className());
        assertEquals("shared", sharedFinding.owningJar());
        assertFalse(sharedFinding.isPluginOwned(), "Shared multi-JAR class must never be marked isPluginOwned");
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-002: Single-basis progression selects 'command' when only commands vary and 'checkpoint' when both counters are static")
    void selectsCommandAndCheckpointEventBasesByProgressionWithoutFallback() {
        String commandLeakClass = "com.example.cmd.UnclosedCommandContext";
        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "CmdPlugin.jar", Set.of(commandLeakClass)
        ));

        // 1. Departures static (0), commands progressing (0, 8, 16, 24, 32) -> basis must be "command"
        ClassRetentionScreener cmdScreener = new ClassRetentionScreener(index);
        for (int i = 0; i < 5; i++) {
            long cmds = i * 8L;
            long inst = 4L + cmds * 2L;
            cmdScreener.recordCheckpoint(new ClassRetentionScreener.HistogramCheckpoint(
                    "cmd-" + i,
                    1_000L + i * 1_000L,
                    0L,
                    cmds,
                    200.0,
                    List.of(new LeakProbe.ClassCount(commandLeakClass, inst, inst * 256L))
            ));
        }
        assertEquals("command", cmdScreener.selectActiveEventBasis());
        List<ClassRetentionFinding> cmdFindings = cmdScreener.screenClassGrowth();
        assertEquals(1, cmdFindings.size());
        assertEquals("command", cmdFindings.get(0).eventBasis());
        assertEquals(2.0, cmdFindings.get(0).slopePerEvent(), 1e-4);

        // 2. Both departures (0) and commands (0) static -> basis must be "checkpoint"
        ClassRetentionScreener chkScreener = new ClassRetentionScreener(index);
        for (int i = 0; i < 5; i++) {
            long inst = 10L + i * 6L;
            chkScreener.recordCheckpoint(new ClassRetentionScreener.HistogramCheckpoint(
                    "chk-" + i,
                    1_000L + i * 1_000L,
                    0L,
                    0L,
                    200.0,
                    List.of(new LeakProbe.ClassCount(commandLeakClass, inst, inst * 256L))
            ));
        }
        assertEquals("checkpoint", chkScreener.selectActiveEventBasis());
        List<ClassRetentionFinding> chkFindings = chkScreener.screenClassGrowth();
        assertEquals(1, chkFindings.size());
        assertEquals("checkpoint", chkFindings.get(0).eventBasis());
        assertEquals(6.0, chkFindings.get(0).slopePerEvent(), 1e-4);
    }
}
