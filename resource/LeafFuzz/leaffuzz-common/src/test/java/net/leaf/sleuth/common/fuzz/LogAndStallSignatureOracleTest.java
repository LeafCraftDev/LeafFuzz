package net.leaf.sleuth.common.fuzz;

import io.github.dailystruggle.helpers.stresstestrtp.LeakProbe;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link LogAndStallSignatureOracle} verifying stack trace deduplication into
 * {@code exc:<ExceptionClass>:<TopPluginFrame>} and {@code stall:<TopPluginFrame>}, root-logger
 * interception, {@link LeakProbe#inGcPauseWindow(long)} stall exclusion, and
 * {@link JarClassOwnershipIndex} attribution ({@code REQ-SLEUTH-FUZZ-003}, {@code ADR-125},
 * {@code leafsleuth-ADR-006}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-122
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace S-004
 * @trace S-005
 */
class LogAndStallSignatureOracleTest {

    @AfterEach
    void cleanupPauseWindow() {
        LeakProbe.clearGcPauseWindow();
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: LogAndStallSignatureOracle deduplicates uncaught exception and event error traces into exc:<ExceptionClass>:<TopPluginFrame> and attributes owning JAR")
    void deduplicatesExceptionLogTracesAndAttributesOwningJar() {
        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "BetterRTP-3.6.13.jar", Set.of("me.SuperRonanCraft.BetterRTP.player.rtp.RTP"),
                "HuskHomes-4.7.2.jar", Set.of("net.william278.huskhomes.event.TeleportListener"),
                "AlphaPlugin.jar", Set.of("com.google.gson.Gson"),
                "BetaPlugin.jar", Set.of("com.google.gson.Gson")
        ));
        LogAndStallSignatureOracle oracle = new LogAndStallSignatureOracle(index);

        String logText =
                "[12:00:00 ERROR]: Could not pass event PlayerTeleportEvent to BetterRTP v3.6.13\n"
                        + "org.bukkit.event.EventException: null\n"
                        + "\tat org.bukkit.plugin.java.JavaPluginLoader$1.execute(JavaPluginLoader.java:310)\n"
                        + "Caused by: java.lang.NullPointerException: Cannot invoke rtp\n"
                        + "\tat java.base/java.util.Objects.requireNonNull(Objects.java:208)\n"
                        + "\tat com.google.gson.Gson.fromJson(Gson.java:912)\n"
                        + "\tat BetterRTP-3.6.13.jar//me.SuperRonanCraft.BetterRTP.player.rtp.RTP.lambda$start$12(RTP.java:42)\n"
                        + "\tat net.minecraft.server.MinecraftServer.tickServer(MinecraftServer.java:1200)\n"
                        + "[12:00:02 ERROR]: Exception in thread \"Server thread\" java.lang.NullPointerException: repeat\n"
                        + "\tat me.SuperRonanCraft.BetterRTP.player.rtp.RTP.lambda$start$99(RTP.java:88)\n"
                        + "\tat net.minecraft.server.MinecraftServer.tickServer(MinecraftServer.java:1200)\n";

        List<FaultSignature> ingested = oracle.ingestLogText(logText, 10_000L);
        assertEquals(2, ingested.size());

        List<FaultSignature> ranked = oracle.rankedSignatures();
        assertEquals(1, ranked.size(), "Both stack traces with normalized lambda digits must deduplicate into 1 signature");

        FaultSignature sig = ranked.get(0);
        assertEquals(
                "exc:java.lang.NullPointerException:me.SuperRonanCraft.BetterRTP.player.rtp.RTP.lambda$start$#",
                sig.signatureId()
        );
        assertEquals("EXCEPTION", sig.kind());
        assertEquals("java.lang.NullPointerException", sig.exceptionClass());
        assertEquals("BetterRTP-3.6.13.jar", sig.suspectJar());
        assertEquals(2L, sig.occurrences());
        assertTrue(sig.isPluginAttributed());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: LogAndStallSignatureOracle parses Thread.print and live slow-tick stacks (>100ms) into stall:<TopPluginFrame> while excluding diagnostic GC pause windows")
    void attributesSlowTickStallsAndExcludesDiagnosticGcPauseWindows() {
        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "SlowBiomeScanner-1.1.jar", Set.of("com.example.scanner.BiomeSpiralSearch")
        ));
        LogAndStallSignatureOracle oracle = new LogAndStallSignatureOracle(index);

        String threadDump =
                "2026-10-29 22:35:00\n"
                        + "Full thread dump OpenJDK 64-Bit Server VM:\n\n"
                        + "\"Netty Epoll Server IO #1\" #30 daemon prio=5 runnable\n"
                        + "   java.lang.Thread.State: RUNNABLE\n"
                        + "\tat com.example.scanner.BiomeSpiralSearch.ioHelper(BiomeSpiralSearch.java:12)\n\n"
                        + "\"Server thread\" #25 prio=5 os_prio=0 tid=0x01 nid=0x02 runnable\n"
                        + "   java.lang.Thread.State: RUNNABLE\n"
                        + "\tat java.base@21.0.2/java.util.HashMap.getNode(HashMap.java:564)\n"
                        + "\tat net.minecraft.world.level.World.getBiome(World.java:400)\n"
                        + "\tat SlowBiomeScanner-1.1.jar//com.example.scanner.BiomeSpiralSearch.scanRadius(BiomeSpiralSearch.java:215)\n"
                        + "\tat net.minecraft.server.MinecraftServer.tickServer(MinecraftServer.java:1150)\n";

        Optional<FaultSignature> dumpStall = oracle.recordThreadDumpStall(threadDump, 245.0, 20_000L);
        assertTrue(dumpStall.isPresent());
        assertEquals("stall:com.example.scanner.BiomeSpiralSearch.scanRadius", dumpStall.get().signatureId());
        assertEquals("SlowBiomeScanner-1.1.jar", dumpStall.get().suspectJar());
        assertEquals(245.0, dumpStall.get().maxDurationMs(), 1e-6);

        // Live slow-tick stack trace sample (> 100 ms) on the same frame deduplicates and updates peak duration
        StackTraceElement[] liveStack = new StackTraceElement[]{
                new StackTraceElement("java.lang.Thread", "sleep", "Thread.java", 100),
                new StackTraceElement("com.example.scanner.BiomeSpiralSearch", "scanRadius", "BiomeSpiralSearch.java", 220),
                new StackTraceElement("net.minecraft.server.MinecraftServer", "tickServer", "MinecraftServer.java", 1150)
        };
        Optional<FaultSignature> liveStall = oracle.recordSlowTickStack(380.0, liveStack, 1_000_000_000L);
        assertTrue(liveStall.isPresent());
        assertEquals("stall:com.example.scanner.BiomeSpiralSearch.scanRadius", liveStall.get().signatureId());
        assertEquals(2L, liveStall.get().occurrences());
        assertEquals(380.0, liveStall.get().maxDurationMs(), 1e-6);

        // Fast tick (<= 100 ms) is ignored
        assertFalse(oracle.recordSlowTickStack(45.0, liveStack, 2_000_000_000L).isPresent());

        // Slow tick inside a diagnostic LeakProbe GC pause window is excluded
        LeakProbe.recordGcPauseWindow(5_000_000_000L, 5_200_000_000L);
        assertFalse(
                oracle.recordSlowTickStack(420.0, liveStack, 5_300_000_000L).isPresent(),
                "Slow tick overlapping LeakProbe GC pause exclusion window must not be recorded as a plugin stall"
        );
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: Root-logger JUL tap intercepts logged Throwables and updates JAR attribution when JarClassOwnershipIndex finishes scanning")
    void rootLoggerTapInterceptsThrowablesAndRefreshesDeferredJarOwnership() {
        LogAndStallSignatureOracle oracle = new LogAndStallSignatureOracle();
        oracle.startRootLoggerTap();
        try {
            IllegalStateException boom = new IllegalStateException("Simulated plugin fault");
            boom.setStackTrace(new StackTraceElement[]{
                    new StackTraceElement("com.example.lateindexed.FaultyListener", "onJoin", "FaultyListener.java", 55),
                    new StackTraceElement("org.bukkit.plugin.SimplePluginManager", "callEvent", "SimplePluginManager.java", 600)
            });
            Logger testLogger = Logger.getLogger("com.example.lateindexed.FaultyListener");
            testLogger.setUseParentHandlers(true);
            // INFO log without Throwable (even containing "Exception" text) must be filtered out by Level.WARNING tap
            testLogger.log(Level.INFO, "Routine info message mentioning Exception\n\tat com.example.lateindexed.FaultyListener.info(FaultyListener.java:10)");
            assertEquals(0L, oracle.totalExceptionsRecorded(), "INFO log without Throwable must be ignored by WARNING root-logger tap");

            testLogger.log(Level.SEVERE, "Unhandled exception in FaultyListener", boom);

            Optional<FaultSignature> beforeIndex = oracle.signature(
                    "exc:java.lang.IllegalStateException:com.example.lateindexed.FaultyListener.onJoin"
            );
            assertTrue(beforeIndex.isPresent(), "Expected root-logger tap to capture logged Throwable");
            assertEquals("server", beforeIndex.get().suspectJar());

            // Now JarClassOwnershipIndex finishes off-thread scanning -> signature ownership is refreshed automatically
            oracle.setOwnershipIndex(JarClassOwnershipIndex.fromJarClassMap(Map.of(
                    "LateIndexedPlugin-2.0.jar", Set.of("com.example.lateindexed.FaultyListener")
            )));
            Optional<FaultSignature> afterIndex = oracle.signature(
                    "exc:java.lang.IllegalStateException:com.example.lateindexed.FaultyListener.onJoin"
            );
            assertTrue(afterIndex.isPresent());
            assertEquals("LateIndexedPlugin-2.0.jar", afterIndex.get().suspectJar());
        } finally {
            oracle.stopRootLoggerTap();
        }
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: normalizeFrameDigits normalizes only lambda, hidden-class, and anonymous suffixes while preserving digits in real class and method names")
    void normalizesOnlyLambdaHiddenAndAnonymousSuffixesWhilePreservingRealClassDigits() {
        // Real class/package/method digits must never be mangled or merged
        assertEquals(
                "net.leaf.sleuth.paper.SleuthPaperCollectorAndS005Test.inFlightTickWatchdog",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "net.leaf.sleuth.paper.SleuthPaperCollectorAndS005Test.inFlightTickWatchdog"
                )
        );
        assertEquals(
                "com.example.v1_20_R3.Log4jHandler.handle2",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "Plugin.jar//com.example.v1_20_R3.Log4jHandler.handle2(Log4jHandler.java:42)"
                )
        );
        assertEquals(
                "com.example.Handler1.onEvent",
                LogAndStallSignatureOracle.normalizeFrameDigits("com.example.Handler1.onEvent")
        );
        assertEquals(
                "com.example.Handler2.onEvent",
                LogAndStallSignatureOracle.normalizeFrameDigits("com.example.Handler2.onEvent")
        );
        assertEquals(
                "com.example.Outer$Handler1.run",
                LogAndStallSignatureOracle.normalizeFrameDigits("com.example.Outer$Handler1.run")
        );

        // Unstable compiler/JVM suffixes must be normalized to '#'
        assertEquals(
                "me.SuperRonanCraft.BetterRTP.player.rtp.RTP.lambda$start$#",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "me.SuperRonanCraft.BetterRTP.player.rtp.RTP.lambda$start$12"
                )
        );
        assertEquals(
                "com.example.MyPlugin$$Lambda$#.accept",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "com.example.MyPlugin$$Lambda$412/0x0000000801234567.accept"
                )
        );
        assertEquals(
                "com.example.MyPlugin$$Lambda$#.accept",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "com.example.MyPlugin$Lambda/0x0000000801234567.accept"
                )
        );
        assertEquals(
                "com.example.HiddenClass/0x#.invoke",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "com.example.HiddenClass/0x0000000800abcdef.invoke"
                )
        );
        assertEquals(
                "org.bukkit.plugin.java.JavaPluginLoader$#.execute",
                LogAndStallSignatureOracle.normalizeFrameDigits(
                        "org.bukkit.plugin.java.JavaPluginLoader$1.execute"
                )
        );
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003 & S-005: extractTargetCoverageTokens and recordMainThreadHazardStack detect grey-box coverage, sync-chunk, sync-io, blocking-wait, and MSPT creep")
    void detectsGreyBoxCoverageAndSub100msMainThreadHazards() {
        JarClassOwnershipIndex index = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "BadPlugin-1.0.jar", Set.of(
                        "com.example.bad.ChunkTeleporter",
                        "com.example.bad.SqliteStorage",
                        "com.example.bad.FutureBlocker",
                        "com.example.bad.StuckWorker"
                )
        ));
        LogAndStallSignatureOracle oracle = new LogAndStallSignatureOracle(index);

        StackTraceElement[] syncChunkStack = new StackTraceElement[]{
                new StackTraceElement("org.bukkit.craftbukkit.CraftWorld", "getChunkAt", "CraftWorld.java", 312),
                new StackTraceElement("com.example.bad.ChunkTeleporter", "teleportNow", "ChunkTeleporter.java", 45),
                new StackTraceElement("net.minecraft.server.MinecraftServer", "tickServer", "MinecraftServer.java", 1150)
        };
        Set<String> cov = oracle.extractTargetCoverageTokens(syncChunkStack);
        assertTrue(cov.contains("cov:BadPlugin-1.0.jar:com.example.bad.ChunkTeleporter.teleportNow:40"));

        Optional<FaultSignature> chunkHazard = oracle.recordMainThreadHazardStack(22.5, syncChunkStack, 100_000L);
        assertTrue(chunkHazard.isPresent());
        assertEquals("hazard:sync-chunk:com.example.bad.ChunkTeleporter.teleportNow", chunkHazard.get().signatureId());
        assertEquals("HAZARD", chunkHazard.get().kind());
        assertEquals("BadPlugin-1.0.jar", chunkHazard.get().suspectJar());

        StackTraceElement[] syncIoStack = new StackTraceElement[]{
                new StackTraceElement("org.sqlite.core.NativeDB", "_exec", "NativeDB.java", 110),
                new StackTraceElement("com.example.bad.SqliteStorage", "savePlayer", "SqliteStorage.java", 88),
                new StackTraceElement("net.minecraft.server.MinecraftServer", "tickServer", "MinecraftServer.java", 1150)
        };
        Optional<FaultSignature> ioHazard = oracle.recordMainThreadHazardStack(31.0, syncIoStack, 200_000L);
        assertTrue(ioHazard.isPresent());
        assertEquals("hazard:sync-io:com.example.bad.SqliteStorage.savePlayer", ioHazard.get().signatureId());

        // ClassLoader I/O on first class load must NOT be misflagged as plugin sync-io
        StackTraceElement[] classLoaderStack = new StackTraceElement[]{
                new StackTraceElement("java.io.FileInputStream", "readBytes", "FileInputStream.java", 280),
                new StackTraceElement("java.lang.ClassLoader", "loadClass", "ClassLoader.java", 520),
                new StackTraceElement("com.example.bad.SqliteStorage", "init", "SqliteStorage.java", 18)
        };
        assertFalse(oracle.recordMainThreadHazardStack(25.0, classLoaderStack, 300_000L).isPresent());

        StackTraceElement[] blockingWaitStack = new StackTraceElement[]{
                new StackTraceElement("java.util.concurrent.CompletableFuture", "waitingGet", "CompletableFuture.java", 1890),
                new StackTraceElement("java.util.concurrent.CompletableFuture", "join", "CompletableFuture.java", 2110),
                new StackTraceElement("com.example.bad.FutureBlocker", "onCommand", "FutureBlocker.java", 54)
        };
        Optional<FaultSignature> waitHazard = oracle.recordMainThreadHazardStack(19.0, blockingWaitStack, 400_000L);
        assertTrue(waitHazard.isPresent());
        assertEquals("hazard:blocking-wait:com.example.bad.FutureBlocker.onCommand", waitHazard.get().signatureId());

        Optional<FaultSignature> creep = oracle.recordRepeatingTaskMsptCreep("BadPlugin-1.0.jar", 5.0, 24.5);
        assertTrue(creep.isPresent());
        assertEquals("hazard:task-creep:BadPlugin-1.0.jar.ScheduledTaskCreep", creep.get().signatureId());
        assertEquals(4L, oracle.totalHazardsRecorded());
    }
}
