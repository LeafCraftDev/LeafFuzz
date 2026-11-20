package net.leaf.fuzz.common;

import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.FindingKind;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.ListenerRegistrationMode;
import io.github.dailystruggle.menu.api.BookContrastValidator;
import io.github.dailystruggle.menu.api.MenuDescriptor;
import net.leaf.fuzz.common.ui.LeafFuzzMenuBuilder;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.BotStepRecord;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.PersonaProfile;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;
import net.leaf.sleuth.common.resource.ClassRetentionScreener;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Built-In Test ({@code [FUZZ bit]}) PBIT/CBIT/IBIT self-test suite verifying {@code LeafFuzz}'s
 * cross-platform archive indexing, command-surface auditing, UCB1 boundary fuzzing + {@code ddmin}
 * shrinking, Bonferroni-corrected class retention screening, and Markdown scorecard generation
 * ({@code leaffuzz-ADR-001}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-001
 * @trace REQ-SLEUTH-FUZZ-002
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 */
public final class LeafFuzzBitSuite {

    /**
     * Single BIT check result.
     *
     * @param code       BIT code identifier
     * @param category   {@code "PBIT"}, {@code "CBIT"}, or {@code "IBIT"}
     * @param passed     whether the invariant check passed
     * @param summary    human-readable result summary
     * @param durationMs execution duration in milliseconds
     */
    public record CheckResult(
            String code,
            String category,
            boolean passed,
            String summary,
            double durationMs
    ) {
    }

    /** Dedicated heap canary class counted in live {@code GC.class_histogram} verification. */
    public static final class LiveHeapCanary {
        public final long nonce;

        public LiveHeapCanary(long nonce) {
            this.nonce = nonce;
        }
    }

    private volatile java.util.function.Supplier<List<CheckResult>> liveCheckSupplier;

    public void setLiveCheckSupplier(java.util.function.Supplier<List<CheckResult>> liveCheckSupplier) {
        this.liveCheckSupplier = liveCheckSupplier;
    }

    /**
     * Executes all PBIT, CBIT, IBIT, and (when attached to a live server) LIVE canary checks
     * and returns their structured results.
     *
     * @return immutable list of check results
     */
    public List<CheckResult> executeAll() {
        List<CheckResult> results = new ArrayList<>();
        results.add(runPbitJarOwnership());
        results.add(runPbitCommandAuditor());
        results.add(runCbitFuzzerAndShrinker());
        results.add(runCbitRetentionScreener());
        results.add(runCbitCausalAuditor());
        results.add(runCbitSliceBitHarness());
        results.add(runIbitOracleAndScorecard());
        java.util.function.Supplier<List<CheckResult>> liveSupplier = this.liveCheckSupplier;
        if (liveSupplier != null) {
            results.add(runLiveJvmHistogramCanary());
            try {
                List<CheckResult> platformLive = liveSupplier.get();
                if (platformLive != null) {
                    results.addAll(platformLive);
                }
            } catch (Throwable t) {
                results.add(new CheckResult(
                        "FUZZ-LIVE-ERR",
                        "LIVE",
                        false,
                        "Live platform canary exception: " + t.getMessage(),
                        0.0
                ));
            }
        }
        return List.copyOf(results);
    }

    private CheckResult runLiveJvmHistogramCanary() {
        long t0 = System.nanoTime();
        try {
            int targetCount = 19 + java.util.concurrent.ThreadLocalRandom.current().nextInt(29);
            List<LiveHeapCanary> held = new ArrayList<>(targetCount);
            for (int i = 0; i < targetCount; i++) {
                held.add(new LiveHeapCanary(System.nanoTime() ^ i));
            }
            String histoWithCanaries = io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.captureHistogram();
            String canaryClassName = LiveHeapCanary.class.getName();
            long observedWhileHeld = 0L;
            for (io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.ClassCount cc
                    : io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.parseHistogram(histoWithCanaries)) {
                if (canaryClassName.equals(cc.name())) {
                    observedWhileHeld += cc.instances();
                }
            }
            // Keep reference alive across first GC histogram capture
            int sink = held.size();
            held.clear();
            held = null;
            String histoAfterRelease = io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.captureHistogram();
            long observedAfterRelease = 0L;
            for (io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.ClassCount cc
                    : io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.parseHistogram(histoAfterRelease)) {
                if (canaryClassName.equals(cc.name())) {
                    observedAfterRelease += cc.instances();
                }
            }
            boolean ok = sink == targetCount
                    && observedWhileHeld >= targetCount
                    && observedAfterRelease < observedWhileHeld;
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-LIVE-001",
                    "LIVE-GC",
                    ok,
                    String.format(
                            Locale.ROOT,
                            "Live JMX GC.class_histogram canary (allocated=%d, post-GC held=%d -> released=%d)",
                            targetCount,
                            observedWhileHeld,
                            observedAfterRelease
                    ),
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-LIVE-001", "LIVE-GC", false, "Exception: " + t.getMessage(), ms);
        }
    }

    /**
     * Executes all checks and formats operator-ready summary lines.
     *
     * @param prefix chat/console prefix
     * @return formatted lines
     */
    public List<String> executeAllAndFormat(String prefix) {
        String p = prefix == null ? "" : prefix;
        List<CheckResult> checks = executeAll();
        List<String> lines = new ArrayList<>();
        long passedCount = checks.stream().filter(CheckResult::passed).count();
        lines.add(p + "&f=== &2[FUZZ bit] Self-Test Suite &7(" + passedCount + "/" + checks.size() + " PASS) ===");
        for (CheckResult c : checks) {
            String badge = c.passed() ? "&a[PASS]" : "&c[FAIL]";
            lines.add(String.format(
                    Locale.ROOT,
                    "%s%s &f%s &7(%s, %.2f ms) - %s",
                    p,
                    badge,
                    c.code(),
                    c.category(),
                    c.durationMs(),
                    c.summary()
            ));
        }
        return List.copyOf(lines);
    }

    private CheckResult runPbitJarOwnership() {
        long t0 = System.nanoTime();
        try {
            JarClassOwnershipIndex idx = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                    "AlphaMod.jar", Set.of("net.example.alpha.AlphaService", "com.google.gson.Gson"),
                    "BetaPlugin.jar", Set.of("net.example.beta.BetaCommand", "com.google.gson.Gson")
            ));
            boolean ok = idx.ownerJarForClass("net.example.alpha.AlphaService").orElse("").equals("AlphaMod.jar")
                    && idx.ownerJarForClass("net.example.beta.BetaCommand").orElse("").equals("BetaPlugin.jar")
                    && idx.ownerJarForClass("com.google.gson.Gson").isEmpty()
                    && idx.sharedClasses().contains("com.google.gson.Gson");
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-PBIT-001",
                    "PBIT",
                    ok,
                    "JarClassOwnershipIndex unique class attribution & shaded collision exclusion",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-PBIT-001", "PBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }

    private CheckResult runPbitCommandAuditor() {
        long t0 = System.nanoTime();
        try {
            RawCommandNode exposedReload = new RawCommandNode(
                    "reload", "literal", null, Map.of(), true, null, null, "TestPlugin.jar", List.of()
            );
            RawCommandNode root = new RawCommandNode(
                    "testplugin", "literal", null, Map.of(), true, null, null, "TestPlugin.jar", List.of(exposedReload)
            );
            RawCommandNode stopNode = new RawCommandNode(
                    "stop", "literal", null, Map.of(), true, null, null, "minecraft", List.of()
            );
            CommandAuditReport report = CommandSurfaceAuditor.auditCommandSurface(
                    Map.of("default", List.of(root, stopNode), "op", List.of(root, stopNode)),
                    List.of(),
                    JarClassOwnershipIndex.empty()
            );
            boolean stopDenied = report.commandTree().nodes().get("stop") != null
                    && report.commandTree().nodes().get("stop").denied();
            boolean reloadFlagged = report.findings().stream()
                    .anyMatch(f -> "testplugin reload".equals(f.nodeId()));
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-PBIT-002",
                    "PBIT",
                    stopDenied && reloadFlagged,
                    "CommandSurfaceAuditor DEFAULT_DENYLIST guard & LeastPrivilegeOracle exposure check",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-PBIT-002", "PBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }

    private CheckResult runCbitFuzzerAndShrinker() {
        long t0 = System.nanoTime();
        try {
            RawCommandNode numArg = new RawCommandNode(
                    "radius",
                    "argument",
                    "brigadier:integer",
                    Map.of("min", 1, "max", 1024),
                    true,
                    null,
                    null,
                    "LeakyRtp.jar",
                    List.of()
            );
            RawCommandNode rtpRoot = new RawCommandNode(
                    "rtp", "literal", null, Map.of(), false, null, null, "LeakyRtp.jar", List.of(numArg)
            );
            CommandAuditReport audit = CommandSurfaceAuditor.auditCommandSurface(
                    Map.of("default", List.of(rtpRoot), "op", List.of(rtpRoot)),
                    List.of(),
                    JarClassOwnershipIndex.fromJarClassMap(Map.of("LeakyRtp.jar", Set.of("com.example.rtp.RtpTask")))
            );
            SleuthServerFuzzer fuzzer = new SleuthServerFuzzer(
                    audit.commandTree(),
                    JarClassOwnershipIndex.fromJarClassMap(Map.of("LeakyRtp.jar", Set.of("com.example.rtp.RtpTask"))),
                    List.of("default"),
                    List.of("quit_lt1s"),
                    new Random(42L)
            );
            List<EpisodeAction> noisyTrace = List.of(
                    EpisodeAction.of("/rtp 16", "quit_lt1s", "rtp <radius>"),
                    EpisodeAction.of("/rtp 512", "quit_lt1s", "rtp <radius>")
            );
            SleuthServerFuzzer.EpisodeRunner runner = actions -> {
                for (EpisodeAction a : actions) {
                    String[] parts = a.commandLine().replace("/", "").trim().split("\\s+");
                    if (parts.length >= 2) {
                        int val = Integer.parseInt(parts[1]);
                        if (val >= 256 && "quit_lt1s".equals(a.followUpShape())) {
                            EpisodeOutcome detectedFault = EpisodeOutcome.fault(
                                    "exc:java.lang.IllegalStateException:com.example.rtp.RtpTask.run",
                                    "LeakyRtp.jar",
                                    12.0,
                                    40.0,
                                    List.of("com.example.rtp.RtpTask.run")
                            );
                            return detectedFault;
                        }
                    }
                }
                return EpisodeOutcome.clean();
            };
            DualAudienceMitigationReport report = fuzzer.minimizeAndRecordFinding(
                    noisyTrace,
                    runner.runEpisode(noisyTrace),
                    runner
            );
            PersonaProfile explorer = PersonaPolicyBotActor.defaultPersonaCatalog().get(0);
            PersonaPolicyBotActor bot = new PersonaPolicyBotActor(explorer, "default", 42);
            BotStepRecord autoStep = bot.stepAutonomousPolicy();
            String prepared = bot.prepareCommandForDispatch("/rtp 256");
            BotStepRecord quitStep = bot.performFollowUpBehavior("quit_lt1s");
            boolean ok = report.minimalCommandSequence().size() == 1
                    && report.bisectedNumericThreshold().orElse("").contains("256")
                    && autoStep != null
                    && "rtp 256".equals(prepared)
                    && !quitStep.online();
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-CBIT-001",
                    "CBIT",
                    ok,
                    "SleuthServerFuzzer ddmin + PersonaPolicyBotActor Int8[16x16] policy & lifecycle follow-up",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-CBIT-001", "CBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }

    private CheckResult runCbitRetentionScreener() {
        long t0 = System.nanoTime();
        try {
            ClassRetentionScreener screener = new ClassRetentionScreener(
                    JarClassOwnershipIndex.fromJarClassMap(Map.of("LeakySessions.jar", Set.of("com.example.SessionLeak")))
            );
            for (int i = 0; i < 4; i++) {
                String histo = String.format(
                        Locale.ROOT,
                        " num     #instances         #bytes  class name (module)%n"
                                + "-------------------------------------------------------%n"
                                + "   1: %14d %14d  com.example.SessionLeak%n",
                        10 + i * 8,
                        (10 + i * 8) * 128
                );
                screener.recordHistogramText("cp-" + i, 1000L + i * 1000L, i * 4L, i * 4L, histo);
            }
            List<ClassRetentionFinding> findings = screener.screenDepartureRetention();
            boolean ok = !findings.isEmpty()
                    && "com.example.SessionLeak".equals(findings.get(0).className())
                    && "LeakySessions.jar".equals(findings.get(0).owningJar());
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-CBIT-002",
                    "CBIT",
                    ok,
                    "ClassRetentionScreener Bonferroni OLS slope detection (+2.00 inst/departure)",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-CBIT-002", "CBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }

    private CheckResult runCbitCausalAuditor() {
        long t0 = System.nanoTime();
        try {
            byte[] vaultHookClass = buildSyntheticConstantPoolClass(
                    "com/example/canary/CanaryVaultHook",
                    List.of("net/milkbowl/vault/economy/Economy", "me/clip/placeholderapi/PlaceholderAPI")
            );
            CausalGraphReport report = BytecodeCausalGraphScanner.analyzeClasses(
                    "plugin:canary",
                    "CanaryPlugin",
                    List.of(vaultHookClass),
                    List.of(),
                    Map.of("config.yml", "warmup:\n  dead-key: true\n")
            );
            java.nio.file.Path tempDir = java.nio.file.Files.createTempDirectory("fuzz-cbit-triage");
            boolean triageOk;
            try {
                java.nio.file.Path validJar = tempDir.resolve("ValidVaultCanary.jar");
                writeCanaryJar(validJar, "name: ValidVaultCanary\nversion: 1.0.0\nmain: com.example.canary.CanaryVaultHook\n",
                        "com/example/canary/CanaryVaultHook.class", vaultHookClass);
                java.nio.file.Path brokenJar = tempDir.resolve("MissingMainCanary.jar");
                writeCanaryJar(brokenJar, "name: MissingMainCanary\nversion: 1.0.0\nmain: com.example.canary.GhostMain\n",
                        "com/example/canary/CanaryVaultHook.class", vaultHookClass);

                net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.ArtifactTriageEntry validEntry =
                        net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.evaluateSingleJar(validJar, true);
                net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.ArtifactTriageEntry brokenEntry =
                        net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.evaluateSingleJar(brokenJar, true);
                triageOk = validEntry.decision() == net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.TriageDecision.SHORTLIST_PASS
                        && validEntry.inferredEcosystemDependencies().containsAll(List.of("PlaceholderAPI", "Vault"))
                        && brokenEntry.decision() == net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.TriageDecision.REJECT
                        && brokenEntry.rejectReasons().contains(
                        net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.HardRejectReason.MISSING_DECLARED_MAIN_CLASS);
                java.nio.file.Files.deleteIfExists(validJar);
                java.nio.file.Files.deleteIfExists(brokenJar);
            } finally {
                java.nio.file.Files.deleteIfExists(tempDir);
            }
            boolean ok = report.findings().size() == 1
                    && report.findings().get(0).kind() == FindingKind.CAUSAL_DEAD_CONFIG_KEY
                    && report.inferredEcosystemDependencies().containsAll(Set.of("Vault", "PlaceholderAPI"))
                    && ListenerRegistrationMode.REGISTERED_CONFIG_GATED != ListenerRegistrationMode.UNREGISTERED
                    && triageOk;
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-CBIT-003",
                    "CBIT",
                    ok,
                    "BytecodeCausalGraphScanner causal audit, constant-pool dep inference & causal batch triage gate",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-CBIT-003", "CBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }

    private static void writeCanaryJar(
            java.nio.file.Path jarPath,
            String pluginYml,
            String classEntryName,
            byte[] classBytes
    ) throws java.io.IOException {
        try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(
                java.nio.file.Files.newOutputStream(jarPath))) {
            zos.putNextEntry(new java.util.zip.ZipEntry("plugin.yml"));
            zos.write(pluginYml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new java.util.zip.ZipEntry(classEntryName));
            zos.write(classBytes);
            zos.closeEntry();
        }
    }

    private static byte[] buildSyntheticConstantPoolClass(
            String thisClassInternal,
            List<String> referencedInternalNames
    ) throws java.io.IOException {
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        try (java.io.DataOutputStream out = new java.io.DataOutputStream(baos)) {
            out.writeInt(0xCAFEBABE);
            out.writeShort(0);
            out.writeShort(61);
            int cpCount = 1 + 4 + (referencedInternalNames.size() * 2);
            out.writeShort(cpCount);
            out.writeByte(1);
            out.writeUTF(thisClassInternal);
            out.writeByte(7);
            out.writeShort(1);
            out.writeByte(1);
            out.writeUTF("java/lang/Object");
            out.writeByte(7);
            out.writeShort(3);
            int nextIdx = 5;
            for (String ref : referencedInternalNames) {
                out.writeByte(1);
                out.writeUTF(ref);
                int utfIdx = nextIdx++;
                out.writeByte(7);
                out.writeShort(utfIdx);
                nextIdx++;
            }
            out.writeShort(0x0021);
            out.writeShort(2);
            out.writeShort(4);
            out.writeShort(0);
            out.writeShort(0);
            out.writeShort(0);
            out.writeShort(0);
        }
        return baos.toByteArray();
    }

    private CheckResult runCbitSliceBitHarness() {
        long t0 = System.nanoTime();
        try {
            BytecodeCausalGraphScanner.CausalChainSlice cleanSlice = new BytecodeCausalGraphScanner.CausalChainSlice(
                    BytecodeCausalGraphScanner.EntryPointKind.COMMAND,
                    "com.example.RtpCmd#onCommand",
                    "/rtp teleports player asynchronously",
                    BytecodeCausalGraphScanner.ListenerRegistrationMode.NOT_APPLICABLE,
                    "",
                    List.of("hasPermission(rtp.use)"),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of("com.example.RtpCmd#onCommand", "com.example.AsyncWorld#getChunkAt"),
                    Set.of("CHUNK_IO", "ASYNC_SCHEDULER", "TELEPORT")
            );
            byte[] magicHeader = new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 61};
            SliceBitHarness cleanHarness = new SliceBitHarness(
                    "CanaryRtp",
                    cleanSlice,
                    List.of(),
                    Map.of("com.example.RtpCmd", magicHeader)
            );
            SliceBitHarness.SliceBitReport cleanReport = cleanHarness.executeFullSliceBit(List.of(), List.of(), 4, 4);

            BytecodeCausalGraphScanner.CausalChainSlice failingSlice = new BytecodeCausalGraphScanner.CausalChainSlice(
                    BytecodeCausalGraphScanner.EntryPointKind.COMMAND,
                    "com.example.BrokenCmd#onCommand",
                    "/broken teleports player",
                    BytecodeCausalGraphScanner.ListenerRegistrationMode.NOT_APPLICABLE,
                    "",
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of(),
                    List.of("com.example.BrokenCmd#onCommand"),
                    Set.of("MESSAGE_ONLY")
            );
            BytecodeCausalGraphScanner.CausalFinding poppedFutureFinding = new BytecodeCausalGraphScanner.CausalFinding(
                    "CAUSAL-1",
                    "BrokenJar",
                    2,
                    FindingKind.CAUSAL_ORPHANED_SUPPLIER,
                    BytecodeCausalGraphScanner.ConfidenceTier.CONFIRMED,
                    100,
                    "com.example.BrokenCmd#onCommand",
                    "BrokenCmd spawns async future",
                    "Future popped via POP opcode",
                    "Chain thenAccept/exceptionally",
                    List.of("com.example.BrokenCmd#onCommand -> POP"),
                    ""
            );
            SliceBitHarness failingHarness = new SliceBitHarness(
                    "BrokenJar",
                    failingSlice,
                    List.of(poppedFutureFinding),
                    Map.of("com.example.BrokenCmd", magicHeader)
            );
            SliceBitHarness.SliceBitReport failingReport = failingHarness.executeFullSliceBit(List.of(), List.of(), 2, 0);

            boolean ok = cleanReport.allPassed()
                    && cleanReport.stateRestored()
                    && cleanHarness.executePbit().passed()
                    && !failingReport.pbitResult().passed()
                    && failingReport.violatedInvariants().contains("S-004-ORPHANED-FUTURE")
                    && failingReport.ibitResult().passed()
                    && failingReport.stateRestored();
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-CBIT-004",
                    "CBIT",
                    ok,
                    "SliceBitHarness per-slice PBIT/CBIT/IBIT & reversible in-memory EphemeralSliceClassLoader session",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-CBIT-004", "CBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }

    private CheckResult runIbitOracleAndScorecard() {
        long t0 = System.nanoTime();
        try {
            LogAndStallSignatureOracle oracle = new LogAndStallSignatureOracle(
                    JarClassOwnershipIndex.fromJarClassMap(Map.of("StallMod.jar", Set.of("com.example.stall.TickBlocker")))
            );
            oracle.recordSlowTickStack(
                    180.0,
                    new StackTraceElement[]{
                            new StackTraceElement("com.example.stall.TickBlocker", "onTick", "TickBlocker.java", 42)
                    },
                    0L
            );
            StackTraceElement[] syncChunkStack = new StackTraceElement[]{
                    new StackTraceElement("net.minecraft.server.level.ServerChunkCache", "getChunk", "ServerChunkCache.java", 120),
                    new StackTraceElement("com.example.stall.TickBlocker", "syncTeleport", "TickBlocker.java", 64)
            };
            var hazardSig = oracle.recordMainThreadHazardStack(28.0, syncChunkStack, 0L);
            Set<String> covTokens = oracle.extractTargetCoverageTokens(syncChunkStack);
            LeafFuzzScorecardReport card = new LeafFuzzScorecardReport(
                    "StallMod",
                    "fabric",
                    "26.1.2",
                    1,
                    4,
                    2,
                    List.of(),
                    8,
                    4,
                    List.of(),
                    oracle.rankedSignatures(),
                    3,
                    List.of(),
                    25L
            );
            String md = card.toMarkdownReport();
            LeafFuzzMenuBuilder menuBuilder = new LeafFuzzMenuBuilder();
            MenuDescriptor book = menuBuilder.buildScorecardBook(card);
            List<String> contrastViolations = BookContrastValidator.auditMenuDescriptor(book);
            boolean ok = card.overallVerdict() == LeafFuzzScorecardReport.Verdict.FAIL
                    && hazardSig.isPresent()
                    && "hazard:sync-chunk:com.example.stall.TickBlocker.syncTeleport".equals(hazardSig.get().signatureId())
                    && covTokens.contains("cov:StallMod.jar:com.example.stall.TickBlocker.syncTeleport:64")
                    && md.contains("stall:com.example.stall.TickBlocker.onTick")
                    && md.contains("StallMod.jar")
                    && contrastViolations.isEmpty();
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult(
                    "FUZZ-IBIT-001",
                    "IBIT",
                    ok,
                    "LogAndStallSignatureOracle stall/hazard/cov attribution, BookContrastValidator scorecard & Markdown export",
                    ms
            );
        } catch (Throwable t) {
            double ms = (System.nanoTime() - t0) / 1_000_000.0;
            return new CheckResult("FUZZ-IBIT-001", "IBIT", false, "Exception: " + t.getMessage(), ms);
        }
    }
}
