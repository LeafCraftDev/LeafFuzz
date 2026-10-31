package io.github.dailystruggle.rtp.common.bit.config.atlas;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.ClaimDeliveryFinding;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.ConfidenceTier;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.FindingKind;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.ListenerRegistrationMode;
import io.github.dailystruggle.rtp.common.bit.config.atlas.LlmConfigDocSynthesizer.LlmHookConfig;
import io.github.dailystruggle.rtp.common.bit.config.atlas.LlmConfigDocSynthesizer.Provider;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies {@link BytecodeCausalGraphScanner} first-order and second-order claim delivery
 * auditing, config-gated listener registration recognition ({@code onEventParsing}), and
 * {@link LlmCausalChainAuditor} closed-world AST symbol grounding ({@code leaffuzz-ADR-001},
 * {@code ADR-125}, {@code corpus-atlas-ADR-002}).
 */
@DisplayName("BytecodeCausalGraphScanner & LlmCausalChainAuditor Tests (REQ-CFG-ATLAS-001, REQ-SLEUTH-FUZZ-004)")
class BytecodeCausalGraphScannerTest {

    /** Synthetic EventHandler annotation whose bytecode name matches Bukkit's @EventHandler. */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface EventHandler {
    }

    static final class PlayerMoveEvent {
    }

    static final class PlayerJoinEvent {
    }

    static final class PlayerTeleportEvent {
    }

    static final class FakeWorld {
        void getChunkAt(int x, int z) {
        }
    }

    static final class FakePlayer {
        void sendMessage(String msg) {
        }

        void teleportAsync(String destination) {
        }
    }

    /**
     * Order 1 Unregistered Listener fixture: has @EventHandler but is never instantiated anywhere.
     */
    static final class UnregisteredMoveCancelListener {
        @EventHandler
        public void onMove(PlayerMoveEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    /**
     * Unconditionally registered listener fixture: instantiated on startup.
     */
    static final class ActiveJoinListener {
        @EventHandler
        public void onJoin(PlayerJoinEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    /**
     * Inline config-gated listener fixture: instantiated inside an {@code if (flag)} block.
     */
    static final class InlineConfigGatedListener {
        @EventHandler
        public void onTeleport(PlayerTeleportEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    /**
     * Early-return config-gated listener fixture: instantiated after {@code if (!flag) return;}.
     */
    static final class EarlyReturnConfigGatedListener {
        @EventHandler
        public void onTeleport(PlayerTeleportEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    /**
     * Helper-method config-gated listener fixture: instantiated inside a helper method that is
     * only invoked when a config condition is true.
     */
    static final class HelperMethodConfigGatedListener {
        @EventHandler
        public void onTeleport(PlayerTeleportEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    /**
     * Synthetic plugin main &amp; config loader class testing:
     * <ul>
     *   <li>Unconditional listener registration ({@link ActiveJoinListener})</li>
     *   <li>Generalized config-gated listener registration across all 3 bytecode patterns:
     *       inline {@code if}, early-return guard, and caller-gated helper method</li>
     *   <li>Unread config field ({@code cancelOnDamage} loaded from {@code warmup.cancel-on-damage} with 0 readers)</li>
     *   <li>Unscaled seconds config field ({@code cooldownSeconds} loaded from {@code cooldown.seconds} and added to {@code System.currentTimeMillis()})</li>
     * </ul>
     */
    @SuppressWarnings("unused")
    static final class SyntheticVibecodedPlugin {
        private boolean cancelOnDamage;
        private int cooldownSeconds;

        boolean getBoolean(String key) {
            return false;
        }

        int getInt(String key) {
            return 5;
        }

        void registerEvents(Object listener) {
        }

        void getCommand(String name) {
        }

        void runTaskAsynchronously(Runnable task) {
            task.run();
        }

        public void onEnable() {
            getCommand("wild");
            loadConfig();
            setupListeners();
            registerEarlyGuardListener();
        }

        public void loadConfig() {
            this.cancelOnDamage = getBoolean("warmup.cancel-on-damage");
            this.cooldownSeconds = getInt("cooldown.seconds");
        }

        private void setupListeners() {
            boolean inlineGate = getBoolean("features.inline-event-gate");
            if (inlineGate) {
                registerEvents(new InlineConfigGatedListener());
            }
            if (getBoolean("features.helper-event-gate")) {
                registerOptionalHelperListener();
            }
            registerEvents(new ActiveJoinListener());
        }

        private void registerEarlyGuardListener() {
            if (!getBoolean("features.early-return-gate")) {
                return;
            }
            registerEvents(new EarlyReturnConfigGatedListener());
        }

        private void registerOptionalHelperListener() {
            registerEvents(new HelperMethodConfigGatedListener());
        }

        public long computeNextAllowedTimestamp() {
            // Bug: adds unscaled cooldownSeconds directly to System.currentTimeMillis() without * 1000L
            return System.currentTimeMillis() + this.cooldownSeconds;
        }

        public void spawnAsyncChunkLoad(FakeWorld world) {
            // Bug (S-005): calls synchronous World#getChunkAt inside an async lambda
            runTaskAsynchronously(() -> world.getChunkAt(0, 0));
        }

        public void swallowDatabaseException() {
            try {
                mightThrowIo();
            } catch (IOException ignored) {
                // Bug (S-004): empty catch handler returning silently
                return;
            }
        }

        private void mightThrowIo() throws IOException {
            throw new IOException("disk full");
        }
    }

    /**
     * Order 2 Hollow + Orphaned Supplier command fixture:
     * <ul>
     *   <li>Spawns {@code CompletableFuture.supplyAsync} and immediately drops the return value ({@code POP}).</li>
     *   <li>Only calls {@code player.sendMessage(...)} with zero teleport/world/inventory mutations.</li>
     * </ul>
     */
    static final class HollowOrphanedWildCommand {
        public boolean onCommand(FakePlayer player) {
            CompletableFuture.supplyAsync(() -> "world:100,64,100");
            player.sendMessage("Teleporting you to the wild...");
            return true;
        }
    }

    @Test
    @DisplayName("Order 1 & Order 2: Detects unregistered listener, dead config key, unwired command, unread field, unit mismatch, orphaned supplier, S-004 swallowed exception, S-005 async chunk load, and hollow command while respecting config-gated listeners")
    void detectsFirstAndSecondOrderBugsAndRespectsConfigGatedListeners() throws IOException {
        List<byte[]> classes = List.of(
                readClassBytes(UnregisteredMoveCancelListener.class),
                readClassBytes(ActiveJoinListener.class),
                readClassBytes(InlineConfigGatedListener.class),
                readClassBytes(EarlyReturnConfigGatedListener.class),
                readClassBytes(HelperMethodConfigGatedListener.class),
                readClassBytes(SyntheticVibecodedPlugin.class),
                readClassBytes(HollowOrphanedWildCommand.class)
        );

        List<JarConfigScanner.CommandDescriptor> commands = List.of(
                new JarConfigScanner.CommandDescriptor(
                        "wild",
                        "VibecodedWild",
                        "Teleports player to a safe random location",
                        "/wild",
                        List.of(),
                        "wild.use",
                        "true"
                ),
                new JarConfigScanner.CommandDescriptor(
                        "unwiredwarp",
                        "VibecodedWild",
                        "Teleports player to a warp",
                        "/unwiredwarp",
                        List.of(),
                        "wild.warp",
                        "op"
                )
        );

        String configYml = """
                features:
                  inline-event-gate: false
                  early-return-gate: false
                  helper-event-gate: false
                warmup:
                  # Cancel warmup when player takes damage
                  cancel-on-damage: true
                  # Completely dead key never referenced in bytecode
                  phantom-particle-spiral: true
                cooldown:
                  seconds: 30
                """;

        CausalGraphReport report = BytecodeCausalGraphScanner.analyzeClasses(
                "plugin:vibecodedwild",
                "VibecodedWild",
                classes,
                commands,
                Map.of("config.yml", configYml)
        );

        assertNotNull(report);

        // 1. Verify Generalized Listener Registration Modes across all 3 config-gating shapes
        Map<String, ListenerRegistrationMode> regMap = report.listenerRegistrations();
        assertEquals(
                ListenerRegistrationMode.UNREGISTERED,
                regMap.get(UnregisteredMoveCancelListener.class.getName()),
                "UnregisteredMoveCancelListener must be flagged as UNREGISTERED"
        );
        assertEquals(
                ListenerRegistrationMode.REGISTERED_UNCONDITIONAL,
                regMap.get(ActiveJoinListener.class.getName()),
                "ActiveJoinListener must be recognized as REGISTERED_UNCONDITIONAL"
        );
        assertEquals(
                ListenerRegistrationMode.REGISTERED_CONFIG_GATED,
                regMap.get(InlineConfigGatedListener.class.getName()),
                "Inline if(config) listener must be recognized as REGISTERED_CONFIG_GATED"
        );
        assertEquals(
                ListenerRegistrationMode.REGISTERED_CONFIG_GATED,
                regMap.get(EarlyReturnConfigGatedListener.class.getName()),
                "Early-return if(!config) return; listener must be recognized as REGISTERED_CONFIG_GATED"
        );
        assertEquals(
                ListenerRegistrationMode.REGISTERED_CONFIG_GATED,
                regMap.get(HelperMethodConfigGatedListener.class.getName()),
                "Caller-gated helper method listener must be recognized as REGISTERED_CONFIG_GATED"
        );
        assertEquals(
                "features.inline-event-gate",
                report.configGatedListeners().get(InlineConfigGatedListener.class.getName())
        );
        assertEquals(
                "features.early-return-gate",
                report.configGatedListeners().get(EarlyReturnConfigGatedListener.class.getName())
        );
        assertEquals(
                "features.helper-event-gate",
                report.configGatedListeners().get(HelperMethodConfigGatedListener.class.getName())
        );

        // Ensure ConfigGatedOnEventTeleports does NOT appear in CLAIM_UNREGISTERED_LISTENER findings
        List<ClaimDeliveryFinding> unregFindings = report.findings().stream()
                .filter(f -> f.kind() == FindingKind.CLAIM_UNREGISTERED_LISTENER)
                .toList();
        assertEquals(1, unregFindings.size());
        assertTrue(unregFindings.get(0).entryPointSymbol().contains("UnregisteredMoveCancelListener"));
        assertEquals(ConfidenceTier.CONFIRMED, unregFindings.get(0).confidenceTier());

        // 2. Verify all expected Order 1 and Order 2 FindingKinds are detected
        Set<FindingKind> detectedKinds = report.findings().stream()
                .map(ClaimDeliveryFinding::kind)
                .collect(Collectors.toSet());

        assertTrue(detectedKinds.contains(FindingKind.CLAIM_UNREGISTERED_LISTENER), "Must detect Order 1 unregistered listener");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_UNWIRED_COMMAND), "Must detect Order 1 unwired command /unwiredwarp");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_DEAD_CONFIG_KEY), "Must detect Order 1 dead config.yml key warmup.phantom-particle-spiral");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_UNREAD_CONFIG_FIELD), "Must detect Order 2 unread field cancelOnDamage");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_UNIT_MISMATCH), "Must detect Order 2 seconds + currentTimeMillis unit mismatch");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_ORPHANED_SUPPLIER), "Must detect Order 2 popped CompletableFuture.supplyAsync");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_SWALLOWED_FAILURE), "Must detect Order 2 S-004 empty catch block");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_ASYNC_MAIN_THREAD_SINK), "Must detect Order 2 S-005 World#getChunkAt in async lambda");
        assertTrue(detectedKinds.contains(FindingKind.CLAIM_HOLLOW_COMMAND), "Must detect Order 2 hollow command sending message only");

        // Verify runtime corroboration upgrades hollow command confidence
        ClaimDeliveryFinding hollow = report.findings().stream()
                .filter(f -> f.kind() == FindingKind.CLAIM_HOLLOW_COMMAND)
                .findFirst()
                .orElseThrow();
        ClaimDeliveryFinding corroborated = hollow.withRuntimeCorroboration(18, 0, 0);
        assertTrue(corroborated.confidencePercent() >= 92);
        assertTrue(corroborated.doesNotDeliver().contains("Corroborated by Stage 2 live fuzzing: 18 execution(s)"));
        assertTrue(corroborated.formatSummaryLine().contains("Claims:"));
        assertTrue(corroborated.formatSummaryLine().contains("Does Not Deliver:"));
    }

    @Test
    @DisplayName("LlmCausalChainAuditor: Closed-world AST symbol gate accepts grounded symbols and rejects hallucinated Class#method references")
    void llmAuditorEnforcesClosedWorldSymbolGate() throws IOException {
        List<byte[]> classes = List.of(
                readClassBytes(HollowOrphanedWildCommand.class),
                readClassBytes(SyntheticVibecodedPlugin.class),
                readClassBytes(FakePlayer.class)
        );
        CausalGraphReport report = BytecodeCausalGraphScanner.analyzeClasses(
                "plugin:vibecodedwild",
                "VibecodedWild",
                classes,
                List.of(),
                Map.of()
        );

        assertTrue(
                LlmCausalChainAuditor.passesClosedWorldSymbolGate(
                        "HollowOrphanedWildCommand#onCommand spawns CompletableFuture#supplyAsync but drops the result before calling Player#teleportAsync.",
                        report.closedWorldSymbols()
                ),
                "Explanation citing real class/method symbols from the JAR and standard Bukkit/JDK sinks must pass"
        );

        assertFalse(
                LlmCausalChainAuditor.passesClosedWorldSymbolGate(
                        "The crash occurs because HallucinatedTeleportManager#dispatchAsync returns null.",
                        report.closedWorldSymbols()
                ),
                "Explanation citing a hallucinated Class#method outside the JAR must be rejected"
        );

        // Verify LlmCausalChainAuditor mock transport enrichment
        LlmHookConfig cfg = new LlmHookConfig(
                Provider.GEMINI,
                "gemini-2.5-flash",
                "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                "",
                11434,
                "test-api-key",
                "GEMINI_API_KEY",
                3000,
                220
        );
        LlmCausalChainAuditor groundedAuditor = new LlmCausalChainAuditor(
                cfg,
                (url, headers, body, timeout) -> "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"{\\\"explanation\\\":\\\"HollowOrphanedWildCommand#onCommand pops the CompletableFuture#supplyAsync result without chaining Player#teleportAsync.\\\"}\"}]}}]}"
        );

        List<ClaimDeliveryFinding> enriched = groundedAuditor.enrichFindingsWithExplanations(report, 2);
        assertTrue(
                enriched.stream().anyMatch(f -> f.llmExplanation().contains("HollowOrphanedWildCommand#onCommand")),
                "Grounded LLM explanation must be attached to the finding"
        );

        String crashExplanation = groundedAuditor.explainProvenFuzzFault(
                "exc:NullPointerException@HollowOrphanedWildCommand#onCommand:42",
                "HollowOrphanedWildCommand#onCommand:42",
                List.of("wild -999999"),
                "quit_lt1s",
                report
        );
        assertTrue(crashExplanation.contains("HollowOrphanedWildCommand#onCommand"));

        // Hallucinating transport must be rejected cleanly (returns empty string)
        LlmCausalChainAuditor hallucinatingAuditor = new LlmCausalChainAuditor(
                cfg,
                (url, headers, body, timeout) -> "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"{\\\"explanation\\\":\\\"FakeClass#fakeMethod threw an exception.\\\"}\"}]}}]}"
        );
        assertEquals(
                "",
                hallucinatingAuditor.explainProvenFuzzFault(
                        "exc:NullPointerException",
                        "HollowOrphanedWildCommand#onCommand:42",
                        List.of("wild"),
                        "quit_lt1s",
                        report
                ),
                "Hallucinated symbol in LLM explanation must be rejected by closed-world AST gate"
        );

        // Verify auditCausalChainsWithLlm across OPENAI_COMPATIBLE and ANTHROPIC providers
        LlmHookConfig openAiCfg = new LlmHookConfig(
                Provider.OPENAI_COMPATIBLE,
                "gpt-4o-mini",
                "https://api.openai.com/v1/chat/completions",
                "",
                11434,
                "sk-test",
                "OPENAI_API_KEY",
                3000,
                220
        );
        LlmCausalChainAuditor openAiAuditor = new LlmCausalChainAuditor(
                openAiCfg,
                (url, headers, body, timeout) -> "{\"choices\":[{\"message\":{\"content\":\"{\\\"status\\\":\\\"BUG\\\",\\\"claims\\\":\\\"HollowOrphanedWildCommand#onCommand teleports player\\\",\\\"doesNotDeliver\\\":\\\"HollowOrphanedWildCommand#onCommand only calls FakePlayer#sendMessage\\\",\\\"clearsWhen\\\":\\\"Call FakePlayer#teleportAsync\\\"}\"}}]}"
        );
        List<ClaimDeliveryFinding> advisoryFindings = openAiAuditor.auditCausalChainsWithLlm(report, 4);
        assertFalse(advisoryFindings.isEmpty());
        assertEquals(ConfidenceTier.ADVISORY, advisoryFindings.get(0).confidenceTier());
        assertEquals(FindingKind.CLAIM_LLM_SEMANTIC_MISMATCH, advisoryFindings.get(0).kind());

        LlmHookConfig anthropicCfg = new LlmHookConfig(
                Provider.ANTHROPIC,
                "claude-3-5-haiku-latest",
                "https://api.anthropic.com/v1/messages",
                "",
                11434,
                "sk-ant-test",
                "ANTHROPIC_API_KEY",
                3000,
                220
        );
        LlmCausalChainAuditor anthropicAuditor = new LlmCausalChainAuditor(
                anthropicCfg,
                (url, headers, body, timeout) -> "{\"content\":[{\"text\":\"{\\\"explanation\\\":\\\"HollowOrphanedWildCommand#onCommand drops the future.\\\"}\"}]}"
        );
        assertTrue(
                anthropicAuditor.explainProvenFuzzFault(
                        "exc:NPE",
                        "HollowOrphanedWildCommand#onCommand:10",
                        List.of("wild"),
                        "repeat",
                        report
                ).contains("HollowOrphanedWildCommand#onCommand")
        );

        // Verify Provider.OFF returns immediately with zero HTTP calls
        LlmHookConfig offCfg = new LlmHookConfig(
                Provider.OFF,
                "none",
                "",
                "",
                11434,
                "",
                "GEMINI_API_KEY",
                1000,
                200
        );
        LlmCausalChainAuditor offAuditor = new LlmCausalChainAuditor(offCfg);
        assertEquals("", offAuditor.explainProvenFuzzFault("exc:NPE", "frame", List.of(), "repeat", report));
        assertTrue(offAuditor.auditCausalChainsWithLlm(report, 4).isEmpty());
        assertEquals(report.findings().size(), offAuditor.enrichFindingsWithExplanations(report, 4).size());
    }

    @Test
    @DisplayName("scanJar: Scans synthetic plugin .jar archive from disk and renders Jminor prompt blocks")
    void scanJarExtractsCausalChainsAndFindingsFromArchive(@TempDir Path tempDir) throws IOException {
        Path jarFile = tempDir.resolve("VibecodedWild.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jarFile.toFile()))) {
            zos.putNextEntry(new ZipEntry("plugin.yml"));
            zos.write("""
                    name: VibecodedWild
                    version: 1.0.0
                    main: io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScannerTest$SyntheticVibecodedPlugin
                    commands:
                      wild:
                        description: Teleports player to a safe random location
                      unwiredwarp:
                        description: Teleports player to warp
                    """.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            zos.putNextEntry(new ZipEntry("config.yml"));
            zos.write("""
                    features:
                      inline-event-gate: false
                      early-return-gate: false
                      helper-event-gate: false
                    warmup:
                      cancel-on-damage: true
                      dead-key: 42
                    cooldown:
                      seconds: 15
                    """.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();

            for (Class<?> cls : List.of(
                    UnregisteredMoveCancelListener.class,
                    ActiveJoinListener.class,
                    InlineConfigGatedListener.class,
                    EarlyReturnConfigGatedListener.class,
                    HelperMethodConfigGatedListener.class,
                    SyntheticVibecodedPlugin.class,
                    HollowOrphanedWildCommand.class
            )) {
                String entryName = cls.getName().replace('.', '/') + ".class";
                zos.putNextEntry(new ZipEntry(entryName));
                zos.write(readClassBytes(cls));
                zos.closeEntry();
            }
        }

        CausalGraphReport scanned = BytecodeCausalGraphScanner.scanJar(jarFile);
        assertNotNull(scanned);
        assertEquals("VibecodedWild", scanned.displayName());
        assertFalse(scanned.entryChains().isEmpty());
        assertFalse(scanned.findings().isEmpty());
        for (var chain : scanned.entryChains()) {
            String block = chain.toJminorPromptBlock();
            assertTrue(block.contains("CAUSAL_CHAIN [ENTRY_"));
            assertTrue(block.contains("REACHABLE_SINKS:"));
        }
        assertNotNull(CausalGraphReport.empty("EmptyTest"));
        assertEquals(100, ConfidenceTier.CONFIRMED.defaultPercent());
        assertEquals("CONFIRMED 100%", ConfidenceTier.CONFIRMED.badge());
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    @interface CommandAlias {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface Subcommand {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    @interface CommandPermission {
        String value();
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.TYPE, ElementType.METHOD})
    @interface Description {
        String value();
    }

    static final class CustomTeleportRequestEvent {
        final FakePlayer player;
        final String destination;

        CustomTeleportRequestEvent(FakePlayer player, String destination) {
            this.player = player;
            this.destination = destination;
        }
    }

    static final class FakePluginManager {
        void callEvent(Object event) {
        }
    }

    static final class DecoupledTeleportSubscriber {
        @EventHandler
        public void onCustomTeleport(CustomTeleportRequestEvent event) {
            if (event != null && event.player != null) {
                event.player.teleportAsync(event.destination);
            }
        }
    }

    @CommandAlias("acfwild|awild")
    @CommandPermission("acfwild.use")
    static final class AnnotatedAndDecoupledCommandFixture {
        private final java.util.Queue<Runnable> pendingJobs = new java.util.concurrent.ConcurrentLinkedQueue<>();
        private final FakePluginManager pluginManager = new FakePluginManager();

        public void registerAll() {
            DecoupledTeleportSubscriber sub = new DecoupledTeleportSubscriber();
            if (sub.hashCode() == -1) {
                pollBackgroundQueue();
            }
        }

        @Subcommand("confirm|force")
        @Description("Teleports player after confirmation")
        public void onConfirm(FakePlayer player, int radius) {
            pluginManager.callEvent(new CustomTeleportRequestEvent(player, "world:" + radius));
        }

        public boolean onCommand(FakePlayer sender, String cmd, String label, String[] args) {
            if (args.length > 0 && args[0].equalsIgnoreCase("confirm")) {
                int dist = args.length > 1 ? Integer.parseInt(args[1]) : 100;
                pendingJobs.offer(() -> sender.teleportAsync("queued:" + dist));
                return true;
            }
            if (args.length > 0 && args[0].equals("reload")) {
                if (hasPermission(sender, "acfwild.admin.reload")) {
                    sender.sendMessage("Reloaded!");
                }
                return true;
            }
            return false;
        }

        private boolean hasPermission(FakePlayer sender, String node) {
            return sender != null && node != null && !node.isEmpty();
        }

        public void pollBackgroundQueue() {
            Runnable job = pendingJobs.poll();
            if (job != null) {
                job.run();
                new FakePlayer().teleportAsync("worker-drain");
            }
        }
    }

    @Test
    @DisplayName("Decoupled dispatch & white-box schemas: Traces callEvent -> @EventHandler, Queue offer -> poll, ACF/Cloud annotations, and BytecodeCommandSchema literals/parsers/permissions")
    void tracesDecoupledEventAndQueueEdgesAndExtractsWhiteBoxCommandSchemas() throws IOException {
        List<byte[]> classes = List.of(
                readClassBytes(CustomTeleportRequestEvent.class),
                readClassBytes(FakePluginManager.class),
                readClassBytes(DecoupledTeleportSubscriber.class),
                readClassBytes(AnnotatedAndDecoupledCommandFixture.class),
                readClassBytes(FakePlayer.class)
        );
        List<JarConfigScanner.CommandDescriptor> declaredCommands = List.of(
                new JarConfigScanner.CommandDescriptor(
                        "acfwild",
                        "AcfWild",
                        "Teleports player via ACF command",
                        "/acfwild confirm <radius>",
                        List.of("awild"),
                        "acfwild.use",
                        "true"
                ),
                new JarConfigScanner.CommandDescriptor(
                        "queuedwild",
                        "AcfWild",
                        "Teleports player via background queue",
                        "/queuedwild confirm <dist>",
                        List.of(),
                        "queuedwild.use",
                        "true"
                )
        );

        CausalGraphReport report = BytecodeCausalGraphScanner.analyzeClasses(
                "plugin:acfwild",
                "AcfWild",
                classes,
                declaredCommands,
                Map.of()
        );

        // 1. Verify @Subcommand("confirm|force") on @CommandAlias("acfwild|awild") is discovered as COMMAND entry point
        //    and traces through CustomTeleportRequestEvent -> DecoupledTeleportSubscriber#onCustomTeleport -> teleportAsync
        var acfChain = report.entryChains().stream()
                .filter(c -> c.entrySymbol().contains("onConfirm"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Expected annotated @Subcommand method onConfirm to be harvested as COMMAND root"));
        assertTrue(
                acfChain.advertisedClaim().contains("/acfwild confirm")
                        && acfChain.advertisedClaim().contains("Teleports player after confirmation"),
                "Expected @CommandAlias + @Subcommand + @Description claim synthesis, got: " + acfChain.advertisedClaim()
        );
        assertTrue(
                acfChain.reachableEffectSinks().contains("EVENT_DISPATCH") && acfChain.reachableEffectSinks().contains("TELEPORT"),
                "Expected callEvent(new CustomTeleportRequestEvent) to link to @EventHandler subscriber's TELEPORT sink, got: " + acfChain.reachableEffectSinks()
        );

        // 2. Verify onCommand queue producer (pendingJobs.offer) links to pollBackgroundQueue consumer (pendingJobs.poll) -> TELEPORT
        var onCommandChain = report.entryChains().stream()
                .filter(c -> c.entrySymbol().contains("onCommand"))
                .findFirst()
                .orElseThrow();
        assertTrue(
                onCommandChain.reachableEffectSinks().contains("QUEUE_HANDOFF") && onCommandChain.reachableEffectSinks().contains("TELEPORT"),
                "Expected queue producer to trace through QUEUE_HANDOFF into consumer's TELEPORT sink, got: " + onCommandChain.reachableEffectSinks()
        );

        // 3. Neither command should be flagged as CLAIM_HOLLOW_COMMAND or CLAIM_UNWIRED_COMMAND
        assertFalse(
                report.findings().stream().anyMatch(f -> f.kind() == FindingKind.CLAIM_HOLLOW_COMMAND),
                "Decoupled event and queue commands delivering TELEPORT via subscriber/worker must not be flagged as hollow: " + report.findings()
        );
        assertFalse(
                report.findings().stream().anyMatch(f -> f.kind() == FindingKind.CLAIM_UNWIRED_COMMAND && f.claims().contains("acfwild")),
                "@CommandAlias(\"acfwild\") must satisfy plugin.yml command wiring check"
        );

        // 4. Verify white-box BytecodeCommandSchema extraction (subcommand literals, argument parsers, inline permissions)
        assertFalse(report.commandSchemas().isEmpty(), "Expected BytecodeCommandSchema list to be populated");
        boolean foundConfirmAndReloadLiterals = report.commandSchemas().stream()
                .anyMatch(s -> s.subcommandLiterals().contains("confirm") && s.subcommandLiterals().contains("reload"));
        assertTrue(foundConfirmAndReloadLiterals, "Expected bytecode string comparisons args[0].equalsIgnoreCase(\"confirm\") and \"reload\" to be extracted: " + report.commandSchemas());

        boolean foundIntegerParser = report.commandSchemas().stream()
                .anyMatch(s -> s.argumentParsers().contains("brigadier:integer"));
        assertTrue(foundIntegerParser, "Expected Integer.parseInt / int parameter to extract brigadier:integer parser: " + report.commandSchemas());

        boolean foundInlinePermission = report.commandSchemas().stream()
                .anyMatch(s -> s.inlinePermissions().contains("acfwild.admin.reload") || s.inlinePermissions().contains("acfwild.use"));
        assertTrue(foundInlinePermission, "Expected inline hasPermission / @CommandPermission to be extracted: " + report.commandSchemas());
    }

    private static byte[] readClassBytes(Class<?> clazz) throws IOException {
        String resourcePath = "/" + clazz.getName().replace('.', '/') + ".class";
        try (InputStream in = clazz.getResourceAsStream(resourcePath)) {
            assertNotNull(in, "Missing class resource: " + resourcePath);
            return in.readAllBytes();
        }
    }
}
