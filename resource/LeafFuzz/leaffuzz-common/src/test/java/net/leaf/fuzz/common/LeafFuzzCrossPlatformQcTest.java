package net.leaf.fuzz.common;

import io.github.dailystruggle.commandsapi.common.CommandsAPI;
import io.github.dailystruggle.menu.api.BookContrastValidator;
import io.github.dailystruggle.menu.api.MenuDescriptor;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.ClaimDeliveryFinding;
import io.github.dailystruggle.rtp.common.bit.config.atlas.JarConfigScanner;
import io.github.dailystruggle.server.api.BookMenuSpec;
import io.github.dailystruggle.server.api.PlayerLifecycleHook;
import io.github.dailystruggle.server.api.ServerAccessor;
import io.github.dailystruggle.server.api.TaskHandle;
import io.github.dailystruggle.server.api.TaskScheduler;
import net.leaf.fuzz.common.cli.LeafFuzzStandaloneCli;
import net.leaf.fuzz.common.cli.LeafFuzzTcpSwarmClient;
import net.leaf.fuzz.common.command.LeafFuzzCommand;
import net.leaf.fuzz.common.ui.LeafFuzzMenuBuilder;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.BotStepRecord;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.PersonaProfile;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-platform verification suite for {@code LeafFuzz} ({@code leaffuzz-ADR-001}).
 *
 * <p>Verifies:
 * <ul>
 *   <li>Architectural purity of {@code leaffuzz-common} (zero Bukkit, Paper, Fabric, NeoForge, or NMS imports).</li>
 *   <li>Multi-format archive scanning in {@link JarClassOwnershipIndex} across Paper ({@code paper-plugin.yml}),
 *       Fabric ({@code fabric.mod.json}), and NeoForge ({@code META-INF/neoforge.mods.toml}).</li>
 *   <li>Reflective Brigadier command-tree extraction and target filtering in {@link BrigadierDispatcherInspector}.</li>
 *   <li>End-to-end 4-stage {@code /fuzz check <target>} execution, {@code ddmin} reproducer shrinking,
 *       post-GC Bonferroni OLS leak screening, and Markdown scorecard export.</li>
 *   <li>{@link LeafFuzzBitSuite} PBIT/CBIT/IBIT self-test execution.</li>
 * </ul>
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-001
 * @trace REQ-SLEUTH-FUZZ-002
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-004
 * @trace S-005
 * @trace S-007
 */
class LeafFuzzCrossPlatformQcTest {

    private static final List<String> FORBIDDEN_IMPORTS = List.of(
            "import org.bukkit.",
            "import io.papermc.",
            "import net.minecraft.",
            "import net.fabricmc.",
            "import net.neoforged."
    );

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-001 & leaffuzz-ADR-001: leaffuzz-common contains zero platform or mod-loader imports")
    void leaffuzzCommonHasZeroPlatformImports() throws IOException {
        Path srcMain = Paths.get("src", "main", "java");
        assertTrue(Files.exists(srcMain), "Expected src/main/java to exist");
        try (Stream<Path> walk = Files.walk(srcMain)) {
            List<Path> javaFiles = walk.filter(p -> p.toString().endsWith(".java")).toList();
            assertFalse(javaFiles.isEmpty());
            for (Path file : javaFiles) {
                String source = Files.readString(file, StandardCharsets.UTF_8);
                for (String forbidden : FORBIDDEN_IMPORTS) {
                    assertFalse(
                            source.contains(forbidden),
                            () -> "Forbidden platform import '" + forbidden + "' found in " + file
                    );
                }
            }
        }
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-001: JarClassOwnershipIndex indexes Paper plugin.yml, Fabric fabric.mod.json, and NeoForge neoforge.mods.toml archives")
    void jarClassOwnershipIndexSupportsPaperFabricAndNeoForgeArchives(@TempDir Path tempDir) throws IOException {
        Path pluginsDir = Files.createDirectories(tempDir.resolve("plugins"));
        Path modsDir = Files.createDirectories(tempDir.resolve("mods"));

        createSyntheticJar(
                pluginsDir.resolve("PaperWarpPlugin-1.0.jar"),
                "paper-plugin.yml",
                "name: PaperWarp\nversion: 1.0\n",
                List.of("com/example/paperwarp/WarpManager.class", "com/google/gson/Gson.class")
        );
        createSyntheticJar(
                modsDir.resolve("fabric-biome-mod-2.0.jar"),
                "fabric.mod.json",
                "{\n  \"schemaVersion\": 1,\n  \"id\": \"fabricbiomemod\",\n  \"version\": \"2.0\"\n}\n",
                List.of("net/example/fabricbiome/BiomeGenerator.class", "com/google/gson/Gson.class")
        );
        createSyntheticJar(
                modsDir.resolve("neoforge-quarry-3.1.jar"),
                "META-INF/neoforge.mods.toml",
                "modLoader = \"javafml\"\n[[mods]]\nmodId = \"neoquarry\"\nversion = \"3.1\"\n",
                List.of("dev/example/neoquarry/QuarryTicker.class")
        );
        createSyntheticJar(
                modsDir.resolve("LeafFuzz-0.1.0.jar"),
                "fabric.mod.json",
                "{\n  \"schemaVersion\": 1,\n  \"id\": \"leaffuzz\"\n}\n",
                List.of("net/leaf/fuzz/common/LeafFuzzRuntime.class")
        );

        JarClassOwnershipIndex idx = JarClassOwnershipIndex.scanArchiveDirectories(
                List.of(pluginsDir, modsDir),
                List.of("leaffuzz")
        );

        assertEquals(3, idx.indexedJarCount(), "Expected 3 indexed archives (excluding self LeafFuzz.jar)");
        assertEquals(
                Optional.of("PaperWarpPlugin-1.0.jar"),
                idx.ownerJarForClass("com.example.paperwarp.WarpManager")
        );
        assertEquals(
                "PaperWarp",
                idx.descriptors().get("PaperWarpPlugin-1.0.jar").pluginId()
        );
        assertEquals(
                Optional.of("fabric-biome-mod-2.0.jar"),
                idx.ownerJarForClass("net.example.fabricbiome.BiomeGenerator")
        );
        assertEquals(
                "fabricbiomemod",
                idx.descriptors().get("fabric-biome-mod-2.0.jar").pluginId()
        );
        assertEquals(
                Optional.of("neoforge-quarry-3.1.jar"),
                idx.ownerJarForClass("dev.example.neoquarry.QuarryTicker")
        );
        assertEquals(
                "neoquarry",
                idx.descriptors().get("neoforge-quarry-3.1.jar").pluginId()
        );
        assertTrue(
                idx.ownerJarForClass("com.google.gson.Gson").isEmpty(),
                "Shared shaded Gson class must not be blamed on a single archive"
        );
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003: BrigadierDispatcherInspector extracts default and op command trees from Brigadier CommandDispatcher")
    void brigadierDispatcherInspectorExtractsAndFiltersCrossPlatformTrees() {
        JarClassOwnershipIndex idx = JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "neoquarry.jar", Set.of(FakeQuarryCommandAction.class.getName()),
                "other.jar", Set.of("com.example.other.OtherCmd")
        ));

        com.mojang.brigadier.CommandDispatcher<Object> dispatcher = new com.mojang.brigadier.CommandDispatcher<>();
        dispatcher.register(
                com.mojang.brigadier.builder.LiteralArgumentBuilder.literal("quarry")
                        .executes(new FakeQuarryCommandAction())
                        .then(com.mojang.brigadier.builder.RequiredArgumentBuilder.argument(
                                        "speed",
                                        com.mojang.brigadier.arguments.IntegerArgumentType.integer(1, 512)
                                )
                                .executes(new FakeBrigadierCommand()))
                        .then(com.mojang.brigadier.builder.LiteralArgumentBuilder.literal("reload")
                                .executes(new FakeQuarryCommandAction()))
                        .then(com.mojang.brigadier.builder.LiteralArgumentBuilder.literal("purge")
                                .requires(new FakeLevelRequirement(2))
                                .executes(new FakeQuarryCommandAction()))
        );
        dispatcher.register(
                com.mojang.brigadier.builder.LiteralArgumentBuilder.literal("other:ping")
                        .executes(new FakeBrigadierCommand())
        );

        Map<String, List<RawCommandNode>> graphs = BrigadierDispatcherInspector.inspectDispatcher(dispatcher, idx);
        assertEquals(2, graphs.get("default").size());
        assertEquals(2, graphs.get("op").size());

        // Verify adminPurgeSub (permission level 2) is excluded from default tier but present in op tier
        RawCommandNode defQuarry = graphs.get("default").get(0);
        assertEquals(2, defQuarry.children().size(), "Default tier must only see speed and reload, not level-2 purge");
        RawCommandNode opQuarry = graphs.get("op").get(0);
        assertEquals(3, opQuarry.children().size(), "OP tier must see speed, reload, and purge");

        // Filter for target "neoquarry"
        Map<String, List<RawCommandNode>> filtered = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                graphs,
                "neoquarry",
                idx
        );
        assertEquals(1, filtered.get("default").size());
        assertEquals("quarry", filtered.get("default").get(0).name());

        // Filter across multiple comma-separated targets ("neoquarry,other")
        Map<String, List<RawCommandNode>> multiFiltered = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                graphs,
                "neoquarry,other",
                idx
        );
        assertEquals(2, multiFiltered.get("default").size());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003 & REQ-SLEUTH-FUZZ-004: Multi-target and boundary-exact target filtering isolates overlapping plugin names across all 4 QC stages")
    void multiTargetAndBoundaryExactFilteringIsolatesOverlappingTargets(@TempDir Path tempDir) throws IOException {
        Path pluginsDir = Files.createDirectories(tempDir.resolve("plugins"));
        createSyntheticJar(
                pluginsDir.resolve("AlphaTeleport-1.0.jar"),
                "plugin.yml",
                "name: AlphaTeleport\nversion: 1.0\n",
                List.of("com/example/alphateleport/AlphaTeleportTask.class")
        );
        createSyntheticJar(
                pluginsDir.resolve("BetterAlphaTeleport-2.0.jar"),
                "plugin.yml",
                "name: BetterAlphaTeleport\nversion: 2.0\n",
                List.of("com/example/betteralphateleport/BetterAlphaSession.class")
        );
        createSyntheticJar(
                pluginsDir.resolve("GammaClaim-1.4.jar"),
                "plugin.yml",
                "name: GammaClaim\nversion: 1.4\n",
                List.of("com/example/gammaclaim/ClaimHandler.class")
        );

        JarClassOwnershipIndex idx = JarClassOwnershipIndex.scanArchiveDirectories(
                List.of(pluginsDir),
                List.of("leaffuzz")
        );

        RawCommandNode alphaCmd = new RawCommandNode(
                "alphatp",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "AlphaTeleport",
                List.of()
        );
        RawCommandNode betterAlphaCmd = new RawCommandNode(
                "betteralphatp",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "BetterAlphaTeleport",
                List.of()
        );
        RawCommandNode gammaCmd = new RawCommandNode(
                "gammaclaim",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "GammaClaim",
                List.of()
        );

        Map<String, List<RawCommandNode>> rawGraphs = Map.of(
                "default", List.of(alphaCmd, betterAlphaCmd, gammaCmd),
                "op", List.of(alphaCmd, betterAlphaCmd, gammaCmd)
        );

        // 1. Boundary-exact isolation: querying "AlphaTeleport" must NOT include "BetterAlphaTeleport"
        Map<String, List<RawCommandNode>> onlyAlpha = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                rawGraphs,
                "AlphaTeleport",
                idx
        );
        assertEquals(1, onlyAlpha.get("default").size());
        assertEquals("alphatp", onlyAlpha.get("default").get(0).name());

        Map<String, List<RawCommandNode>> onlyBetterAlpha = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                rawGraphs,
                "BetterAlphaTeleport",
                idx
        );
        assertEquals(1, onlyBetterAlpha.get("default").size());
        assertEquals("betteralphatp", onlyBetterAlpha.get("default").get(0).name());

        // 2. Generalized multi-target selection: "AlphaTeleport,GammaClaim" selects both without "BetterAlphaTeleport"
        Map<String, List<RawCommandNode>> multi = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                rawGraphs,
                "AlphaTeleport,GammaClaim",
                idx
        );
        assertEquals(2, multi.get("default").size());
        assertEquals(
                List.of("alphatp", "gammaclaim"),
                multi.get("default").stream().map(RawCommandNode::name).toList()
        );

        // 3. Verify Stage 1-4 runtime filtering across single and multi-target runs
        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        runtime.setOwnershipIndex(idx);
        runtime.setPlatformCommandGraphSupplier(() -> rawGraphs);
        runtime.setCustomEpisodeRunner(actions -> EpisodeOutcome.clean());
        runtime.start();

        runtime.faultOracle().recordSlowTickStack(
                140.0,
                new StackTraceElement[]{
                        new StackTraceElement("com.example.alphateleport.AlphaTeleportTask", "run", "AlphaTeleportTask.java", 42)
                },
                0L
        );
        runtime.faultOracle().recordSlowTickStack(
                150.0,
                new StackTraceElement[]{
                        new StackTraceElement("com.example.betteralphateleport.BetterAlphaSession", "tick", "BetterAlphaSession.java", 19)
                },
                0L
        );

        LeafFuzzScorecardReport singleCard = runtime.runQcCheck("AlphaTeleport", 4);
        assertEquals(1, singleCard.auditedCommands());
        assertEquals(1, singleCard.faultSignatures().size());
        assertEquals("AlphaTeleport-1.0.jar", singleCard.faultSignatures().get(0).suspectJar());

        LeafFuzzScorecardReport multiCard = runtime.runQcCheck("AlphaTeleport,BetterAlphaTeleport", 4);
        assertEquals(2, multiCard.auditedCommands());
        assertEquals(2, multiCard.faultSignatures().size());

        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004 & S-004 & S-005 & S-007: /fuzz check <target> executes all 4 QC stages and writes Markdown report")
    void fullFourStageQcCheckAndCommandTreeExecution(@TempDir Path tempDir) throws IOException {
        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);

        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        runtime.setOwnershipIndex(JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "NeoQuarry.jar", Set.of("dev.example.neoquarry.QuarryTicker", "dev.example.neoquarry.QuarrySession")
        )));

        RawCommandNode speedArg = new RawCommandNode(
                "speed",
                "argument",
                "brigadier:integer",
                Map.of("min", 1, "max", 1024),
                true,
                null,
                null,
                "NeoQuarry.jar",
                List.of()
        );
        RawCommandNode exposedReload = new RawCommandNode(
                "reload",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "NeoQuarry.jar",
                List.of()
        );
        RawCommandNode quarryRoot = new RawCommandNode(
                "quarry",
                "literal",
                null,
                Map.of(),
                false,
                null,
                null,
                "NeoQuarry.jar",
                List.of(speedArg, exposedReload)
        );
        runtime.setPlatformCommandGraphSupplier(() -> Map.of(
                "default", List.of(quarryRoot),
                "op", List.of(quarryRoot)
        ));

        // Deterministic episode runner where speed >= 256 triggers a stall signature in NeoQuarry.jar
        runtime.setCustomEpisodeRunner((List<EpisodeAction> actions) -> {
            for (EpisodeAction act : actions) {
                String[] parts = act.commandLine().replace("/", "").trim().split("\\s+");
                if (parts.length >= 2) {
                    try {
                        int val = Integer.parseInt(parts[1]);
                        if (val >= 256) {
                            runtime.faultOracle().recordSlowTickStack(
                                    165.0,
                                    new StackTraceElement[]{
                                            new StackTraceElement("dev.example.neoquarry.QuarryTicker", "tickQuarry", "QuarryTicker.java", 88)
                                    },
                                    0L
                            );
                            return EpisodeOutcome.fault(
                                    "stall:dev.example.neoquarry.QuarryTicker.tickQuarry",
                                    "NeoQuarry.jar",
                                    10.0,
                                    165.0,
                                    List.of("dev.example.neoquarry.QuarryTicker.tickQuarry")
                            );
                        }
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
            return EpisodeOutcome.clean();
        });

        runtime.start();

        // Simulate 4 player quit events and post-GC histograms with a leaking QuarrySession class
        for (int i = 0; i < 4; i++) {
            if (quitListenerRef.get() != null) {
                quitListenerRef.get().accept(UUID.randomUUID());
            }
            String histo = String.format(
                    Locale.ROOT,
                    " num     #instances         #bytes  class name (module)%n"
                            + "-------------------------------------------------------%n"
                            + "   1: %14d %14d  dev.example.neoquarry.QuarrySession%n",
                    5 + i * 6,
                    (5 + i * 6) * 256
            );
            runtime.retentionScreener().recordHistogramText(
                    "cp-" + i,
                    1000L + i * 1000L,
                    runtime.retentionScreener().totalDepartures(),
                    i * 2L,
                    histo
            );
        }

        LeafFuzzCommand cmd = new LeafFuzzCommand("fuzz", accessor, runtime);
        assertEquals(
                Set.of("CHECK", "REPORT", "RESET", "TEST", "RELOAD"),
                cmd.getCommandLookup().keySet(),
                "Top-level /fuzz command tree must expose exactly the 5 core subcommands"
        );
        assertEquals(
                Set.of("target", "episodes", "players", "stage"),
                cmd.getParameterLookup().keySet(),
                "Root /fuzz command must expose target=, episodes=, players=, and stage= parameters"
        );

        // Verify bare positional arguments are rejected by CommandsAPI (commands-api-ADR-001 Rule 4 & 6)
        java.util.concurrent.CompletableFuture<Boolean> badPositional = cmd.onCommand(
                CommandsAPI.serverId,
                perm -> true,
                messages::add,
                new String[]{"check", "NeoQuarry", "16"},
                0,
                Map.of()
        );
        CommandsAPI.execute();
        assertFalse(badPositional.join(), "Bare positional tokens without '=' must be rejected by CommandsAPI");

        // Verify root-level parameters `/fuzz target=NeoQuarry episodes=16` delegate directly to checkSub
        java.util.concurrent.CompletableFuture<Boolean> cmdFuture = cmd.onCommand(
                CommandsAPI.serverId,
                perm -> true,
                messages::add,
                new String[]{"target=NeoQuarry", "episodes=16"},
                0,
                Map.of()
        );
        CommandsAPI.execute();
        assertTrue(cmdFuture.join());

        LeafFuzzScorecardReport card = runtime.latestScorecard();
        assertNotNull(card, "Expected /fuzz check NeoQuarry to produce a LeafFuzzScorecardReport");
        assertEquals(LeafFuzzScorecardReport.Verdict.WARN, card.stage1CommandSurfaceVerdict());
        assertEquals(LeafFuzzScorecardReport.Verdict.FAIL, card.stage2BoundaryFuzzVerdict());
        assertEquals(LeafFuzzScorecardReport.Verdict.FAIL, card.stage3StallAndExceptionVerdict());
        assertEquals(LeafFuzzScorecardReport.Verdict.FAIL, card.stage4MemoryRetentionVerdict());
        assertEquals(LeafFuzzScorecardReport.Verdict.FAIL, card.overallVerdict());

        assertFalse(card.shrunkReproducers().isEmpty());
        assertTrue(
                card.shrunkReproducers().get(0).bisectedNumericThreshold().orElse("").contains("256"),
                "Expected bisected threshold to isolate speed >= 256"
        );

        Path reportFile = tempDir.resolve("reports").resolve("neoquarry-qc-report.md");
        assertTrue(Files.isRegularFile(reportFile), "Expected Markdown scorecard file to be written");
        String md = Files.readString(reportFile, StandardCharsets.UTF_8);
        assertTrue(md.startsWith("STATUS: FAIL | Target: `NeoQuarry`"), "Expected Markdown report to lead with STATUS on line 1");
        assertTrue(md.contains("Moderation Evidence Summary:"));
        assertTrue(md.contains("quarry reload"));
        assertTrue(md.contains("stall:dev.example.neoquarry.QuarryTicker.tickQuarry"));
        assertTrue(md.contains("dev.example.neoquarry.QuarrySession"));

        Path yamlDataFile = tempDir.resolve("reports").resolve("neoquarry-qc-data.yml");
        Path jsonDataFile = tempDir.resolve("reports").resolve("neoquarry-qc-data.json");
        assertTrue(Files.isRegularFile(yamlDataFile), "Expected publishable YAML data file to be written");
        assertTrue(Files.isRegularFile(jsonDataFile), "Expected publishable JSON data file to be written");
        String yamlData = Files.readString(yamlDataFile, StandardCharsets.UTF_8);
        String jsonData = Files.readString(jsonDataFile, StandardCharsets.UTF_8);
        assertTrue(yamlData.startsWith("status: FAIL\nmoderation_ready: false\n"), "Expected YAML data file to lead with status on line 1");
        assertTrue(yamlData.contains("BuiltByBit (BBB) / Modrinth"));
        assertTrue(jsonData.startsWith("{\n  \"status\": \"FAIL\",\n  \"moderationReady\": false,"), "Expected JSON data file to lead with status as first key");
        assertTrue(jsonData.contains("\"stageVerdicts\""));

        // Verify [FUZZ bit] self-test suite passes 100%
        List<LeafFuzzBitSuite.CheckResult> bitResults = runtime.bitSuite().executeAll();
        assertEquals(6, bitResults.size());
        assertTrue(bitResults.stream().allMatch(LeafFuzzBitSuite.CheckResult::passed));

        // Verify LeafFuzzMenuBuilder produces WCAG 2.1 contrast-compliant Book scorecard and /fuzz report opens it
        LeafFuzzMenuBuilder menuBuilder = new LeafFuzzMenuBuilder();
        MenuDescriptor book = menuBuilder.buildScorecardBook(runtime);
        assertEquals(4, book.pages().size(), "Expected Overview, Live Telemetry, Perms/Reproducers, and Faults/Leaks pages");
        List<String> contrastViolations = BookContrastValidator.auditMenuDescriptor(book);
        assertTrue(contrastViolations.isEmpty(), () -> "Book contrast violations: " + contrastViolations);

        java.util.concurrent.CompletableFuture<Boolean> reportFuture = cmd.onCommand(
                UUID.fromString("00000000-0000-0000-0000-000000000042"),
                perm -> true,
                messages::add,
                new String[]{"report"},
                0,
                Map.of()
        );
        CommandsAPI.execute();
        assertTrue(reportFuture.join());
        assertNotNull(accessor.lastRenderedBook(), "Expected /fuzz report to render BookMenuSpec via ServerAccessor");
        assertTrue(BookContrastValidator.auditBookMenuSpec(accessor.lastRenderedBook()).isEmpty());

        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-BIO-001 & REQ-SLEUTH-FUZZ-004: PersonaPolicyBotActor evaluates 256-byte Int8[16x16] policy genome, round-trips sleuth_persona_v1 JSONL, and drives live episodes")
    void personaPolicyBotActorEvaluatesPolicyGenomeAndDrivesLiveEpisodes(@TempDir Path tempDir) throws IOException {
        List<PersonaProfile> builtins = PersonaPolicyBotActor.defaultPersonaCatalog();
        assertEquals(8, builtins.size());

        PersonaProfile explorer = builtins.get(0);
        String jsonLine = explorer.toJsonLine();
        PersonaProfile roundTripped = PersonaPolicyBotActor.fromJsonLine(jsonLine);
        assertNotNull(roundTripped);
        assertEquals(explorer.playerName(), roundTripped.playerName());
        assertEquals(explorer.pretrainedPolicyBase64(), roundTripped.pretrainedPolicyBase64());

        // Write custom personas.jsonl into rootFolder and verify LeafFuzzRuntime loads it
        Path personasFile = tempDir.resolve("personas.jsonl");
        Files.writeString(personasFile, jsonLine + "\n", StandardCharsets.UTF_8);

        PersonaPolicyBotActor bot = new PersonaPolicyBotActor(roundTripped, "default", 99);
        for (int s = 0; s < 8; s++) {
            BotStepRecord step = bot.stepAutonomousPolicy();
            assertNotNull(step);
            assertTrue(step.skillIndex() >= 0 && step.skillIndex() < PersonaPolicyBotActor.POLICY_NUM_ACTIONS);
            assertTrue(PersonaPolicyBotActor.POLICY_MICRO_SKILLS.contains(step.selectedSkill()));
        }

        // Verify directed manipulation: command alias/self expansion + chunk_border_thrash + quit_lt1s
        String cmd = bot.prepareCommandForDispatch("/targetcmd {self} 64");
        assertEquals("targetcmd LeafExplorer 64", cmd);
        int chunkXBefore = bot.x() >> 4;
        BotStepRecord borderStep = bot.performFollowUpBehavior("chunk_border_thrash");
        assertTrue((borderStep.x() >> 4) != chunkXBefore, "chunk_border_thrash must cross a 16-block chunk boundary");
        BotStepRecord quitStep = bot.performFollowUpBehavior("quit_lt1s");
        assertFalse(quitStep.online(), "quit_lt1s must transition bot to offline");

        // Verify LeafFuzzRuntime live episode execution with BrigadierSyntheticSourceFactory
        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        assertEquals(1, runtime.personaCatalog().size());

        List<String> dispatchedCommands = new ArrayList<>();
        List<Object> dispatchedSources = new ArrayList<>();
        FakeExecutableBrigadierDispatcher brigDispatcher = new FakeExecutableBrigadierDispatcher(
                dispatchedCommands,
                dispatchedSources
        );
        runtime.setBrigadierDispatcherSupplier(() -> brigDispatcher);
        RawCommandNode pingNode = new RawCommandNode(
                "ping",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "TestMod.jar",
                List.of()
        );
        runtime.setPlatformCommandGraphSupplier(() -> Map.of(
                "default", List.of(pingNode),
                "op", List.of(pingNode)
        ));

        LeafFuzzScorecardReport report = runtime.runQcCheck("TestMod", 6);
        assertEquals(6, report.episodesExecuted());
        assertFalse(dispatchedCommands.isEmpty(), "Expected Brigadier dispatcher to receive persona bot commands");
        assertFalse(dispatchedSources.isEmpty(), "Expected Brigadier dispatcher to receive synthetic player source");
        assertFalse(runtime.recentBotSteps().isEmpty(), "Expected runtime to record persona bot step telemetry");
        runtime.close();
    }

    @Test
    @DisplayName("Stage 5: LeafFuzzRuntime & LeafFuzzScorecardReport audit first-order and second-order claim delivery, corroborate hollow commands with Stage 2 telemetry, and pass BookContrastValidator")
    void stage5ClaimDeliveryAuditAndScorecardIntegration(@TempDir Path tempDir) throws IOException {
        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();

        CausalGraphReport syntheticCausalReport = BytecodeCausalGraphScanner.analyzeClasses(
                "plugin:vibecodedwild",
                "VibecodedWild",
                List.of(),
                List.of(new JarConfigScanner.CommandDescriptor(
                        "unwiredwild",
                        "VibecodedWild",
                        "Teleports player to a random location",
                        "/unwiredwild",
                        List.of(),
                        "wild.use",
                        "true"
                )),
                Map.of("config.yml", "warmup:\n  dead-cancel-on-move: true\n")
        );
        runtime.registerCausalGraphReport("VibecodedWild.jar", syntheticCausalReport);

        // Simulate Stage 2 live command execution with 0 teleports and 0 menus
        runtime.recordEpisodeObservation("/unwiredwild", 1, 6, 0, 0, List.of(), 0, 0.0, 6, false);

        List<ClaimDeliveryFinding> findings = runtime.auditClaimDelivery("VibecodedWild");
        assertFalse(findings.isEmpty(), "Expected Order 1/Order 2 claim delivery findings");

        LeafFuzzScorecardReport card = runtime.runQcCheck("VibecodedWild", 1);
        assertFalse(card.claimFindings().isEmpty());
        assertEquals(LeafFuzzScorecardReport.Verdict.WARN, card.stage5ClaimDeliveryVerdict());

        String md = card.toMarkdownReport();
        assertTrue(md.contains("5. Claim & Causal Delivery Audit"));
        assertTrue(md.contains("Stage 5 Findings: First-Order & Second-Order Claim Delivery"));
        assertTrue(md.contains("Claims:"));
        assertTrue(md.contains("Does Not Deliver:"));

        LeafFuzzMenuBuilder menuBuilder = new LeafFuzzMenuBuilder();
        MenuDescriptor book = menuBuilder.buildScorecardBook(card);
        List<String> contrastViolations = BookContrastValidator.auditMenuDescriptor(book);
        assertTrue(
                contrastViolations.isEmpty(),
                () -> "Expected zero WCAG 2.1 contrast violations on Stage 5 book page, got: " + contrastViolations
        );

        // Verify `/fuzz check target=VibecodedWild stage=claims` command
        LeafFuzzCommand cmd = new LeafFuzzCommand("fuzz", accessor, runtime);
        messages.clear();
        assertTrue(cmd.onCommand(
                UUID.randomUUID(),
                Map.of("target", List.of("VibecodedWild"), "stage", List.of("claims")),
                null
        ));
        assertTrue(
                messages.stream().anyMatch(m -> m.contains("Claim Delivery Audit") && m.contains("VibecodedWild")),
                "Expected stage=claims output in command reply"
        );
        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004 & S-005: /fuzz check players=100 and players=auto disperse bots on an Archimedean spiral and ramp to instability without a special target")
    void concurrentHundredPlayerSwarmAndRampToInstabilityWithoutTarget(@TempDir Path tempDir) {
        // 1. Verify 100-player Archimedean spiral dispersion covers >= 85 distinct chunks
        java.util.Set<String> uniqueSpiralChunks = new java.util.HashSet<>();
        for (int i = 0; i < 100; i++) {
            NmsEmbeddedPlayerSession.SpiralAnchor anchor =
                    NmsEmbeddedPlayerSession.computeSpiralAnchor(i, NmsEmbeddedPlayerSession.DEFAULT_SPIRAL_STRIDE_BLOCKS);
            uniqueSpiralChunks.add(anchor.chunkX() + "," + anchor.chunkZ());
        }
        assertTrue(
                uniqueSpiralChunks.size() >= 85,
                "Expected 100 spiral anchors to disperse across >= 85 unique chunks, got " + uniqueSpiralChunks.size()
        );

        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();

        RawCommandNode spawnCmd = new RawCommandNode(
                "spawn",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "CoreSpawn.jar",
                List.of()
        );
        runtime.setPlatformCommandGraphSupplier(() -> Map.of(
                "default", List.of(spawnCmd),
                "op", List.of(spawnCmd)
        ));
        runtime.setCustomEpisodeRunner(actions -> {
            runtime.recordEpisodeObservation("/spawn", 1, 1, 0, 0, List.of(), 1, 128.0, 1, false);
            return EpisodeOutcome.clean();
        });

        // 2. Stable 100-player survival run (`/fuzz check players=100` on target=all)
        runtime.setPlatformMsptSupplier(() -> 18.5);
        LeafFuzzScorecardReport passCard = runtime.runQcCheck("all", 8, 100);
        assertEquals(100, passCard.telemetry().targetConcurrentPlayers());
        assertEquals(100, passCard.telemetry().peakConcurrentPlayers());
        assertEquals(100, passCard.telemetry().maxStablePlayers());
        assertTrue(passCard.telemetry().loadedChunksAtPeak() >= 100);
        assertTrue(passCard.telemetry().instabilityTrigger().isEmpty());
        assertEquals(LeafFuzzScorecardReport.Verdict.PASS, passCard.stage2BoundaryFuzzVerdict());
        assertEquals(LeafFuzzScorecardReport.Verdict.PASS, passCard.overallVerdict());
        assertTrue(passCard.toMarkdownReport().contains("100/100 players` (max stable: `100 players`"));

        // 3. Target-free ramp-to-instability (`/fuzz check players=auto`) where MSPT crosses 55ms at 50+ players
        final int[] currentPop = {0};
        runtime.setPlatformSwarmController(new LeafFuzzRuntime.SwarmRosterController() {
            @Override
            public LeafFuzzRuntime.SwarmSnapshot rampToPopulation(int targetPlayers) {
                currentPop[0] = targetPlayers;
                return new LeafFuzzRuntime.SwarmSnapshot(targetPlayers, targetPlayers * 6, targetPlayers * 2, targetPlayers, 0);
            }

            @Override
            public LeafFuzzRuntime.SwarmSnapshot stepConcurrentSwarm(int churnCount) {
                return new LeafFuzzRuntime.SwarmSnapshot(currentPop[0], currentPop[0] * 6, currentPop[0] * 2, currentPop[0], churnCount);
            }

            @Override
            public LeafFuzzRuntime.SwarmSnapshot captureSnapshot() {
                return new LeafFuzzRuntime.SwarmSnapshot(currentPop[0], currentPop[0] * 6, currentPop[0] * 2, 0, 0);
            }

            @Override
            public void teardownAll() {
                currentPop[0] = 0;
            }
        });
        runtime.setPlatformMsptSupplier(() -> currentPop[0] >= 50 ? 68.4 : 21.0);

        LeafFuzzCommand cmd = new LeafFuzzCommand("fuzz", accessor, runtime);
        java.util.concurrent.CompletableFuture<Boolean> autoRampFuture = cmd.onCommand(
                CommandsAPI.serverId,
                perm -> true,
                messages::add,
                new String[]{"check", "players=auto", "episodes=8"},
                0,
                Map.of()
        );
        CommandsAPI.execute();
        assertTrue(autoRampFuture.join());

        LeafFuzzScorecardReport rampCard = runtime.latestScorecard();
        assertNotNull(rampCard);
        assertEquals(25, rampCard.telemetry().maxStablePlayers(), "Expected last stable step before 50-player spike to be 25");
        assertEquals(50, rampCard.telemetry().peakConcurrentPlayers(), "Expected ramp to halt immediately at 50 players");
        assertTrue(rampCard.telemetry().instabilityTrigger().contains("at 50 players"));
        assertEquals(LeafFuzzScorecardReport.Verdict.WARN, rampCard.stage2BoundaryFuzzVerdict());
        assertEquals(0, currentPop[0], "Expected swarm teardownAll() to leave 0 active bots after check");

        // 4. Verify config.yml defaultPlayers: auto parses to AUTO_RAMP_PLAYERS and passes directory validation
        LeafFuzzConfig autoCfg = LeafFuzzConfig.parse("check:\n  defaultEpisodes: 24\n  defaultPlayers: auto\n", "");
        assertEquals(LeafFuzzRuntime.AUTO_RAMP_PLAYERS, autoCfg.defaultPlayers());
        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: LeafFuzzStandaloneCli and LeafFuzzTcpSwarmClient extract bench-swarm.js and run TCP protocol swarm")
    void standaloneCliAndTcpSwarmClientVerifyProtocolAndExtractMineflayer(@TempDir Path tempDir) throws Exception {
        // 1. Verify bundled bench-swarm.js extraction via CLI
        Path extractedJs = tempDir.resolve("extracted-bench-swarm.js");
        java.io.ByteArrayOutputStream cliOut = new java.io.ByteArrayOutputStream();
        java.io.ByteArrayOutputStream cliErr = new java.io.ByteArrayOutputStream();
        int extractCode = LeafFuzzStandaloneCli.executeCli(
                new String[]{"extract-mineflayer", "--out", extractedJs.toString()},
                new java.io.PrintStream(cliOut),
                new java.io.PrintStream(cliErr)
        );
        assertEquals(0, extractCode);
        assertTrue(Files.isRegularFile(extractedJs));
        assertTrue(Files.size(extractedJs) > 1000L);

        // 2. Start an embedded loopback mock Minecraft TCP server handling SLP + Offline Login
        try (java.net.ServerSocket mockServer = new java.net.ServerSocket(0, 128, java.net.InetAddress.getByName("127.0.0.1"))) {
            int port = mockServer.getLocalPort();
            java.util.concurrent.atomic.AtomicBoolean running = new java.util.concurrent.atomic.AtomicBoolean(true);
            Thread acceptThread = Thread.ofVirtual().start(() -> {
                while (running.get() && !mockServer.isClosed()) {
                    try {
                        java.net.Socket client = mockServer.accept();
                        Thread.ofVirtual().start(() -> handleMockMinecraftConnection(client));
                    } catch (IOException ignored) {
                        break;
                    }
                }
            });

            Path swarmReportMd = tempDir.resolve("swarm-report.md");
            int swarmExit = LeafFuzzStandaloneCli.executeCli(
                    new String[]{
                            "swarm",
                            "--host", "127.0.0.1",
                            "--port", String.valueOf(port),
                            "--players", "12",
                            "--duration-sec", "1",
                            "--report", swarmReportMd.toString()
                    },
                    new java.io.PrintStream(cliOut),
                    new java.io.PrintStream(cliErr)
            );
            running.set(false);
            mockServer.close();
            acceptThread.join(1000L);

            assertEquals(0, swarmExit, () -> "Expected standalone TCP swarm to PASS, output: " + cliOut);
            assertTrue(Files.isRegularFile(swarmReportMd));
            String md = Files.readString(swarmReportMd, StandardCharsets.UTF_8);
            assertTrue(md.contains("**PASS**"));
            assertTrue(md.contains("`12/12`"));
            assertTrue(md.contains("1.21.4-Mock"));
        }
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: White-box BytecodeCommandSchema seeds penetrate deep subcommand branches when onTabComplete is absent")
    void whiteBoxBytecodeCommandSchemasSeedDeepSubcommandsDuringStage2Fuzzing(@TempDir Path tempDir) {
        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);

        runtime.setOwnershipIndex(JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "VibeWild.jar", Set.of("dev.vibe.wild.WildCommand")
        )));

        // Register a black-box command root `/wild` that has NO tab-completer children at all
        RawCommandNode bareWildRoot = new RawCommandNode(
                "wild",
                "literal",
                null,
                Map.of(),
                true,
                null,
                null,
                "VibeWild.jar",
                List.of()
        );
        runtime.setPlatformCommandGraphSupplier(() -> Map.of(
                "default", List.of(bareWildRoot),
                "op", List.of(bareWildRoot)
        ));

        // Register a CausalGraphReport carrying white-box BytecodeCommandSchema hints extracted from bytecode:
        // `args[0].equalsIgnoreCase("confirm")` + `Integer.parseInt(args[1])` + `hasPermission("vibewild.admin")`
        io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.BytecodeCommandSchema schema =
                new io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.BytecodeCommandSchema(
                        "wild",
                        "dev/vibe/wild/WildCommand#onCommand",
                        List.of("confirm", "reload"),
                        List.of("brigadier:integer"),
                        List.of("vibewild.admin")
                );
        io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.CausalGraphReport causalReport =
                new io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.CausalGraphReport(
                        "plugin:vibewild",
                        "VibeWild",
                        List.of(),
                        Map.of(),
                        Map.of(),
                        List.of(),
                        Set.of(),
                        List.of(schema)
                );
        runtime.registerCausalGraphReport("VibeWild.jar", causalReport);

        // Verify Stage 1 auditCommandSurface augments `/wild` with `wild confirm <wb_arg0>` on default/op
        // while keeping `wild reload` (state-mutating + inline permission guard) off the unprivileged `default` tier
        var surfaceAudit = runtime.auditCommandSurface("VibeWild");
        assertTrue(
                surfaceAudit.commandTree().nodes().containsKey("wild confirm <wb_arg0>"),
                "Expected white-box subcommand + integer parser leaf 'wild confirm <wb_arg0>' in merged CommandTree: "
                        + surfaceAudit.commandTree().nodes().keySet()
        );
        assertFalse(
                surfaceAudit.findings().stream().anyMatch(f -> "wild reload".equals(f.nodeId())),
                "Expected inline permission guard on 'reload' to prevent false-positive default-tier exposure"
        );

        // Verify Stage 2 fuzzer reaches `/wild confirm <int>` and triggers a deep-branch fault when arg >= 256
        List<String> observedDispatches = new ArrayList<>();
        runtime.setCustomEpisodeRunner(actions -> {
            for (EpisodeAction act : actions) {
                String cmdLine = act.commandLine().replace("/", "").trim();
                observedDispatches.add(cmdLine);
                if (cmdLine.startsWith("wild confirm ")) {
                    String[] parts = cmdLine.split("\\s+");
                    if (parts.length >= 3) {
                        try {
                            int v = Integer.parseInt(parts[2]);
                            if (v <= 0 || v >= 256) {
                                return EpisodeOutcome.fault(
                                        "exc:IllegalArgumentException@WildCommand#onCommand:44",
                                        "VibeWild.jar",
                                        0.0,
                                        0.0,
                                        List.of("dev.vibe.wild.WildCommand")
                                );
                            }
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
            }
            return EpisodeOutcome.clean();
        });

        LeafFuzzScorecardReport card = runtime.runQcCheck("VibeWild", 16, 1);
        assertNotNull(card);
        assertTrue(
                observedDispatches.stream().anyMatch(c -> c.startsWith("wild confirm ")),
                "Expected Stage 2 fuzzer to exercise white-box seeded '/wild confirm <int>' branch, dispatches: " + observedDispatches
        );
        assertFalse(card.shrunkReproducers().isEmpty(), "Expected Stage 2 fuzzer to discover and shrink the deep '/wild confirm' fault");
        runtime.close();
    }

    private static void handleMockMinecraftConnection(java.net.Socket client) {
        try (client) {
            client.setSoTimeout(2000);
            java.io.InputStream in = client.getInputStream();
            java.io.OutputStream out = client.getOutputStream();
            LeafFuzzTcpSwarmClient.RawPacket handshake = LeafFuzzTcpSwarmClient.readPacket(in, -1);
            java.io.ByteArrayInputStream hsIn = new java.io.ByteArrayInputStream(handshake.payload());
            LeafFuzzTcpSwarmClient.readVarInt(hsIn); // protocol
            LeafFuzzTcpSwarmClient.readUtfString(hsIn, 255); // host
            hsIn.readNBytes(2); // port
            int nextState = LeafFuzzTcpSwarmClient.readVarInt(hsIn);
            if (nextState == 1) {
                // Status request (0x00)
                LeafFuzzTcpSwarmClient.readPacket(in, -1);
                java.io.ByteArrayOutputStream statusPayload = new java.io.ByteArrayOutputStream();
                LeafFuzzTcpSwarmClient.writeUtfString(
                        statusPayload,
                        "{\"version\":{\"name\":\"1.21.4-Mock\",\"protocol\":769},\"players\":{\"max\":200,\"online\":0}}"
                );
                LeafFuzzTcpSwarmClient.sendPacket(out, 0x00, statusPayload.toByteArray(), -1);
                // Ping request (0x01) -> Pong (0x01)
                LeafFuzzTcpSwarmClient.RawPacket ping = LeafFuzzTcpSwarmClient.readPacket(in, -1);
                LeafFuzzTcpSwarmClient.sendPacket(out, 0x01, ping.payload(), -1);
            } else if (nextState == 2) {
                // Login Start (0x00)
                LeafFuzzTcpSwarmClient.RawPacket loginStart = LeafFuzzTcpSwarmClient.readPacket(in, -1);
                java.io.ByteArrayInputStream lsIn = new java.io.ByteArrayInputStream(loginStart.payload());
                String username = LeafFuzzTcpSwarmClient.readUtfString(lsIn, 16);
                // Send Set Compression (0x03) with threshold 64
                java.io.ByteArrayOutputStream compPayload = new java.io.ByteArrayOutputStream();
                LeafFuzzTcpSwarmClient.writeVarInt(compPayload, 64);
                LeafFuzzTcpSwarmClient.sendPacket(out, 0x03, compPayload.toByteArray(), -1);
                // Send Login Success (0x02) compressed
                java.io.ByteArrayOutputStream successPayload = new java.io.ByteArrayOutputStream();
                java.io.DataOutputStream sdos = new java.io.DataOutputStream(successPayload);
                UUID u = UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
                sdos.writeLong(u.getMostSignificantBits());
                sdos.writeLong(u.getLeastSignificantBits());
                LeafFuzzTcpSwarmClient.writeUtfString(successPayload, username);
                LeafFuzzTcpSwarmClient.writeVarInt(successPayload, 0);
                LeafFuzzTcpSwarmClient.sendPacket(out, 0x02, successPayload.toByteArray(), 64);
                // Keep socket open until client closes
                while (!client.isClosed()) {
                    if (in.read() == -1) {
                        break;
                    }
                }
            }
        } catch (IOException ignored) {
        }
    }

    private static void createSyntheticJar(
            Path jarPath,
            String descriptorEntryName,
            String descriptorContent,
            Collection<String> classEntries
    ) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jarPath.toFile()))) {
            if (descriptorEntryName != null && descriptorContent != null) {
                zos.putNextEntry(new ZipEntry(descriptorEntryName));
                zos.write(descriptorContent.getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
            for (String cls : classEntries) {
                zos.putNextEntry(new ZipEntry(cls));
                zos.write(new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
                zos.closeEntry();
            }
        }
    }

    public static final class FakeExecutableBrigadierDispatcher
            implements BrigadierSyntheticSourceFactory.BrigadierExecutableDispatcher {
        private final List<String> commands;
        private final List<Object> sources;

        public FakeExecutableBrigadierDispatcher(List<String> commands, List<Object> sources) {
            this.commands = commands;
            this.sources = sources;
        }

        @Override
        public int execute(String input, Object source) {
            commands.add(input);
            sources.add(source);
            return 1;
        }
    }

    public static final class FakeLevelRequirement
            implements BrigadierDispatcherInspector.BrigadierPermissionRequirement<Object> {
        private final int requiredLevel;

        public FakeLevelRequirement(int requiredLevel) {
            this.requiredLevel = requiredLevel;
        }

        @Override
        public Integer requiredPermissionLevel() {
            return requiredLevel;
        }

        @Override
        public boolean test(Object source) {
            if (source instanceof BrigadierSyntheticSourceFactory.SyntheticCommandSourceStub stub) {
                return stub.hasPermissionLevel(requiredLevel);
            }
            return false;
        }
    }

    public static final class FakeBrigadierCommand implements com.mojang.brigadier.Command<Object> {
        @Override
        public int run(com.mojang.brigadier.context.CommandContext<Object> context) {
            return 1;
        }
    }

    public static final class FakeQuarryCommandAction implements com.mojang.brigadier.Command<Object> {
        @Override
        public int run(com.mojang.brigadier.context.CommandContext<Object> context) {
            return 1;
        }
    }

    private static final class FakeServerAccessor implements ServerAccessor {
        private final Path rootFolder;
        private final List<String> messages;
        private final AtomicReference<Consumer<UUID>> quitListenerRef;
        private volatile BookMenuSpec lastRenderedBook;

        FakeServerAccessor(
                Path rootFolder,
                List<String> messages,
                AtomicReference<Consumer<UUID>> quitListenerRef
        ) {
            this.rootFolder = rootFolder;
            this.messages = messages;
            this.quitListenerRef = quitListenerRef;
        }

        BookMenuSpec lastRenderedBook() {
            return lastRenderedBook;
        }

        @Override
        public void renderBookOrChat(UUID playerId, BookMenuSpec spec) {
            this.lastRenderedBook = spec;
        }

        @Override
        public String getServerVersion() {
            return "26.1.2";
        }

        @Override
        public String getPlatform() {
            return "neoforge";
        }

        @Override
        public Integer getServerIntVersion() {
            return 26;
        }

        @Override
        public void log(Level level, String message) {
        }

        @Override
        public void log(Level level, String message, Throwable throwable) {
        }

        @Override
        public Path getRootFolder() {
            return rootFolder;
        }

        @Override
        public void sendMessage(UUID playerId, String message, boolean error) {
            messages.add(message);
        }

        @Override
        public PlayerLifecycleHook getPlayerLifecycleHook() {
            return new PlayerLifecycleHook() {
                @Override
                public AutoCloseable onPlayerJoin(Consumer<UUID> listener) {
                    return () -> {
                    };
                }

                @Override
                public AutoCloseable onPlayerQuit(Consumer<UUID> listener) {
                    quitListenerRef.set(listener);
                    return () -> quitListenerRef.set(null);
                }
            };
        }

        @Override
        public Optional<TaskScheduler> scheduler() {
            return Optional.of(new TaskScheduler() {
                @Override
                public TaskHandle runSync(Runnable task) {
                    task.run();
                    return dummyHandle();
                }

                @Override
                public TaskHandle runSyncDelayed(Runnable task, long delayTicks) {
                    return dummyHandle();
                }

                @Override
                public TaskHandle runSyncTimer(Runnable task, long delayTicks, long periodTicks) {
                    return dummyHandle();
                }

                @Override
                public TaskHandle runAsync(Runnable task) {
                    task.run();
                    return dummyHandle();
                }

                private TaskHandle dummyHandle() {
                    return new TaskHandle() {
                        @Override
                        public void cancel() {
                        }

                        @Override
                        public boolean isCancelled() {
                            return false;
                        }
                    };
                }
            });
        }
    }
}
