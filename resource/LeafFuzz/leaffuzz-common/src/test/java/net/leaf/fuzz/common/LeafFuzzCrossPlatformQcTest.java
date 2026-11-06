package net.leaf.fuzz.common;

import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalFinding;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.bytecode.JarConfigScanner;
import io.github.dailystruggle.commandsapi.common.CommandsAPI;
import io.github.dailystruggle.menu.api.BookContrastValidator;
import io.github.dailystruggle.menu.api.MenuDescriptor;
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

        // Verify bare positional arguments are rejected by CommandsAPI on both 4-arg and 6-arg entry points (commands-api-ADR-001 Rule 4 & 6)
        java.util.concurrent.CompletableFuture<Boolean> badPositional4Arg = cmd.onCommand(
                CommandsAPI.serverId,
                perm -> true,
                messages::add,
                new String[]{"check", "NeoQuarry", "16"}
        );
        CommandsAPI.execute();
        assertFalse(badPositional4Arg.join(), "Bare positional tokens without '=' must be rejected by 4-arg TreeCommand.onCommand");

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
        assertEquals(7, bitResults.size());
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
        assertEquals("targetcmd LF_Explr 64", cmd);
        for (PersonaProfile profile : builtins) {
            PersonaPolicyBotActor pBot = new PersonaPolicyBotActor(profile, "default", 1);
            PersonaPolicyBotActor opBot = new PersonaPolicyBotActor(profile, "op", 1);
            assertTrue(pBot.actorName(0).endsWith("_p") && pBot.actorName(0).length() <= 16);
            assertTrue(opBot.actorName(0).endsWith("_op") && opBot.actorName(0).length() <= 16);
            assertTrue(opBot.actorName(24).endsWith("_op_24") && opBot.actorName(24).length() <= 16);
        }
        PersonaProfile longCustom = PersonaPolicyBotActor.fromJsonLine(
                "{\"schema\":\"sleuth_persona_v1\",\"player_name\":\"LeafHomesteaderExtra\",\"expected_solver\":\"HUMAN_QUANTIZED_GCD\"}"
        );
        PersonaPolicyBotActor customBot = new PersonaPolicyBotActor(longCustom, "op", 7);
        assertTrue(customBot.actorName(12).startsWith("LF_"));
        assertTrue(customBot.actorName(12).endsWith("_op_12"));
        assertTrue(customBot.actorName(12).length() <= 16);
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
    @DisplayName("Stage 5: LeafFuzzRuntime & LeafFuzzScorecardReport audit first-order and second-order causal invariants, corroborate hollow commands with Stage 2 telemetry, and pass BookContrastValidator")
    void stage5CausalAuditAndScorecardIntegration(@TempDir Path tempDir) throws IOException {
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

        List<CausalFinding> findings = runtime.auditCausalDelivery("VibecodedWild");
        assertFalse(findings.isEmpty(), "Expected Order 1/Order 2 causal audit findings");

        LeafFuzzScorecardReport card = runtime.runQcCheck("VibecodedWild", 1);
        assertFalse(card.causalFindings().isEmpty());
        assertEquals(LeafFuzzScorecardReport.Verdict.WARN, card.stage5CausalAuditVerdict());

        String md = card.toMarkdownReport();
        assertTrue(md.contains("5. Bytecode & Causal Audit"));
        assertTrue(md.contains("Stage 5 Findings: First-Order & Second-Order Bytecode & Causal Audit"));
        assertTrue(md.contains("Declared:"));
        assertTrue(md.contains("Finding:"));

        LeafFuzzMenuBuilder menuBuilder = new LeafFuzzMenuBuilder();
        MenuDescriptor book = menuBuilder.buildScorecardBook(card);
        List<String> contrastViolations = BookContrastValidator.auditMenuDescriptor(book);
        assertTrue(
                contrastViolations.isEmpty(),
                () -> "Expected zero WCAG 2.1 contrast violations on Stage 5 book page, got: " + contrastViolations
        );

        // Verify `/fuzz check target=VibecodedWild stage=causal` command
        LeafFuzzCommand cmd = new LeafFuzzCommand("fuzz", accessor, runtime);
        messages.clear();
        assertTrue(cmd.onCommand(
                UUID.randomUUID(),
                Map.of("target", List.of("VibecodedWild"), "stage", List.of("causal")),
                null
        ));
        assertTrue(
                messages.stream().anyMatch(m -> m.contains("Bytecode & Causal Audit") && m.contains("VibecodedWild")),
                "Expected stage=causal output in command reply"
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
        io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.BytecodeCommandSchema schema =
                new io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.BytecodeCommandSchema(
                        "wild",
                        "dev/vibe/wild/WildCommand#onCommand",
                        List.of("confirm", "reload"),
                        List.of("brigadier:integer"),
                        List.of("vibewild.admin")
                );
        io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport causalReport =
                new io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport(
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

    @Test
    @DisplayName("SliceBitHarness & auditSliceBit: Runs per-slice PBIT/CBIT/IBIT in memory, restores EphemeralSliceClassLoader state, and never mutates .jar files on disk")
    void sliceBitHarnessRunsInMemoryRestoresStateAndLeavesDiskJarUntouched(@TempDir Path tempDir) throws Exception {
        Path pluginsDir = Files.createDirectories(tempDir.resolve("plugins"));
        Path jarPath = pluginsDir.resolve("SliceTarget.jar");
        byte[] sampleClassBytes;
        try (var in = FakeBrigadierCommand.class.getResourceAsStream(
                "/" + FakeBrigadierCommand.class.getName().replace('.', '/') + ".class")) {
            assertNotNull(in);
            sampleClassBytes = in.readAllBytes();
        }
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jarPath.toFile()))) {
            zos.putNextEntry(new ZipEntry("plugin.yml"));
            zos.write(("name: SliceTarget\nversion: 1.0.0\nmain: dev.slice.SliceTarget\n"
                    + "commands:\n  slicetp:\n    description: Teleports player\n").getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
            zos.putNextEntry(new ZipEntry(FakeBrigadierCommand.class.getName().replace('.', '/') + ".class"));
            zos.write(sampleClassBytes);
            zos.closeEntry();
        }

        byte[] shaBefore = SliceBitHarness.computeFileSha256(jarPath);
        long mtimeBefore = Files.getLastModifiedTime(jarPath).toMillis();

        // 1. Verify EphemeralSliceClassLoader + InMemorySliceBitSession loads class in memory and restores state on close
        Map<String, Object> baselineAttrs = Map.of("counter", 0, "status", "BASELINE");
        SliceBitHarness.InMemorySliceBitSession capturedSession;
        try (SliceBitHarness.InMemorySliceBitSession session = new SliceBitHarness.InMemorySliceBitSession(
                LeafFuzzCrossPlatformQcTest.class.getClassLoader(),
                Map.of(FakeBrigadierCommand.class.getName(), sampleClassBytes),
                baselineAttrs,
                null
        )) {
            capturedSession = session;
            session.putTemporaryProbeAttribute("counter", 99);
            session.putTemporaryProbeAttribute("ibit.injected", Boolean.TRUE);
            assertEquals(99, session.currentAttributes().get("counter"));
            Class<?> loaded = session.ephemeralLoader().findClass(FakeBrigadierCommand.class.getName());
            assertNotNull(loaded);
            assertEquals(FakeBrigadierCommand.class.getName(), loaded.getName());
        }
        assertTrue(capturedSession.isRestored(), "Session must mark restored=true after close()");
        assertTrue(capturedSession.ephemeralLoader().isClosed(), "EphemeralSliceClassLoader must be closed after session exit");
        assertEquals(baselineAttrs, capturedSession.currentAttributes(), "Working attributes must revert to exact baseline map");

        // 2. Verify LeafFuzzRuntime#auditSliceBit and BitRegistry integration without mutating disk .jar
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, new ArrayList<>(), new AtomicReference<>());
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.setOwnershipIndex(JarClassOwnershipIndex.fromJarClassMap(Map.of(
                "SliceTarget.jar", Set.of(FakeBrigadierCommand.class.getName())
        )));
        CausalGraphReport scannedFromJar = BytecodeCausalGraphScanner.scanJar(jarPath);
        assertNotNull(scannedFromJar);
        CausalGraphReport syntheticReport = new CausalGraphReport(
                "plugin:slicetarget",
                "SliceTarget",
                List.of(new BytecodeCausalGraphScanner.CausalChainSlice(
                        BytecodeCausalGraphScanner.EntryPointKind.COMMAND,
                        FakeBrigadierCommand.class.getName() + "#run",
                        "/slicetp teleports player",
                        BytecodeCausalGraphScanner.ListenerRegistrationMode.NOT_APPLICABLE,
                        "",
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of(FakeBrigadierCommand.class.getName() + "#run"),
                        Set.of("TELEPORT")
                )),
                Map.of(),
                Map.of(),
                List.of(),
                Set.of()
        );
        runtime.registerCausalGraphReport("SliceTarget.jar", syntheticReport);

        List<SliceBitHarness.SliceBitReport> sliceReports = runtime.auditSliceBit("SliceTarget");
        assertEquals(1, sliceReports.size());
        SliceBitHarness.SliceBitReport sr = sliceReports.get(0);
        assertTrue(sr.allPassed(), "Clean slice with 0 faults/leaks must pass PBIT, CBIT, and IBIT: " + sr);
        assertTrue(sr.stateRestored(), "SliceBitReport must confirm in-memory state restoration");

        io.github.dailystruggle.bit.BitRegistry registry = new io.github.dailystruggle.bit.BitRegistry();
        SliceBitHarness harness = new SliceBitHarness(
                "SliceTarget",
                syntheticReport.entryChains().get(0),
                List.of(),
                Map.of(FakeBrigadierCommand.class.getName(), sampleClassBytes)
        );
        assertTrue(registry.register("leaffuzz:slice:slicetp", harness));
        assertEquals(io.github.dailystruggle.bit.BitHealth.HEALTHY, registry.getHealthStatus());

        // 3. Verify PBIT invariant attribution for CAUSAL_SHARED_STATE_RACE, CAUSAL_SYNC_MAIN_THREAD_IO, and CAUSAL_UNCLOSED_RESOURCE_LEAK
        String entrySym = FakeBrigadierCommand.class.getName() + "#run";
        List<BytecodeCausalGraphScanner.CausalFinding> parityFindings = List.of(
                new BytecodeCausalGraphScanner.CausalFinding(
                        "CAUSAL-10",
                        "SliceTarget",
                        2,
                        BytecodeCausalGraphScanner.FindingKind.CAUSAL_SHARED_STATE_RACE,
                        BytecodeCausalGraphScanner.ConfidenceTier.CONFIRMED,
                        95,
                        entrySym,
                        "Shared state",
                        "Lock-set mismatch",
                        "Synchronize",
                        List.of(entrySym),
                        ""
                ),
                new BytecodeCausalGraphScanner.CausalFinding(
                        "CAUSAL-11",
                        "SliceTarget",
                        2,
                        BytecodeCausalGraphScanner.FindingKind.CAUSAL_SYNC_MAIN_THREAD_IO,
                        BytecodeCausalGraphScanner.ConfidenceTier.CONFIRMED,
                        95,
                        entrySym,
                        "Main thread command",
                        "Synchronous chunk load",
                        "Use async chunk load",
                        List.of(entrySym),
                        ""
                ),
                new BytecodeCausalGraphScanner.CausalFinding(
                        "CAUSAL-12",
                        "SliceTarget",
                        2,
                        BytecodeCausalGraphScanner.FindingKind.CAUSAL_UNCLOSED_RESOURCE_LEAK,
                        BytecodeCausalGraphScanner.ConfidenceTier.CONFIRMED,
                        95,
                        entrySym,
                        "Resource allocation",
                        "Unclosed FileOutputStream",
                        "Use try-with-resources",
                        List.of(entrySym),
                        ""
                )
        );
        SliceBitHarness parityHarness = new SliceBitHarness(
                "SliceTarget",
                syntheticReport.entryChains().get(0),
                parityFindings,
                Map.of(FakeBrigadierCommand.class.getName(), sampleClassBytes)
        );
        SliceBitHarness.SliceBitReport parityBitReport = parityHarness.executeFullSliceBit(List.of(), List.of(), 1, 1);
        assertFalse(parityBitReport.pbitResult().passed(), "PBIT must fail when parity findings are present");
        assertTrue(parityBitReport.violatedInvariants().contains("CAUSAL-SHARED-STATE-RACE"));
        assertTrue(parityBitReport.violatedInvariants().contains("S-005-SYNC-MAIN-IO"));
        assertTrue(parityBitReport.violatedInvariants().contains("S-002-RESOURCE-LEAK"));

        byte[] shaAfter = SliceBitHarness.computeFileSha256(jarPath);
        long mtimeAfter = Files.getLastModifiedTime(jarPath).toMillis();
        assertTrue(java.util.Arrays.equals(shaBefore, shaAfter), "Target .jar SHA-256 on disk must remain 100% identical");
        assertEquals(mtimeBefore, mtimeAfter, "Target .jar mtime on disk must remain untouched");
        runtime.close();
    }

    @Test
    @DisplayName("commands-api-ADR-001 & leaffuzz-ADR-001: LeafFuzzCommand enforces pure CommandsAPI structure without String[] interception, full tab completion, and execution of all clickable book/chat commands")
    void leafFuzzCommandTreeTabCompletionAndClickableCommandExecution(@TempDir Path tempDir) throws Exception {
        // 1. Structural guard: LeafFuzzCommand must not declare any method intercepting raw String[] args
        for (java.lang.reflect.Method m : LeafFuzzCommand.class.getDeclaredMethods()) {
            boolean hasStringArrayParam = java.util.Arrays.stream(m.getParameterTypes())
                    .anyMatch(pt -> pt == String[].class);
            assertFalse(
                    hasStringArrayParam,
                    () -> "LeafFuzzCommand must rely on pure TreeCommand (CommandsAPI) dispatch without raw String[] interception: " + m
            );
        }

        Path modsDir = Files.createDirectories(tempDir.resolve("mods"));
        createSyntheticJar(
                modsDir.resolve("NeoQuarry.jar"),
                "META-INF/neoforge.mods.toml",
                "modLoader=\"javafml\"\n[[mods]]\nmodId=\"NeoQuarry\"\n",
                List.of("dev/example/neoquarry/QuarryTicker.class", "dev/example/neoquarry/QuarrySession.class")
        );

        List<String> messages = new ArrayList<>();
        AtomicReference<Consumer<UUID>> quitListenerRef = new AtomicReference<>();
        FakeServerAccessor accessor = new FakeServerAccessor(tempDir, messages, quitListenerRef);
        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();

        RawCommandNode speedArg = new RawCommandNode(
                "speed",
                "argument",
                "brigadier:integer",
                Map.of("min", 1, "max", 512),
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
        runtime.setCustomEpisodeRunner(actions -> {
            runtime.recordEpisodeObservation("/quarry 256", 1, 1, 1, 1, List.of("QuarryGui"), 1, 32.0, 1, false);
            for (EpisodeAction act : actions) {
                if (act.commandLine().contains("256") || act.commandLine().contains("512")) {
                    runtime.faultOracle().recordSlowTickStack(
                            150.0,
                            new StackTraceElement[]{
                                    new StackTraceElement("dev.example.neoquarry.QuarryTicker", "tickQuarry", "QuarryTicker.java", 88)
                            },
                            0L
                    );
                    return EpisodeOutcome.fault(
                            "stall:dev.example.neoquarry.QuarryTicker.tickQuarry",
                            "NeoQuarry.jar",
                            10.0,
                            150.0,
                            List.of("dev.example.neoquarry.QuarryTicker.tickQuarry")
                    );
                }
            }
            return EpisodeOutcome.clean();
        });
        runtime.start();
        runtime.setOwnershipIndex(JarClassOwnershipIndex.scanArchiveDirectories(List.of(modsDir), List.of("leaffuzz")));
        // 2. Command tree hierarchy & parameter definitions across /fuzz, /leaffuzz, /qc, and blank fallback
        LeafFuzzCommand defaultNameCmd = new LeafFuzzCommand("   ", accessor, runtime);
        assertEquals("fuzz", defaultNameCmd.name());

        LeafFuzzCommand fuzzCmd = new LeafFuzzCommand("fuzz", accessor, runtime);
        LeafFuzzCommand leafFuzzCmd = new LeafFuzzCommand("leaffuzz", accessor, runtime);
        LeafFuzzCommand qcCmd = new LeafFuzzCommand("qc", accessor, runtime);
        Map<String, LeafFuzzCommand> commandRoots = Map.of(
                "fuzz", fuzzCmd,
                "leaffuzz", leafFuzzCmd,
                "qc", qcCmd
        );

        for (Map.Entry<String, LeafFuzzCommand> rootEntry : commandRoots.entrySet()) {
            LeafFuzzCommand root = rootEntry.getValue();
            assertEquals(rootEntry.getKey(), root.name());
            assertEquals("leaffuzz.admin", root.permission());
            assertFalse(root.description().isBlank());
            assertEquals(null, root.parent());
            assertEquals(0L, root.avgTime());
            assertEquals(Set.of("CHECK", "REPORT", "RESET", "TEST", "RELOAD"), root.getCommandLookup().keySet());
            assertEquals(Set.of("target", "episodes", "players", "stage"), root.getParameterLookup().keySet());

            for (Map.Entry<String, io.github.dailystruggle.commandsapi.common.CommandsAPICommand> subEntry : root.getCommandLookup().entrySet()) {
                io.github.dailystruggle.commandsapi.common.CommandsAPICommand sub = subEntry.getValue();
                assertNotNull(sub);
                assertEquals(subEntry.getKey(), sub.name().toUpperCase(Locale.ROOT));
                assertEquals("leaffuzz.admin", sub.permission());
                assertFalse(sub.description().isBlank());
                assertEquals(root, sub.parent());
                assertEquals(0L, sub.avgTime());
                assertTrue(sub instanceof io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand);
                io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand subTree =
                        (io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand) sub;
                assertTrue(subTree.getCommandLookup().isEmpty(), "Leaf subcommands must have no nested children");
            }
            io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand checkNode =
                    (io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand) root.getCommandLookup().get("CHECK");
            assertEquals(Set.of("target", "episodes", "players", "stage"), checkNode.getParameterLookup().keySet());

            io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand resetNode =
                    (io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand) root.getCommandLookup().get("RESET");
            assertEquals(Set.of("scope"), resetNode.getParameterLookup().keySet());

            for (String noParamSub : List.of("REPORT", "TEST", "RELOAD")) {
                io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand leaf =
                        (io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand) root.getCommandLookup().get(noParamSub);
                assertTrue(leaf.getParameterLookup().isEmpty());
            }
        }

        UUID playerId = UUID.fromString("00000000-0000-0000-0000-000000000042");

        // 3. Reject bare positional tokens on BOTH 4-arg and 6-arg onCommand overloads, plus bad parameters & permissions
        for (String[] positionalArgs : List.of(
                new String[]{"NeoQuarry"},
                new String[]{"check", "NeoQuarry"},
                new String[]{"check", "NeoQuarry", "16"},
                new String[]{"reset", "faults"}
        )) {
            messages.clear();
            java.util.concurrent.CompletableFuture<Boolean> res4 = fuzzCmd.onCommand(
                    playerId, perm -> true, messages::add, positionalArgs
            );
            CommandsAPI.execute();
            assertFalse(res4.join(), () -> "4-arg onCommand must reject positional args: " + java.util.Arrays.toString(positionalArgs));
            assertTrue(messages.stream().anyMatch(m -> m.contains("Unknown subcommand")), () -> "Expected invalid-command message, got: " + messages);

            messages.clear();
            java.util.concurrent.CompletableFuture<Boolean> res6 = fuzzCmd.onCommand(
                    playerId, perm -> true, messages::add, positionalArgs, 0, Map.of()
            );
            CommandsAPI.execute();
            assertFalse(res6.join(), () -> "6-arg onCommand must reject positional args: " + java.util.Arrays.toString(positionalArgs));
            assertTrue(messages.stream().anyMatch(m -> m.contains("Unknown subcommand")), () -> "Expected invalid-command message, got: " + messages);
        }

        for (String[] malformedParamArgs : List.of(
                new String[]{"check", "unknown=value"},
                new String[]{"check", "target="},
                new String[]{"unknown=value"}
        )) {
            messages.clear();
            java.util.concurrent.CompletableFuture<Boolean> res = fuzzCmd.onCommand(
                    playerId, perm -> true, messages::add, malformedParamArgs
            );
            CommandsAPI.execute();
            assertFalse(res.join());
            assertTrue(messages.stream().anyMatch(m -> m.contains("Invalid parameter")), () -> "Expected badParameter message, got: " + messages);
        }

        for (String[] badValueArgs : List.of(
                new String[]{"check", "episodes=0"},
                new String[]{"check", "episodes=100001"},
                new String[]{"check", "episodes=abc"},
                new String[]{"check", "players=0"},
                new String[]{"check", "players=501"},
                new String[]{"check", "players=invalid"},
                new String[]{"check", "stage=bogus"},
                new String[]{"reset", "scope=bogus"}
        )) {
            messages.clear();
            java.util.concurrent.CompletableFuture<Boolean> badRes =
                    fuzzCmd.onCommand(playerId, perm -> true, messages::add, badValueArgs);
            CommandsAPI.execute();
            assertFalse(badRes.join(), () -> "Invalid parameter value must return false: " + java.util.Arrays.toString(badValueArgs));
            assertTrue(
                    messages.stream().anyMatch(m -> m.contains("Invalid parameter")),
                    () -> "Expected badParameter message for " + java.util.Arrays.toString(badValueArgs) + ", got: " + messages
            );
        }
        // Permission denial on root and subcommands
        for (String[] deniedArgs : List.of(
                new String[0],
                new String[]{"check", "target=NeoQuarry"},
                new String[]{"report"},
                new String[]{"reset"},
                new String[]{"test"},
                new String[]{"reload"}
        )) {
            messages.clear();
            java.util.concurrent.CompletableFuture<Boolean> denied = fuzzCmd.onCommand(
                    playerId, perm -> false, messages::add, deniedArgs
            );
            CommandsAPI.execute();
            assertFalse(denied.join());
            assertTrue(messages.stream().anyMatch(m -> m.contains("do not have permission")), () -> "Expected noPermission message, got: " + messages);
        }

        // Help output on root and all 5 subcommands
        for (String[] helpArgs : List.of(
                new String[]{"help"},
                new String[]{"check", "help"},
                new String[]{"report", "help"},
                new String[]{"reset", "help"},
                new String[]{"test", "help"},
                new String[]{"reload", "help"}
        )) {
            messages.clear();
            fuzzCmd.onCommand(playerId, perm -> true, messages::add, helpArgs);
            CommandsAPI.execute();
            assertTrue(messages.stream().anyMatch(m -> m.contains("Command: ")), () -> "Expected help output for " + java.util.Arrays.toString(helpArgs) + ", got: " + messages);
        }

        // 4. Tab completion across root, subcommands, parameter keys/values, comma-lists, permissions, and Brigadier bridge
        List<String> rootTab = fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{""});
        assertEquals(
                Set.of("check", "report", "reset", "test", "reload", "target=", "episodes=", "players=", "stage=", "help"),
                Set.copyOf(rootTab)
        );
        assertEquals(Set.of("report", "reset", "reload"), Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"re"})));
        assertEquals(List.of("check"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"c"}));
        assertEquals(Set.of("test", "target="), Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"t"})));

        List<String> targetTab = fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"target="});
        assertTrue(targetTab.containsAll(List.of("target=all", "target=NeoQuarry", "target=NeoQuarry.jar")), "Expected indexed targets in target= completion: " + targetTab);

        List<String> chainedTargetTab = fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"target=NeoQuarry,"});
        assertTrue(chainedTargetTab.contains("target=NeoQuarry,all"));
        assertFalse(chainedTargetTab.contains("target=NeoQuarry,NeoQuarry"));

        assertEquals(
                Set.of("episodes=24", "episodes=100", "episodes=250", "episodes=1000", "episodes=5000", "episodes=7200"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"episodes="}))
        );
        assertEquals(
                Set.of("players=auto", "players=ramp", "players=1", "players=10", "players=25", "players=50", "players=100", "players=200"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"players="}))
        );
        assertEquals(
                Set.of("stage=all", "stage=commands", "stage=fuzz", "stage=faults", "stage=leaks", "stage=causal", "stage=snapshot"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"stage="}))
        );

        List<String> afterRootParamTab = fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"target=NeoQuarry", ""});
        assertFalse(afterRootParamTab.contains("target="), "Already-used parameter must not be suggested again");
        assertTrue(afterRootParamTab.containsAll(List.of("episodes=", "players=", "stage=")));

        assertEquals(
                Set.of("target=", "episodes=", "players=", "stage=", "help"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"check", ""}))
        );
        assertEquals(
                Set.of("stage=all", "stage=commands", "stage=fuzz", "stage=faults", "stage=leaks", "stage=causal", "stage=snapshot"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"check", "stage="}))
        );
        assertEquals(List.of("stage=causal"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"check", "stage=ca"}));
        assertEquals(List.of("players=ramp"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"check", "players=r"}));
        assertEquals(
                Set.of("episodes=", "players=", "stage=", "help"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"check", "target=NeoQuarry", ""}))
        );

        assertEquals(Set.of("scope=", "help"), Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"reset", ""})));
        assertEquals(
                Set.of("scope=all", "scope=faults", "scope=leaks", "scope=campaign"),
                Set.copyOf(fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"reset", "scope="}))
        );
        assertEquals(List.of("scope=campaign"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"reset", "scope=ca"}));
        assertEquals(List.of("help"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"report", ""}));
        assertEquals(List.of("help"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"test", ""}));
        assertEquals(List.of("help"), fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"reload", ""}));

        // Permission-denied tab completion must not leak admin subcommands or parameters
        assertEquals(List.of("help"), fuzzCmd.onTabComplete(playerId, perm -> false, new String[]{""}));
        assertEquals(List.of("help"), fuzzCmd.onTabComplete(playerId, perm -> false, new String[]{"check", ""}));
        assertEquals(List.of("help"), fuzzCmd.onTabComplete(playerId, perm -> false, new String[]{"reset", ""}));

        // Brigadier bridge tab completion & execution parity
        io.github.dailystruggle.commandsapi.brigadier.BrigadierBridgeContext<UUID> brigCtx =
                new io.github.dailystruggle.commandsapi.brigadier.BrigadierBridgeContext<>(
                        id -> id,
                        (id, perm) -> true,
                        (id, msg) -> messages.add(msg)
                );
        com.mojang.brigadier.CommandDispatcher<UUID> brigDispatcher = new com.mojang.brigadier.CommandDispatcher<>();
        for (LeafFuzzCommand root : commandRoots.values()) {
            brigDispatcher.register(io.github.dailystruggle.commandsapi.brigadier.BrigadierCommandAdapter.toBrigadier(root, brigCtx));
        }

        com.mojang.brigadier.ParseResults<UUID> parseRoot = brigDispatcher.parse("fuzz ", playerId);
        List<String> brigRootSuggestions = brigDispatcher.getCompletionSuggestions(parseRoot).join()
                .getList().stream().map(com.mojang.brigadier.suggestion.Suggestion::getText).toList();
        assertTrue(brigRootSuggestions.containsAll(List.of("check", "report", "reset", "test", "reload", "target=", "episodes=", "players=", "stage=")));

        com.mojang.brigadier.ParseResults<UUID> parseCheckStage = brigDispatcher.parse("fuzz check stage=", playerId);
        List<String> brigStageSuggestions = brigDispatcher.getCompletionSuggestions(parseCheckStage).join()
                .getList().stream().map(com.mojang.brigadier.suggestion.Suggestion::getText).toList();
        assertTrue(brigStageSuggestions.containsAll(List.of("stage=all", "stage=commands", "stage=fuzz", "stage=faults", "stage=leaks", "stage=causal", "stage=snapshot")));

        com.mojang.brigadier.ParseResults<UUID> parseResetScope = brigDispatcher.parse("fuzz reset scope=", playerId);
        List<String> brigScopeSuggestions = brigDispatcher.getCompletionSuggestions(parseResetScope).join()
                .getList().stream().map(com.mojang.brigadier.suggestion.Suggestion::getText).toList();
        assertTrue(brigScopeSuggestions.containsAll(List.of("scope=all", "scope=faults", "scope=leaks", "scope=campaign")));

        // 5. Execute all clickable commands from Idle Overview Book (before any QC scorecard exists)
        LeafFuzzRuntime idleRuntime = new LeafFuzzRuntime(accessor);
        idleRuntime.load();
        LeafFuzzCommand idleFuzzCmd = new LeafFuzzCommand("fuzz", accessor, idleRuntime);
        java.util.concurrent.CompletableFuture<Boolean> bareFuzzFuture = idleFuzzCmd.onCommand(
                playerId, perm -> true, messages::add, new String[0]
        );
        CommandsAPI.execute();
        assertTrue(bareFuzzFuture.join());
        BookMenuSpec idleBook = accessor.lastRenderedBook();
        idleRuntime.close();
        assertNotNull(idleBook, "Bare /fuzz must render the idle overview BookMenuSpec when no scorecard exists");
        assertTrue(BookContrastValidator.auditBookMenuSpec(idleBook).isEmpty());

        List<BookMenuSpec.Fragment> idleClickables = collectClickableFragments(idleBook);
        assertEquals(5, idleClickables.size(), "Idle overview book must expose 5 clickable fragments");

        List<String> idleSuggests = idleClickables.stream()
                .filter(f -> f.clickAction() == BookMenuSpec.ClickAction.SUGGEST_COMMAND)
                .map(BookMenuSpec.Fragment::clickValue)
                .toList();
        assertEquals(List.of("/fuzz check target="), idleSuggests);
        // Verify the suggested prefix tab-completes and executes once a target is filled in
        List<String> suggestCompletions = fuzzCmd.onTabComplete(playerId, perm -> true, new String[]{"check", "target="});
        assertTrue(suggestCompletions.contains("target=NeoQuarry"));
        assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, idleSuggests.get(0) + "NeoQuarry episodes=4", messages));

        List<String> idleRunCmds = idleClickables.stream()
                .filter(f -> f.clickAction() == BookMenuSpec.ClickAction.RUN_COMMAND)
                .map(BookMenuSpec.Fragment::clickValue)
                .toList();
        assertEquals(
                List.of(
                        "/fuzz check players=auto",
                        "/fuzz check stage=commands target=all",
                        "/fuzz check stage=leaks",
                        "/fuzz test"
                ),
                idleRunCmds
        );
        for (String clickCmd : idleRunCmds) {
            assertTrue(
                    dispatchClickableCommand(commandRoots, brigDispatcher, playerId, clickCmd, messages),
                    () -> "Idle book clickable RUN_COMMAND failed to execute: " + clickCmd
            );
        }

        // 6. Execute all clickable commands from interactive chat action bars across /fuzz, /leaffuzz, and /qc
        for (String alias : List.of("fuzz", "leaffuzz", "qc")) {
            accessor.interactiveLines().clear();
            LeafFuzzCommand root = commandRoots.get(alias);
            java.util.concurrent.CompletableFuture<Boolean> checkFut = root.onCommand(
                    playerId, perm -> true, messages::add, new String[]{"check", "target=NeoQuarry", "episodes=4"}
            );
            CommandsAPI.execute();
            assertTrue(checkFut.join());
            assertFalse(accessor.interactiveLines().isEmpty(), "Expected interactive chat line for /" + alias + " check");

            List<String> chatRunCmds = accessor.interactiveLines().stream()
                    .flatMap(l -> l.fragments().stream())
                    .filter(f -> f.clickAction() == BookMenuSpec.ClickAction.RUN_COMMAND)
                    .map(BookMenuSpec.Fragment::clickValue)
                    .toList();
            assertEquals(
                    List.of("/" + alias + " report", "/" + alias + " check target=NeoQuarry"),
                    chatRunCmds
            );
            for (String chatClickCmd : chatRunCmds) {
                assertTrue(
                        dispatchClickableCommand(commandRoots, brigDispatcher, playerId, chatClickCmd, messages),
                        () -> "Interactive chat clickable RUN_COMMAND failed: " + chatClickCmd
                );
            }
        }

        // 7. Populate all 5 scorecard stages (Commands, Reproducers/Telemetry, Faults, Leaks, Causal) and execute all 5-page Book clickable commands
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
                    "cp-cmd-" + i,
                    1000L + i * 1000L,
                    runtime.retentionScreener().totalDepartures(),
                    i * 2L,
                    histo
            );
        }
        CausalGraphReport causalReport = BytecodeCausalGraphScanner.analyzeClasses(
                "mod:neoquarry",
                "NeoQuarry",
                List.of(),
                List.of(new JarConfigScanner.CommandDescriptor(
                        "quarry",
                        "NeoQuarry",
                        "Teleports player to quarry",
                        "/quarry",
                        List.of(),
                        "neoquarry.use",
                        "true"
                )),
                Map.of("config.yml", "warmup:\n  dead-cancel-on-move: true\n")
        );
        runtime.registerCausalGraphReport("NeoQuarry.jar", causalReport);

        assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, "/fuzz check target=NeoQuarry episodes=16", messages));
        assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, "/fuzz report", messages));

        BookMenuSpec fullBook = accessor.lastRenderedBook();
        assertNotNull(fullBook);
        assertEquals(5, fullBook.pages().size(), "Full scorecard book must contain all 5 pages (Overview, Telemetry, Perms/Reproducers, Faults/Leaks, Causal)");
        assertTrue(BookContrastValidator.auditBookMenuSpec(fullBook).isEmpty());

        List<BookMenuSpec.Fragment> fullBookClickables = collectClickableFragments(fullBook);
        List<String> fullBookRunCmds = fullBookClickables.stream()
                .filter(f -> f.clickAction() == BookMenuSpec.ClickAction.RUN_COMMAND)
                .map(BookMenuSpec.Fragment::clickValue)
                .toList();
        assertTrue(fullBookRunCmds.containsAll(List.of(
                "/fuzz check stage=commands target=NeoQuarry",
                "/fuzz check stage=faults",
                "/fuzz check stage=leaks",
                "/fuzz check stage=causal target=NeoQuarry",
                "/fuzz check target=NeoQuarry",
                "/fuzz test"
        )), "Expected all stage drill-downs, re-check, and BIT self-test clickable commands in scorecard book: " + fullBookRunCmds);

        for (String bookRunCmd : fullBookRunCmds) {
            messages.clear();
            assertTrue(
                    dispatchClickableCommand(commandRoots, brigDispatcher, playerId, bookRunCmd, messages),
                    () -> "Scorecard book clickable RUN_COMMAND failed: " + bookRunCmd
            );
            assertFalse(messages.isEmpty(), () -> "Expected output messages when executing clickable book command: " + bookRunCmd);
        }

        List<String> fullBookSuggestCmds = fullBookClickables.stream()
                .filter(f -> f.clickAction() == BookMenuSpec.ClickAction.SUGGEST_COMMAND)
                .map(BookMenuSpec.Fragment::clickValue)
                .toList();
        assertTrue(fullBookSuggestCmds.contains("/fuzz check target=NeoQuarry"));
        assertTrue(
                fullBookSuggestCmds.stream().anyMatch(s -> s.contains("lp group default permission set ") && s.endsWith(" false")),
                "Expected LuckPerms remediation SUGGEST_COMMAND on Perms & Reproducers page: " + fullBookSuggestCmds
        );
        for (String suggestCmd : fullBookSuggestCmds) {
            if (suggestCmd.startsWith("/fuzz ")) {
                assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, suggestCmd, messages));
            }
        }

        // 8. Exercise remaining stage=snapshot, reset scopes, and reload subcommands
        assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, "/fuzz check stage=snapshot", messages));
        for (String scope : List.of("faults", "leaks", "campaign", "all")) {
            messages.clear();
            assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, "/fuzz reset scope=" + scope, messages));
            assertTrue(messages.stream().anyMatch(m -> m.contains("Reset complete") && m.contains("scope=&f" + scope)));
        }
        messages.clear();
        assertTrue(dispatchClickableCommand(commandRoots, brigDispatcher, playerId, "/fuzz reload", messages));
        assertTrue(messages.stream().anyMatch(m -> m.toLowerCase(Locale.ROOT).contains("configuration and messages reloaded")));

        runtime.close();
    }

    private static List<BookMenuSpec.Fragment> collectClickableFragments(BookMenuSpec book) {
        List<BookMenuSpec.Fragment> out = new ArrayList<>();
        for (BookMenuSpec.Page page : book.pages()) {
            for (BookMenuSpec.Line line : page.lines()) {
                for (BookMenuSpec.Fragment frag : line.fragments()) {
                    if (frag.clickAction() != BookMenuSpec.ClickAction.NONE) {
                        out.add(frag);
                    }
                }
            }
        }
        return out;
    }

    private static boolean dispatchClickableCommand(
            Map<String, LeafFuzzCommand> commandRoots,
            com.mojang.brigadier.CommandDispatcher<UUID> brigDispatcher,
            UUID callerId,
            String clickCommandLine,
            List<String> messages
    ) throws com.mojang.brigadier.exceptions.CommandSyntaxException {
        assertNotNull(clickCommandLine);
        assertTrue(clickCommandLine.startsWith("/"), "Clickable command must start with '/': " + clickCommandLine);
        String withoutSlash = clickCommandLine.substring(1).trim();
        String[] parts = withoutSlash.split("\\s+");
        assertTrue(parts.length >= 1);
        LeafFuzzCommand root = commandRoots.get(parts[0]);
        assertNotNull(root, "Unknown root command in clickable action: " + parts[0]);
        String[] args = java.util.Arrays.copyOfRange(parts, 1, parts.length);

        // Execute through 4-arg TreeCommand.onCommand (Bukkit/Paper path)
        java.util.concurrent.CompletableFuture<Boolean> fut = root.onCommand(
                callerId,
                perm -> true,
                messages::add,
                args
        );
        CommandsAPI.execute();
        if (!Boolean.TRUE.equals(fut.join())) {
            return false;
        }

        // Also execute through BrigadierCommandAdapter (Fabric/NeoForge/Brigadier path)
        int brigResult = brigDispatcher.execute(withoutSlash, callerId);
        CommandsAPI.execute();
        return brigResult == 1;
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
        private final List<BookMenuSpec.Line> interactiveLines = new ArrayList<>();

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

        List<BookMenuSpec.Line> interactiveLines() {
            return interactiveLines;
        }

        @Override
        public void renderBookOrChat(UUID playerId, BookMenuSpec spec) {
            this.lastRenderedBook = spec;
        }

        @Override
        public void sendInteractiveLine(UUID playerId, BookMenuSpec.Line line) {
            this.interactiveLines.add(line);
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

    @Test
    @DisplayName("LeafFuzzRuntime supplies self-contained Plugin UML workspaceTab and configKeyBadges bundle for LeafConfig")
    void leafFuzzSuppliesPluginUmlWorkspaceTabAndCausalKeyBadgesToLeafConfig() {
        BytecodeCausalGraphScanner.CausalChainSlice cmdSlice =
                new BytecodeCausalGraphScanner.CausalChainSlice(
                        BytecodeCausalGraphScanner.EntryPointKind.COMMAND,
                        "com.example.crate.CrateCommand#onCommand",
                        "/crate open",
                        BytecodeCausalGraphScanner.ListenerRegistrationMode.NOT_APPLICABLE,
                        "broadcast-wins",
                        List.of("if (config.getBoolean(\"broadcast-wins\"))"),
                        List.of("cooldownSeconds", "broadcast-wins"),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of("CrateCommand#onCommand", "CrateService#openCrate"),
                        Set.of("INVENTORY_MENU", "MESSAGE_SEND"),
                        BytecodeCausalGraphScanner.EffectFrame.empty(),
                        List.of(),
                        List.of(new BytecodeCausalGraphScanner.ProofObligation(
                                "S-005",
                                BytecodeCausalGraphScanner.ProofStatus.VIOLATED,
                                "Synchronous JDBC query on command thread"
                        ))
                );
        CausalFinding deadKeyFinding =
                new CausalFinding(
                        "CAUSAL-1",
                        "StandaloneCrate",
                        1,
                        BytecodeCausalGraphScanner.FindingKind.CAUSAL_DEAD_CONFIG_KEY,
                        BytecodeCausalGraphScanner.ConfidenceTier.CONFIRMED,
                        100,
                        "legacy-placebo-toggle",
                        "Config key 'legacy-placebo-toggle' declared in config.yml",
                        "0 bytecode readers in JAR",
                        "Read 'legacy-placebo-toggle' or remove from config.yml",
                        List.of("No ldc 'legacy-placebo-toggle' in class pool"),
                        ""
                );
        CausalGraphReport report =
                new CausalGraphReport(
                        "plugin:standalonecrate",
                        "StandaloneCrate",
                        List.of(cmdSlice),
                        Map.of(),
                        Map.of("com.example.crate.CrateWinListener", "broadcast-wins"),
                        List.of(deadKeyFinding),
                        Set.of("com.example.crate.CrateCommand#onCommand"),
                        List.of()
                );

        Map<String, Object> bundle = LeafFuzzRuntime.buildLeafConfigWorkspaceExtensionForReports(List.of(report));
        assertEquals("leaffuzz", bundle.get("providerId"));
        assertEquals("LeafFuzz", bundle.get("displayName"));

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> tabs = (List<Map<String, Object>>) bundle.get("workspaceTabs");
        assertEquals(1, tabs.size());
        Map<String, Object> umlTab = tabs.get(0);
        assertEquals("plugin-uml", umlTab.get("tabId"));
        assertEquals("LeafFuzzUmlTabKernel.render", umlTab.get("clientRendererFn"));
        String payloadJson = String.valueOf(umlTab.get("initialPayloadJson"));
        assertTrue(payloadJson.contains("\"artifactId\":\"plugin:standalonecrate\"")
                && payloadJson.contains("\"stereotype\":\"COMMAND\"")
                && payloadJson.contains("\"stereotype\":\"CONFIG_GUARD\""));
        assertTrue(
                payloadJson.contains("Main-Thread Blocking I/O: Synchronous JDBC query on command thread"),
                "Violated S-005 proof obligation must be translated to plain-English Main-Thread Blocking I/O warning"
        );
        assertFalse(
                payloadJson.contains("\"S-005:") || payloadJson.contains("CAUSAL_DEAD_CONFIG_KEY:"),
                "Operator-facing Plugin UML payload must not leak raw S-005 or CAUSAL_* enum prefixes"
        );
        String kernelJs = String.valueOf(umlTab.get("clientScriptKernel"));
        assertTrue(kernelJs.contains("window.LeafFuzzUmlTabKernel=")
                && kernelJs.contains("zoomIntoUmlComponent")
                && kernelJs.contains("setViewMode")
                && kernelJs.contains("uml-state-causal-svg")
                && kernelJs.contains("stateDiagram-v2")
                && kernelJs.contains("humanizeHazard")
                && kernelJs.contains("humanizeRegMode")
                && kernelJs.contains("4. SERVER ACTIONS & WARNINGS"));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> badges = (List<Map<String, Object>>) bundle.get("configKeyBadges");
        assertTrue(badges.stream().anyMatch(b -> "legacy-placebo-toggle".equals(b.get("keyPath"))
                && "DEAD_KEY".equals(b.get("status"))
                && "leaffuzz:plugin-uml".equals(b.get("targetTabId"))));
        assertTrue(badges.stream().anyMatch(b -> "cooldownSeconds".equals(b.get("keyPath"))
                && "HOT_RELOAD".equals(b.get("provenReloadTier"))));
        net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport mitigation =
                net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport.build(
                        "exc:StandaloneCrate:CrateGiveAll",
                        "StandaloneCrate.jar",
                        List.of("/crate giveall diamond 64"),
                        "SOLO",
                        Optional.of("64"),
                        null,
                        null
                );
        LeafFuzzScorecardReport scorecard = new LeafFuzzScorecardReport(
                "StandaloneCrate",
                "paper",
                "1.21.4",
                1,
                4,
                2,
                List.of(new net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.LeastPrivilegeFinding(
                        "/crate giveall",
                        List.of("crate"),
                        "STATE_MUTATING_DEFAULT_EXPOSURE",
                        "HIGH",
                        "StandaloneCrate.jar",
                        "<none>",
                        "economy/reward mutation keyword",
                        "aliases:\n  crate: []"
                )),
                12,
                4,
                List.of(mitigation),
                List.of(),
                3,
                List.of(),
                450L,
                LeafFuzzScorecardReport.ExecutionTelemetry.empty(),
                List.of(deadKeyFinding)
        );

        Map<String, Object> enrichedBundle = LeafFuzzRuntime.buildLeafConfigWorkspaceExtensionForReports(
                List.of(report),
                List.of(scorecard)
        );
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> enrichedTabs = (List<Map<String, Object>>) enrichedBundle.get("workspaceTabs");
        String enrichedPayload = String.valueOf(enrichedTabs.get(0).get("initialPayloadJson"));
        assertTrue(enrichedPayload.contains("\"scorecard\":{")
                        && enrichedPayload.contains("\"stage1Verdict\":\"WARN\"")
                        && enrichedPayload.contains("\"stage2Verdict\":\"FAIL\"")
                        && enrichedPayload.contains("crate giveall"),
                "Scorecard-enriched LeafFuzz bundle must embed 5-stage QC verdict and open-command mitigations");
        String enrichedKernel = String.valueOf(enrichedTabs.get(0).get("clientScriptKernel"));
        assertTrue(enrichedKernel.contains("lockCommandInConfig")
                        && enrichedKernel.contains("stageCommandsYmlOverride"),
                "LeafFuzz UML tab kernel must expose 1-click lockCommandInConfig -> stageCommandsYmlOverride handoff");
    }

    @Test
    @DisplayName("ADR-125 & leaffuzz-ADR-001: PersonaPolicyBotActor step_away_anchor and rtp_or_anchor expand multi-chunk spiral and classify mining/building skills")
    void personaPolicyBotActorOutwardSpiralExplorationAndSkillClassification(@TempDir Path tempDir) {
        PersonaProfile explorerProfile = PersonaPolicyBotActor.defaultPersonaCatalog().stream()
                .filter(p -> p.taxonomyArchetype().contains("explorer"))
                .findFirst()
                .orElse(PersonaPolicyBotActor.defaultPersonaCatalog().get(0));
        PersonaPolicyBotActor bot = new PersonaPolicyBotActor(explorerProfile, "default", 42);
        bot.setLocation(0, 64, 0);

        for (int i = 0; i < 16; i++) {
            BotStepRecord step = bot.executeMicroSkillByIndex(3); // step_away_anchor
            assertTrue(step.isExplorationSkill(), "step_away_anchor must be classified as exploration skill");
            assertFalse(step.isWorldMutationSkill(), "step_away_anchor must not be classified as world mutation");
        }
        assertTrue(
                bot.chunksExploredCount() >= 6,
                "16 outward step_away_anchor steps must traverse >= 6 distinct chunks instead of looping in a 4x4 square, got "
                        + bot.chunksExploredCount()
        );

        int chunksBeforeRtp = bot.chunksExploredCount();
        BotStepRecord rtpStep = bot.executeMicroSkillByIndex(1); // rtp_or_anchor
        assertTrue(rtpStep.isExplorationSkill());
        assertTrue(
                bot.chunksExploredCount() > chunksBeforeRtp,
                "rtp_or_anchor must advance to a new spiral anchor chunk"
        );

        BotStepRecord digStep = bot.executeMicroSkillByIndex(4); // harvest_nearest
        assertTrue(digStep.isMiningSkill());
        assertTrue(digStep.isWorldMutationSkill());
        assertEquals(3, digStep.targetBlockOffset().length);

        BotStepRecord placeStep = bot.executeMicroSkillByIndex(8); // place_wall_ring
        assertTrue(placeStep.isBuildingSkill());
        assertTrue(placeStep.isWorldMutationSkill());
        assertEquals(3, placeStep.targetBlockOffset().length);
        FakeServerAccessor accessor = new FakeServerAccessor(
                tempDir,
                new ArrayList<>(),
                new AtomicReference<>()
        );
        try (LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor)) {
            runtime.load();
            NmsEmbeddedPlayerSession.NmsSwarmRosterController swarm =
                    new NmsEmbeddedPlayerSession.NmsSwarmRosterController(runtime, () -> null);
            LeafFuzzRuntime.SwarmSnapshot snap = swarm.rampToPopulation(16);
            assertEquals(16, snap.onlinePlayers());
            for (int tick = 0; tick < 8; tick++) {
                swarm.stepConcurrentSwarm(0);
            }
            assertTrue(
                    runtime.recentBotSteps().stream().anyMatch(BotStepRecord::isWorldMutationSkill),
                    "Stepping a 16-bot mixed explorer/builder swarm must execute mining/building micro-skills"
            );
            swarm.teardownAll();
        }
    }
}
