package net.leaf.fuzz.common.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import net.leaf.fuzz.common.LeafFuzzBitSuite;
import net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.ArtifactTriageEntry;
import net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.HardRejectReason;
import net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.TriageBatchReport;
import net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.TriageConfig;
import net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunner.TriageDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies {@link LeafFuzzBatchTriageRunner} and {@link LeafFuzzStandaloneCli} headless Pass 1
 * static batch triage funnel, {@code < 0.5%} false-positive hard-reject gate, zero-penalty
 * constant-pool dependency inference, and JSON/CSV/Markdown shortlist exports.
 *
 * @governedBy leaffuzz-ADR-001, ADR-115, ADR-125
 * @trace REQ-FUZZ-TRIAGE-001, REQ-FUZZ-TRIAGE-002, REQ-FUZZ-TRIAGE-003, REQ-FUZZ-TRIAGE-004
 */
@DisplayName("LeafFuzzBatchTriageRunner & CLI Triage Funnel Tests (REQ-FUZZ-TRIAGE-001..004)")
class LeafFuzzBatchTriageRunnerTest {

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface EventHandler {
    }

    static final class PlayerJoinEvent {
    }

    static final class FakePlayer {
        void teleportAsync(String destination) {
        }

        void sendMessage(String msg) {
        }
    }

    static final class FakeBlock {
        void setType(String material) {
        }
    }

    static final class FakeWorld {
        void getChunkAt(int x, int z) {
        }
    }

    static final class FakeScheduler {
        void runTaskAsynchronously(Object plugin, Runnable task) {
            if (task != null) {
                task.run();
            }
        }
    }

    /** Valid wired listener and command handler fixture. */
    public static final class ValidTeleportPluginFixture {
        public void onEnable() {
            ValidJoinListener listener = new ValidJoinListener();
            if (listener.hashCode() == -1) {
                throw new IllegalStateException();
            }
        }

        public boolean onCommand(FakePlayer sender, String cmd, String label, String[] args) {
            sender.teleportAsync("world:0,100,0");
            return true;
        }
    }

    public static final class ValidJoinListener {
        @EventHandler
        public void onJoin(PlayerJoinEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    /** Unregistered listener fixture for 100% unwired entrypoint test. */
    public static final class UnwiredOrphanListener {
        @EventHandler
        public void onJoin(PlayerJoinEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    public static final class EmptyMainStub {
    }

    /** Confirmed S-005 fixture: async worker lambda mutating main-thread world chunk state. */
    public static final class AsyncWorldMutatorPluginFixture {
        private final FakeScheduler scheduler = new FakeScheduler();
        private final FakeWorld world = new FakeWorld();

        public boolean onCommand(FakePlayer sender, String cmd, String label, String[] args) {
            scheduler.runTaskAsynchronously(this, () -> world.getChunkAt(0, 0));
            return true;
        }
    }

    /** Confirmed S-004 fixture: operational entrypoint silently swallowing IOException. */
    public static final class SwallowedIoCommandFixture {
        public void swallowDatabaseException() {
            try {
                mightThrowIo();
            } catch (IOException ignored) {
                return;
            }
        }

        private void mightThrowIo() throws IOException {
            throw new IOException("disk full");
        }
    }

    /** Valid plugin with a minor hollow-command deduction to test deterministic score ranking. */
    public static final class HollowCommandPluginFixture {
        public boolean onCommand(FakePlayer sender, String cmd, String label, String[] args) {
            sender.sendMessage("Teleporting soon...");
            return true;
        }
    }

    @Test
    @DisplayName("evaluateSingleJar: Undeclared Vault/PlaceholderAPI constant-pool hooks incur 0.0 penalty and export in manifest")
    void undeclaredEcosystemDependenciesIncurZeroPenalty(@TempDir Path tempDir) throws Exception {
        Path jar = tempDir.resolve("EconomyTeleport.jar");
        byte[] hookBytes = buildSyntheticConstantPoolClass(
                "com/example/econ/EconomyBridge",
                List.of(
                        "net/milkbowl/vault/economy/Economy",
                        "me/clip/placeholderapi/PlaceholderAPI",
                        "com/sk89q/worldguard/WorldGuard",
                        "net/luckperms/api/LuckPerms",
                        "com/acme/sharedcore/api/CoreService"
                )
        );
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: EconomyTeleport
                    version: 2.1.0
                    main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$ValidTeleportPluginFixture
                    softdepend: [Vault]
                    commands:
                      econtp:
                        description: Teleports player with economy charge
                    """);
            writeClassEntry(zos, ValidTeleportPluginFixture.class);
            writeClassEntry(zos, ValidJoinListener.class);
            writeClassEntry(zos, FakePlayer.class);
            writeClassEntry(zos, PlayerJoinEvent.class);
            zos.putNextEntry(new ZipEntry("com/example/econ/EconomyBridge.class"));
            zos.write(hookBytes);
            zos.closeEntry();
        }

        ArtifactTriageEntry entry = LeafFuzzBatchTriageRunner.evaluateSingleJar(jar, true);
        assertEquals(TriageDecision.SHORTLIST_PASS, entry.decision());
        assertTrue(entry.rejectReasons().isEmpty());
        assertEquals(100.0, entry.compositeScore(), 0.01);
        assertEquals(List.of("Vault"), entry.declaredDependencies());
        assertEquals(
                List.of("LuckPerms", "PlaceholderAPI", "Vault", "WorldGuard"),
                entry.inferredEcosystemDependencies()
        );
        assertEquals(List.of("com.acme.sharedcore"), entry.inferredExternalPackages());
    }

    @Test
    @DisplayName("evaluateSingleJar: Rejects corrupt ZIP, 0-class archive, missing main class, 100% unwired entrypoints, S-004, and S-005")
    void hardRejectGateCatchesDeterministicClosedWorldDefects(@TempDir Path tempDir) throws Exception {
        // 1. Corrupt ZIP file
        Path corruptJar = tempDir.resolve("CorruptArchive.jar");
        Files.writeString(corruptJar, "not-a-valid-zip-header", StandardCharsets.UTF_8);
        ArtifactTriageEntry corruptEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(corruptJar, true);
        assertEquals(TriageDecision.REJECT, corruptEntry.decision());
        assertTrue(corruptEntry.rejectReasons().contains(HardRejectReason.CORRUPT_OR_EMPTY_ARCHIVE));

        // 2. Archive with 0 .class entries
        Path emptyJar = tempDir.resolve("NoClasses.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(emptyJar.toFile()))) {
            writeZipText(zos, "plugin.yml", "name: NoClasses\nversion: 1.0.0\n");
        }
        ArtifactTriageEntry emptyEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(emptyJar, true);
        assertEquals(TriageDecision.REJECT, emptyEntry.decision());
        assertTrue(emptyEntry.rejectReasons().contains(HardRejectReason.CORRUPT_OR_EMPTY_ARCHIVE));

        // 3. Missing declared main class
        Path missingMainJar = tempDir.resolve("MissingMain.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(missingMainJar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: MissingMain
                    version: 1.0.0
                    main: com.example.nonexistent.GhostMain
                    """);
            writeClassEntry(zos, EmptyMainStub.class);
        }
        ArtifactTriageEntry missingMainEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(missingMainJar, true);
        assertEquals(TriageDecision.REJECT, missingMainEntry.decision());
        assertTrue(missingMainEntry.rejectReasons().contains(HardRejectReason.MISSING_DECLARED_MAIN_CLASS));

        // 4. 100% unwired commands and listeners (with 0 reflection/DI)
        Path unwiredJar = tempDir.resolve("AllUnwired.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(unwiredJar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: AllUnwired
                    version: 1.0.0
                    main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$EmptyMainStub
                    commands:
                      ghostwarp:
                        description: Unwired warp command
                    """);
            writeClassEntry(zos, EmptyMainStub.class);
            writeClassEntry(zos, UnwiredOrphanListener.class);
            writeClassEntry(zos, PlayerJoinEvent.class);
        }
        ArtifactTriageEntry unwiredEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(unwiredJar, true);
        assertEquals(TriageDecision.REJECT, unwiredEntry.decision());
        assertTrue(unwiredEntry.rejectReasons().contains(HardRejectReason.ALL_ENTRYPOINTS_UNWIRED));

        // 5. CONFIRMED S-005 async main-thread world mutation
        Path s005Jar = tempDir.resolve("AsyncWorldMutator.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(s005Jar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: AsyncWorldMutator
                    version: 1.0.0
                    main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$AsyncWorldMutatorPluginFixture
                    commands:
                      badasync:
                        description: Mutates world asynchronously
                    """);
            writeClassEntry(zos, AsyncWorldMutatorPluginFixture.class);
            writeClassEntry(zos, FakeScheduler.class);
            writeClassEntry(zos, FakeWorld.class);
            writeClassEntry(zos, FakeBlock.class);
            writeClassEntry(zos, FakePlayer.class);
        }
        ArtifactTriageEntry s005Entry = LeafFuzzBatchTriageRunner.evaluateSingleJar(s005Jar, true);
        assertEquals(TriageDecision.REJECT, s005Entry.decision());
        assertTrue(s005Entry.rejectReasons().contains(HardRejectReason.CONFIRMED_S005_ASYNC_MAIN_SINK));

        // 6. CONFIRMED S-004 swallowed IOException
        Path s004Jar = tempDir.resolve("SwallowedIo.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(s004Jar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: SwallowedIo
                    version: 1.0.0
                    main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$SwallowedIoCommandFixture
                    """);
            writeClassEntry(zos, SwallowedIoCommandFixture.class);
        }
        ArtifactTriageEntry s004Entry = LeafFuzzBatchTriageRunner.evaluateSingleJar(s004Jar, true);
        assertEquals(TriageDecision.REJECT, s004Entry.decision());
        assertTrue(s004Entry.rejectReasons().contains(HardRejectReason.CONFIRMED_S004_SWALLOWED_IO_FAILURE));
    }

    @Test
    @DisplayName("executeCli triage: Filters synthetic batch with 0.0% FPR (<0.5%), caps top-N shortlist, and writes JSON/CSV/MD")
    void cliTriageFiltersSyntheticQueueWithZeroFalsePositivesAndCapsShortlist(@TempDir Path tempDir) throws Exception {
        Path submissionsDir = tempDir.resolve("submissions");
        Files.createDirectories(submissionsDir);

        // Self-archive must be ignored automatically
        Files.writeString(submissionsDir.resolve("LeafFuzz-0.1.0.jar"), "self-jar-placeholder", StandardCharsets.UTF_8);

        // Create 20 clean valid plugins (with undeclared ecosystem hooks) and 10 valid plugins with minor hollow/dead-config deductions
        for (int i = 1; i <= 20; i++) {
            Path jar = submissionsDir.resolve(String.format("ValidCleanPlugin-%02d.jar", i));
            byte[] hookBytes = buildSyntheticConstantPoolClass(
                    "com/example/valid" + i + "/VaultHook",
                    List.of("net/milkbowl/vault/economy/Economy", "me/clip/placeholderapi/PlaceholderAPI")
            );
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jar.toFile()))) {
                writeZipText(zos, "plugin.yml", String.format("""
                        name: ValidCleanPlugin%02d
                        version: 1.0.%d
                        main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$ValidTeleportPluginFixture
                        commands:
                          rtp%02d:
                            description: Teleports player to safe location
                        """, i, i, i));
                writeClassEntry(zos, ValidTeleportPluginFixture.class);
                writeClassEntry(zos, ValidJoinListener.class);
                writeClassEntry(zos, FakePlayer.class);
                writeClassEntry(zos, PlayerJoinEvent.class);
                zos.putNextEntry(new ZipEntry("com/example/valid" + i + "/VaultHook.class"));
                zos.write(hookBytes);
                zos.closeEntry();
            }
        }

        for (int i = 1; i <= 10; i++) {
            Path jar = submissionsDir.resolve(String.format("ValidMinorWarningPlugin-%02d.jar", i));
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jar.toFile()))) {
                writeZipText(zos, "plugin.yml", String.format("""
                        name: ValidMinorWarningPlugin%02d
                        version: 1.0.%d
                        main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$HollowCommandPluginFixture
                        commands:
                          teleport%02d:
                            description: Teleports player to arena
                        """, i, i, i));
                writeZipText(zos, "config.yml", "unused-setting-" + i + ": true\n");
                writeClassEntry(zos, HollowCommandPluginFixture.class);
                writeClassEntry(zos, FakePlayer.class);
            }
        }

        // Create 5 hard-reject defective archives
        Files.writeString(submissionsDir.resolve("Defect01-Corrupt.jar"), "corrupt-bytes", StandardCharsets.UTF_8);
        for (int i = 2; i <= 5; i++) {
            Path jar = submissionsDir.resolve(String.format("Defect%02d-MissingMain.jar", i));
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(jar.toFile()))) {
                writeZipText(zos, "plugin.yml", "name: Defect" + i + "\nversion: 1.0.0\nmain: com.ghost.Missing" + i + "\n");
                writeClassEntry(zos, EmptyMainStub.class);
            }
        }

        Path jsonOut = tempDir.resolve("out/triage.json");
        Path csvOut = tempDir.resolve("out/triage.csv");
        Path mdOut = tempDir.resolve("out/triage.md");

        ByteArrayOutputStream outBuf = new ByteArrayOutputStream();
        ByteArrayOutputStream errBuf = new ByteArrayOutputStream();
        int exitCode = LeafFuzzStandaloneCli.executeCli(
                new String[]{
                        "triage",
                        "--input-dir", submissionsDir.toString(),
                        "--max-pass", "12",
                        "--threads", "4",
                        "--out-json", jsonOut.toString(),
                        "--out-csv", csvOut.toString(),
                        "--out-md", mdOut.toString()
                },
                new PrintStream(outBuf, true, StandardCharsets.UTF_8),
                new PrintStream(errBuf, true, StandardCharsets.UTF_8)
        );

        assertEquals(0, exitCode, () -> "CLI stderr: " + errBuf.toString(StandardCharsets.UTF_8));
        assertTrue(outBuf.toString(StandardCharsets.UTF_8).contains("scanned=35 shortlist_pass=12 deferred_rank=18 rejected=5"));
        assertTrue(Files.isRegularFile(jsonOut));
        assertTrue(Files.isRegularFile(csvOut));
        assertTrue(Files.isRegularFile(mdOut));

        TriageBatchReport report1 = LeafFuzzBatchTriageRunner.runBatchTriage(
                new TriageConfig(submissionsDir, 12, 4, true, null, null, null)
        );
        TriageBatchReport report2 = LeafFuzzBatchTriageRunner.runBatchTriage(
                new TriageConfig(submissionsDir, 12, 4, true, null, null, null)
        );

        assertEquals(35, report1.totalScanned());
        assertEquals(12, report1.shortlistPassCount());
        assertEquals(18, report1.deferredRankCount());
        assertEquals(5, report1.rejectedCount());
        assertEquals(12, report1.shortlist().size());

        // Verify 0.0% (< 0.5%) false-positive rejection rate across all 30 valid plugins
        long validRejected = report1.entries().stream()
                .filter(e -> e.jarFileName().startsWith("Valid"))
                .filter(e -> e.decision() == TriageDecision.REJECT)
                .count();
        assertEquals(0L, validRejected, "Zero valid plugins may be rejected by the <0.5% FPR gate");

        // Verify all 12 shortlisted entries are from the higher-scoring clean valid plugins
        for (ArtifactTriageEntry shortlisted : report1.shortlist()) {
            assertTrue(shortlisted.jarFileName().startsWith("ValidCleanPlugin-"));
            assertEquals(100.0, shortlisted.compositeScore(), 0.01);
            assertTrue(shortlisted.inferredEcosystemDependencies().containsAll(List.of("PlaceholderAPI", "Vault")));
        }

        // Verify deterministic ordering across repeated runs
        assertEquals(
                report1.entries().stream().map(ArtifactTriageEntry::jarFileName).toList(),
                report2.entries().stream().map(ArtifactTriageEntry::jarFileName).toList()
        );

        String jsonText = Files.readString(jsonOut, StandardCharsets.UTF_8);
        String csvText = Files.readString(csvOut, StandardCharsets.UTF_8);
        String mdText = Files.readString(mdOut, StandardCharsets.UTF_8);
        assertTrue(jsonText.contains("\"shortlistPassCount\": 12"));
        assertTrue(jsonText.contains("\"inferredEcosystemDependencies\": [\"PlaceholderAPI\", \"Vault\"]"));
        assertTrue(csvText.contains("SHORTLIST_PASS"));
        assertTrue(csvText.contains("DEFERRED_RANK"));
        assertTrue(mdText.contains("# LeafFuzz Pass 1 Static Batch Triage Report"));

        // Verify BIT self-test suite passes with the triage canary
        LeafFuzzBitSuite bitSuite = new LeafFuzzBitSuite();
        List<LeafFuzzBitSuite.CheckResult> bitChecks = bitSuite.executeAll();
        assertTrue(bitChecks.stream().allMatch(LeafFuzzBitSuite.CheckResult::passed), () -> "BIT results: " + bitChecks);
    }

    @Test
    @DisplayName("evaluateSingleJar: Causal tracing prevents false positives on Folia fallback adapters, helper IOException catches, and Fabric Jar-in-Jar mods")
    void causalTracingPreventsRealWorldFalsePositives(@TempDir Path tempDir) throws Exception {
        // 1. Plugin with delivered teleport command + non-entrypoint helper catching IOException + Folia/RegionScheduler reference
        Path foliaCompatJar = tempDir.resolve("FoliaCompatPlugin.jar");
        byte[] regionRefBytes = buildSyntheticConstantPoolClass(
                "com/example/folia/FoliaRegionBridge",
                List.of("io/papermc/paper/threadedregions/scheduler/RegionScheduler")
        );
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(foliaCompatJar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: FoliaCompatPlugin
                    version: 1.0.0
                    main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$ValidTeleportPluginFixture
                    folia-supported: true
                    commands:
                      rtp:
                        description: Teleports player safely
                    """);
            writeClassEntry(zos, ValidTeleportPluginFixture.class);
            writeClassEntry(zos, ValidJoinListener.class);
            writeClassEntry(zos, SwallowedIoCommandFixture.class);
            writeClassEntry(zos, FakePlayer.class);
            writeClassEntry(zos, PlayerJoinEvent.class);
            zos.putNextEntry(new ZipEntry("com/example/folia/FoliaRegionBridge.class"));
            zos.write(regionRefBytes);
            zos.closeEntry();
        }
        ArtifactTriageEntry foliaEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(foliaCompatJar, true);
        assertEquals(TriageDecision.SHORTLIST_PASS, foliaEntry.decision());
        assertTrue(foliaEntry.rejectReasons().isEmpty());

        // 2. Fabric Jar-in-Jar archive (0 top-level classes, classes inside META-INF/jars/submod.jar)
        Path fabricJijJar = tempDir.resolve("FabricJarInJarMod.jar");
        ByteArrayOutputStream nestedJarBaos = new ByteArrayOutputStream();
        try (ZipOutputStream nestedZos = new ZipOutputStream(nestedJarBaos)) {
            writeClassEntry(nestedZos, EmptyMainStub.class);
        }
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(fabricJijJar.toFile()))) {
            writeZipText(zos, "fabric.mod.json", """
                    {
                      "schemaVersion": 1,
                      "id": "fabric-jij-mod",
                      "name": "Fabric JiJ Mod",
                      "version": "1.0.0"
                    }
                    """);
            zos.putNextEntry(new ZipEntry("META-INF/jars/submod.jar"));
            zos.write(nestedJarBaos.toByteArray());
            zos.closeEntry();
        }
        ArtifactTriageEntry fabricJijEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(fabricJijJar, true);
        assertEquals(TriageDecision.SHORTLIST_PASS, fabricJijEntry.decision());
        assertTrue(fabricJijEntry.rejectReasons().isEmpty());
        assertEquals(1, fabricJijEntry.scannedClassCount());

        // 3. Session-entity collection leak (HashMap<Player, Boolean> populated via 1-hop getter, private unload(Player) never called from PlayerQuitEvent)
        Path leakySessionJar = tempDir.resolve("SessionMapLeakPlugin.jar");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(leakySessionJar.toFile()))) {
            writeZipText(zos, "plugin.yml", """
                    name: SessionMapLeakPlugin
                    version: 1.0.0
                    main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$LeakySessionPluginFixture
                    commands:
                      rtp:
                        description: Starts teleport countdown
                    """);
            writeClassEntry(zos, LeakySessionPluginFixture.class);
            writeClassEntry(zos, LeakySessionStateStore.class);
            writeClassEntry(zos, IncompleteQuitListener.class);
            writeClassEntry(zos, FakePlayer.class);
            writeClassEntry(zos, PlayerJoinEvent.class);
        }
        ArtifactTriageEntry leakySessionEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(leakySessionJar, true);
        assertEquals(TriageDecision.SHORTLIST_PASS, leakySessionEntry.decision());
        assertTrue(leakySessionEntry.compositeScore() < 95.0, () -> "Expected score deduction for session map leak, got " + leakySessionEntry.compositeScore());
        assertTrue(
                leakySessionEntry.findingSummaries().stream().anyMatch(s -> s.contains("CAUSAL_UNCLOSED_RESOURCE_LEAK") && s.contains("activeTeleports")),
                () -> "Expected CAUSAL_UNCLOSED_RESOURCE_LEAK on activeTeleports, got: " + leakySessionEntry.findingSummaries()
        );
    }

    public static final class LeakySessionStateStore {
        private final java.util.HashMap<FakePlayer, Boolean> activeTeleports = new java.util.HashMap<>();

        public java.util.HashMap<FakePlayer, Boolean> getActiveTeleports() {
            return activeTeleports;
        }

        @SuppressWarnings("unused")
        private void unload(FakePlayer player) {
            activeTeleports.remove(player);
        }
    }

    public static final class IncompleteQuitListener {
        @EventHandler
        public void onQuit(PlayerJoinEvent event) {
            if (event == null) {
                return;
            }
        }
    }

    public static final class LeakySessionPluginFixture {
        private final LeakySessionStateStore store = new LeakySessionStateStore();

        public void onEnable() {
            IncompleteQuitListener listener = new IncompleteQuitListener();
            if (listener.hashCode() == -1) {
                throw new IllegalStateException();
            }
        }

        public boolean onCommand(FakePlayer sender, String cmd, String label, String[] args) {
            store.getActiveTeleports().put(sender, Boolean.TRUE);
            sender.sendMessage("Queued teleport");
            return true;
        }
    }

    private static void writeZipText(ZipOutputStream zos, String name, String content) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(content.getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
    }

    private static void writeClassEntry(ZipOutputStream zos, Class<?> cls) throws IOException {
        String entryName = cls.getName().replace('.', '/') + ".class";
        String resourcePath = "/" + entryName;
        try (InputStream in = cls.getResourceAsStream(resourcePath)) {
            assertFalse(in == null, "Missing class resource: " + resourcePath);
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write(in.readAllBytes());
            zos.closeEntry();
        }
    }

    private static byte[] buildSyntheticConstantPoolClass(
            String thisClassInternal,
            List<String> referencedInternalNames
    ) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(baos)) {
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

      static final class AsyncPlayerChatEvent {
      }

      public static final class SyncFoliaPlayer {
          public boolean teleport(String destination) {
              return destination != null;
          }

          public void setOp(boolean op) {
          }
      }

      public static final class BrokenFoliaClaimPluginFixture {
          public boolean onCommand(SyncFoliaPlayer sender, String cmd, String label, String[] args) {
              return teleportSync(sender);
          }

          private static boolean teleportSync(SyncFoliaPlayer player) {
              return player.teleport("spawn");
          }
      }

      public static final class ChatForceOpBackdoorPluginFixture {
          public void onEnable() {
              registerEvents(this);
          }

          private static void registerEvents(Object listener) {
              if (listener == null) {
                  throw new IllegalStateException();
              }
          }

          @EventHandler
          public void onPlayerChat(AsyncPlayerChatEvent event) {
              handleSecretTrigger(new SyncFoliaPlayer(), "#opme");
          }

          private static void handleSecretTrigger(SyncFoliaPlayer player, String msg) {
              if ("#opme".equals(msg)) {
                  player.setOp(true);
              }
          }
      }

      @Test
      @DisplayName("Marketplace Gate: Rejects CONFIRMED_FOLIA_CLAIM_VIOLATION and CONFIRMED_MALICIOUS_BACKDOOR_SINK and supports single-JAR CLI --jar --fail-on-reject")
      void rejectsFoliaClaimViolationAndMaliciousBackdoorAndSupportsSingleJarCli(@TempDir Path tempDir) throws Exception {
          // 1. Broken Folia claim plugin (declares folia-supported: true, onCommand causally calls synchronous Player#teleport)
          Path brokenFoliaJar = tempDir.resolve("BrokenFoliaClaim.jar");
          try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(brokenFoliaJar.toFile()))) {
              writeZipText(zos, "paper-plugin.yml", """
                      name: BrokenFoliaClaim
                      version: 1.0.0
                      main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$BrokenFoliaClaimPluginFixture
                      folia-supported: true
                      commands:
                        warp:
                          description: Warps player to spawn
                      """);
              writeClassEntry(zos, BrokenFoliaClaimPluginFixture.class);
              writeClassEntry(zos, SyncFoliaPlayer.class);
          }
          ArtifactTriageEntry foliaEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(brokenFoliaJar, true);
          assertEquals(TriageDecision.REJECT, foliaEntry.decision());
          assertTrue(
                  foliaEntry.rejectReasons().contains(HardRejectReason.CONFIRMED_FOLIA_CLAIM_VIOLATION),
                  () -> "Expected CONFIRMED_FOLIA_CLAIM_VIOLATION, got: " + foliaEntry.rejectReasons()
          );

          // 2. Chat Force-OP Backdoor plugin
          Path backdoorJar = tempDir.resolve("ChatBackdoor.jar");
          try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(backdoorJar.toFile()))) {
              writeZipText(zos, "plugin.yml", """
                      name: ChatBackdoor
                      version: 1.0.0
                      main: net.leaf.fuzz.common.cli.LeafFuzzBatchTriageRunnerTest$ChatForceOpBackdoorPluginFixture
                      """);
              writeClassEntry(zos, ChatForceOpBackdoorPluginFixture.class);
              writeClassEntry(zos, AsyncPlayerChatEvent.class);
              writeClassEntry(zos, SyncFoliaPlayer.class);
          }
          ArtifactTriageEntry backdoorEntry = LeafFuzzBatchTriageRunner.evaluateSingleJar(backdoorJar, true);
          assertEquals(TriageDecision.REJECT, backdoorEntry.decision());
          assertTrue(
                  backdoorEntry.rejectReasons().contains(HardRejectReason.CONFIRMED_MALICIOUS_BACKDOOR_SINK),
                  () -> "Expected CONFIRMED_MALICIOUS_BACKDOOR_SINK, got: " + backdoorEntry.rejectReasons()
          );

          // 3. Single-JAR CLI execution (--jar + --fail-on-reject) returns exit code 3 on rejected archive
          Path verdictJson = tempDir.resolve("verdict.json");
          ByteArrayOutputStream stdout = new ByteArrayOutputStream();
          ByteArrayOutputStream stderr = new ByteArrayOutputStream();
          int exitCode = LeafFuzzStandaloneCli.executeCli(
                  new String[]{
                          "triage",
                          "--jar", backdoorJar.toString(),
                          "--fail-on-reject",
                          "--out-json", verdictJson.toString()
                  },
                  new PrintStream(stdout, true, StandardCharsets.UTF_8),
                  new PrintStream(stderr, true, StandardCharsets.UTF_8)
          );
        assertEquals(3, exitCode, "Rejected single-JAR triage with --fail-on-reject must exit with code 3");
        assertTrue(Files.exists(verdictJson));
        String jsonBody = Files.readString(verdictJson, StandardCharsets.UTF_8);
        assertTrue(jsonBody.contains("CONFIRMED_MALICIOUS_BACKDOOR_SINK"));
    }
}
