package net.leaf.fuzz.common;

import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalFinding;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.bytecode.BytecodeCausalGraphScanner.FindingKind;
import io.github.dailystruggle.bytecode.LlmCausalChainAuditor;
import io.github.dailystruggle.bytecode.LlmConfigDocSynthesizer.HttpTransport;
import io.github.dailystruggle.bytecode.LlmConfigDocSynthesizer.Provider;
import io.github.dailystruggle.commandsapi.common.CommandsAPI;
import io.github.dailystruggle.server.api.ServerAccessor;
import io.github.dailystruggle.server.api.TaskHandle;
import net.leaf.fuzz.common.command.LeafFuzzCommand;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.RawCommandNode;
import net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.fuzz.NodeBandit;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.BotStepRecord;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.PersonaProfile;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;
import net.leaf.sleuth.common.resource.ClassRetentionScreener;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.logging.Level;

/**
 * Cross-platform lifecycle coordinator for {@code LeafFuzz} across Paper, Spigot, Folia, Fabric,
 * and NeoForge ({@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Coordinates off-thread {@code plugins/*.jar} and {@code mods/*.jar} indexing
 * ({@link JarClassOwnershipIndex}), Brigadier/Bukkit command-surface auditing
 * ({@link CommandSurfaceAuditor}), UCB1 boundary &amp; lifecycle fuzzing
 * ({@link SleuthServerFuzzer}), main-thread stall and exception attribution
 * ({@link LogAndStallSignatureOracle}), and post-GC class retention screening
 * ({@link ClassRetentionScreener}).
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
public final class LeafFuzzRuntime implements AutoCloseable {

    /** Sentinel value for {@code players=auto} / {@code players=ramp} capacity discovery. */
    public static final int AUTO_RAMP_PLAYERS = -1;

    private static final List<String> SELF_ARCHIVE_PREFIXES = List.of(
            "leaffuzz",
            "leafsleuth",
            "stresstestrtp"
    );

    private final ServerAccessor accessor;
    private final List<AutoCloseable> subscriptions = new ArrayList<>();
    private final ClassRetentionScreener retentionScreener = new ClassRetentionScreener();
    private final LogAndStallSignatureOracle faultOracle = new LogAndStallSignatureOracle();
    private final LeafFuzzBitSuite bitSuite = new LeafFuzzBitSuite();
    private final AtomicBoolean checkRunning = new AtomicBoolean(false);
    private final AtomicInteger personaEpisodeCounter = new AtomicInteger(0);
    private final List<BotStepRecord> recentBotSteps = new CopyOnWriteArrayList<>();

    private volatile LeafFuzzConfig config = LeafFuzzConfig.defaults();
    private volatile List<PersonaProfile> personaCatalog = PersonaPolicyBotActor.defaultPersonaCatalog();
    private volatile JarClassOwnershipIndex ownershipIndex = JarClassOwnershipIndex.empty();
    private volatile FuzzCampaignStateStore campaignStateStore;
    private volatile Supplier<Map<String, List<RawCommandNode>>> platformCommandGraphSupplier;
    private volatile Supplier<Object> brigadierDispatcherSupplier;
    private volatile SleuthServerFuzzer.EpisodeRunner platformEpisodeRunner;
    private volatile SleuthServerFuzzer.EpisodeRunner customEpisodeRunner;
    private volatile SwarmRosterController platformSwarmController;
    private volatile LeafFuzzScorecardReport latestScorecard;
    private volatile String activeTargetFilter = "all";
    private volatile Thread mainServerThread;
    private volatile long lastTickStartNanos;
    private volatile boolean started;
    private volatile java.util.function.DoubleSupplier platformMsptSupplier;

    private final Object telemetryLock = new Object();
    private int obsBotsSpawned;
    private int obsCommandsDispatched;
    private int obsMenusOpened;
    private int obsMenuSlotsClicked;
    private int obsTeleports;
    private double obsMaxTeleportDistance;
    private int obsInfoResponses;
    private int obsUsageErrors;
    private int obsBlockSkillsExecuted;
    private int obsTargetConcurrentPlayers = 1;
    private int obsPeakConcurrentPlayers;
    private int obsLoadedChunksAtPeak;
    private int obsEntitiesAtPeak;
    private int obsMaxStablePlayers;
    private String obsInstabilityTrigger = "";
    private final List<Double> obsIdleMsptSamples = new ArrayList<>();
    private final List<Double> obsFuzzMsptSamples = new ArrayList<>();
    private final Set<String> obsCoverageTokens = new LinkedHashSet<>();
    private final Set<String> obsClickedMenuItems = new LinkedHashSet<>();
    private final Map<String, int[]> obsMenuSlotStats = new java.util.LinkedHashMap<>();
    private final Map<String, int[]> obsCommandStats = new java.util.LinkedHashMap<>();
    private final Map<String, Double> obsCommandMaxDist = new java.util.LinkedHashMap<>();
    private final Map<String, CausalGraphReport> causalGraphCache = new java.util.concurrent.ConcurrentHashMap<>();
    private volatile HttpTransport customLlmHttpTransport;
    private volatile List<SleuthServerFuzzer> activeTargetFuzzers = List.of();

    /**
     * Snapshot of concurrent swarm population, loaded chunks, and tracked entities.
     */
    public record SwarmSnapshot(
            int onlinePlayers,
            int loadedChunks,
            int trackedEntities,
            int backgroundActionsExecuted,
            int churnedDepartures
    ) {
    }

    /**
     * Platform-specific or virtual concurrent player roster controller maintaining {@code N}
     * simultaneous online bots dispersed across an Archimedean spiral ({@code S-002}, {@code S-005}).
     */
    public interface SwarmRosterController extends AutoCloseable {
        SwarmSnapshot rampToPopulation(int targetPlayers);

        SwarmSnapshot stepConcurrentSwarm(int churnCount);

        SwarmSnapshot captureSnapshot();

        void teardownAll();

        @Override
        default void close() {
            teardownAll();
        }
    }

    public LeafFuzzRuntime(ServerAccessor accessor) {
        this.accessor = Objects.requireNonNull(accessor, "accessor");
    }

    /**
     * Loads {@code config.yml}, {@code messages.yml}, and optional {@code personas.jsonl}
     * ({@code sleuth_persona_v1}) and initializes the campaign state store.
     */
    public void load() {
        Path root = accessor.getRootFolder();
        this.config = LeafFuzzConfig.load(root);
        this.faultOracle.setSlowTickThresholdMs(this.config.slowTickThresholdMs());
        this.campaignStateStore = FuzzCampaignStateStore.forDataFolder(root);
        if (root != null) {
            this.personaCatalog = PersonaPolicyBotActor.loadPersonasOrDefault(root.resolve("personas.jsonl"));
        }
    }

    /**
     * Registers a custom catalog of {@link PersonaProfile} profiles for synthetic
     * bot episodes.
     *
     * @param personas non-empty list of persona profiles (or {@code null} to restore defaults)
     */
    public void setPersonaCatalog(List<PersonaProfile> personas) {
        this.personaCatalog = (personas == null || personas.isEmpty())
                ? PersonaPolicyBotActor.defaultPersonaCatalog()
                : List.copyOf(personas);
    }

    /**
     * Returns the active catalog of {@link PersonaProfile} profiles driving synthetic
     * bot episodes.
     *
     * @return immutable list of persona profiles
     */
    public List<PersonaProfile> personaCatalog() {
        return personaCatalog;
    }

    /**
     * Returns the most recent synthetic persona bot step records captured during live episodes.
     *
     * @return immutable list of recent bot step records
     */
    public List<BotStepRecord> recentBotSteps() {
        return Collections.unmodifiableList(new ArrayList<>(recentBotSteps));
    }

    /**
     * Spawns a new in-JVM {@link PersonaPolicyBotActor} for the next episode using the active
     * {@link #personaCatalog()} and specified permission tier ({@code "default"} or {@code "op"}).
     *
     * @param permissionTier {@code "default"} or {@code "op"}
     * @return initialized {@link PersonaPolicyBotActor}
     */
    public PersonaPolicyBotActor spawnPersonaBotActor(String permissionTier) {
        int epIdx = personaEpisodeCounter.getAndIncrement();
        PersonaProfile persona = PersonaPolicyBotActor.selectPersonaForEpisode(this.personaCatalog, epIdx);
        PersonaPolicyBotActor bot = new PersonaPolicyBotActor(persona, permissionTier, 1337 + epIdx * 31);
        NmsEmbeddedPlayerSession.assignSpiralAnchor(bot, epIdx);
        return bot;
    }

    /**
     * Registers a platform-specific concurrent player swarm roster controller.
     *
     * @param controller swarm roster controller
     */
    public void setPlatformSwarmController(SwarmRosterController controller) {
        this.platformSwarmController = controller;
    }

    public SwarmRosterController platformSwarmController() {
        return platformSwarmController;
    }

    /**
     * Registers a platform-specific raw command graph supplier (for example,
     * {@code PaperCommandTreeInspector} on Bukkit/Paper/Folia).
     *
     * @param supplier supplier returning {@code "default"} and {@code "op"} command trees
     */
    public void setPlatformCommandGraphSupplier(Supplier<Map<String, List<RawCommandNode>>> supplier) {
        this.platformCommandGraphSupplier = supplier;
    }

    /**
     * Registers a live Brigadier {@code CommandDispatcher} supplier (used on Fabric and NeoForge).
     *
     * @param dispatcherSupplier supplier returning the active {@code CommandDispatcher}
     */
    public void setBrigadierDispatcherSupplier(Supplier<Object> dispatcherSupplier) {
        this.brigadierDispatcherSupplier = dispatcherSupplier;
    }

    /**
     * Registers a platform-specific live episode runner that dispatches commands with
     * synthetic player sessions and fires platform lifecycle events.
     *
     * @param platformEpisodeRunner platform episode runner
     */
    public void setPlatformEpisodeRunner(SleuthServerFuzzer.EpisodeRunner platformEpisodeRunner) {
        this.platformEpisodeRunner = platformEpisodeRunner;
    }

    /**
     * Overrides the episode execution harness (used for deterministic unit testing).
     *
     * @param customEpisodeRunner episode runner override
     */
    public void setCustomEpisodeRunner(SleuthServerFuzzer.EpisodeRunner customEpisodeRunner) {
        this.customEpisodeRunner = customEpisodeRunner;
    }

    /**
     * Starts event hooks, off-thread JAR ownership indexing, root-logger fault tapping, and
     * {@code /fuzz} (aliases {@code /leaffuzz}, {@code /qc}) command registration.
     */
    public void start() {
        if (this.campaignStateStore == null) {
            load();
        }
        if (started) {
            return;
        }
        started = true;

        this.faultOracle.startRootLoggerTap();
        refreshJarOwnershipIndexAsync();

        subscriptions.add(
                accessor.getPlayerLifecycleHook()
                        .onPlayerQuit(playerId -> retentionScreener.recordPlayerDeparture())
        );

        LeafFuzzCommand fuzzCmd = new LeafFuzzCommand("fuzz", accessor, this);
        accessor.registerCommands(fuzzCmd, "leaffuzz", "qc");

        LeafFuzzCommand leafFuzzAlias = new LeafFuzzCommand("leaffuzz", accessor, this);
        accessor.registerCommands(leafFuzzAlias);

        LeafFuzzCommand qcAlias = new LeafFuzzCommand("qc", accessor, this);
        accessor.registerCommands(qcAlias);

        Runnable tickTask = this::onServerTick;
        accessor.scheduler().ifPresentOrElse(
                s -> {
                    TaskHandle handle = s.runSyncTimer(tickTask, 1L, 1L);
                    if (handle != null) {
                        subscriptions.add(handle::cancel);
                    }
                },
                () -> accessor.scheduleRepeatingTask(tickTask, 1L, 1L)
        );
    }

    private void onServerTick() {
        if (!started) {
            return;
        }
        CommandsAPI.execute();
        this.mainServerThread = Thread.currentThread();
        this.lastTickStartNanos = System.nanoTime();
    }

    public void setPlatformMsptSupplier(java.util.function.DoubleSupplier platformMsptSupplier) {
        this.platformMsptSupplier = platformMsptSupplier;
    }

    public double currentServerMspt() {
        java.util.function.DoubleSupplier sup = this.platformMsptSupplier;
        if (sup != null) {
            try {
                double v = sup.getAsDouble();
                if (Double.isFinite(v) && v >= 0.0) {
                    return v;
                }
            } catch (Throwable ex) {
                accessor.log(Level.FINEST, "[LeafFuzz] Platform MSPT supplier fallback: " + ex.getMessage(), ex);
            }
        }
        long tickStart = this.lastTickStartNanos;
        if (tickStart > 0L) {
            double elapsed = (System.nanoTime() - tickStart) / 1_000_000.0;
            if (elapsed >= 0.0 && elapsed <= 10_000.0) {
                return Math.min(50.0, elapsed);
            }
        }
        return 0.0;
    }

    /**
     * Resets the current tick start timestamp so harness player-spawn setup time
     * ({@code PlayerList#placeNewPlayer}) is not charged against the target plugin's tick budget.
     */
    public void resetTickStartNanos() {
        this.lastTickStartNanos = System.nanoTime();
    }

    /**
     * Samples the live main server thread stack from an off-tick thread when the current tick
     * has exceeded {@link LogAndStallSignatureOracle#slowTickThresholdMs()} outside GC pauses,
     * and records active fuzz MSPT telemetry.
     */
    public void sampleMainThreadIfStalled() {
        sampleEpisodeCoverageAndStalls(null);
    }

    /**
     * Samples the live main server thread and active worker threads for zero-instrumentation
     * grey-box coverage tokens ({@code cov:<Jar>:<Class.method:lineBucket>}), evaluates sub-100ms
     * main-thread synchronous hazards ({@code sync-chunk}, {@code sync-io}, {@code blocking-wait}),
     * and records slow-tick stalls ({@code > slowTickThresholdMs}) outside GC pauses.
     *
     * @param episodeCoverageOut optional collection receiving newly observed coverage tokens for the current episode
     */
    public void sampleEpisodeCoverageAndStalls(java.util.Collection<String> episodeCoverageOut) {
        Thread main = this.mainServerThread;
        long tickStart = this.lastTickStartNanos;
        long now = System.nanoTime();
        if (retentionScreener.inGcPauseWindow(now)) {
            return;
        }
        if (episodeCoverageOut != null) {
            Set<String> covTokens = faultOracle.sampleActiveThreadCoverage(main);
            if (!covTokens.isEmpty()) {
                episodeCoverageOut.addAll(covTokens);
                synchronized (telemetryLock) {
                    if (obsCoverageTokens.size() < 4096) {
                        obsCoverageTokens.addAll(covTokens);
                    }
                }
            }
        }
        if (main == null || tickStart <= 0L || Thread.currentThread() == main) {
            return;
        }
        double elapsedMs = (now - tickStart) / 1_000_000.0;
        double reportedMspt = currentServerMspt();
        StackTraceElement[] stack = main.getStackTrace();
        if (isIdleOrHarnessStack(stack)) {
            this.lastTickStartNanos = now;
            if (reportedMspt > 0.0) {
                synchronized (telemetryLock) {
                    if (obsFuzzMsptSamples.size() < 4096) {
                        obsFuzzMsptSamples.add(reportedMspt);
                    }
                }
            }
            return;
        }
        double sampleVal = reportedMspt > 0.0
                ? (elapsedMs > faultOracle.slowTickThresholdMs() ? Math.min(elapsedMs, 250.0) : reportedMspt)
                : (elapsedMs <= 5000.0 ? Math.min(elapsedMs, 250.0) : 0.0);
        if (sampleVal > 0.0) {
            synchronized (telemetryLock) {
                if (obsFuzzMsptSamples.size() < 4096) {
                    obsFuzzMsptSamples.add(sampleVal);
                }
            }
        }
        if (elapsedMs < 5.0) {
            return;
        }
        if (episodeCoverageOut != null) {
            Set<String> mainCov = faultOracle.extractTargetCoverageTokens(stack);
            if (!mainCov.isEmpty()) {
                episodeCoverageOut.addAll(mainCov);
                synchronized (telemetryLock) {
                    if (obsCoverageTokens.size() < 4096) {
                        obsCoverageTokens.addAll(mainCov);
                    }
                }
            }
        }
        faultOracle.recordMainThreadHazardStack(elapsedMs, stack, now);
        if (elapsedMs > faultOracle.slowTickThresholdMs()) {
            faultOracle.recordSlowTickStack(elapsedMs, stack, now);
        }
    }

    /**
     * Records execution of a reversible world block/interact micro-skill during an episode.
     */
    public void recordBlockSkillExecution() {
        synchronized (telemetryLock) {
            this.obsBlockSkillsExecuted++;
        }
    }

    /**
     * Records observed activity and causal outcomes from a single episode execution.
     */
    public void recordEpisodeObservation(
            String commandLine,
            int botsSpawned,
            int commandsDispatched,
            int menusOpened,
            int menuSlotsClicked,
            List<String> clickedItems,
            int teleportsConfirmed,
            double maxTeleportDistanceBlocks,
            int infoResponses,
            boolean usageError
    ) {
        String cmdKey = (commandLine == null || commandLine.isBlank()) ? "/unknown" : commandLine.trim();
        if (!cmdKey.startsWith("/")) {
            cmdKey = "/" + cmdKey;
        }
        synchronized (telemetryLock) {
            this.obsBotsSpawned += Math.max(0, botsSpawned);
            this.obsCommandsDispatched += Math.max(0, commandsDispatched);
            this.obsMenusOpened += Math.max(0, menusOpened);
            this.obsMenuSlotsClicked += Math.max(0, menuSlotsClicked);
            this.obsTeleports += Math.max(0, teleportsConfirmed);
            if (maxTeleportDistanceBlocks > this.obsMaxTeleportDistance) {
                this.obsMaxTeleportDistance = maxTeleportDistanceBlocks;
            }
            this.obsInfoResponses += Math.max(0, infoResponses);
            if (usageError) {
                this.obsUsageErrors++;
            }
            if (clickedItems != null) {
                for (String item : clickedItems) {
                    if (item != null && !item.isBlank()) {
                        String key = item.trim();
                        if (this.obsClickedMenuItems.size() < 32) {
                            this.obsClickedMenuItems.add(key);
                        }
                        int[] mSt = this.obsMenuSlotStats.computeIfAbsent(key, k -> new int[4]);
                        mSt[0]++; // clicks
                        if (teleportsConfirmed > 0) {
                            mSt[1]++;
                        }
                        if (infoResponses > 0) {
                            mSt[2]++;
                        }
                        if (teleportsConfirmed <= 0 && infoResponses <= 0) {
                            mSt[3]++;
                        }
                    }
                }
            }
            int[] stats = this.obsCommandStats.computeIfAbsent(cmdKey, k -> new int[6]);
            stats[0]++; // episodes
            stats[1] += Math.max(0, menusOpened);
            stats[2] += Math.max(0, menuSlotsClicked);
            stats[3] += Math.max(0, teleportsConfirmed);
            stats[4] += Math.max(0, infoResponses);
            if (usageError) {
                stats[5]++;
            }
            double prevDist = this.obsCommandMaxDist.getOrDefault(cmdKey, 0.0);
            if (maxTeleportDistanceBlocks > prevDist) {
                this.obsCommandMaxDist.put(cmdKey, maxTeleportDistanceBlocks);
            }
        }
    }

    /**
     * Records a live concurrent player swarm census snapshot during a QC pass.
     *
     * @param onlinePlayers   simultaneous online bots/players
     * @param loadedChunks    loaded chunks across server worlds
     * @param trackedEntities tracked entities across server worlds
     */
    public void recordSwarmTelemetry(int onlinePlayers, int loadedChunks, int trackedEntities) {
        synchronized (telemetryLock) {
            if (onlinePlayers > this.obsPeakConcurrentPlayers) {
                this.obsPeakConcurrentPlayers = onlinePlayers;
            }
            if (loadedChunks > this.obsLoadedChunksAtPeak) {
                this.obsLoadedChunksAtPeak = loadedChunks;
            }
            if (trackedEntities > this.obsEntitiesAtPeak) {
                this.obsEntitiesAtPeak = trackedEntities;
            }
        }
    }

    private void resetRunTelemetry() {
        resetRunTelemetry(1);
    }

    private void resetRunTelemetry(int targetConcurrentPlayers) {
        synchronized (telemetryLock) {
            this.obsBotsSpawned = 0;
            this.obsCommandsDispatched = 0;
            this.obsMenusOpened = 0;
            this.obsMenuSlotsClicked = 0;
            this.obsTeleports = 0;
            this.obsMaxTeleportDistance = 0.0;
            this.obsInfoResponses = 0;
            this.obsUsageErrors = 0;
            this.obsBlockSkillsExecuted = 0;
            this.obsTargetConcurrentPlayers = Math.max(1, Math.min(500, targetConcurrentPlayers));
            this.obsPeakConcurrentPlayers = 0;
            this.obsLoadedChunksAtPeak = 0;
            this.obsEntitiesAtPeak = 0;
            this.obsMaxStablePlayers = 0;
            this.obsInstabilityTrigger = "";
            this.obsIdleMsptSamples.clear();
            this.obsFuzzMsptSamples.clear();
            this.obsCoverageTokens.clear();
            this.obsClickedMenuItems.clear();
            this.obsMenuSlotStats.clear();
            this.obsCommandStats.clear();
            this.obsCommandMaxDist.clear();
        }
    }

    private void sampleIdleWindowWithTelemetry(long durationMs) {
        long deadline = System.currentTimeMillis() + Math.max(50L, durationMs);
        while (System.currentTimeMillis() < deadline) {
            double mspt = currentServerMspt();
            if (mspt > 0.0) {
                synchronized (telemetryLock) {
                    obsIdleMsptSamples.add(mspt);
                }
            }
            try {
                Thread.sleep(50L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private LeafFuzzScorecardReport.ExecutionTelemetry buildExecutionTelemetry(String targetFilter) {
        List<ClassRetentionScreener.HistogramCheckpoint> cps = retentionScreener.checkpoints();
        double baselineHeapMb = 0.0;
        double finalHeapMb = 0.0;
        int totalClasses = 0;
        long totalInstances = 0L;
        List<String> topTargetDeltas = new ArrayList<>();

        if (!cps.isEmpty()) {
            ClassRetentionScreener.HistogramCheckpoint first = cps.get(0);
            ClassRetentionScreener.HistogramCheckpoint last = cps.get(cps.size() - 1);
            baselineHeapMb = Math.max(0.0, first.oldGenAfterGcMb());
            finalHeapMb = Math.max(0.0, last.oldGenAfterGcMb());
            totalClasses = last.classCounts().size();
            for (io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.ClassCount cc : last.classCounts()) {
                totalInstances += cc.instances();
            }
            Map<String, Long> firstMap = new java.util.HashMap<>();
            for (io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.ClassCount cc : first.classCounts()) {
                firstMap.put(cc.name(), cc.instances());
            }
            List<Map.Entry<String, long[]>> targetClassRows = new ArrayList<>();
            for (io.github.dailystruggle.helpers.stresstestrtp.LeakProbe.ClassCount cc : last.classCounts()) {
                String cls = cc.name();
                if (cls == null || cls.contains("$$Lambda") || LogAndStallSignatureOracle.isPlatformOrJdkClass(cls)) {
                    continue;
                }
                java.util.Optional<String> ownerOpt = ownershipIndex.ownerJarForClass(cls);
                String owner = ownerOpt.orElse("");
                if (BrigadierDispatcherInspector.matchesTargetIdentifier(owner, cls, targetFilter, ownershipIndex)) {
                    long i0 = firstMap.getOrDefault(cls, 0L);
                    long i1 = cc.instances();
                    targetClassRows.add(Map.entry(cls, new long[]{i0, i1, i1 - i0}));
                }
            }
            targetClassRows.sort((a, b) -> {
                int c = Long.compare(Math.abs(b.getValue()[2]), Math.abs(a.getValue()[2]));
                if (c != 0) return c;
                return Long.compare(b.getValue()[1], a.getValue()[1]);
            });
            for (int i = 0; i < Math.min(4, targetClassRows.size()); i++) {
                Map.Entry<String, long[]> row = targetClassRows.get(i);
                String fullCls = row.getKey();
                int dot = fullCls.lastIndexOf('.');
                String shortCls = dot >= 0 ? fullCls.substring(dot + 1) : fullCls;
                long[] vals = row.getValue();
                topTargetDeltas.add(String.format(
                        Locale.ROOT,
                        "%s: %d -> %d inst (%+d)",
                        shortCls,
                        vals[0],
                        vals[1],
                        vals[2]
                ));
            }
        }

        synchronized (telemetryLock) {
            double idleMean = computeMean(obsIdleMsptSamples);
            double idleP95 = computePercentile(obsIdleMsptSamples, 0.95);
            double fuzzMean = computeMean(obsFuzzMsptSamples);
            double fuzzP95 = computePercentile(obsFuzzMsptSamples, 0.95);
            double fuzzMax = computePercentile(obsFuzzMsptSamples, 1.0);
            if (fuzzMean <= 0.0 && idleMean > 0.0) {
                fuzzMean = idleMean;
                fuzzP95 = idleP95;
                fuzzMax = idleP95;
            }
            List<String> rankedMenuItems = new ArrayList<>();
            if (!obsMenuSlotStats.isEmpty()) {
                List<Map.Entry<String, int[]>> slotEntries = new ArrayList<>(obsMenuSlotStats.entrySet());
                slotEntries.sort((a, b) -> {
                    int[] sa = a.getValue();
                    int[] sb = b.getValue();
                    int c = Integer.compare(sb[0], sa[0]);
                    if (c != 0) return c;
                    return Integer.compare(sb[1] * 3 + sb[2], sa[1] * 3 + sa[2]);
                });
                for (Map.Entry<String, int[]> se : slotEntries) {
                    int[] st = se.getValue();
                    List<String> outcomeParts = new ArrayList<>();
                    outcomeParts.add(st[0] + " clk");
                    if (st[1] > 0) {
                        outcomeParts.add(st[1] + " tp");
                    }
                    if (st[2] > 0) {
                        outcomeParts.add(st[2] + " info");
                    }
                    if (st[1] == 0 && st[2] == 0) {
                        outcomeParts.add("0 eff/pruned");
                    }
                    rankedMenuItems.add(se.getKey() + " [" + String.join(", ", outcomeParts) + "]");
                }
            } else {
                rankedMenuItems.addAll(obsClickedMenuItems);
            }

            List<Map.Entry<String, int[]>> cmdEntries = new ArrayList<>(obsCommandStats.entrySet());
            cmdEntries.sort((a, b) -> {
                int[] sa = a.getValue();
                int[] sb = b.getValue();
                int scoreA = sa[3] * 4 + sa[2] * 2 + sa[4] + sa[0];
                int scoreB = sb[3] * 4 + sb[2] * 2 + sb[4] + sb[0];
                int c = Integer.compare(scoreB, scoreA);
                if (c != 0) return c;
                return Integer.compare(sb[0], sa[0]);
            });
            List<String> cmdSummaries = new ArrayList<>();
            if (!obsCoverageTokens.isEmpty() || obsBlockSkillsExecuted > 0) {
                cmdSummaries.add(String.format(
                        Locale.ROOT,
                        "Coverage Guidance: %d code-path buckets, %d world block/interact probes",
                        obsCoverageTokens.size(),
                        obsBlockSkillsExecuted
                ));
            }
            for (Map.Entry<String, int[]> e : cmdEntries) {
                int[] st = e.getValue();
                double maxDist = obsCommandMaxDist.getOrDefault(e.getKey(), 0.0);
                StringBuilder sb = new StringBuilder();
                sb.append(e.getKey()).append(": ").append(st[0]).append("ep (");
                List<String> parts = new ArrayList<>();
                if (st[1] > 0 || st[2] > 0) {
                    parts.add(st[1] + " menu/" + st[2] + " click");
                }
                if (st[3] > 0) {
                    parts.add(String.format(Locale.ROOT, "%d tp [max %.0fb]", st[3], maxDist));
                }
                if (st[4] > 0) {
                    parts.add(st[4] + " msg");
                }
                if (st[5] > 0) {
                    parts.add(st[5] + " usage_err");
                }
                if (parts.isEmpty()) {
                    parts.add("0 effects");
                }
                sb.append(String.join(", ", parts)).append(')');
                cmdSummaries.add(sb.toString());
            }
            for (SleuthServerFuzzer tf : this.activeTargetFuzzers) {
                List<NodeBandit.BanditArmStats> topArms = tf.bandit().topLearnedArms(3);
                for (NodeBandit.BanditArmStats arm : topArms) {
                    if (arm.pulls() >= 2 && arm.meanReward() > 0.5) {
                        cmdSummaries.add(String.format(
                                Locale.ROOT,
                                "UCB1[/%s + %s]: %d pulls (Q=%.2f, nov=%d)",
                                arm.nodeId(),
                                arm.followUpShape(),
                                arm.pulls(),
                                arm.meanReward(),
                                arm.noveltyHits()
                        ));
                    }
                }
            }
            int effPeakPlayers = Math.max(obsPeakConcurrentPlayers, obsBotsSpawned > 0 ? 1 : 0);
            int effStablePlayers = obsMaxStablePlayers > 0
                    ? obsMaxStablePlayers
                    : (obsInstabilityTrigger.isEmpty() && fuzzP95 <= 55.0 ? effPeakPlayers : 0);
            if (obsTargetConcurrentPlayers > 1 || obsPeakConcurrentPlayers > 1) {
                String breakSuffix = obsInstabilityTrigger.isEmpty()
                        ? "stable through ceiling"
                        : "unstable -> " + obsInstabilityTrigger;
                cmdSummaries.add(0, String.format(
                        Locale.ROOT,
                        "Concurrent Roster Survival: %d/%d peak online, maxStable=%d (%d chunks, %d entities; %s)",
                        effPeakPlayers,
                        obsTargetConcurrentPlayers,
                        effStablePlayers,
                        obsLoadedChunksAtPeak,
                        obsEntitiesAtPeak,
                        breakSuffix
                ));
            }
            return new LeafFuzzScorecardReport.ExecutionTelemetry(
                    obsBotsSpawned,
                    obsCommandsDispatched,
                    obsMenusOpened,
                    obsMenuSlotsClicked,
                    obsTeleports,
                    obsMaxTeleportDistance,
                    obsInfoResponses,
                    obsUsageErrors,
                    idleMean,
                    idleP95,
                    fuzzMean,
                    fuzzP95,
                    fuzzMax,
                    obsIdleMsptSamples.size() + obsFuzzMsptSamples.size(),
                    baselineHeapMb,
                    finalHeapMb,
                    totalClasses,
                    totalInstances,
                    List.copyOf(rankedMenuItems),
                    cmdSummaries,
                    topTargetDeltas,
                    obsTargetConcurrentPlayers,
                    effPeakPlayers,
                    obsLoadedChunksAtPeak,
                    obsEntitiesAtPeak,
                    effStablePlayers,
                    obsInstabilityTrigger
            );
        }
    }

    private static double computeMean(List<Double> vals) {
        if (vals == null || vals.isEmpty()) {
            return 0.0;
        }
        double sum = 0.0;
        for (double v : vals) {
            sum += v;
        }
        return sum / vals.size();
    }

    private static double computePercentile(List<Double> vals, double q) {
        if (vals == null || vals.isEmpty()) {
            return 0.0;
        }
        List<Double> sorted = new ArrayList<>(vals);
        Collections.sort(sorted);
        if (sorted.size() == 1) {
            return sorted.get(0);
        }
        double pos = Math.max(0.0, Math.min(1.0, q)) * (sorted.size() - 1);
        int lo = (int) Math.floor(pos);
        int hi = (int) Math.ceil(pos);
        if (lo == hi) {
            return sorted.get(lo);
        }
        double frac = pos - lo;
        return sorted.get(lo) * (1.0 - frac) + sorted.get(hi) * frac;
    }

    private static boolean isIdleOrHarnessStack(StackTraceElement[] stack) {
        if (stack == null || stack.length == 0) {
            return true;
        }
        for (int i = 0; i < Math.min(32, stack.length); i++) {
            StackTraceElement el = stack[i];
            if (el == null) {
                continue;
            }
            String cls = el.getClassName();
            String method = el.getMethodName();
            if (i < 8 && (method.contains("waitUntilNextTick")
                    || method.contains("parkNanos")
                    || method.equals("park")
                    || method.contains("waitForTasks")
                    || (cls.equals("java.lang.Thread") && method.equals("sleep")))) {
                return true;
            }
            if (cls.contains("LiveServerPlayerSession")
                    || cls.contains("NmsEmbeddedPlayerSession")
                    || cls.contains("LeafFuzzBitSuite")
                    || (cls.contains("PlayerList") && (method.equals("placeNewPlayer") || method.equals("remove")))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Scans {@code plugins/*.jar} and {@code mods/*.jar} off-thread via {@link ServerAccessor#scheduler()}
     * (or synchronously if no async scheduler is present in headless tests).
     */
    public void refreshJarOwnershipIndexAsync() {
        Runnable scanTask = this::refreshJarOwnershipIndexNow;
        accessor.scheduler().ifPresentOrElse(
                s -> s.runAsync(scanTask),
                scanTask
        );
    }

    /**
     * Synchronously scans {@code plugins/*.jar} and {@code mods/*.jar} if archive directories exist.
     */
    public void refreshJarOwnershipIndexNow() {
        List<Path> dirs = resolveArchiveDirectories(accessor.getRootFolder());
        if (!dirs.isEmpty()) {
            JarClassOwnershipIndex scanned = JarClassOwnershipIndex.scanArchiveDirectories(
                    dirs,
                    SELF_ARCHIVE_PREFIXES
            );
            setOwnershipIndex(scanned);
        }
    }

    /**
     * Updates the active {@link JarClassOwnershipIndex} across the runtime, retention screener,
     * and fault signature oracle.
     *
     * @param index non-null ownership index
     */
    public void setOwnershipIndex(JarClassOwnershipIndex index) {
        JarClassOwnershipIndex nonNull = index != null ? index : JarClassOwnershipIndex.empty();
        this.ownershipIndex = nonNull;
        this.retentionScreener.setOwnershipIndex(nonNull);
        this.faultOracle.setOwnershipIndex(nonNull);
        this.causalGraphCache.clear();
    }

    /**
     * Registers or overrides a pre-scanned {@link CausalGraphReport} for a plugin/mod archive
     * (used by in-JVM BIT checks and unit tests).
     *
     * @param jarOrPluginName plugin or archive identifier
     * @param report          causal graph report
     */
    public void registerCausalGraphReport(String jarOrPluginName, CausalGraphReport report) {
        if (jarOrPluginName != null && !jarOrPluginName.isBlank() && report != null) {
            this.causalGraphCache.put(jarOrPluginName.trim(), report);
        }
    }

    /**
     * Sets a custom {@link HttpTransport} for {@link LlmCausalChainAuditor} (used for deterministic
     * testing without live network calls).
     *
     * @param transport custom HTTP transport, or {@code null} for default HTTP transport
     */
    public void setCustomLlmHttpTransport(HttpTransport transport) {
        this.customLlmHttpTransport = transport;
    }

    /**
     * Executes Stage 5 (First-Order &amp; Second-Order Bytecode &amp; Causal Audit) across matching
     * target plugin/mod archives, corroborating static {@code CAUSAL_HOLLOW_COMMAND} findings with
     * live Stage 2 execution telemetry and optionally enriching with {@link LlmCausalChainAuditor}.
     *
     * @param targetFilter plugin/mod name, comma-separated list, or {@code "all"}
     * @return immutable list of {@link CausalFinding}s
     */
    public List<CausalFinding> auditCausalDelivery(String targetFilter) {
        if (this.ownershipIndex.indexedJarCount() == 0) {
            refreshJarOwnershipIndexNow();
        }
        String effTarget = (targetFilter == null || targetFilter.isBlank()) ? "all" : targetFilter.trim();
        List<CausalGraphReport> matchedReports = resolveCausalReportsForTarget(effTarget);
        if (matchedReports.isEmpty()) {
            return List.of();
        }

        int liveCmdDispatches;
        int liveTeleports;
        int liveMenus;
        synchronized (telemetryLock) {
            liveCmdDispatches = this.obsCommandsDispatched;
            liveTeleports = this.obsTeleports;
            liveMenus = this.obsMenusOpened;
        }

        var llmHookCfg = this.config.llmAudit().toLlmHookConfig();
        LlmCausalChainAuditor llmAuditor = llmHookCfg.provider() != Provider.OFF
                ? new LlmCausalChainAuditor(llmHookCfg, this.customLlmHttpTransport)
                : null;

        List<CausalFinding> out = new ArrayList<>();
        for (CausalGraphReport report : matchedReports) {
            List<CausalFinding> baseFindings = llmAuditor != null
                    ? llmAuditor.enrichFindingsWithExplanations(report, this.config.llmAudit().maxChainsPerTarget())
                    : report.findings();
            for (CausalFinding f : baseFindings) {
                if (f.kind() == FindingKind.CAUSAL_HOLLOW_COMMAND
                        && liveCmdDispatches > 0
                        && liveTeleports == 0
                        && liveMenus == 0) {
                    out.add(f.withRuntimeCorroboration(liveCmdDispatches, liveTeleports, liveMenus));
                } else {
                    out.add(f);
                }
            }
            if (llmAuditor != null && !"all".equalsIgnoreCase(effTarget)) {
                out.addAll(llmAuditor.auditCausalChainsWithLlm(report, this.config.llmAudit().maxChainsPerTarget()));
            }
        }
        return List.copyOf(out);
    }

    /**
     * Executes per-slice Built-In Test ({@code PBIT} / {@code CBIT} / {@code IBIT}) harnesses across
     * all discovered {@link BytecodeCausalGraphScanner.CausalChainSlice}s for {@code targetFilter}
     * strictly in memory, restoring all temporary probe state after each slice audit.
     *
     * @param targetFilter plugin/mod name, comma-separated list, or {@code "all"}
     * @return immutable list of {@link SliceBitHarness.SliceBitReport}s
     */
    public List<SliceBitHarness.SliceBitReport> auditSliceBit(String targetFilter) {
        if (this.ownershipIndex.indexedJarCount() == 0) {
            refreshJarOwnershipIndexNow();
        }
        String effTarget = (targetFilter == null || targetFilter.isBlank()) ? "all" : targetFilter.trim();
        List<CausalGraphReport> matchedReports = resolveCausalReportsForTarget(effTarget);
        if (matchedReports.isEmpty()) {
            return List.of();
        }

        int liveCmdDispatches;
        int liveEffects;
        synchronized (telemetryLock) {
            liveCmdDispatches = this.obsCommandsDispatched;
            liveEffects = this.obsTeleports + this.obsMenusOpened;
        }
        List<FaultSignature> targetFaults = filterFaultsForTarget(
                faultOracle.rankedSignatures(),
                effTarget,
                this.ownershipIndex
        );
        List<ClassRetentionFinding> targetLeaks = filterRetentionForTarget(
                retentionScreener.checkpointCount() >= ClassRetentionScreener.MIN_CHECKPOINTS
                        ? retentionScreener.screenClassGrowth()
                        : retentionScreener.latestFindings(),
                effTarget,
                this.ownershipIndex
        );

        List<SliceBitHarness.SliceBitReport> reports = new ArrayList<>();
        for (CausalGraphReport report : matchedReports) {
            reports.addAll(SliceBitHarness.auditReportSlices(
                    report,
                    Map.of(),
                    targetFaults,
                    targetLeaks,
                    liveCmdDispatches,
                    liveEffects
            ));
        }
        return List.copyOf(reports);
    }

    /**
     * Returns all scanned {@link CausalGraphReport}s across indexed plugin/mod archives so
     * sibling workspaces (such as {@code LeafConfig}) can ingest {@code LeafFuzz}'s reverse-engineering
     * causal chains, dead-key findings, and clickable UML component models when {@code LeafFuzz} is installed.
     *
     * @return immutable list of {@link CausalGraphReport}s
     */
    public List<CausalGraphReport> currentCausalGraphReports() {
        if (this.ownershipIndex.indexedJarCount() == 0) {
            refreshJarOwnershipIndexNow();
        }
        return List.copyOf(resolveCausalReportsForTarget("all"));
    }

    /**
     * Builds the open-ended {@code LeafConfig} workspace extension bundle (`workspaceTabs` and
     * `configKeyBadges`) owned and supplied by {@code LeafFuzz}.
     *
     * @return extension bundle map ready for registration in {@code LeafConfig}
     */
    public Map<String, Object> buildLeafConfigWorkspaceExtension() {
        LeafFuzzScorecardReport sc = this.latestScorecard;
        return buildLeafConfigWorkspaceExtensionForReports(
                currentCausalGraphReports(),
                sc == null ? List.of() : List.of(sc)
        );
    }

    /**
     * Converts a collection of {@link CausalGraphReport}s into {@code LeafFuzz}'s self-contained
     * {@code LeafConfig} workspace extension bundle (`workspaceTabs` with the {@code plugin-uml}
     * tab + {@code LeafFuzzUmlTabKernel} client script, and `configKeyBadges`).
     *
     * @param reports causal graph reports scanned by {@code LeafFuzz}
     * @return extension bundle map
     */
    public static Map<String, Object> buildLeafConfigWorkspaceExtensionForReports(
            Collection<CausalGraphReport> reports
    ) {
        return buildLeafConfigWorkspaceExtensionForReports(reports, List.of());
    }

    /**
     * Converts {@link CausalGraphReport}s and optional 5-stage {@link LeafFuzzScorecardReport}s
     * into {@code LeafFuzz}'s self-contained {@code LeafConfig} workspace extension bundle.
     *
     * @param reports    causal graph reports scanned by {@code LeafFuzz}
     * @param scorecards optional live 5-stage QC scorecards
     * @return extension bundle map
     */
    public static Map<String, Object> buildLeafConfigWorkspaceExtensionForReports(
            Collection<CausalGraphReport> reports,
            Collection<LeafFuzzScorecardReport> scorecards
    ) {
        List<CausalGraphReport> safeReports = reports == null ? List.of() : reports.stream()
                .filter(Objects::nonNull)
                .toList();
        List<LeafFuzzScorecardReport> safeScorecards = scorecards == null ? List.of() : scorecards.stream()
                .filter(Objects::nonNull)
                .toList();
        List<Map<String, Object>> badgeMaps = new ArrayList<>();
        StringBuilder modelsJson = new StringBuilder("{\"models\":[");
        Set<String> seenArtifacts = new LinkedHashSet<>();
        int modelIdx = 0;
        for (CausalGraphReport report : safeReports) {
            String artId = report.artifactId() == null || report.artifactId().isBlank()
                    ? ("plugin:" + report.displayName().toLowerCase(Locale.ROOT))
                    : report.artifactId();
            if (!seenArtifacts.add(artId.toLowerCase(Locale.ROOT))) {
                continue;
            }
            if (modelIdx++ > 0) {
                modelsJson.append(',');
            }
            LeafFuzzScorecardReport matchedScorecard = matchScorecardForArtifact(
                    artId,
                    report.displayName(),
                    safeScorecards
            );
            appendPluginUmlModelJsonAndCollectBadges(report, matchedScorecard, modelsJson, badgeMaps);
        }
        modelsJson.append("]}");

        Map<String, Object> umlTab = new LinkedHashMap<>();
        umlTab.put("tabId", "plugin-uml");
        umlTab.put("title", "Plugin UML");
        umlTab.put("icon", "🔬");
        umlTab.put("description", "Clickable per-plugin component UML & bytecode causal model supplied by LeafFuzz");
        umlTab.put("initialPayloadJson", modelsJson.toString());
        umlTab.put("clientRendererFn", "LeafFuzzUmlTabKernel.render");
        umlTab.put("clientScriptKernel", leafConfigUmlTabClientKernelJs());

        Map<String, Object> bundle = new LinkedHashMap<>();
        bundle.put("providerId", "leaffuzz");
        bundle.put("displayName", "LeafFuzz");
        bundle.put("workspaceTabs", List.of(Collections.unmodifiableMap(umlTab)));
        bundle.put("configKeyBadges", Collections.unmodifiableList(badgeMaps));
        return Collections.unmodifiableMap(bundle);
    }

    private static LeafFuzzScorecardReport matchScorecardForArtifact(
            String artifactId,
            String displayName,
            List<LeafFuzzScorecardReport> scorecards
    ) {
        if (scorecards == null || scorecards.isEmpty()) {
            return null;
        }
        String stem = (artifactId == null ? "" : artifactId.toLowerCase(Locale.ROOT)).replace("plugin:", "").trim();
        String disp = displayName == null ? "" : displayName.toLowerCase(Locale.ROOT).trim();
        for (LeafFuzzScorecardReport sc : scorecards) {
            String t = sc.targetName() == null ? "" : sc.targetName().toLowerCase(Locale.ROOT).trim();
            if (t.equals(disp) || t.equals(stem) || "all".equals(t)
                    || (!disp.isEmpty() && t.contains(disp))
                    || (!stem.isEmpty() && t.contains(stem))) {
                return sc;
            }
        }
        return scorecards.size() == 1 ? scorecards.get(0) : null;
    }

    private static String formatFindingKindTitle(BytecodeCausalGraphScanner.FindingKind kind) {
        if (kind == null) {
            return "Plugin Warning";
        }
        return switch (kind) {
            case CAUSAL_UNREGISTERED_LISTENER -> "Inactive Event Listener";
            case CAUSAL_UNWIRED_COMMAND -> "Unregistered Command";
            case CAUSAL_DEAD_CONFIG_KEY -> "Unused Config Setting";
            case CAUSAL_UNREAD_CONFIG_FIELD -> "Ignored Config Field";
            case CAUSAL_ORPHANED_SUPPLIER -> "Dropped Async Result";
            case CAUSAL_SWALLOWED_FAILURE -> "Silently Ignored Error";
            case CAUSAL_ASYNC_MAIN_THREAD_SINK -> "Unsafe Off-Thread World Call";
            case CAUSAL_UNIT_MISMATCH -> "Time Unit Mismatch (s vs ms)";
            case CAUSAL_HOLLOW_COMMAND -> "Chat-Only Command (No Action)";
            case CAUSAL_SHARED_STATE_RACE -> "Concurrent State Race";
            case CAUSAL_SYNC_MAIN_THREAD_IO -> "Main-Thread Blocking I/O";
            case CAUSAL_UNCLOSED_RESOURCE_LEAK -> "Unreleased Memory / Resource";
            case CAUSAL_LLM_SEMANTIC_MISMATCH -> "Config Condition Mismatch";
        };
    }
    private static String formatProofRuleTitle(String ruleId) {
        if (ruleId == null) {
            return "Runtime Safety Warning";
        }
        return switch (ruleId.trim().toUpperCase(Locale.ROOT)) {
            case "S-001" -> "Unsafe Teleport Destination";
            case "S-002" -> "Unreleased Memory / Resource";
            case "S-003" -> "Protected Claim Bypass";
            case "S-004" -> "Silently Ignored Error";
            case "S-005" -> "Main-Thread Blocking I/O";
            case "S-006" -> "Premature Startup API Call";
            case "S-007" -> "Missing Command Failure Feedback";
            default -> "Runtime Safety Warning";
        };
    }

    private static String formatRawFindingTokenDescription(String token) {
        if (token == null || token.isBlank()) {
            return "Potential server lag or reliability issue detected in plugin execution path.";
        }
        return switch (token.trim().toUpperCase(Locale.ROOT)) {
            case "CAUSAL_SYNC_MAIN_THREAD_IO" ->
                    "Runs synchronous file, database, or chunk I/O on the main server thread (can cause tick lag spikes).";
            case "CAUSAL_ASYNC_MAIN_THREAD_SINK" ->
                    "Calls main-thread-only world or entity APIs from a background thread.";
            case "CAUSAL_SWALLOWED_FAILURE" ->
                    "Catches and ignores an operational exception without logging or notifying the player.";
            case "CAUSAL_UNCLOSED_RESOURCE_LEAK" ->
                    "Opens a file stream, chunk ticket, or player session entry without closing or cleaning it up.";
            case "CAUSAL_SHARED_STATE_RACE" ->
                    "Reads and modifies shared plugin state across threads without consistent synchronization.";
            case "CAUSAL_ORPHANED_SUPPLIER" ->
                    "Starts an asynchronous task but discards its return value before completing the action.";
            case "CAUSAL_HOLLOW_COMMAND" ->
                    "Sends a chat message without performing the expected teleport, menu, or world action.";
            default -> token.replace('_', ' ').toLowerCase(Locale.ROOT);
        };
    }

    private static String sanitizeOperatorHazardText(String text) {
        if (text == null || text.isBlank()) {
            return "";
        }
        return text
                .replace("(violates S-005 / CAUSAL-MAIN-IO)", "(blocks the main server thread and causes tick lag spikes)")
                .replace("(violates S-005 / regional threading)", "(unsafe off-thread world access)")
                .replace("(violates F-001..F-003 / S-005)", "(incompatible with Folia regional threading and causes main-thread lag)")
                .replace("(violates S-005)", "(blocks the main server thread)")
                .replace("(violates S-004)", "(silently hides errors from operators and players)")
                .replace("(violates S-002)", "(risks memory or chunk-ticket leaks)")
                .replace("(violating S-002)", "(retaining memory after players disconnect)")
                .replace(" (S-002)", "")
                .replace(" (S-003)", "")
                .replace(" (S-004)", "")
                .replace(" (S-005)", "")
                .trim();
    }

    private static String formatEffectSinkLabel(String sink) {
        if (sink == null || sink.isBlank()) {
            return "Server Action";
        }
        return switch (sink.trim().toUpperCase(Locale.ROOT)) {
            case "STATE_MUTATION" -> "Updates Plugin State";
            case "MESSAGE_ONLY", "MESSAGE_SEND" -> "Sends Chat Message";
            case "TELEPORT" -> "Teleports Player";
            case "STORAGE_IO" -> "Disk / Database I/O";
            case "CHUNK_IO" -> "Loads World Chunks";
            case "WORLD_MUTATION" -> "Modifies World Blocks";
            case "INVENTORY_MENU" -> "Opens GUI Menu";
            case "ECONOMY_TX" -> "Economy Transaction";
            case "SCHEDULER_TASK" -> "Schedules Server Task";
            case "ASYNC_SCHEDULER" -> "Runs Background Task";
            case "NETWORK_IO" -> "Network Request";
            case "PERMISSION_CHECK" -> "Checks Permission";
            default -> sink.replace('_', ' ');
        };
    }

    private static String formatReloadTierLabel(String provenTier) {
        if (provenTier == null || provenTier.isBlank()) {
            return "Plugin reload";
        }
        return switch (provenTier.trim().toUpperCase(Locale.ROOT)) {
            case "HOT_RELOAD" -> "Updates immediately";
            case "PLUGIN_RELOAD" -> "Requires plugin reload";
            case "SERVER_RESTART" -> "Requires server restart";
            default -> provenTier;
        };
    }

    private static void appendPluginUmlModelJsonAndCollectBadges(
            CausalGraphReport report,
            LeafFuzzScorecardReport scorecard,
            StringBuilder sb,
            List<Map<String, Object>> badgeMapsOut
    ) {
        String artId = (report.artifactId() == null || report.artifactId().isBlank())
                ? "plugin:unknown"
                : report.artifactId();
        String displayName = (report.displayName() == null || report.displayName().isBlank())
                ? artId
                : report.displayName();
        String reloadCmd = "/" + displayName.toLowerCase(Locale.ROOT) + " reload";
        Map<String, List<String>> findingsBySymbolOrKey = new LinkedHashMap<>();
        Map<String, String> findingTextById = new LinkedHashMap<>();
        Set<String> deadKeys = new LinkedHashSet<>();
        Set<String> unreadFieldKeys = new LinkedHashSet<>();
        for (BytecodeCausalGraphScanner.CausalFinding f : report.findings()) {
            String badgeText = formatFindingKindTitle(f.kind()) + ": " + sanitizeOperatorHazardText(f.causalDefect());
            if (f.findingId() != null && !f.findingId().isBlank()) {
                findingTextById.put(f.findingId().trim(), badgeText);
            }
            String sym = f.entryPointSymbol();
            findingsBySymbolOrKey.computeIfAbsent(sym, k -> new ArrayList<>()).add(badgeText);
            if (f.kind() == BytecodeCausalGraphScanner.FindingKind.CAUSAL_DEAD_CONFIG_KEY) {
                deadKeys.add(sym.toLowerCase(Locale.ROOT));
                findingsBySymbolOrKey.computeIfAbsent(sym.toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(badgeText);
            } else if (f.kind() == BytecodeCausalGraphScanner.FindingKind.CAUSAL_UNREAD_CONFIG_FIELD) {
                unreadFieldKeys.add(sym.toLowerCase(Locale.ROOT));
                findingsBySymbolOrKey.computeIfAbsent(sym.toLowerCase(Locale.ROOT), k -> new ArrayList<>()).add(badgeText);
            }
        }

        Map<String, Set<String>> keyToGatedComponents = new LinkedHashMap<>();
        Map<String, Set<String>> keyToHazards = new LinkedHashMap<>();
        Map<String, Set<String>> keyToReaders = new LinkedHashMap<>();
        Set<String> hotReloadKeys = new LinkedHashSet<>();
        Set<String> addedCompIds = new LinkedHashSet<>();

        List<Map<String, Object>> components = new ArrayList<>();
        List<Map<String, String>> edges = new ArrayList<>();

        int idx = 0;
        for (BytecodeCausalGraphScanner.CausalChainSlice slice : report.entryChains()) {
            if (slice == null) continue;
            idx++;
            String compId = "comp-" + idx;
            String stereotype = switch (slice.kind()) {
                case COMMAND -> "COMMAND";
                case EVENT -> "EVENT_LISTENER";
                case SUPPLIER -> "ASYNC_WORKER";
            };
            String rawSym = slice.entrySymbol();
            int hashIdx = rawSym.indexOf('#');
            String className = (hashIdx > 0 ? rawSym.substring(0, hashIdx) : rawSym).replace('/', '.');
            String simpleClass = className.contains(".") ? className.substring(className.lastIndexOf('.') + 1) : className;
            String methodPart = hashIdx > 0 ? rawSym.substring(hashIdx + 1) : "";
            int parenIdx = methodPart.indexOf('(');
            if (parenIdx > 0) {
                methodPart = methodPart.substring(0, parenIdx);
            }
            String label = methodPart.isBlank() ? simpleClass : (simpleClass + "#" + methodPart);
            String regMode = slice.registrationMode().name();
            String gateKey = slice.gatingConfigKey();

            Set<String> hazardSet = new LinkedHashSet<>(findingsBySymbolOrKey.getOrDefault(rawSym, List.of()));
            for (BytecodeCausalGraphScanner.ProofObligation po : slice.proofObligations()) {
                if (po.status() == BytecodeCausalGraphScanner.ProofStatus.VIOLATED) {
                    String ev = po.evidence() == null ? "" : po.evidence().trim();
                    int colon = ev.indexOf(':');
                    String maybeFindingId = colon > 0 ? ev.substring(0, colon).trim() : "";
                    String mappedFinding = findingTextById.get(maybeFindingId);
                    if (mappedFinding != null) {
                        hazardSet.add(mappedFinding);
                    } else if (ev.matches("^CAUSAL-\\d+:[A-Z0-9_]+$")) {
                        if (hazardSet.isEmpty()) {
                            String kindToken = ev.substring(colon + 1).trim();
                            hazardSet.add(formatProofRuleTitle(po.ruleId()) + ": " + formatRawFindingTokenDescription(kindToken));
                        }
                    } else {
                        String title = formatProofRuleTitle(po.ruleId());
                        String cleanEv = sanitizeOperatorHazardText(ev);
                        hazardSet.add(cleanEv.isEmpty() ? title : (title + ": " + cleanEv));
                    }
                }
            }
            List<String> hazards = new ArrayList<>(hazardSet);

            boolean isLiveEntry = (slice.kind() == BytecodeCausalGraphScanner.EntryPointKind.EVENT
                    || slice.kind() == BytecodeCausalGraphScanner.EntryPointKind.COMMAND)
                    && !methodPart.toLowerCase(Locale.ROOT).contains("onenable")
                    && !methodPart.toLowerCase(Locale.ROOT).contains("init");

            List<String> friendlySinks = slice.reachableEffectSinks().stream()
                    .map(LeafFuzzRuntime::formatEffectSinkLabel)
                    .toList();
            String friendlyType = switch (slice.kind()) {
                case COMMAND -> "Command handler";
                case EVENT -> "Event listener";
                case SUPPLIER -> "Background worker";
            };
            String summary = !slice.declaredBehavior().isBlank()
                    ? sanitizeOperatorHazardText(slice.declaredBehavior())
                    : (friendlyType + " in " + simpleClass
                            + (slice.hopTrace().isEmpty() ? "" : (" (" + slice.hopTrace().size() + " method call(s))"))
                            + (friendlySinks.isEmpty() ? "" : (" -> " + String.join(", ", friendlySinks))));

            if (addedCompIds.add(compId)) {
                Map<String, Object> compNode = new LinkedHashMap<>();
                compNode.put("componentId", compId);
                compNode.put("label", label);
                compNode.put("stereotype", stereotype);
                compNode.put("className", className);
                compNode.put("entrySymbol", rawSym);
                compNode.put("registrationMode", regMode);
                compNode.put("gatingConfigKey", gateKey);
                compNode.put("readConfigKeys", slice.readConfigKeys());
                compNode.put("hopTrace", slice.hopTrace());
                compNode.put("effectSinks", new ArrayList<>(slice.reachableEffectSinks()));
                compNode.put("hazards", hazards);
                compNode.put("summary", summary);
                components.add(compNode);
            }

            if (!gateKey.isBlank()) {
                String gLow = gateKey.toLowerCase(Locale.ROOT);
                keyToGatedComponents.computeIfAbsent(gLow, k -> new LinkedHashSet<>()).add(label);
                if (!hazards.isEmpty()) {
                    keyToHazards.computeIfAbsent(gLow, k -> new LinkedHashSet<>()).addAll(hazards);
                }
                String cfgCompId = "cfg-" + gLow.replaceAll("[^a-z0-9_.-]", "_");
                if (addedCompIds.add(cfgCompId)) {
                    Map<String, Object> cfgNode = new LinkedHashMap<>();
                    cfgNode.put("componentId", cfgCompId);
                    cfgNode.put("label", gateKey);
                    cfgNode.put("stereotype", "CONFIG_GUARD");
                    cfgNode.put("className", "config.yml");
                    cfgNode.put("entrySymbol", gateKey);
                    cfgNode.put("registrationMode", "CONFIG_GATE");
                    cfgNode.put("gatingConfigKey", gateKey);
                    cfgNode.put("readConfigKeys", List.of(gateKey));
                    cfgNode.put("hopTrace", List.of());
                    cfgNode.put("effectSinks", List.of());
                    cfgNode.put("hazards", List.of());
                    cfgNode.put("summary", "Feature toggle in config.yml controlling " + label);
                    components.add(cfgNode);
                }
                edges.add(Map.of("fromId", cfgCompId, "toId", compId, "relation", "GATED_BY", "label", "enables " + label));
            }

            for (String rk : slice.readConfigKeys()) {
                String rkLow = rk.toLowerCase(Locale.ROOT);
                keyToReaders.computeIfAbsent(rkLow, k -> new LinkedHashSet<>()).add(label);
                if (isLiveEntry) {
                    hotReloadKeys.add(rkLow);
                }
                if (!hazards.isEmpty()) {
                    keyToHazards.computeIfAbsent(rkLow, k -> new LinkedHashSet<>()).addAll(hazards);
                }
                String cfgCompId = "cfg-" + rkLow.replaceAll("[^a-z0-9_.-]", "_");
                if (addedCompIds.add(cfgCompId)) {
                    Map<String, Object> cfgNode = new LinkedHashMap<>();
                    cfgNode.put("componentId", cfgCompId);
                    cfgNode.put("label", rk);
                    cfgNode.put("stereotype", "CONFIG_GUARD");
                    cfgNode.put("className", "config.yml");
                    cfgNode.put("entrySymbol", rk);
                    cfgNode.put("registrationMode", "CONFIG_KEY");
                    cfgNode.put("gatingConfigKey", "");
                    cfgNode.put("readConfigKeys", List.of(rk));
                    cfgNode.put("hopTrace", List.of());
                    cfgNode.put("effectSinks", List.of());
                    cfgNode.put("hazards", List.of());
                    cfgNode.put("summary", "Configuration setting read by " + label);
                    components.add(cfgNode);
                }
                edges.add(Map.of("fromId", cfgCompId, "toId", compId, "relation", "READS_KEY", "label", "read by " + label));
            }

            for (String sink : slice.reachableEffectSinks()) {
                String sinkId = "sink-" + sink.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_.-]", "_");
                String friendlySink = formatEffectSinkLabel(sink);
                if (addedCompIds.add(sinkId)) {
                    Map<String, Object> sinkNode = new LinkedHashMap<>();
                    sinkNode.put("componentId", sinkId);
                    sinkNode.put("label", friendlySink);
                    sinkNode.put("stereotype", "EFFECT_SINK");
                    sinkNode.put("className", "Server Action");
                    sinkNode.put("entrySymbol", sink);
                    sinkNode.put("registrationMode", "ACTIVE");
                    sinkNode.put("gatingConfigKey", "");
                    sinkNode.put("readConfigKeys", List.of());
                    sinkNode.put("hopTrace", List.of());
                    sinkNode.put("effectSinks", List.of(sink));
                    sinkNode.put("hazards", List.of());
                    sinkNode.put("summary", "Server runtime action: " + friendlySink);
                    components.add(sinkNode);
                }
                edges.add(Map.of("fromId", compId, "toId", sinkId, "relation", "TRIGGERS_SINK", "label", friendlySink));
            }
        }

        for (Map.Entry<String, String> gatedEntry : report.configGatedListeners().entrySet()) {
            String listenerCls = gatedEntry.getKey().replace('/', '.');
            String simpleCls = listenerCls.contains(".") ? listenerCls.substring(listenerCls.lastIndexOf('.') + 1) : listenerCls;
            String gk = gatedEntry.getValue();
            String gkLow = gk.toLowerCase(Locale.ROOT);
            keyToGatedComponents.computeIfAbsent(gkLow, k -> new LinkedHashSet<>()).add(simpleCls);
        }

        Set<String> allCandidateKeys = new LinkedHashSet<>();
        allCandidateKeys.addAll(deadKeys);
        allCandidateKeys.addAll(unreadFieldKeys);
        for (BytecodeCausalGraphScanner.CausalChainSlice s : report.entryChains()) {
            if (!s.gatingConfigKey().isBlank()) allCandidateKeys.add(s.gatingConfigKey());
            allCandidateKeys.addAll(s.readConfigKeys());
        }
        allCandidateKeys.addAll(report.configGatedListeners().values());

        List<Map<String, Object>> modelBadges = new ArrayList<>();
        for (String keyPath : allCandidateKeys) {
            if (keyPath == null || keyPath.isBlank()) continue;
            String kLow = keyPath.toLowerCase(Locale.ROOT);
            String leafLow = kLow.contains(".") ? kLow.substring(kLow.lastIndexOf('.') + 1) : kLow;
            boolean isDead = deadKeys.contains(kLow) || deadKeys.contains(leafLow);
            boolean isUnread = !isDead && (unreadFieldKeys.contains(kLow) || unreadFieldKeys.contains(leafLow));

            List<String> gated = new ArrayList<>(keyToGatedComponents.getOrDefault(kLow, Set.of()));
            if (gated.isEmpty() && !leafLow.equals(kLow)) {
                gated.addAll(keyToGatedComponents.getOrDefault(leafLow, Set.of()));
            }
            List<String> hazards = new ArrayList<>(keyToHazards.getOrDefault(kLow, Set.of()));
            if (hazards.isEmpty() && !leafLow.equals(kLow)) {
                hazards.addAll(keyToHazards.getOrDefault(leafLow, Set.of()));
            }
            List<String> readers = new ArrayList<>(keyToReaders.getOrDefault(kLow, Set.of()));
            if (readers.isEmpty() && !leafLow.equals(kLow)) {
                readers.addAll(keyToReaders.getOrDefault(leafLow, Set.of()));
            }

            String status;
            if (isDead) {
                status = "DEAD_KEY";
            } else if (isUnread) {
                status = "UNREAD_FIELD";
            } else if (!hazards.isEmpty()) {
                status = "HAZARD_GATE";
            } else {
                status = "WIRED";
            }

            String provenTier;
            if (hotReloadKeys.contains(kLow) || hotReloadKeys.contains(leafLow)) {
                provenTier = "HOT_RELOAD";
            } else if (!gated.isEmpty()) {
                provenTier = "SERVER_RESTART";
            } else {
                provenTier = "PLUGIN_RELOAD";
            }

            String tierLabel = formatReloadTierLabel(provenTier);
            String summary;
            if (isDead) {
                summary = "Unused in plugin code (0 references in JAR — changing this setting has no effect).";
            } else if (isUnread) {
                summary = "Loaded into a plugin field that is never used during execution.";
            } else if (!gated.isEmpty()) {
                summary = "Enables or disables " + String.join(", ", gated) + " (" + tierLabel + ").";
            } else if (!readers.isEmpty()) {
                summary = "Used by " + String.join(", ", readers) + " (" + tierLabel + ").";
            } else {
                summary = "Active plugin configuration setting (" + tierLabel + ").";
            }

            Map<String, Object> badge = new LinkedHashMap<>();
            badge.put("artifactId", artId);
            badge.put("displayName", displayName);
            badge.put("keyPath", keyPath);
            badge.put("status", status);
            badge.put("provenReloadTier", provenTier);
            badge.put("reloadCommand", reloadCmd);
            badge.put("gatedComponents", List.copyOf(gated));
            badge.put("hazards", List.copyOf(hazards));
            badge.put("summary", summary);
            badge.put("targetTabId", "leaffuzz:plugin-uml");
            badge.put("targetFocusId", artId + "::" + keyPath);
            Map<String, Object> immutableBadge = Collections.unmodifiableMap(badge);
            modelBadges.add(immutableBadge);
            badgeMapsOut.add(immutableBadge);
        }

        sb.append("{\"artifactId\":\"").append(escapeJson(artId)).append("\"")
                .append(",\"displayName\":\"").append(escapeJson(displayName)).append("\"")
                .append(",\"version\":\"latest\"")
                .append(",\"components\":[");
        for (int i = 0; i < components.size(); i++) {
            if (i > 0) sb.append(',');
            Map<String, Object> c = components.get(i);
            sb.append("{\"componentId\":\"").append(escapeJson(String.valueOf(c.get("componentId")))).append("\"")
                    .append(",\"label\":\"").append(escapeJson(String.valueOf(c.get("label")))).append("\"")
                    .append(",\"stereotype\":\"").append(escapeJson(String.valueOf(c.get("stereotype")))).append("\"")
                    .append(",\"className\":\"").append(escapeJson(String.valueOf(c.get("className")))).append("\"")
                    .append(",\"entrySymbol\":\"").append(escapeJson(String.valueOf(c.get("entrySymbol")))).append("\"")
                    .append(",\"registrationMode\":\"").append(escapeJson(String.valueOf(c.get("registrationMode")))).append("\"")
                    .append(",\"gatingConfigKey\":\"").append(escapeJson(String.valueOf(c.get("gatingConfigKey")))).append("\"")
                    .append(",\"readConfigKeys\":");
            appendJsonStringList(sb, (List<?>) c.get("readConfigKeys"));
            sb.append(",\"hopTrace\":");
            appendJsonStringList(sb, (List<?>) c.get("hopTrace"));
            sb.append(",\"effectSinks\":");
            appendJsonStringList(sb, (List<?>) c.get("effectSinks"));
            sb.append(",\"hazards\":");
            appendJsonStringList(sb, (List<?>) c.get("hazards"));
            sb.append(",\"summary\":\"").append(escapeJson(String.valueOf(c.get("summary")))).append("\"}");
        }
        sb.append("],\"edges\":[");
        for (int i = 0; i < edges.size(); i++) {
            if (i > 0) sb.append(',');
            Map<String, String> e = edges.get(i);
            sb.append("{\"fromId\":\"").append(escapeJson(e.getOrDefault("fromId", ""))).append("\"")
                    .append(",\"toId\":\"").append(escapeJson(e.getOrDefault("toId", ""))).append("\"")
                    .append(",\"relation\":\"").append(escapeJson(e.getOrDefault("relation", ""))).append("\"")
                    .append(",\"label\":\"").append(escapeJson(e.getOrDefault("label", ""))).append("\"}");
        }
        sb.append("],\"keyBadges\":[");
        for (int i = 0; i < modelBadges.size(); i++) {
            if (i > 0) sb.append(',');
            Map<String, Object> b = modelBadges.get(i);
            sb.append("{\"keyPath\":\"").append(escapeJson(String.valueOf(b.get("keyPath")))).append("\"")
                    .append(",\"status\":\"").append(escapeJson(String.valueOf(b.get("status")))).append("\"")
                    .append(",\"provenReloadTier\":\"").append(escapeJson(String.valueOf(b.get("provenReloadTier")))).append("\"")
                    .append(",\"reloadCommand\":\"").append(escapeJson(String.valueOf(b.get("reloadCommand")))).append("\"")
                    .append(",\"gatedComponents\":");
            appendJsonStringList(sb, (List<?>) b.get("gatedComponents"));
            sb.append(",\"hazards\":");
            appendJsonStringList(sb, (List<?>) b.get("hazards"));
            sb.append(",\"summary\":\"").append(escapeJson(String.valueOf(b.get("summary")))).append("\"}");
        }
        sb.append(']');
        if (scorecard != null) {
            sb.append(",\"scorecard\":{")
                    .append("\"overallVerdict\":\"").append(scorecard.overallVerdict().name()).append("\",")
                    .append("\"stage1Verdict\":\"").append(scorecard.stage1CommandSurfaceVerdict().name()).append("\",")
                    .append("\"stage2Verdict\":\"").append(scorecard.stage2BoundaryFuzzVerdict().name()).append("\",")
                    .append("\"stage3Verdict\":\"").append(scorecard.stage3StallAndExceptionVerdict().name()).append("\",")
                    .append("\"stage4Verdict\":\"").append(scorecard.stage4MemoryRetentionVerdict().name()).append("\",")
                    .append("\"stage5Verdict\":\"").append(scorecard.stage5CausalAuditVerdict().name()).append("\",")
                    .append("\"openCommands\":[");
            var lpfList = scorecard.leastPrivilegeFindings();
            for (int i = 0; i < lpfList.size(); i++) {
                var lpf = lpfList.get(i);
                String rawCmd = lpf.nodeId() == null ? "" : lpf.nodeId().trim();
                String rootLit = rawCmd.startsWith("/") ? rawCmd.substring(1) : rawCmd;
                int sp = rootLit.indexOf(' ');
                String alias = sp > 0 ? rootLit.substring(0, sp) : rootLit;
                String snippet = "aliases:\n  " + alias + ": []";
                if (i > 0) sb.append(',');
                sb.append("{\"commandPath\":\"").append(escapeJson(rawCmd)).append("\"")
                        .append(",\"alias\":\"").append(escapeJson(alias)).append("\"")
                        .append(",\"reason\":\"").append(escapeJson(lpf.rationale())).append("\"")
                        .append(",\"commandsYmlSnippet\":\"").append(escapeJson(snippet)).append("\"}");
            }
            sb.append("],\"reproducers\":[");
            var repList = scorecard.shrunkReproducers();
            for (int i = 0; i < repList.size(); i++) {
                var rep = repList.get(i);
                if (i > 0) sb.append(',');
                sb.append("{\"signatureId\":\"").append(escapeJson(rep.signatureId())).append("\"")
                        .append(",\"summary\":\"").append(escapeJson(rep.authorReproducerSummary())).append("\"")
                        .append(",\"commandsYmlSnippet\":\"").append(escapeJson(rep.commandsYmlOverrideSnippet())).append("\"}");
            }
            sb.append("]}");
        }
        sb.append('}');
    }

    private static void appendJsonStringList(StringBuilder sb, List<?> items) {
        sb.append('[');
        if (items != null) {
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append('"').append(escapeJson(String.valueOf(items.get(i)))).append('"');
            }
        }
        sb.append(']');
    }

    private static String escapeJson(String s) {
        if (s == null || s.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }

    /**
     * Self-contained client rendering kernel supplied by {@code LeafFuzz} to mount and render
     * its {@code 🔬 Plugin UML} top-level workspace tab inside {@code LeafConfig}.
     */
    public static String leafConfigUmlTabClientKernelJs() {
        return "window.LeafFuzzUmlTabKernel=(function(){"
                + "var state={models:[],activeArtifactId:'',activeComponentId:'',viewMode:'flowchart',container:null,api:null};"
                + "function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;').replace(/'/g,'&#39;');}"
                + "function trunc(s,n){var t=String(s==null?'':s);return t.length>n?t.substring(0,n-1)+'…':t;}"
                + "var SINK_LABELS={STATE_MUTATION:'Updates Plugin State',MESSAGE_ONLY:'Sends Chat Message',MESSAGE_SEND:'Sends Chat Message',TELEPORT:'Teleports Player',STORAGE_IO:'Disk / Database I/O',CHUNK_IO:'Loads World Chunks',WORLD_MUTATION:'Modifies World Blocks',INVENTORY_MENU:'Opens GUI Menu',ECONOMY_TX:'Economy Transaction',SCHEDULER_TASK:'Schedules Server Task',ASYNC_SCHEDULER:'Runs Background Task',NETWORK_IO:'Network Request',PERMISSION_CHECK:'Checks Permission',CLEAN_EXECUTION:'No Lag Risks Found'};"
                + "var SINK_SUBS={STATE_MUTATION:'Modifies in-memory plugin data',MESSAGE_ONLY:'Sends chat feedback to player',MESSAGE_SEND:'Sends chat feedback to player',TELEPORT:'Moves player in the world',STORAGE_IO:'Reads or writes disk/database',CHUNK_IO:'Loads or generates world chunks',WORLD_MUTATION:'Changes world blocks or entities',INVENTORY_MENU:'Opens inventory menu screen',ECONOMY_TX:'Updates player economy balance',SCHEDULER_TASK:'Queues task on server scheduler',ASYNC_SCHEDULER:'Runs task on background thread',NETWORK_IO:'Opens external network connection',PERMISSION_CHECK:'Verifies player permission'};"
                + "var HZ_TITLES={CAUSAL_SYNC_MAIN_THREAD_IO:'Main-Thread Blocking I/O',CAUSAL_ASYNC_MAIN_THREAD_SINK:'Unsafe Off-Thread World Call',CAUSAL_SWALLOWED_FAILURE:'Silently Ignored Error',CAUSAL_UNCLOSED_RESOURCE_LEAK:'Unreleased Memory / Resource',CAUSAL_SHARED_STATE_RACE:'Concurrent State Race',CAUSAL_ORPHANED_SUPPLIER:'Dropped Async Result',CAUSAL_HOLLOW_COMMAND:'Chat-Only Command (No Action)',CAUSAL_DEAD_CONFIG_KEY:'Unused Config Setting',CAUSAL_UNREAD_CONFIG_FIELD:'Ignored Config Field',CAUSAL_UNIT_MISMATCH:'Time Unit Mismatch (s vs ms)',CAUSAL_UNREGISTERED_LISTENER:'Inactive Event Listener',CAUSAL_UNWIRED_COMMAND:'Unregistered Command','S-001':'Unsafe Teleport Destination','S-002':'Unreleased Memory / Resource','S-003':'Protected Claim Bypass','S-004':'Silently Ignored Error','S-005':'Main-Thread Blocking I/O','S-006':'Premature Startup API Call','S-007':'Missing Command Failure Feedback'};"
                + "function humanizeStereotype(st){var m={COMMAND:'Command',EVENT_LISTENER:'Event Listener',ASYNC_WORKER:'Background Task',CONFIG_GUARD:'Config Setting',EFFECT_SINK:'Server Action',COMPONENT:'Plugin Component'};return m[st]||st||'Component';}"
                + "function humanizeRegMode(rm,st,longForm){if(st==='COMMAND'&&(!rm||rm==='NOT_APPLICABLE'||rm==='ACTIVE'))return longForm?'Registered Command (Always Active)':'Always Active';var m={REGISTERED_UNCONDITIONAL:'Always Active',ACTIVE:'Always Active',REGISTERED_CONFIG_GATED:'Config-Gated',CONFIG_GATE:'Feature Toggle',CONFIG_KEY:'Read by Plugin',UNREGISTERED:'Inactive (Not Registered)',NOT_APPLICABLE:'Always Active'};return m[rm]||rm||'Always Active';}"
                + "function humanizeCfgSub(sub){var s=String(sub||'');if(s==='CONFIG_GATE'||s==='GATES ENTRY')return 'Feature Toggle';if(s==='CONFIG_KEY'||s==='READ BY SLICE')return 'Read by Plugin';return s.replace(/DEAD_KEY/g,'Unused Setting').replace(/UNREAD_FIELD/g,'Ignored Field').replace(/HAZARD_GATE/g,'Controls Warning Path').replace(/WIRED/g,'Active Setting').replace(/HOT_RELOAD/g,'Live Reload').replace(/PLUGIN_RELOAD/g,'Plugin Reload').replace(/SERVER_RESTART/g,'Server Restart');}"
                + "function humanizeSinkLabel(sk){var k=String(sk||'').trim();return SINK_LABELS[k]||k.replace(/_/g,' ');}"
                + "function humanizeSinkSub(sk){var k=String(sk||'').trim();return SINK_SUBS[k]||'Server Runtime Action';}"
                + "function humanizeHazard(hz){var raw=String(hz||'').trim();var idx=raw.indexOf(':');var head=idx>0?raw.substring(0,idx).trim():raw;var tail=idx>0?raw.substring(idx+1).trim():'';var title=HZ_TITLES[head]||head;if(/^CAUSAL-\\d+:[A-Z0-9_]+$/i.test(tail)){var tok=tail.split(':')[1]||'';title=HZ_TITLES[tok]||title;tail='Runs synchronous blocking work or unsafe state access on this path.';}tail=tail.replace(/\\(violates S-005[^)]*\\)/gi,'(blocks the main server thread and causes lag spikes)').replace(/\\(violates F-001[^)]*\\)/gi,'(incompatible with regional threading)').replace(/\\(violates S-004[^)]*\\)/gi,'(silently hides errors from operators)').replace(/\\(violates S-002[^)]*\\)/gi,'(risks memory or chunk-ticket leaks)').replace(/\\bS-005\\b/g,'Main-Thread Blocking I/O').replace(/\\bS-004\\b/g,'Silently Ignored Error').replace(/\\bS-002\\b/g,'Unreleased Memory / Resource');return {title:title,detail:tail||title,full:tail?(title+': '+tail):title};}"
                + "function humanizeHopNodeLabel(sym){var s=String(sym||'').replace(/^Hop\\s+\\d+:\\s*/i,'');var arrowIdx=s.indexOf('->');if(arrowIdx>0)s=s.substring(0,arrowIdx).trim();return s;}"
                + "function humanizeHopLine(h){var s=String(h||'').replace(/^Hop\\s+(\\d+):/i,function(_,n){return 'Step '+(Number(n)+1)+':';});s=s.replace(/->\\s*sinks=\\[([^\\]]*)\\]/gi,function(_,list){var items=list.split(',').map(function(x){return humanizeSinkLabel(x.trim());}).filter(Boolean);return items.length?(' → Actions: '+items.join(', ')):'';});return humanizeHazard(s).full;}"
                + "function render(container,tabDesc,api){"
                + "if(!container)return;state.container=container;state.api=api||state.api;"
                + "if(tabDesc&&tabDesc.initialPayload&&Array.isArray(tabDesc.initialPayload.models)){state.models=tabDesc.initialPayload.models;}"
                + "if(state.models.length>0&&!state.activeArtifactId){state.activeArtifactId=state.models[0].artifactId||'';}"
                + "draw();"
                + "}"
                + "function focus(container,tabDesc,focusId,api){"
                + "if(container)state.container=container;if(api)state.api=api;"
                + "if(tabDesc&&tabDesc.initialPayload&&Array.isArray(tabDesc.initialPayload.models)){state.models=tabDesc.initialPayload.models;}"
                + "var raw=String(focusId||'');var parts=raw.split('::');"
                + "var artHint=(parts[0]||'').toLowerCase();var keyHint=(parts[1]||raw).toLowerCase();"
                + "var m=state.models.find(function(x){return String(x.artifactId||'').toLowerCase()===artHint||String(x.displayName||'').toLowerCase()===artHint;})||state.models[0];"
                + "if(m){state.activeArtifactId=m.artifactId;"
                + "var c=(m.components||[]).find(function(n){return String(n.gatingConfigKey||'').toLowerCase()===keyHint||(Array.isArray(n.readConfigKeys)&&n.readConfigKeys.some(function(rk){return String(rk).toLowerCase()===keyHint;}));});"
                + "state.activeComponentId=c?c.componentId:'';}"
                + "draw();"
                + "}"
                + "function selectPlugin(artId){state.activeArtifactId=String(artId||'');state.activeComponentId='';draw();}"
                + "function setViewMode(mode){state.viewMode=(mode==='cards'?'cards':'flowchart');draw();}"
                + "function zoomIntoUmlComponent(compId){state.activeComponentId=String(compId||'');draw();}"
                + "function zoomOutUmlComponent(){state.activeComponentId='';draw();}"
                + "function jumpKey(file,key){if(state.api&&typeof state.api.openConfigKey==='function'){state.api.openConfigKey(file,key);}}"
                + "function lockCommandInConfig(alias,snippet){if(state.api&&typeof state.api.stageCommandsYmlOverride==='function'){state.api.stageCommandsYmlOverride(alias,snippet);}else if(typeof window.stageCommandsYmlMitigation==='function'){window.stageCommandsYmlMitigation(alias,snippet);}}"
                + "function hopKeyFromTrace(trace){if(!Array.isArray(trace)||!trace.length)return '';for(var i=1;i<trace.length;i++){var s=String(trace[i]||'');if(/^Hop\\s+1:/i.test(s)&&s.indexOf('lambda$')<0&&s.indexOf('ServerAccessor#')<0&&s.indexOf('$CommandOutcome')<0)return s;}return trace.length>1?trace[1]:trace[0];}"
                + "function buildFlowchartSvgAndMermaid(active,vis,allComps,allEdges,focused,cfgPath){"
                + "var entryPool=vis.filter(function(c){return c.stereotype==='COMMAND'||c.stereotype==='EVENT_LISTENER'||c.stereotype==='ASYNC_WORKER'||c.stereotype==='COMPONENT';});"
                + "entryPool.sort(function(a,b){"
                + "var af=(focused&&a.componentId===focused.componentId)?100:0;"
                + "var bf=(focused&&b.componentId===focused.componentId)?100:0;"
                + "var ah=(Array.isArray(a.hazards)?a.hazards.length:0)*10+(Array.isArray(a.readConfigKeys)?a.readConfigKeys.length:0)*3+(a.gatingConfigKey?5:0)+(Array.isArray(a.hopTrace)?a.hopTrace.length:0);"
                + "var bh=(Array.isArray(b.hazards)?b.hazards.length:0)*10+(Array.isArray(b.readConfigKeys)?b.readConfigKeys.length:0)*3+(b.gatingConfigKey?5:0)+(Array.isArray(b.hopTrace)?b.hopTrace.length:0);"
                + "return (bf+bh)-(af+ah);"
                + "});"
                + "var entries=entryPool.slice(0,6);"
                + "var cfgNodes=[];var cfgSeen=new Set();"
                + "vis.filter(function(c){return c.stereotype==='CONFIG_GUARD';}).forEach(function(c){if(cfgNodes.length<6&&!cfgSeen.has(c.label)){cfgSeen.add(c.label);cfgNodes.push({id:c.componentId,label:c.label,sub:humanizeCfgSub(c.registrationMode||'CONFIG_GATE'),status:'GATE',compId:c.componentId,keyPath:c.gatingConfigKey||c.label});}});"
                + "entries.forEach(function(e){"
                + "if(e.gatingConfigKey&&!cfgSeen.has(e.gatingConfigKey)&&cfgNodes.length<6){cfgSeen.add(e.gatingConfigKey);cfgNodes.push({id:'cfg-'+e.gatingConfigKey,label:e.gatingConfigKey,sub:'Feature Toggle',status:'GATE',compId:e.componentId,keyPath:e.gatingConfigKey});}"
                + "(e.readConfigKeys||[]).forEach(function(rk){if(!cfgSeen.has(rk)&&cfgNodes.length<6){cfgSeen.add(rk);cfgNodes.push({id:'cfg-'+rk,label:rk,sub:'Read by Plugin',status:'WIRED',compId:e.componentId,keyPath:rk});}});"
                + "});"
                + "(active.keyBadges||[]).forEach(function(b){if(!cfgSeen.has(b.keyPath)&&cfgNodes.length<6){cfgSeen.add(b.keyPath);cfgNodes.push({id:'badge-'+b.keyPath,label:b.keyPath,sub:humanizeCfgSub((b.status||'WIRED')+' · '+(b.provenReloadTier||'RELOAD')),status:b.status||'WIRED',compId:'',keyPath:b.keyPath});}});"
                + "if(!cfgNodes.length){cfgNodes.push({id:'cfg-default',label:'plugin.yml / config.yml',sub:'Plugin Startup',status:'WIRED',compId:entries[0]?entries[0].componentId:'',keyPath:''});}"
                + "var hopNodes=[];var hopSeen=new Map();"
                + "var svgEdges=[];var mermaidLines=['stateDiagram-v2','  direction LR'];"
                + "entries.forEach(function(e){"
                + "var gk=e.gatingConfigKey||'';"
                + "if(gk){var cn=cfgNodes.find(function(x){return x.label===gk;});if(cn){svgEdges.push({fromCol:0,fromId:cn.id,toCol:1,toId:e.componentId,label:'enables',color:'#f9e2af',dashed:false});mermaidLines.push('  '+cn.label.replace(/[^a-zA-Z0-9_]/g,'_')+' --> '+e.componentId.replace(/[^a-zA-Z0-9_]/g,'_')+' : enables');}}"
                + "(e.readConfigKeys||[]).slice(0,2).forEach(function(rk){var cn=cfgNodes.find(function(x){return x.label===rk;});if(cn&&rk!==gk){svgEdges.push({fromCol:0,fromId:cn.id,toCol:1,toId:e.componentId,label:'reads',color:'#89b4fa',dashed:true});mermaidLines.push('  '+cn.label.replace(/[^a-zA-Z0-9_]/g,'_')+' --> '+e.componentId.replace(/[^a-zA-Z0-9_]/g,'_')+' : reads');}});"
                + "var trace=Array.isArray(e.hopTrace)&&e.hopTrace.length>0?e.hopTrace:[e.label+'#dispatch'];"
                + "var hopSym=hopKeyFromTrace(trace);"
                + "var hopKey=hopSym;"
                + "if(!hopSeen.has(hopKey)&&hopNodes.length<6){"
                + "var hid='hop-'+hopNodes.length;"
                + "hopSeen.set(hopKey,hid);"
                + "hopNodes.push({id:hid,label:humanizeHopNodeLabel(hopSym),sub:trace.length+(trace.length===1?' method call':' method calls'),compId:e.componentId,stepCount:trace.length});"
                + "}"
                + "var targetHopId=hopSeen.get(hopKey)||(hopNodes[0]&&hopNodes[0].id);"
                + "if(targetHopId){svgEdges.push({fromCol:1,fromId:e.componentId,toCol:2,toId:targetHopId,label:trace.length>1?(trace.length+' calls'):'calls',color:'#cba6f7',dashed:false});mermaidLines.push('  '+e.componentId.replace(/[^a-zA-Z0-9_]/g,'_')+' --> '+targetHopId.replace(/[^a-zA-Z0-9_]/g,'_')+' : calls ('+trace.length+' steps)');}"
                + "});"
                + "var sinkNodes=[];var sinkSeen=new Map();"
                + "entries.forEach(function(e){"
                + "var trace=Array.isArray(e.hopTrace)&&e.hopTrace.length>0?e.hopTrace:[e.label+'#dispatch'];"
                + "var fromHopId=hopSeen.get(hopKeyFromTrace(trace))||(hopNodes[0]&&hopNodes[0].id);"
                + "(e.hazards||[]).slice(0,2).forEach(function(hz){"
                + "var hInfo=humanizeHazard(hz);"
                + "var sid='hz-'+hInfo.title.replace(/[^a-zA-Z0-9_]/g,'_');"
                + "if(!sinkSeen.has(sid)&&sinkNodes.length<6){sinkSeen.set(sid,true);sinkNodes.push({id:sid,label:hInfo.title,sub:trunc(hInfo.detail,34),kind:'HAZARD',compId:e.componentId});}"
                + "if(fromHopId&&sinkSeen.has(sid)){svgEdges.push({fromCol:2,fromId:fromHopId,toCol:3,toId:sid,label:'⚠️ warning',color:'#f38ba8',dashed:false});mermaidLines.push('  '+fromHopId.replace(/[^a-zA-Z0-9_]/g,'_')+' --> '+sid+' : WARNING '+hInfo.title);}"
                + "});"
                + "(e.effectSinks||[]).slice(0,2).forEach(function(sk){"
                + "var sLabel=humanizeSinkLabel(sk);"
                + "var sid='sink-'+String(sk).replace(/[^a-zA-Z0-9_]/g,'_');"
                + "if(!sinkSeen.has(sid)&&sinkNodes.length<6){sinkSeen.set(sid,true);sinkNodes.push({id:sid,label:sLabel,sub:humanizeSinkSub(sk),kind:'SINK',compId:e.componentId});}"
                + "if(fromHopId&&sinkSeen.has(sid)){svgEdges.push({fromCol:2,fromId:fromHopId,toCol:3,toId:sid,label:'runs',color:'#94e2d5',dashed:false});mermaidLines.push('  '+fromHopId.replace(/[^a-zA-Z0-9_]/g,'_')+' --> '+sid+' : runs '+sLabel);}"
                + "});"
                + "});"
                + "if(!sinkNodes.length){sinkNodes.push({id:'sink-ok',label:'No Lag Risks Found',sub:'Runs safely without blocking tick',kind:'SINK',compId:entries[0]?entries[0].componentId:''});if(hopNodes[0]){svgEdges.push({fromCol:2,fromId:hopNodes[0].id,toCol:3,toId:'sink-ok',label:'completes',color:'#a6e3a1',dashed:false});}}"
                + "var maxRows=Math.max(cfgNodes.length,entries.length,hopNodes.length,sinkNodes.length,1);"
                + "var svgH=Math.max(360,76+maxRows*68);"
                + "var colX=[22,292,582,852];var colW=[210,226,216,204];"
                + "var posMap={};"
                + "function layoutCol(arr,cIdx){arr.forEach(function(n,i){var y=64+i*66;posMap[cIdx+':'+n.id]={x:colX[cIdx],y:y,w:colW[cIdx],h:50};});}"
                + "layoutCol(cfgNodes,0);layoutCol(entries.map(function(e){return {id:e.componentId};}),1);layoutCol(hopNodes,2);layoutCol(sinkNodes,3);"
                + "var defs='<defs>'"
                + "+'<marker id=\"uml-arr-amber\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#f9e2af\"/></marker>'"
                + "+'<marker id=\"uml-arr-blue\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#89b4fa\"/></marker>'"
                + "+'<marker id=\"uml-arr-mauve\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#cba6f7\"/></marker>'"
                + "+'<marker id=\"uml-arr-teal\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#94e2d5\"/></marker>'"
                + "+'<marker id=\"uml-arr-red\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"6\" markerHeight=\"6\" orient=\"auto-start-reverse\"><path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#f38ba8\"/></marker>'"
                + "+'</defs>';"
                + "var laneHeaders=["
                + "{x:colX[0],w:colW[0],title:'1. CONFIG SETTINGS & TOGGLES',col:'#f9e2af'},"
                + "{x:colX[1],w:colW[1],title:'2. COMMANDS & EVENT LISTENERS',col:'#89b4fa'},"
                + "{x:colX[2],w:colW[2],title:'3. INTERNAL CALL PATH',col:'#cba6f7'},"
                + "{x:colX[3],w:colW[3],title:'4. SERVER ACTIONS & WARNINGS',col:'#94e2d5'}"
                + "].map(function(lh){return '<g><rect x=\"'+lh.x+'\" y=\"14\" width=\"'+lh.w+'\" height=\"32\" rx=\"6\" fill=\"rgba(24,24,37,0.9)\" stroke=\"'+lh.col+'\" stroke-opacity=\"0.45\"/><text x=\"'+(lh.x+10)+'\" y=\"34\" fill=\"'+lh.col+'\" font-size=\"11\" font-weight=\"700\" font-family=\"ui-monospace,monospace\">'+esc(lh.title)+'</text></g>';}).join('');"
                + "var edgeSvg=svgEdges.map(function(ed){"
                + "var p1=posMap[ed.fromCol+':'+ed.fromId];var p2=posMap[ed.toCol+':'+ed.toId];if(!p1||!p2)return '';"
                + "var x1=p1.x+p1.w;var y1=p1.y+p1.h/2;var x2=p2.x;var y2=p2.y+p2.h/2;"
                + "var dx=Math.max(28,(x2-x1)*0.48);"
                + "var mk=ed.color==='#f38ba8'?'uml-arr-red':(ed.color==='#f9e2af'?'uml-arr-amber':(ed.color==='#cba6f7'?'uml-arr-mauve':(ed.color==='#94e2d5'?'uml-arr-teal':'uml-arr-blue')));"
                + "var mx=(x1+x2)/2;var my=(y1+y2)/2-5;"
                + "return '<g><path d=\"M '+x1+' '+y1+' C '+(x1+dx)+' '+y1+', '+(x2-dx)+' '+y2+', '+x2+' '+y2+'\" fill=\"none\" stroke=\"'+ed.color+'\" stroke-width=\"1.8\" '+(ed.dashed?'stroke-dasharray=\"4,3\" ':'')+'marker-end=\"url(#'+mk+')\" opacity=\"0.88\"/>'"
                + "+'<rect x=\"'+(mx-28)+'\" y=\"'+(my-9)+'\" width=\"56\" height=\"14\" rx=\"4\" fill=\"#11111b\" stroke=\"'+ed.color+'\" stroke-width=\"0.7\" opacity=\"0.92\"/>'"
                + "+'<text x=\"'+mx+'\" y=\"'+my+'\" text-anchor=\"middle\" fill=\"'+ed.color+'\" font-size=\"9\" font-family=\"ui-monospace,monospace\">'+esc(trunc(ed.label,12))+'</text></g>';"
                + "}).join('');"
                + "var cfgSvg=cfgNodes.map(function(n){var p=posMap['0:'+n.id];var c=(n.status==='DEAD_KEY'||n.status==='UNREAD_FIELD')?'#f38ba8':(n.status==='HAZARD_GATE'?'#f9e2af':'#a6e3a1');"
                + "var clickAct=n.compId?('window.LeafFuzzUmlTabKernel.zoomIntoUmlComponent(\\''+esc(n.compId)+'\\')'):(n.keyPath?('window.LeafFuzzUmlTabKernel.jumpKey(\\''+esc(cfgPath)+'\\',\\''+esc(n.keyPath)+'\\')'):'');"
                + "return '<g style=\"cursor:pointer;\" onclick=\"'+clickAct+'\"><rect x=\"'+p.x+'\" y=\"'+p.y+'\" width=\"'+p.w+'\" height=\"'+p.h+'\" rx=\"7\" fill=\"#181825\" stroke=\"'+c+'\" stroke-width=\"1.5\"/>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+19)+'\" fill=\"#f9e2af\" font-size=\"11\" font-weight=\"700\" font-family=\"ui-monospace,monospace\">⚙️ '+esc(trunc(n.label,22))+'</text>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+36)+'\" fill=\"'+c+'\" font-size=\"9.5\" font-family=\"ui-monospace,monospace\">'+esc(trunc(n.sub,26))+'</text></g>';}).join('');"
                + "var entSvg=entries.map(function(e){var p=posMap['1:'+e.componentId];var sel=focused&&focused.componentId===e.componentId;var haz=Array.isArray(e.hazards)&&e.hazards.length>0;var c=sel?'#89b4fa':(haz?'#f38ba8':'#89b4fa');"
                + "return '<g style=\"cursor:pointer;\" onclick=\"window.LeafFuzzUmlTabKernel.zoomIntoUmlComponent(\\''+esc(e.componentId)+'\\')\"><rect x=\"'+p.x+'\" y=\"'+p.y+'\" width=\"'+p.w+'\" height=\"'+p.h+'\" rx=\"7\" fill=\"'+(sel?'#1e293b':'#181825')+'\" stroke=\"'+c+'\" stroke-width=\"'+(sel?'2.4':'1.6')+'\"/>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+18)+'\" fill=\"'+c+'\" font-size=\"10.5\" font-weight=\"700\" font-family=\"ui-monospace,monospace\">⚡ '+esc(trunc(e.label,25))+'</text>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+35)+'\" fill=\"#a6adc8\" font-size=\"9.5\" font-family=\"ui-monospace,monospace\">'+esc(humanizeStereotype(e.stereotype))+' '+(haz?'· ⚠️ '+e.hazards.length+(e.hazards.length===1?' warning':' warnings'):'· '+esc(humanizeRegMode(e.registrationMode,e.stereotype,false)))+'</text></g>';}).join('');"
                + "var hopSvg=hopNodes.map(function(n){var p=posMap['2:'+n.id];"
                + "return '<g style=\"cursor:pointer;\" onclick=\"window.LeafFuzzUmlTabKernel.zoomIntoUmlComponent(\\''+esc(n.compId)+'\\')\"><rect x=\"'+p.x+'\" y=\"'+p.y+'\" width=\"'+p.w+'\" height=\"'+p.h+'\" rx=\"12\" fill=\"#181825\" stroke=\"#cba6f7\" stroke-width=\"1.5\"/>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+19)+'\" fill=\"#cba6f7\" font-size=\"10.5\" font-weight=\"700\" font-family=\"ui-monospace,monospace\">⛓️ '+esc(trunc(n.label,24))+'</text>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+36)+'\" fill=\"#a6adc8\" font-size=\"9.5\" font-family=\"ui-monospace,monospace\">Call Path ('+esc(n.sub)+')</text></g>';}).join('');"
                + "var sinkSvg=sinkNodes.map(function(n){var p=posMap['3:'+n.id];var isHz=n.kind==='HAZARD';var c=isHz?'#f38ba8':'#94e2d5';"
                + "return '<g style=\"cursor:pointer;\" onclick=\"window.LeafFuzzUmlTabKernel.zoomIntoUmlComponent(\\''+esc(n.compId)+'\\')\"><rect x=\"'+p.x+'\" y=\"'+p.y+'\" width=\"'+p.w+'\" height=\"'+p.h+'\" rx=\"7\" fill=\"'+(isHz?'rgba(243,139,168,0.12)':'#181825')+'\" stroke=\"'+c+'\" stroke-width=\"1.6\"/>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+19)+'\" fill=\"'+c+'\" font-size=\"10.2\" font-weight=\"700\" font-family=\"ui-monospace,monospace\">'+(isHz?'⚠️ ':'🎯 ')+esc(trunc(n.label,26))+'</text>'"
                + "+'<text x=\"'+(p.x+10)+'\" y=\"'+(p.y+36)+'\" fill=\"#a6adc8\" font-size=\"9\" font-family=\"ui-monospace,monospace\">'+esc(trunc(n.sub,30))+'</text></g>';}).join('');"
                + "var svgHtml='<svg id=\"uml-state-causal-svg\" viewBox=\"0 0 1080 '+svgH+'\" style=\"width:100%;height:'+svgH+'px;min-height:380px;max-height:450px;flex-shrink:0;display:block;background:radial-gradient(circle at 20% 20%, rgba(137,180,250,0.06), rgba(17,17,27,0.95));border:1px solid var(--overlay);border-radius:8px;\">'+defs+laneHeaders+edgeSvg+cfgSvg+entSvg+hopSvg+sinkSvg+'</svg>';"
                + "return {svg:svgHtml,mermaid:mermaidLines.join('\\n')};"
                + "}"
                + "function draw(){"
                + "var el=state.container;if(!el)return;"
                + "var models=Array.isArray(state.models)?state.models:[];"
                + "if(!models.length){el.innerHTML='<div style=\"padding:24px;color:var(--subtext);\">No plugin UML models loaded in this LeafFuzz session.</div>';return;}"
                + "var active=models.find(function(m){return m.artifactId===state.activeArtifactId;})||models[0];"
                + "state.activeArtifactId=active.artifactId;"
                + "var allComps=Array.isArray(active.components)?active.components:[];"
                + "var allEdges=Array.isArray(active.edges)?active.edges:[];"
                + "var focused=state.activeComponentId?allComps.find(function(c){return c.componentId===state.activeComponentId;}):null;"
                + "var conn=new Set();if(focused){conn.add(focused.componentId);allEdges.forEach(function(e){if(e.fromId===focused.componentId)conn.add(e.toId);if(e.toId===focused.componentId)conn.add(e.fromId);});}"
                + "var vis=focused?allComps.filter(function(c){return conn.has(c.componentId);}):allComps;"
                + "var sideHtml=models.map(function(m){var act=m.artifactId===active.artifactId;var dead=(m.keyBadges||[]).filter(function(b){return b.status==='DEAD_KEY'||b.status==='UNREAD_FIELD';}).length;"
                + "return '<button type=\"button\" onclick=\"window.LeafFuzzUmlTabKernel.selectPlugin(\\''+esc(m.artifactId)+'\\')\" style=\"text-align:left;padding:9px 11px;border-radius:6px;border:1px solid '+(act?'var(--accent)':'var(--overlay)')+';background:'+(act?'rgba(137,180,250,0.14)':'var(--dark)')+';color:var(--text);cursor:pointer;display:flex;flex-direction:column;gap:3px;\">'"
                + "+'<div style=\"display:flex;justify-content:space-between;align-items:center;\"><b style=\"font-size:0.82rem;color:'+(act?'var(--accent)':'var(--text)')+';\">🧩 '+esc(m.displayName||m.artifactId)+'</b><span style=\"font-size:0.66rem;color:var(--subtext);font-family:var(--mono);\">'+esc(m.version||'')+'</span></div>'"
                + "+'<div style=\"font-size:0.69rem;color:var(--subtext);\">'+(m.components||[]).length+' flow nodes'+(dead>0?' · <span style=\"color:var(--red);\">'+dead+' unused key(s)</span>':'')+'</div></button>';}).join('');"
                + "function lane(title,icon,types,col){var items=vis.filter(function(c){return types.indexOf(c.stereotype)>=0;});if(!items.length)return '';"
                + "var cards=items.map(function(c){var sel=focused&&c.componentId===focused.componentId;var haz=Array.isArray(c.hazards)&&c.hazards.length>0;"
                + "var outs=allEdges.filter(function(e){return e.fromId===c.componentId;}).slice(0,4).map(function(e){var t=allComps.find(function(x){return x.componentId===e.toId;});return '<span style=\"font-size:0.65rem;padding:1px 5px;border-radius:3px;background:rgba(255,255,255,0.06);color:var(--subtext);font-family:var(--mono);\">&rarr; '+esc(t?humanizeSinkLabel(t.label):e.toId)+'</span>';}).join(' ');"
                + "return '<div onclick=\"window.LeafFuzzUmlTabKernel.zoomIntoUmlComponent(\\''+esc(c.componentId)+'\\')\" style=\"padding:10px 12px;border-radius:6px;border:1px solid '+(sel?'var(--accent)':(haz?'var(--red)':'var(--overlay)'))+';background:'+(sel?'rgba(137,180,250,0.16)':'var(--dark)')+';cursor:pointer;min-width:210px;max-width:310px;flex:1 1 230px;\">'"
                + "+'<div style=\"display:flex;justify-content:space-between;align-items:center;gap:6px;margin-bottom:4px;\"><span style=\"font-size:0.64rem;font-family:var(--mono);padding:1px 5px;border-radius:3px;background:rgba(0,0,0,0.35);color:'+col+';\">'+esc(humanizeStereotype(c.stereotype))+'</span>'+(haz?'<span style=\"font-size:0.64rem;color:var(--red);font-weight:700;\">⚠️ '+c.hazards.length+(c.hazards.length===1?' WARNING':' WARNINGS')+'</span>':'<span style=\"font-size:0.64rem;color:var(--green);\">'+esc(humanizeRegMode(c.registrationMode,c.stereotype,false))+'</span>')+'</div>'"
                + "+'<div style=\"font-weight:700;font-size:0.82rem;color:var(--text);font-family:var(--mono);word-break:break-all;\">'+esc(humanizeSinkLabel(c.label))+'</div>'"
                + "+'<div style=\"font-size:0.72rem;color:var(--subtext);margin-top:3px;\">'+esc(c.summary||'')+'</div>'+(outs?'<div style=\"margin-top:6px;display:flex;flex-wrap:wrap;gap:4px;\">'+outs+'</div>':'')+'</div>';}).join('');"
                + "return '<div style=\"background:rgba(0,0,0,0.18);border:1px solid var(--overlay);border-radius:8px;padding:12px 14px;\"><div style=\"font-size:0.78rem;font-weight:700;color:'+col+';margin-bottom:9px;\">'+icon+' '+esc(title)+' ('+items.length+')</div><div style=\"display:flex;flex-wrap:wrap;gap:10px;\">'+cards+'</div></div>';}"
                + "var cfgPath='plugins/'+active.displayName+'/config.yml';"
                + "var badgeRows=(active.keyBadges||[]).map(function(b){var sc=(b.status==='DEAD_KEY'||b.status==='UNREAD_FIELD')?'var(--red)':(b.status==='HAZARD_GATE'?'var(--yellow)':'var(--green)');"
                + "return '<div style=\"display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 9px;border-radius:5px;background:var(--dark);border:1px solid var(--overlay);font-size:0.74rem;\"><div><code style=\"color:var(--accent);font-weight:700;\">'+esc(b.keyPath)+'</code> <span style=\"color:'+sc+';font-weight:700;margin-left:6px;\">['+esc(humanizeCfgSub(b.status))+']</span> <span style=\"color:var(--subtext);font-family:var(--mono);\">('+esc(humanizeCfgSub(b.provenReloadTier))+')</span><div style=\"font-size:0.70rem;color:var(--subtext);margin-top:2px;\">'+esc(b.summary||'')+'</div></div>'"
                + "+'<button type=\"button\" class=\"btn\" style=\"padding:2px 8px;font-size:0.69rem;white-space:nowrap;\" onclick=\"window.LeafFuzzUmlTabKernel.jumpKey(\\''+esc(cfgPath)+'\\',\\''+esc(b.keyPath)+'\\')\">Edit Key ↗</button></div>';}).join('');"
                + "var inspHtml='';if(focused){"
                + "var links=(focused.readConfigKeys||[]).map(function(rk){return '<button type=\"button\" class=\"btn\" style=\"padding:2px 7px;font-size:0.69rem;\" onclick=\"window.LeafFuzzUmlTabKernel.jumpKey(\\''+esc(cfgPath)+'\\',\\''+esc(rk)+'\\')\">⚙️ '+esc(rk)+' ↗</button>';}).join(' ');"
                + "var hops=(focused.hopTrace||[]).map(function(h){return '<li style=\"margin:2px 0;font-family:var(--mono);font-size:0.71rem;\">'+esc(humanizeHopLine(h))+'</li>';}).join('');"
                + "var hzs=(focused.hazards||[]).map(function(hz){return '<li style=\"margin:2px 0;color:var(--red);\">'+esc(humanizeHazard(hz).full)+'</li>';}).join('');"
                + "inspHtml='<div style=\"margin-bottom:6px;\"><b style=\"font-size:0.86rem;color:var(--accent);font-family:var(--mono);\">'+esc(humanizeSinkLabel(focused.label))+'</b> <span style=\"font-size:0.71rem;color:var(--subtext);\">('+esc(focused.className||'-')+')</span></div>'"
                + "+'<div style=\"margin-bottom:6px;padding:6px 8px;border-radius:5px;background:var(--dark);border:1px solid var(--overlay);\">'+esc(focused.summary||'')+'</div>'"
                + "+'<div style=\"margin-bottom:4px;\"><b>Activation Status:</b> <code>'+esc(humanizeRegMode(focused.registrationMode,focused.stereotype,true))+'</code>'+(focused.gatingConfigKey?' · <span style=\"color:var(--yellow);\"><b>Controlled by Config Key:</b> <code>'+esc(focused.gatingConfigKey)+'</code></span>':'')+'</div>'"
                + "+(links?'<div style=\"margin-bottom:6px;\"><b>Linked Config Keys:</b> <span style=\"display:inline-flex;flex-wrap:wrap;gap:4px;\">'+links+'</span></div>':'')"
                + "+(hops?'<div style=\"margin-bottom:6px;\"><b>🧭 Execution Call Path ('+focused.hopTrace.length+' step(s)):</b><ol style=\"margin:3px 0 0 18px;padding:0;\">'+hops+'</ol></div>':'')"
                + "+(hzs?'<div style=\"margin-bottom:4px;\"><b>⚠️ Potential Lag &amp; Reliability Warnings:</b><ul style=\"margin:3px 0 0 16px;padding:0;\">'+hzs+'</ul></div>':'<div style=\"color:var(--green);font-size:0.73rem;\">✔ No main-thread lag, silent error, or memory leak risks detected on this path.</div>');"
                + "}else{inspHtml='<p style=\"margin:0 0 6px 0;\">Viewing config-to-action flowchart for <b>'+esc(active.displayName)+'</b> (<code>'+esc(active.artifactId)+'</code>).</p><p style=\"color:var(--subtext);margin:0;\">Click any box in the flowchart (or switch to View B: Component Cards) to see which config settings it reads, what server actions it runs, and any lag or error warnings.</p>';}"
                + "var scStripHtml='';if(active.scorecard){"
                + "var sc=active.scorecard;var openCmds=Array.isArray(sc.openCommands)?sc.openCommands:[];"
                + "var cmdFixes=openCmds.slice(0,4).map(function(oc){return '<div style=\"display:flex;justify-content:space-between;align-items:center;gap:8px;padding:4px 8px;border-radius:4px;background:rgba(243,139,168,0.10);border:1px solid rgba(243,139,168,0.35);font-size:0.72rem;\"><span>🔓 <code>'+esc(oc.commandPath)+'</code> open to default players ('+esc(oc.reason||'')+')</span><button type=\"button\" class=\"btn\" style=\"padding:2px 7px;font-size:0.68rem;border-color:var(--green);color:var(--green);\" onclick=\"window.LeafFuzzUmlTabKernel.lockCommandInConfig(\\''+esc(oc.alias||'command')+'\\',\\''+esc(oc.commandsYmlSnippet||'')+'\\')\">🔒 Lock in commands.yml</button></div>';}).join('');"
                + "scStripHtml='<div style=\"padding:8px 12px;border-radius:6px;background:var(--mantle);border:1px solid var(--overlay);display:flex;flex-direction:column;gap:6px;\"><div style=\"display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;font-size:0.74rem;\"><b style=\"color:var(--accent);\">🛡️ 5-Stage Health Check Verdict: '+esc(sc.overallVerdict||'PASS')+'</b><span style=\"color:var(--subtext);font-family:var(--mono);font-size:0.70rem;\">Permissions: '+esc(sc.stage1Verdict)+' · Command Fuzzing: '+esc(sc.stage2Verdict)+' · Lag Spikes: '+esc(sc.stage3Verdict)+' · Memory Leaks: '+esc(sc.stage4Verdict)+' · Code Audit: '+esc(sc.stage5Verdict)+'</span></div>'+cmdFixes+'</div>';"
                + "}"
                + "var isFlow=state.viewMode!=='cards';"
                + "var flowData=buildFlowchartSvgAndMermaid(active,allComps,allComps,allEdges,focused,cfgPath);"
                + "var abToggleHtml='<div style=\"display:inline-flex;border:1px solid var(--overlay);border-radius:6px;overflow:hidden;background:var(--dark);\">'"
                + "+'<button type=\"button\" onclick=\"window.LeafFuzzUmlTabKernel.setViewMode(\\'flowchart\\')\" style=\"padding:5px 11px;font-size:0.74rem;font-weight:700;border:none;cursor:pointer;background:'+(isFlow?'var(--accent)':'transparent')+';color:'+(isFlow?'#11111b':'var(--text)')+';\">📐 View A: Config-to-Action Flowchart (Mermaid)</button>'"
                + "+'<button type=\"button\" onclick=\"window.LeafFuzzUmlTabKernel.setViewMode(\\'cards\\')\" style=\"padding:5px 11px;font-size:0.74rem;font-weight:700;border:none;cursor:pointer;background:'+(!isFlow?'var(--accent)':'transparent')+';color:'+(!isFlow?'#11111b':'var(--text)')+';\">🗂️ View B: Component Cards &amp; Wiring</button>'"
                + "+'</div>';"
                + "var mainBodyHtml='';"
                + "if(isFlow){"
                + "mainBodyHtml='<div style=\"flex:1;display:flex;flex-direction:column;overflow-y:auto;padding:14px 18px;background:var(--base);gap:12px;\">'"
                + "+'<div style=\"display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--overlay);padding-bottom:10px;flex-wrap:wrap;gap:8px;\"><div><h2 style=\"margin:0;font-size:1.12rem;color:var(--accent);\">🔬 '+esc(active.displayName||active.artifactId)+' — Config-to-Action Flowchart (Mermaid UML)</h2><span style=\"font-size:0.73rem;color:var(--subtext);font-family:var(--mono);\">How config settings control commands &amp; events, what server actions they run, and where lag or errors can occur</span></div><div style=\"display:flex;gap:8px;align-items:center;\">'+(focused?'<button type=\"button\" class=\"btn\" style=\"padding:4px 10px;font-size:0.73rem;\" onclick=\"window.LeafFuzzUmlTabKernel.zoomOutUmlComponent()\">🔍 Full Plugin Flowchart</button>':'')+abToggleHtml+'<span class=\"session-badge\">SUPPLIED BY LEAFFUZZ</span></div></div>'"
                + "+scStripHtml+flowData.svg"
                + "+'<div style=\"display:grid;grid-template-columns:1.15fr 0.85fr;gap:12px;align-items:start;\">'"
                + "+'<div style=\"background:var(--mantle);border:1px solid var(--overlay);border-radius:8px;padding:12px 14px;max-height:260px;overflow-y:auto;\"><div class=\"tracker-title\" style=\"margin-bottom:6px;\"><span>🔍 Component Zoom Inspector</span><span class=\"tracker-badge\">'+(focused?esc(humanizeStereotype(focused.stereotype)):'FLOWCHART OVERVIEW')+'</span></div><div style=\"font-size:0.76rem;color:var(--text);line-height:1.45;\">'+inspHtml+'</div></div>'"
                + "+'<div style=\"background:var(--mantle);border:1px solid var(--overlay);border-radius:8px;padding:12px 14px;max-height:260px;overflow-y:auto;\"><div class=\"tracker-title\" style=\"margin-bottom:6px;\"><span>📋 Mermaid stateDiagram-v2 Source</span><span class=\"tracker-badge\">direction LR</span></div><pre style=\"margin:0;padding:8px 10px;border-radius:5px;background:#11111b;border:1px solid var(--overlay);color:var(--green);font-family:var(--mono);font-size:0.69rem;max-height:195px;overflow:auto;line-height:1.4;\">'+esc(flowData.mermaid)+'</pre></div>'"
                + "+'</div></div>';"
                + "}else{"
                + "mainBodyHtml='<div style=\"flex:1;display:flex;flex-direction:column;overflow-y:auto;padding:16px 20px;background:var(--base);\">'"
                + "+'<div style=\"display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--overlay);padding-bottom:10px;margin-bottom:12px;flex-wrap:wrap;gap:8px;\"><div><h2 style=\"margin:0;font-size:1.12rem;color:var(--accent);\">🔬 '+esc(active.displayName||active.artifactId)+' — Component Cards &amp; Key Wiring</h2><span style=\"font-size:0.73rem;color:var(--subtext);font-family:var(--mono);\">Click any component box to inspect its execution path, config toggles, and server actions</span></div><div style=\"display:flex;gap:8px;align-items:center;\">'+(focused?'<button type=\"button\" class=\"btn\" style=\"padding:4px 10px;font-size:0.73rem;\" onclick=\"window.LeafFuzzUmlTabKernel.zoomOutUmlComponent()\">🔍 Zoom Out</button>':'')+abToggleHtml+'<span class=\"session-badge\">SUPPLIED BY LEAFFUZZ</span></div></div>'"
                + "+scStripHtml+'<div style=\"display:flex;flex-direction:column;gap:14px;\">'+lane('Configuration Settings & Toggles','⚙️',['CONFIG_GUARD'],'var(--yellow)')+lane('Plugin Entry Points (Commands, Event Listeners & Background Tasks)','⚡',['COMMAND','EVENT_LISTENER','ASYNC_WORKER','COMPONENT'],'var(--accent)')+lane('Server Actions & Side Effects','🎯',['EFFECT_SINK'],'var(--teal)')+(badgeRows?'<div style=\"background:rgba(0,0,0,0.18);border:1px solid var(--overlay);border-radius:8px;padding:12px 14px;\"><div style=\"font-size:0.78rem;font-weight:700;color:var(--mauve);margin-bottom:8px;\">🔬 Config Setting Usage &amp; Reload Behavior ('+active.keyBadges.length+')</div><div style=\"display:flex;flex-direction:column;gap:6px;\">'+badgeRows+'</div></div>':'')+'</div></div>'"
                + "+'<aside style=\"width:330px;border-left:1px solid var(--overlay);background:var(--mantle);padding:14px 16px;overflow-y:auto;\"><div class=\"tracker-title\" style=\"margin-bottom:8px;\"><span>🔍 Component Zoom Inspector</span><span class=\"tracker-badge\">'+(focused?esc(humanizeStereotype(focused.stereotype)):'PLUGIN OVERVIEW')+'</span></div><div style=\"font-size:0.78rem;color:var(--text);line-height:1.5;\">'+inspHtml+'</div></aside>';"
                + "}"
                + "el.style.display='';el.innerHTML='<div style=\"display:flex;width:100%;height:100%;overflow:hidden;\">'"
                + "+'<aside style=\"width:240px;border-right:1px solid var(--overlay);background:var(--mantle);display:flex;flex-direction:column;overflow-y:auto;\"><div style=\"padding:12px 14px;border-bottom:1px solid var(--overlay);\"><h3 style=\"margin:0;font-size:0.9rem;color:var(--accent);\">🔬 Plugins (Vertical Tabs)</h3><span style=\"font-size:0.72rem;color:var(--subtext);\">Supplied by LeafFuzz</span></div><div style=\"display:flex;flex-direction:column;gap:6px;padding:10px;\">'+sideHtml+'</div></aside>'"
                + "+mainBodyHtml+'</div>';"
                + "}"
                + "return {render:render,focus:focus,selectPlugin:selectPlugin,setViewMode:setViewMode,zoomIntoUmlComponent:zoomIntoUmlComponent,zoomOutUmlComponent:zoomOutUmlComponent,jumpKey:jumpKey,lockCommandInConfig:lockCommandInConfig};"
                + "})();";
    }
    private List<CausalGraphReport> resolveCausalReportsForTarget(String effTarget) {
        List<CausalGraphReport> reports = new ArrayList<>();
        Set<String> seenIds = new LinkedHashSet<>();

        for (JarClassOwnershipIndex.JarDescriptor desc : this.ownershipIndex.descriptors().values()) {
            if (!BrigadierDispatcherInspector.matchesTargetIdentifier(
                    desc.jarName(),
                    desc.pluginId(),
                    effTarget,
                    this.ownershipIndex
            )) {
                continue;
            }
            CausalGraphReport report = this.causalGraphCache.get(desc.jarName());
            if (report == null && desc.jarPath() != null && Files.isRegularFile(desc.jarPath())) {
                try {
                    report = BytecodeCausalGraphScanner.scanJar(desc.jarPath());
                    this.causalGraphCache.put(desc.jarName(), report);
                } catch (IOException e) {
                    accessor.log(Level.FINE, "[LeafFuzz] Skipping causal graph scan for " + desc.jarName() + ": " + e.getMessage(), e);
                }
            }
            if (report != null && seenIds.add(report.artifactId() + ":" + desc.jarName())) {
                reports.add(report);
            }
        }

        for (var entry : this.causalGraphCache.entrySet()) {
            String key = entry.getKey();
            CausalGraphReport report = entry.getValue();
            if (seenIds.contains(report.artifactId() + ":" + key)) {
                continue;
            }
            if (BrigadierDispatcherInspector.matchesTargetIdentifier(
                    key,
                    report.displayName(),
                    effTarget,
                    this.ownershipIndex
            )) {
                seenIds.add(report.artifactId() + ":" + key);
                reports.add(report);
            }
        }
        return reports;
    }

    private List<DualAudienceMitigationReport> enrichReproducersWithAstLlm(
            List<DualAudienceMitigationReport> reproducers,
            String effTarget
    ) {
        if (reproducers == null || reproducers.isEmpty() || !this.config.llmAudit().explainFuzzFaults()) {
            return reproducers;
        }
        var llmHookCfg = this.config.llmAudit().toLlmHookConfig();
        if (llmHookCfg.provider() == Provider.OFF) {
            return reproducers;
        }
        List<CausalGraphReport> reports = resolveCausalReportsForTarget(effTarget);
        if (reports.isEmpty()) {
            return reproducers;
        }
        LlmCausalChainAuditor auditor = new LlmCausalChainAuditor(llmHookCfg, this.customLlmHttpTransport);
        List<DualAudienceMitigationReport> enriched = new ArrayList<>(reproducers.size());
        for (DualAudienceMitigationReport r : reproducers) {
            CausalGraphReport matchingReport = reports.get(0);
            for (CausalGraphReport cand : reports) {
                if (cand.displayName().equalsIgnoreCase(r.suspectJar())
                        || r.suspectJar().toLowerCase(Locale.ROOT).contains(cand.displayName().toLowerCase(Locale.ROOT))) {
                    matchingReport = cand;
                    break;
                }
            }
            String explanation = auditor.explainProvenFuzzFault(
                    r.signatureId(),
                    r.signatureId(),
                    r.minimalCommandSequence(),
                    r.followUpShape(),
                    matchingReport
            );
            if (!explanation.isEmpty() && !r.authorReproducerSummary().contains("[AST Root Cause:")) {
                enriched.add(new DualAudienceMitigationReport(
                        r.signatureId(),
                        r.suspectJar(),
                        r.minimalCommandSequence(),
                        r.followUpShape(),
                        r.bisectedNumericThreshold(),
                        r.commandsYmlOverrideSnippet(),
                        r.permissionRevokeCommand(),
                        r.authorReproducerSummary() + " [AST Root Cause: " + explanation + "]"
                ));
            } else {
                enriched.add(r);
            }
        }
        return List.copyOf(enriched);
    }

    /**
     * Resolves candidate {@code plugins/} and {@code mods/} archive directories relative to the
     * plugin/mod configuration folder and working directory.
     *
     * @param rootFolder plugin or mod configuration directory
     * @return list of existing archive directories
     */
    public static List<Path> resolveArchiveDirectories(Path rootFolder) {
        Set<Path> candidates = new LinkedHashSet<>();
        if (rootFolder != null) {
            Path absRoot = rootFolder.toAbsolutePath().normalize();
            Path parent = absRoot.getParent();
            if (parent != null) {
                String parentName = parent.getFileName() != null
                        ? parent.getFileName().toString().toLowerCase(Locale.ROOT)
                        : "";
                if ("plugins".equals(parentName) || "mods".equals(parentName)) {
                    candidates.add(parent);
                }
                Path serverRoot = parent.getParent();
                if (serverRoot != null) {
                    candidates.add(serverRoot.resolve("plugins"));
                    candidates.add(serverRoot.resolve("mods"));
                }
            }
        }
        candidates.add(Path.of("plugins").toAbsolutePath().normalize());
        candidates.add(Path.of("mods").toAbsolutePath().normalize());

        List<Path> existing = new ArrayList<>();
        for (Path p : candidates) {
            if (Files.isDirectory(p)) {
                existing.add(p);
            }
        }
        return existing;
    }

    /**
     * Extracts the live per-tier ({@code "default"} and {@code "op"}) command trees from the
     * active platform adapter or Brigadier dispatcher.
     *
     * @return map of per-tier raw command trees
     */
    public Map<String, List<RawCommandNode>> inspectLiveCommandGraphs() {
        Supplier<Map<String, List<RawCommandNode>>> platSupplier = this.platformCommandGraphSupplier;
        if (platSupplier != null) {
            try {
                Map<String, List<RawCommandNode>> graphs = platSupplier.get();
                if (graphs != null && !graphs.isEmpty()) {
                    return graphs;
                }
            } catch (Throwable ex) {
                accessor.log(Level.FINE, "[LeafFuzz] Platform command graph supplier fallback: " + ex.getMessage(), ex);
            }
        }
        Supplier<Object> brigSupplier = this.brigadierDispatcherSupplier;
        if (brigSupplier != null) {
            try {
                Object dispatcher = brigSupplier.get();
                if (dispatcher != null) {
                    return BrigadierDispatcherInspector.inspectDispatcher(dispatcher, this.ownershipIndex);
                }
            } catch (Throwable ex) {
                accessor.log(Level.FINE, "[LeafFuzz] Brigadier dispatcher inspection fallback: " + ex.getMessage(), ex);
            }
        }
        return Map.of("default", List.of(), "op", List.of());
    }

    /**
     * Audits the live command surface, optionally scoped to {@code targetFilter}.
     *
     * @param targetFilter plugin/mod name, JAR name, or {@code "all"}
     * @return command surface audit report
     */
    public CommandAuditReport auditCommandSurface(String targetFilter) {
        if (this.ownershipIndex.indexedJarCount() == 0) {
            refreshJarOwnershipIndexNow();
        }
        Map<String, List<RawCommandNode>> rawGraphs = inspectLiveCommandGraphs();
        Map<String, List<RawCommandNode>> filtered = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                rawGraphs,
                targetFilter,
                this.ownershipIndex
        );
        List<CommandSurfaceAuditor.WhiteBoxCommandHint> whiteBoxHints = resolveWhiteBoxCommandHints(targetFilter);
        return CommandSurfaceAuditor.auditCommandSurface(
                filtered,
                this.config.extraDenylist(),
                this.ownershipIndex,
                whiteBoxHints
        );
    }

    private List<CommandSurfaceAuditor.WhiteBoxCommandHint> resolveWhiteBoxCommandHints(String targetFilter) {
        String effTarget = (targetFilter == null || targetFilter.isBlank()) ? "all" : targetFilter.trim();
        List<CausalGraphReport> reports = resolveCausalReportsForTarget(effTarget);
        if (reports.isEmpty()) {
            return List.of();
        }
        List<CommandSurfaceAuditor.WhiteBoxCommandHint> hints = new ArrayList<>();
        for (CausalGraphReport report : reports) {
            for (BytecodeCausalGraphScanner.BytecodeCommandSchema schema : report.commandSchemas()) {
                hints.add(new CommandSurfaceAuditor.WhiteBoxCommandHint(
                        schema.rootCommand(),
                        schema.subcommandLiterals(),
                        schema.argumentParsers(),
                        schema.inlinePermissions(),
                        report.displayName()
                ));
            }
        }
        return List.copyOf(hints);
    }

    /**
     * Executes the 4-stage automated QC check ({@code /fuzz check <target>}) across one or more
     * target plugins/mods (comma-separated or {@code "all"}) and writes the Markdown scorecard
     * to {@code <rootFolder>/reports/<target>-qc-report.md}.
     *
     * @param targetFilter one or more comma-separated plugin/mod names or {@code "all"}
     * @param episodes     episode budget ({@code <= 0} uses {@link LeafFuzzConfig#defaultEpisodes()})
     * @return completed {@link LeafFuzzScorecardReport}
     */
    public LeafFuzzScorecardReport runQcCheck(String targetFilter, int episodes) {
        return runQcCheck(targetFilter, episodes, this.config.defaultPlayers());
    }

    /**
     * Executes the 4-stage automated QC check ({@code /fuzz check <target>}) with a concurrent
     * player survival roster of {@code players} simultaneous online bots dispersed across an
     * Archimedean spiral ({@code S-005}).
     *
     * @param targetFilter one or more comma-separated plugin/mod names or {@code "all"}
     * @param episodes     episode budget ({@code <= 0} uses {@link LeafFuzzConfig#defaultEpisodes()})
     * @param players      concurrent player roster target ({@code <= 0} uses {@link LeafFuzzConfig#defaultPlayers()})
     * @return completed {@link LeafFuzzScorecardReport}
     */
    public LeafFuzzScorecardReport runQcCheck(String targetFilter, int episodes, int players) {
        long t0 = System.currentTimeMillis();
        String effTarget = (targetFilter == null || targetFilter.isBlank()) ? "all" : targetFilter.trim();
        this.activeTargetFilter = effTarget;
        int effEpisodes = episodes > 0 ? episodes : this.config.defaultEpisodes();
        int rawPlayers = (players == 0) ? this.config.defaultPlayers() : players;
        boolean autoRamp = (rawPlayers == AUTO_RAMP_PLAYERS);
        int effPlayers = autoRamp
                ? Math.max(100, this.config.defaultPlayers())
                : Math.max(1, Math.min(500, rawPlayers > 0 ? rawPlayers : this.config.defaultPlayers()));
        resetRunTelemetry(effPlayers);

        // Stage 1: Command & Least-Privilege Surface Audit
        CommandAuditReport cmdAudit = auditCommandSurface(effTarget);
        int auditedNodes = cmdAudit.totalNodes();
        int defaultNodes = cmdAudit.defaultTierNodes();

        // Stage 2: Boundary & Lifecycle Fuzz Pass + Concurrent Roster Survival / Ramp-to-Instability
        List<DualAudienceMitigationReport> shrunkReproducers = new ArrayList<>();
        int executedEpisodes = 0;
        int distinctArms = 0;
        SwarmRosterController swarm = resolveSwarmController();

        try {
            if (!cmdAudit.commandTree().executableAllowedNodes().isEmpty() && effEpisodes > 0) {
                SleuthServerFuzzer fuzzer = new SleuthServerFuzzer(
                        cmdAudit.commandTree(),
                        this.ownershipIndex,
                        List.of("default", "op"),
                        NodeBandit.DEFAULT_FOLLOW_UP_SHAPES,
                        new Random(1337L)
                );
                distinctArms = fuzzer.bandit().armCount();
                if (distinctArms > 0) {
                    SleuthServerFuzzer.EpisodeRunner runner = this.customEpisodeRunner != null
                            ? this.customEpisodeRunner
                            : (this.platformEpisodeRunner != null ? this.platformEpisodeRunner : this::executeLiveEpisode);
                    boolean sampleLiveRetention = (this.customEpisodeRunner == null && this.platformEpisodeRunner != null && effEpisodes >= 3);
                    if (sampleLiveRetention) {
                        captureQuietLiveSnapshot("qc-baseline");
                        int batches = effPlayers > 1 ? 4 : 3;
                        List<Integer> rampSchedule = computePlayerRampSchedule(autoRamp ? AUTO_RAMP_PLAYERS : effPlayers, batches);
                        boolean rampHalted = false;
                        int baseBatch = effEpisodes / batches;
                        int rem = effEpisodes % batches;
                        for (int b = 0; b < batches; b++) {
                            if (effPlayers > 1 && !rampHalted) {
                                int stepPop = rampSchedule.get(Math.min(b, rampSchedule.size() - 1));
                                rampSwarmAndRecord(swarm, stepPop);
                            }
                            int count = baseBatch + (b < rem ? 1 : 0);
                            for (int i = 0; i < count; i++) {
                                fuzzer.runSingleEpisode(runner);
                                executedEpisodes++;
                            }
                            if (effPlayers > 1 && !rampHalted) {
                                int stepPop = rampSchedule.get(Math.min(b, rampSchedule.size() - 1));
                                stepSwarmAndRecord(swarm, Math.max(1, stepPop / 10));
                                if (!evaluateStepStability(stepPop, effTarget)) {
                                    rampHalted = true;
                                }
                            }
                            captureQuietLiveSnapshot("qc-batch-" + (b + 1));
                        }
                        shrunkReproducers.addAll(filterReproducersForTarget(fuzzer.findings(), effTarget, this.ownershipIndex));
                    } else if (effPlayers > 1) {
                        List<Integer> rampSchedule = computePlayerRampSchedule(autoRamp ? AUTO_RAMP_PLAYERS : effPlayers, 4);
                        int steps = rampSchedule.size();
                        int baseBatch = effEpisodes / steps;
                        int rem = effEpisodes % steps;
                        boolean rampHalted = false;
                        for (int s = 0; s < steps; s++) {
                            int stepPop = rampSchedule.get(s);
                            if (!rampHalted) {
                                rampSwarmAndRecord(swarm, stepPop);
                            }
                            int count = baseBatch + (s < rem ? 1 : 0);
                            for (int i = 0; i < count; i++) {
                                fuzzer.runSingleEpisode(runner);
                                executedEpisodes++;
                            }
                            if (!rampHalted) {
                                stepSwarmAndRecord(swarm, Math.max(1, stepPop / 10));
                                if (!evaluateStepStability(stepPop, effTarget)) {
                                    rampHalted = true;
                                }
                            }
                        }
                        shrunkReproducers.addAll(filterReproducersForTarget(fuzzer.findings(), effTarget, this.ownershipIndex));
                    } else {
                        List<DualAudienceMitigationReport> campaignFindings = fuzzer.runCampaign(effEpisodes, runner);
                        shrunkReproducers.addAll(filterReproducersForTarget(campaignFindings, effTarget, this.ownershipIndex));
                        executedEpisodes = effEpisodes;
                    }
                }
            } else if (effEpisodes > 0 && effPlayers > 1) {
                List<Integer> rampSchedule = computePlayerRampSchedule(autoRamp ? AUTO_RAMP_PLAYERS : effPlayers, 4);
                for (int stepPop : rampSchedule) {
                    rampSwarmAndRecord(swarm, stepPop);
                    stepSwarmAndRecord(swarm, Math.max(1, stepPop / 10));
                    if (!evaluateStepStability(stepPop, effTarget)) {
                        break;
                    }
                }
            }
        } finally {
            teardownSwarmSafe(swarm);
        }

        // Stage 3: Main-Thread Stall & Exception Signatures matching target(s)
        List<FaultSignature> targetFaults = filterFaultsForTarget(
                faultOracle.rankedSignatures(),
                effTarget,
                this.ownershipIndex
        );

        // Stage 4: Post-GC Class Retention Screen matching target(s)
        List<ClassRetentionFinding> targetLeaks = filterRetentionForTarget(
                retentionScreener.checkpointCount() >= ClassRetentionScreener.MIN_CHECKPOINTS
                        ? retentionScreener.screenClassGrowth()
                        : retentionScreener.latestFindings(),
                effTarget,
                this.ownershipIndex
        );

        long elapsed = Math.max(1L, System.currentTimeMillis() - t0);
        LeafFuzzScorecardReport.ExecutionTelemetry execTelemetry = buildExecutionTelemetry(effTarget);
        List<CausalFinding> causalFindings = auditCausalDelivery(effTarget);
        List<DualAudienceMitigationReport> finalReproducers = enrichReproducersWithAstLlm(shrunkReproducers, effTarget);
        LeafFuzzScorecardReport scorecard = new LeafFuzzScorecardReport(
                effTarget,
                accessor.getPlatform(),
                accessor.getServerVersion(),
                ownershipIndex.indexedJarCount(),
                auditedNodes,
                defaultNodes,
                cmdAudit.findings(),
                executedEpisodes,
                distinctArms,
                finalReproducers,
                targetFaults,
                retentionScreener.checkpointCount(),
                targetLeaks,
                elapsed,
                execTelemetry,
                causalFindings
        );
        this.latestScorecard = scorecard;
        try {
            scorecard.writeMarkdownReport(accessor.getRootFolder());
        } catch (IOException e) {
            accessor.log(Level.WARNING, "[LeafFuzz] Failed to write Markdown QC scorecard", e);
        }
        return scorecard;
    }

    /**
     * Executes the 4-stage automated QC check asynchronously across server ticks when a platform
     * {@link io.github.dailystruggle.server.api.TaskScheduler} is available, running episode batches
     * on the main thread, allowing server ticks to advance between batches so delayed warmup/async
     * callbacks fire after {@code quit_lt1s}, and capturing post-GC {@link ClassRetentionScreener}
     * histograms off-thread ({@code S-005}). Falls back to synchronous {@link #runQcCheck(String, int)}
     * in headless unit tests.
     *
     * @param targetFilter one or more comma-separated plugin/mod names or {@code "all"}
     * @param episodes     episode budget ({@code <= 0} uses {@link LeafFuzzConfig#defaultEpisodes()})
     * @param onComplete   callback invoked with the completed {@link LeafFuzzScorecardReport}
     */
    public void runQcCheckAsync(
            String targetFilter,
            int episodes,
            Consumer<LeafFuzzScorecardReport> onComplete
    ) {
        runQcCheckAsync(targetFilter, episodes, this.config.defaultPlayers(), onComplete);
    }

    /**
     * Executes the 4-stage automated QC check asynchronously with a concurrent player survival
     * roster of {@code players} simultaneous online bots dispersed across an Archimedean spiral.
     *
     * @param targetFilter one or more comma-separated plugin/mod names or {@code "all"}
     * @param episodes     episode budget ({@code <= 0} uses {@link LeafFuzzConfig#defaultEpisodes()})
     * @param players      concurrent player roster target ({@code <= 0} uses {@link LeafFuzzConfig#defaultPlayers()})
     * @param onComplete   callback invoked with the completed {@link LeafFuzzScorecardReport}
     */
    public void runQcCheckAsync(
            String targetFilter,
            int episodes,
            int players,
            Consumer<LeafFuzzScorecardReport> onComplete
    ) {
        int rawPlayers = (players == 0) ? this.config.defaultPlayers() : players;
        boolean autoRamp = (rawPlayers == AUTO_RAMP_PLAYERS);
        int effPlayers = autoRamp
                ? Math.max(100, this.config.defaultPlayers())
                : Math.max(1, Math.min(500, rawPlayers > 0 ? rawPlayers : this.config.defaultPlayers()));
        if (accessor.scheduler().isEmpty() || this.customEpisodeRunner != null) {
            LeafFuzzScorecardReport card = runQcCheck(targetFilter, episodes, rawPlayers);
            if (onComplete != null) {
                onComplete.accept(card);
            }
            return;
        }
        long t0 = System.currentTimeMillis();
        String effTarget = (targetFilter == null || targetFilter.isBlank()) ? "all" : targetFilter.trim();
        this.activeTargetFilter = effTarget;
        int effEpisodes = episodes > 0 ? episodes : this.config.defaultEpisodes();
        resetRunTelemetry(effPlayers);
        faultOracle.clear();

        Map<String, List<RawCommandNode>> rawGraphs = inspectLiveCommandGraphs();
        io.github.dailystruggle.server.api.TaskScheduler sched = accessor.scheduler().get();
        sched.runAsync(() -> {
            if (this.ownershipIndex.indexedJarCount() == 0) {
                refreshJarOwnershipIndexNow();
            }
            Map<String, List<RawCommandNode>> filteredGraphs = BrigadierDispatcherInspector.filterTierGraphsForTarget(
                    rawGraphs,
                    effTarget,
                    this.ownershipIndex
            );
            List<CommandSurfaceAuditor.WhiteBoxCommandHint> whiteBoxHints = resolveWhiteBoxCommandHints(effTarget);
            CommandAuditReport cmdAudit = CommandSurfaceAuditor.auditCommandSurface(
                    filteredGraphs,
                    this.config.extraDenylist(),
                    this.ownershipIndex,
                    whiteBoxHints
            );
            int auditedNodes = cmdAudit.totalNodes();
            int defaultNodes = cmdAudit.defaultTierNodes();
            List<DualAudienceMitigationReport> shrunkReproducers = new ArrayList<>();
            int executedEpisodes = 0;
            int distinctArms = 0;
            SwarmRosterController swarm = resolveSwarmController();

            try {
                if (!cmdAudit.commandTree().executableAllowedNodes().isEmpty() && effEpisodes > 0) {
                    List<SleuthServerFuzzer> targetFuzzers = buildStratifiedTargetFuzzers(effTarget, cmdAudit);
                    this.activeTargetFuzzers = targetFuzzers;
                    for (SleuthServerFuzzer tf : targetFuzzers) {
                        distinctArms += tf.bandit().armCount();
                    }
                    if (distinctArms > 0 && !targetFuzzers.isEmpty()) {
                        SleuthServerFuzzer.EpisodeRunner runner = this.platformEpisodeRunner != null
                                ? this.platformEpisodeRunner
                                : this::executeLiveEpisode;
                        retentionScreener.reset();
                        captureQuietLiveSnapshot("qc-baseline");
                        sampleIdleWindowWithTelemetry(2000L);
                        captureQuietLiveSnapshot("qc-idle-control");

                        List<Integer> batchSizes = new ArrayList<>();
                        if (effEpisodes <= 60) {
                            int[] batchWeights = {1, 2, 3};
                            int weightSum = 6;
                            int rem = effEpisodes;
                            for (int b = 0; b < batchWeights.length && rem > 0; b++) {
                                int c = (b == batchWeights.length - 1)
                                        ? rem
                                        : Math.max(1, Math.min(rem, Math.round((float) effEpisodes * batchWeights[b] / weightSum)));
                                rem -= c;
                                batchSizes.add(c);
                            }
                        } else {
                            int rem = effEpisodes;
                            int stepBatch = 25;
                            while (rem > 0) {
                                int c = Math.min(stepBatch, rem);
                                batchSizes.add(c);
                                rem -= c;
                            }
                        }

                        List<Integer> rampSchedule = computePlayerRampSchedule(
                                autoRamp ? AUTO_RAMP_PLAYERS : effPlayers,
                                batchSizes.size()
                        );
                        boolean rampHalted = false;
                        int rrCursor = 0;
                        for (int b = 0; b < batchSizes.size(); b++) {
                            if (effPlayers > 1 && !rampHalted) {
                                int stepPop = rampSchedule.get(Math.min(b, rampSchedule.size() - 1));
                                rampSwarmAndRecord(swarm, stepPop);
                                resetTickStartNanos();
                            }
                            int count = batchSizes.get(b);
                            final int startCursor = rrCursor;
                            rrCursor += count;
                            for (int i = 0; i < count; i++) {
                                SleuthServerFuzzer activeFuzzer = targetFuzzers.get((startCursor + i) % targetFuzzers.size());
                                try {
                                    activeFuzzer.runSingleEpisode(runner);
                                    executedEpisodes++;
                                } catch (Throwable ex) {
                                    accessor.log(Level.FINE, "[LeafFuzz] Episode execution exception: " + ex.getMessage(), ex);
                                }
                                sampleMainThreadIfStalled();
                            }
                            if (effPlayers > 1 && !rampHalted) {
                                int stepPop = rampSchedule.get(Math.min(b, rampSchedule.size() - 1));
                                stepSwarmAndRecord(swarm, Math.max(1, stepPop / 10));
                                if (!evaluateStepStability(stepPop, effTarget)) {
                                    rampHalted = true;
                                }
                            }
                            faultOracle.detectDeadlocksAndStuckWorkers(System.nanoTime());
                            boolean shouldCaptureGc = (effEpisodes <= 60)
                                    || (b < 4)
                                    || ((b + 1) % 4 == 0)
                                    || (b == batchSizes.size() - 1);
                            if (shouldCaptureGc) {
                                try {
                                    Thread.sleep(1200L);
                                } catch (InterruptedException ie) {
                                    Thread.currentThread().interrupt();
                                    break;
                                }
                                captureQuietLiveSnapshot("qc-batch-" + (b + 1));
                            }
                            // Publish live interim scorecard & Markdown report after every batch so /fuzz report works mid-run
                            List<DualAudienceMitigationReport> interimRepros = new ArrayList<>();
                            for (SleuthServerFuzzer tf : targetFuzzers) {
                                interimRepros.addAll(filterReproducersForTarget(tf.findings(), effTarget, this.ownershipIndex));
                            }
                            List<FaultSignature> interimFaults = filterFaultsForTarget(
                                    faultOracle.rankedSignatures(),
                                    effTarget,
                                    this.ownershipIndex
                            );
                            List<ClassRetentionFinding> interimLeaks = filterRetentionForTarget(
                                    retentionScreener.checkpointCount() >= ClassRetentionScreener.MIN_CHECKPOINTS
                                            ? retentionScreener.screenClassGrowth()
                                            : retentionScreener.latestFindings(),
                                    effTarget,
                                    this.ownershipIndex
                            );
                            long interimElapsed = Math.max(1L, System.currentTimeMillis() - t0);
                            LeafFuzzScorecardReport.ExecutionTelemetry interimTel = buildExecutionTelemetry(effTarget);
                            LeafFuzzScorecardReport interimCard = new LeafFuzzScorecardReport(
                                    effTarget,
                                    accessor.getPlatform(),
                                    accessor.getServerVersion(),
                                    ownershipIndex.indexedJarCount(),
                                    auditedNodes,
                                    defaultNodes,
                                    cmdAudit.findings(),
                                    executedEpisodes,
                                    distinctArms,
                                    interimRepros,
                                    interimFaults,
                                    retentionScreener.checkpointCount(),
                                    interimLeaks,
                                    interimElapsed,
                                    interimTel
                            );
                            this.latestScorecard = interimCard;
                            try {
                                interimCard.writeMarkdownReport(accessor.getRootFolder());
                            } catch (IOException ex) {
                                accessor.log(Level.FINE, "[LeafFuzz] Interim Markdown report write failed: " + ex.getMessage(), ex);
                            }
                            if (effEpisodes > 60) {
                                String topMenu = interimTel.clickedMenuItems().isEmpty()
                                        ? "none"
                                        : interimTel.clickedMenuItems().get(0);
                                accessor.log(
                                        Level.INFO,
                                        String.format(
                                                Locale.ROOT,
                                                "[LeafFuzz] [Checkpoint %d/%d] ep=%d/%d (%.1fs) | bots=%d (concurrent=%d/%d), menus=%d/%d clk, tp=%d (max %.0fb), mspt p95=%.1f, heap=%.1fMB, CPs=%d, leaks=%d | topSlot=%s",
                                                b + 1,
                                                batchSizes.size(),
                                                executedEpisodes,
                                                effEpisodes,
                                                interimElapsed / 1000.0,
                                                interimTel.botsSpawned(),
                                                interimTel.peakConcurrentPlayers(),
                                                interimTel.targetConcurrentPlayers(),
                                                interimTel.menusOpened(),
                                                interimTel.menuSlotsClicked(),
                                                interimTel.teleportsObserved(),
                                                interimTel.maxTeleportDistanceBlocks(),
                                                interimTel.fuzzMsptP95(),
                                                interimTel.finalHeapMb(),
                                                retentionScreener.checkpointCount(),
                                                interimLeaks.size(),
                                                topMenu
                                        )
                                );
                            }
                        }
                        for (SleuthServerFuzzer tf : targetFuzzers) {
                            shrunkReproducers.addAll(
                                    filterReproducersForTarget(tf.findings(), effTarget, this.ownershipIndex)
                            );
                        }
                    }
                } else if (effEpisodes > 0 && effPlayers > 1) {
                    rampSwarmAndRecord(swarm, effPlayers);
                    stepSwarmAndRecord(swarm, Math.max(1, effPlayers / 10));
                }
            } finally {
                teardownSwarmSafe(swarm);
            }
            if (executedEpisodes > 0) {
                try {
                    Thread.sleep(600L);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                captureQuietLiveSnapshot("qc-post-teardown");
                double baselineIdleP95;
                synchronized (telemetryLock) {
                    baselineIdleP95 = computePercentile(obsIdleMsptSamples, 0.95);
                }
                if (baselineIdleP95 > 0.0 && effPlayers <= 1) {
                    List<Double> cooldownSamples = new ArrayList<>();
                    long cdDeadline = System.currentTimeMillis() + 500L;
                    while (System.currentTimeMillis() < cdDeadline) {
                        double m = currentServerMspt();
                        if (m > 0.0) {
                            cooldownSamples.add(m);
                        }
                        try {
                            Thread.sleep(50L);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                    double postRunIdleP95 = computePercentile(cooldownSamples, 0.95);
                    faultOracle.recordRepeatingTaskMsptCreep(effTarget, baselineIdleP95, postRunIdleP95);
                }
            }

            List<FaultSignature> targetFaults = filterFaultsForTarget(
                    faultOracle.rankedSignatures(),
                    effTarget,
                    this.ownershipIndex
            );
            List<ClassRetentionFinding> targetLeaks = filterRetentionForTarget(
                    retentionScreener.checkpointCount() >= ClassRetentionScreener.MIN_CHECKPOINTS
                            ? retentionScreener.screenClassGrowth()
                            : retentionScreener.latestFindings(),
                    effTarget,
                    this.ownershipIndex
            );

            long elapsed = Math.max(1L, System.currentTimeMillis() - t0);
            LeafFuzzScorecardReport.ExecutionTelemetry execTelemetry = buildExecutionTelemetry(effTarget);
            List<CausalFinding> causalFindings = auditCausalDelivery(effTarget);
            List<DualAudienceMitigationReport> finalReproducers = enrichReproducersWithAstLlm(shrunkReproducers, effTarget);
            LeafFuzzScorecardReport scorecard = new LeafFuzzScorecardReport(
                    effTarget,
                    accessor.getPlatform(),
                    accessor.getServerVersion(),
                    ownershipIndex.indexedJarCount(),
                    auditedNodes,
                    defaultNodes,
                    cmdAudit.findings(),
                    executedEpisodes,
                    distinctArms,
                    finalReproducers,
                    targetFaults,
                    retentionScreener.checkpointCount(),
                    targetLeaks,
                    elapsed,
                    execTelemetry,
                    causalFindings
            );
            this.latestScorecard = scorecard;
            try {
                scorecard.writeMarkdownReport(accessor.getRootFolder());
            } catch (IOException e) {
                accessor.log(Level.WARNING, "[LeafFuzz] Failed to write Markdown QC scorecard", e);
            }
            if (onComplete != null) {
                sched.runSync(() -> onComplete.accept(scorecard));
            }
        });
    }

    private EpisodeOutcome executeLiveEpisode(List<EpisodeAction> actions) {
        if (actions == null || actions.isEmpty()) {
            return EpisodeOutcome.clean();
        }
        long exceptionsBefore = faultOracle.totalExceptionsRecorded();
        long stallsBefore = faultOracle.totalStallsRecorded();
        List<String> capturedOutput = new ArrayList<>();
        List<String> observedTokens = new ArrayList<>();
        boolean usageError = false;

        String primaryTier = actions.get(0).tier();
        PersonaPolicyBotActor bot = spawnPersonaBotActor(primaryTier);
        // Step autonomous policy once before command sequence to establish realistic player state
        BotStepRecord preStep = bot.stepAutonomousPolicy();
        recordRecentBotStep(preStep);
        observedTokens.add("persona:" + bot.persona().taxonomyArchetype());
        observedTokens.add("skill:" + preStep.selectedSkill());

        for (EpisodeAction action : actions) {
            String rawCmd = action.commandLine();
            if (rawCmd == null || rawCmd.isBlank()) {
                continue;
            }
            String cleanCmd = bot.prepareCommandForDispatch(rawCmd);
            if (cleanCmd.isEmpty()) {
                continue;
            }
            // Double-check DEFAULT_DENYLIST before dispatching any command
            String lower = cleanCmd.trim().toLowerCase(Locale.ROOT);
            if (lower.equals("stop")
                    || lower.startsWith("stop ")
                    || lower.equals("restart")
                    || lower.startsWith("restart ")
                    || lower.startsWith("op ")
                    || lower.startsWith("deop ")
                    || lower.startsWith("ban")
                    || lower.startsWith("kick ")
                    || lower.startsWith("reload")) {
                continue;
            }

            String shape = action.followUpShape() != null
                    ? action.followUpShape().trim().toLowerCase(Locale.ROOT)
                    : "repeat";
            int dispatches = switch (shape) {
                case "repeat" -> 2;
                case "concurrent" -> 3;
                default -> 1;
            };

            long t0 = System.nanoTime();
            for (int d = 0; d < dispatches; d++) {
                retentionScreener.recordCommandExecution();
                try {
                    if (!dispatchViaBrigadierIfAvailable(cleanCmd, bot, capturedOutput)) {
                        accessor.executeCommandWithCapture(cleanCmd, capturedOutput::add);
                    }
                } catch (Throwable t) {
                    FaultSignature sig = faultOracle.recordThrowable(t, "Command dispatch: /" + cleanCmd);
                    return EpisodeOutcome.fault(
                            sig.signatureId(),
                            sig.suspectJar(),
                            0.0,
                            (System.nanoTime() - t0) / 1_000_000.0,
                            List.of(sig.topPluginFrame())
                    );
                }
            }

            BotStepRecord followStep = bot.performFollowUpBehavior(shape);
            recordRecentBotStep(followStep);
            observedTokens.add("followup:" + followStep.selectedSkill());
            if (!followStep.online()) {
                retentionScreener.recordPlayerDeparture();
            }
        }

        for (String line : capturedOutput) {
            String low = line.toLowerCase(Locale.ROOT);
            if (low.contains("unknown command") || low.contains("usage:") || low.contains("invalid argument")) {
                usageError = true;
                break;
            }
        }

        if (faultOracle.totalExceptionsRecorded() > exceptionsBefore
                || faultOracle.totalStallsRecorded() > stallsBefore) {
            List<FaultSignature> ranked = faultOracle.rankedSignatures();
            if (!ranked.isEmpty()) {
                FaultSignature latest = ranked.get(0);
                return EpisodeOutcome.fault(
                        latest.signatureId(),
                        latest.suspectJar(),
                        0.0,
                        latest.maxDurationMs(),
                        List.of(latest.topPluginFrame())
                );
            }
        }

        return new EpisodeOutcome(
                false,
                null,
                null,
                0.0,
                0.0,
                observedTokens,
                usageError
        );
    }

    private void recordRecentBotStep(BotStepRecord step) {
        if (step == null) {
            return;
        }
        recentBotSteps.add(step);
        while (recentBotSteps.size() > 64) {
            recentBotSteps.remove(0);
        }
    }

    /**
     * Records a synthetic persona bot step from a platform episode runner.
     *
     * @param step executed bot step record
     */
    public void recordPlatformBotStep(BotStepRecord step) {
        recordRecentBotStep(step);
    }

    @SuppressWarnings("unchecked")
    private boolean dispatchViaBrigadierIfAvailable(
            String cleanCmd,
            PersonaPolicyBotActor bot,
            List<String> capturedOutput
    ) {
        Supplier<Object> brigSupplier = this.brigadierDispatcherSupplier;
        if (brigSupplier == null) {
            return false;
        }
        try {
            Object dispatcher = brigSupplier.get();
            if (dispatcher == null) {
                return false;
            }
            Object syntheticSource = BrigadierSyntheticSourceFactory.createSource(
                    Object.class,
                    bot.actorUuid(),
                    bot.actorName(),
                    bot.isOp(),
                    bot.x(),
                    bot.y(),
                    bot.z()
            );
            if (dispatcher instanceof com.mojang.brigadier.CommandDispatcher<?> brigDispatcher) {
                ((com.mojang.brigadier.CommandDispatcher<Object>) brigDispatcher).execute(cleanCmd, syntheticSource);
                return true;
            }
            if (dispatcher instanceof BrigadierSyntheticSourceFactory.BrigadierExecutableDispatcher execDispatcher) {
                execDispatcher.execute(cleanCmd, syntheticSource);
                return true;
            }
        } catch (com.mojang.brigadier.exceptions.CommandSyntaxException cse) {
            capturedOutput.add("Invalid argument: " + cse.getMessage());
            return true;
        } catch (RuntimeException re) {
            throw re;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
        return false;
    }

    private List<SleuthServerFuzzer> buildStratifiedTargetFuzzers(
            String effTarget,
            CommandAuditReport combinedAudit
    ) {
        List<String> selectors = BrigadierDispatcherInspector.parseTargetSelectors(effTarget);
        if (selectors.size() <= 1) {
            return List.of(new SleuthServerFuzzer(
                    combinedAudit.commandTree(),
                    this.ownershipIndex,
                    List.of("default", "op"),
                    NodeBandit.DEFAULT_FOLLOW_UP_SHAPES,
                    new Random(1337L)
            ));
        }
        List<SleuthServerFuzzer> fuzzers = new ArrayList<>(selectors.size());
        long seed = 1337L;
        for (String sel : selectors) {
            CommandAuditReport subAudit = auditCommandSurface(sel);
            if (!subAudit.commandTree().executableAllowedNodes().isEmpty()) {
                SleuthServerFuzzer tf = new SleuthServerFuzzer(
                        subAudit.commandTree(),
                        this.ownershipIndex,
                        List.of("default", "op"),
                        NodeBandit.DEFAULT_FOLLOW_UP_SHAPES,
                        new Random(seed++)
                );
                if (tf.bandit().armCount() > 0) {
                    fuzzers.add(tf);
                }
            }
        }
        if (fuzzers.isEmpty()) {
            return List.of(new SleuthServerFuzzer(
                    combinedAudit.commandTree(),
                    this.ownershipIndex,
                    List.of("default", "op"),
                    NodeBandit.DEFAULT_FOLLOW_UP_SHAPES,
                    new Random(1337L)
            ));
        }
        return fuzzers;
    }

    private void captureQuietLiveSnapshot(String label) {
        try {
            if (!retentionScreener.isSnapshotBusy()) {
                retentionScreener.captureLiveSnapshot(label);
            }
        } catch (Throwable ex) {
            accessor.log(Level.FINE, "[LeafFuzz] Live snapshot capture skipped (" + label + "): " + ex.getMessage(), ex);
        }
    }

    private static List<DualAudienceMitigationReport> filterReproducersForTarget(
            List<DualAudienceMitigationReport> all,
            String target,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (all == null || all.isEmpty()) {
            return List.of();
        }
        if (BrigadierDispatcherInspector.parseTargetSelectors(target).isEmpty()) {
            return all;
        }
        List<DualAudienceMitigationReport> out = new ArrayList<>();
        for (DualAudienceMitigationReport r : all) {
            String jar = r.suspectJar();
            if (jar == null || jar.isBlank() || "unknown".equalsIgnoreCase(jar) || "server".equalsIgnoreCase(jar)) {
                out.add(r);
            } else if (BrigadierDispatcherInspector.matchesTargetIdentifier(
                    jar,
                    r.signatureId(),
                    target,
                    ownershipIndex
            )) {
                out.add(r);
            }
        }
        return List.copyOf(out);
    }

    private static List<FaultSignature> filterFaultsForTarget(
            List<FaultSignature> all,
            String target,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (all == null || all.isEmpty()) {
            return List.of();
        }
        if (BrigadierDispatcherInspector.parseTargetSelectors(target).isEmpty()) {
            return all;
        }
        List<FaultSignature> out = new ArrayList<>();
        for (FaultSignature s : all) {
            if (BrigadierDispatcherInspector.matchesTargetIdentifier(
                    s.suspectJar(),
                    s.topPluginFrame(),
                    target,
                    ownershipIndex
            )) {
                out.add(s);
            }
        }
        return List.copyOf(out);
    }

    private static List<ClassRetentionFinding> filterRetentionForTarget(
            List<ClassRetentionFinding> all,
            String target,
            JarClassOwnershipIndex ownershipIndex
    ) {
        if (all == null || all.isEmpty()) {
            return List.of();
        }
        boolean hasIndexedJars = ownershipIndex != null && ownershipIndex.indexedJarCount() > 0;
        if (BrigadierDispatcherInspector.parseTargetSelectors(target).isEmpty()) {
            if (!hasIndexedJars) {
                return all;
            }
            List<ClassRetentionFinding> pluginOnly = new ArrayList<>();
            for (ClassRetentionFinding f : all) {
                if (f.isPluginOwned() && (f.peakInstances() - f.baselineInstances()) >= 4L) {
                    pluginOnly.add(f);
                }
            }
            return List.copyOf(pluginOnly);
        }
        List<ClassRetentionFinding> out = new ArrayList<>();
        for (ClassRetentionFinding f : all) {
            if (hasIndexedJars && (f.peakInstances() - f.baselineInstances()) < 4L) {
                continue;
            }
            if (BrigadierDispatcherInspector.matchesTargetIdentifier(
                    f.owningJar(),
                    f.className(),
                    target,
                    ownershipIndex
            )) {
                out.add(f);
            }
        }
        return List.copyOf(out);
    }

    /**
     * Validates and reloads {@code config.yml} and {@code messages.yml}.
     *
     * @return list of validation errors (empty when reload succeeded)
     */
    public List<String> reloadAndValidate() {
        Path root = accessor.getRootFolder();
        List<String> errors = LeafFuzzConfig.validateDirectory(root);
        if (!errors.isEmpty()) {
            return errors;
        }
        this.config = LeafFuzzConfig.load(root);
        this.faultOracle.setSlowTickThresholdMs(this.config.slowTickThresholdMs());
        refreshJarOwnershipIndexAsync();
        return List.of();
    }

    public ServerAccessor accessor() {
        return accessor;
    }

    public LeafFuzzConfig config() {
        return config;
    }

    public JarClassOwnershipIndex ownershipIndex() {
        return ownershipIndex;
    }

    public ClassRetentionScreener retentionScreener() {
        return retentionScreener;
    }

    public LogAndStallSignatureOracle faultOracle() {
        return faultOracle;
    }

    public LeafFuzzBitSuite bitSuite() {
        return bitSuite;
    }

    public FuzzCampaignStateStore campaignStateStore() {
        if (campaignStateStore == null) {
            campaignStateStore = FuzzCampaignStateStore.forDataFolder(accessor.getRootFolder());
        }
        return campaignStateStore;
    }

    public LeafFuzzScorecardReport latestScorecard() {
        return latestScorecard;
    }

    public String activeTargetFilter() {
        return activeTargetFilter;
    }

    public AtomicBoolean checkRunning() {
        return checkRunning;
    }

    private SwarmRosterController resolveSwarmController() {
        SwarmRosterController plat = this.platformSwarmController;
        return plat != null ? plat : new VirtualPersonaSwarmController(this);
    }

    /**
     * Builds a monotonically increasing concurrent player ramp schedule up to the requested
     * ceiling (or {@code 10 -> 25 -> 50 -> 75 -> 100} in {@link #AUTO_RAMP_PLAYERS} mode).
     */
    public static List<Integer> computePlayerRampSchedule(int players, int batches) {
        int steps = Math.max(1, batches);
        if (players == AUTO_RAMP_PLAYERS) {
            int[] defaultLadder = {10, 25, 50, 75, 100};
            if (steps <= defaultLadder.length) {
                List<Integer> out = new ArrayList<>(steps);
                for (int i = 0; i < steps; i++) {
                    int idx = (i == steps - 1)
                            ? defaultLadder.length - 1
                            : (i * (defaultLadder.length - 1)) / Math.max(1, steps - 1);
                    out.add(defaultLadder[idx]);
                }
                return out;
            }
            List<Integer> out = new ArrayList<>(steps);
            for (int i = 0; i < steps; i++) {
                int pop = Math.max(10, Math.round(100.0f * (i + 1) / steps));
                out.add(pop);
            }
            return out;
        }
        int ceiling = Math.max(1, Math.min(500, players));
        if (ceiling <= 1 || steps <= 1) {
            return List.of(ceiling);
        }
        List<Integer> schedule = new ArrayList<>(steps);
        for (int i = 0; i < steps; i++) {
            int pop = (i == steps - 1)
                    ? ceiling
                    : Math.max(1, Math.round((float) ceiling * (i + 1) / steps));
            schedule.add(pop);
        }
        return schedule;
    }

    private boolean evaluateStepStability(int stepPop, String targetFilter) {
        double liveMspt = currentServerMspt();
        if (liveMspt > 0.0) {
            synchronized (telemetryLock) {
                if (obsFuzzMsptSamples.size() < 4096) {
                    obsFuzzMsptSamples.add(liveMspt);
                }
            }
        }
        List<FaultSignature> targetFaults = filterFaultsForTarget(
                faultOracle.rankedSignatures(),
                targetFilter,
                this.ownershipIndex
        );
        synchronized (telemetryLock) {
            if (!targetFaults.isEmpty()) {
                FaultSignature sig = targetFaults.get(0);
                if (this.obsInstabilityTrigger.isEmpty()) {
                    this.obsInstabilityTrigger = String.format(
                            Locale.ROOT,
                            "fault:%s (%s) at %d players",
                            sig.signatureId(),
                            sig.suspectJar(),
                            stepPop
                    );
                }
                return false;
            }
            double p95 = computePercentile(obsFuzzMsptSamples, 0.95);
            double effectiveMspt = Math.max(liveMspt, p95);
            if (effectiveMspt > 55.0) {
                if (this.obsInstabilityTrigger.isEmpty()) {
                    this.obsInstabilityTrigger = String.format(
                            Locale.ROOT,
                            "mspt_p95=%.1fms (>55.0ms) at %d players",
                            effectiveMspt,
                            stepPop
                    );
                }
                return false;
            }
            if (this.obsPeakConcurrentPlayers >= stepPop) {
                this.obsMaxStablePlayers = Math.max(this.obsMaxStablePlayers, stepPop);
            }
            return true;
        }
    }

    private void rampSwarmAndRecord(SwarmRosterController swarm, int targetPlayers) {
        if (swarm == null || targetPlayers <= 0) {
            return;
        }
        try {
            SwarmSnapshot snap = swarm.rampToPopulation(targetPlayers);
            if (snap != null) {
                recordSwarmTelemetry(snap.onlinePlayers(), snap.loadedChunks(), snap.trackedEntities());
                synchronized (telemetryLock) {
                    this.obsBotsSpawned += Math.max(0, snap.onlinePlayers());
                    this.obsBlockSkillsExecuted += Math.max(0, snap.backgroundActionsExecuted());
                }
            }
        } catch (Throwable ex) {
            accessor.log(Level.FINE, "[LeafFuzz] Swarm ramp warning: " + ex.getMessage(), ex);
        }
    }

    private void stepSwarmAndRecord(SwarmRosterController swarm, int churnCount) {
        if (swarm == null) {
            return;
        }
        try {
            SwarmSnapshot snap = swarm.stepConcurrentSwarm(churnCount);
            if (snap != null) {
                recordSwarmTelemetry(snap.onlinePlayers(), snap.loadedChunks(), snap.trackedEntities());
                synchronized (telemetryLock) {
                    this.obsBotsSpawned += Math.max(0, snap.churnedDepartures());
                    this.obsBlockSkillsExecuted += Math.max(0, snap.backgroundActionsExecuted());
                }
            }
        } catch (Throwable ex) {
            accessor.log(Level.FINE, "[LeafFuzz] Swarm step warning: " + ex.getMessage(), ex);
        }
    }

    private void teardownSwarmSafe(SwarmRosterController swarm) {
        if (swarm == null) {
            return;
        }
        try {
            swarm.teardownAll();
        } catch (Throwable ex) {
            accessor.log(Level.FINE, "[LeafFuzz] Swarm teardown warning: " + ex.getMessage(), ex);
        }
    }

    /**
     * Platform-neutral spiral-dispersed persona swarm controller used when no live NMS server
     * is bound (or as a fallback in headless unit tests).
     */
    private static final class VirtualPersonaSwarmController implements SwarmRosterController {
        private final LeafFuzzRuntime runtime;
        private final List<PersonaPolicyBotActor> roster = new ArrayList<>();
        private final Set<String> activeChunks = new LinkedHashSet<>();
        private int churnCursor;

        VirtualPersonaSwarmController(LeafFuzzRuntime runtime) {
            this.runtime = runtime;
        }

        @Override
        public synchronized SwarmSnapshot rampToPopulation(int targetPlayers) {
            int clamped = Math.max(1, Math.min(500, targetPlayers));
            while (roster.size() < clamped) {
                int slot = roster.size();
                PersonaPolicyBotActor bot = runtime.spawnPersonaBotActor((slot & 7) == 0 ? "op" : "default");
                NmsEmbeddedPlayerSession.SpiralAnchor anchor = NmsEmbeddedPlayerSession.assignSpiralAnchor(bot, slot);
                markChunkNeighborhood(anchor.chunkX(), anchor.chunkZ());
                BotStepRecord step = bot.stepAutonomousPolicy();
                runtime.recordPlatformBotStep(step);
                roster.add(bot);
            }
            return new SwarmSnapshot(roster.size(), activeChunks.size(), roster.size() * 2, roster.size(), 0);
        }

        @Override
        public synchronized SwarmSnapshot stepConcurrentSwarm(int churnCount) {
            if (roster.isEmpty()) {
                return new SwarmSnapshot(0, 0, 0, 0, 0);
            }
            int actions = 0;
            for (PersonaPolicyBotActor bot : roster) {
                BotStepRecord step = bot.stepAutonomousPolicy();
                runtime.recordPlatformBotStep(step);
                markChunkNeighborhood(bot.x() >> 4, bot.z() >> 4);
                actions++;
            }
            int toChurn = Math.max(0, Math.min(roster.size(), churnCount));
            for (int c = 0; c < toChurn; c++) {
                int idx = Math.floorMod(churnCursor++, roster.size());
                runtime.retentionScreener().recordPlayerDeparture();
                PersonaPolicyBotActor replacement = runtime.spawnPersonaBotActor((idx & 7) == 0 ? "op" : "default");
                NmsEmbeddedPlayerSession.SpiralAnchor anchor = NmsEmbeddedPlayerSession.assignSpiralAnchor(replacement, idx);
                markChunkNeighborhood(anchor.chunkX(), anchor.chunkZ());
                roster.set(idx, replacement);
            }
            return new SwarmSnapshot(roster.size(), activeChunks.size(), roster.size() * 2, actions, toChurn);
        }

        @Override
        public synchronized SwarmSnapshot captureSnapshot() {
            return new SwarmSnapshot(roster.size(), activeChunks.size(), roster.size() * 2, 0, 0);
        }

        @Override
        public synchronized void teardownAll() {
            for (int i = 0; i < roster.size(); i++) {
                runtime.retentionScreener().recordPlayerDeparture();
            }
            roster.clear();
            activeChunks.clear();
        }

        private void markChunkNeighborhood(int cx, int cz) {
            for (int dx = -1; dx <= 1; dx++) {
                for (int dz = -1; dz <= 1; dz++) {
                    activeChunks.add((cx + dx) + "," + (cz + dz));
                }
            }
        }
    }

    @Override
    public void close() {
        started = false;
        teardownSwarmSafe(this.platformSwarmController);
        faultOracle.stopRootLoggerTap();
        for (AutoCloseable sub : subscriptions) {
            try {
                sub.close();
            } catch (Exception ex) {
                accessor.log(Level.FINE, "[LeafFuzz] Subscription close warning: " + ex.getMessage(), ex);
            }
        }
        subscriptions.clear();
    }
}
