package net.leaf.fuzz.common;

import io.github.dailystruggle.commandsapi.common.CommandsAPI;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.CausalGraphReport;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.ClaimDeliveryFinding;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.FindingKind;
import io.github.dailystruggle.rtp.common.bit.config.atlas.LlmCausalChainAuditor;
import io.github.dailystruggle.rtp.common.bit.config.atlas.LlmConfigDocSynthesizer.HttpTransport;
import io.github.dailystruggle.rtp.common.bit.config.atlas.LlmConfigDocSynthesizer.Provider;
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
import java.util.Collections;
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
     * Executes Stage 5 (First-Order &amp; Second-Order Causal Claim Delivery Audit) across matching
     * target plugin/mod archives, corroborating static {@code CLAIM_HOLLOW_COMMAND} findings with
     * live Stage 2 execution telemetry and optionally enriching with {@link LlmCausalChainAuditor}.
     *
     * @param targetFilter plugin/mod name, comma-separated list, or {@code "all"}
     * @return immutable list of {@link ClaimDeliveryFinding}s
     */
    public List<ClaimDeliveryFinding> auditClaimDelivery(String targetFilter) {
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

        List<ClaimDeliveryFinding> out = new ArrayList<>();
        for (CausalGraphReport report : matchedReports) {
            List<ClaimDeliveryFinding> baseFindings = llmAuditor != null
                    ? llmAuditor.enrichFindingsWithExplanations(report, this.config.llmAudit().maxChainsPerTarget())
                    : report.findings();
            for (ClaimDeliveryFinding f : baseFindings) {
                if (f.kind() == FindingKind.CLAIM_HOLLOW_COMMAND
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
        List<ClaimDeliveryFinding> claimFindings = auditClaimDelivery(effTarget);
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
                claimFindings
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
            List<ClaimDeliveryFinding> claimFindings = auditClaimDelivery(effTarget);
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
                    claimFindings
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
