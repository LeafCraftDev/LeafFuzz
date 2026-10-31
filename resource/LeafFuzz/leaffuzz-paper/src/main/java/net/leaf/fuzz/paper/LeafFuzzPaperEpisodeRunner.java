package net.leaf.fuzz.paper;

import net.leaf.fuzz.common.BrigadierDispatcherInspector;
import net.leaf.fuzz.common.LeafFuzzBitSuite;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.fuzz.common.NmsEmbeddedPlayerSession;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.BotStepRecord;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import org.bukkit.Bukkit;
import org.bukkit.Location;
import org.bukkit.Material;
import org.bukkit.Server;
import org.bukkit.World;
import org.bukkit.block.Block;
import org.bukkit.block.BlockFace;
import org.bukkit.block.BlockState;
import org.bukkit.block.data.BlockData;
import org.bukkit.command.CommandException;
import org.bukkit.command.CommandMap;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.HandlerList;
import org.bukkit.event.Listener;
import org.bukkit.event.block.Action;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.inventory.ClickType;
import org.bukkit.event.inventory.InventoryAction;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryCloseEvent;
import org.bukkit.event.inventory.InventoryType;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.inventory.EquipmentSlot;
import org.bukkit.inventory.Inventory;
import org.bukkit.inventory.InventoryHolder;
import org.bukkit.inventory.InventoryView;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.PlayerInventory;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.permissions.Permission;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.PluginManager;

import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Target-agnostic Paper / Spigot / Folia synthetic persona episode runner for {@code LeafFuzz}
 * ({@code ADR-125}, {@code leaffuzz-ADR-001}, {@code leafsleuth-ADR-002}, {@code leafsleuth-ADR-006}).
 *
 * <p>Spawns an in-JVM {@link PersonaPolicyBotActor} per episode, steps its 256-byte
 * {@code Int8[16x16]} policy genome, dispatches target commands through a target-agnostic
 * synthetic {@link Player} proxy (so commands requiring {@code sender instanceof Player} execute
 * their real player-context code paths across both {@code default} and {@code op} tiers), and
 * triggers platform lifecycle follow-up events ({@link PlayerQuitEvent}, {@link PlayerMoveEvent},
 * {@link InventoryCloseEvent}) without synchronous chunk loads ({@code S-005}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @governedBy leafsleuth-ADR-002
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-BIO-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-005
 */
public final class LeafFuzzPaperEpisodeRunner
        implements SleuthServerFuzzer.EpisodeRunner, LeafFuzzRuntime.SwarmRosterController {

    private final Server server;
    private final LeafFuzzRuntime runtime;
    private final Map<String, MenuExplorationState> menuExplorationByKey = new ConcurrentHashMap<>();
    private final List<LiveServerPlayerSession> activeSwarmSessions = new ArrayList<>();
    private final List<PersonaPolicyBotActor> activeSwarmActors = new ArrayList<>();
    private final Set<String> virtualSwarmChunks = ConcurrentHashMap.newKeySet();
    private int swarmChurnCursor;
    private volatile int cachedMainThreadChunks;
    private volatile int cachedMainThreadEntities;

    public LeafFuzzPaperEpisodeRunner(Server server, LeafFuzzRuntime runtime) {
        this.server = server;
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.runtime.setPlatformSwarmController(this);
    }

    @Override
    public synchronized LeafFuzzRuntime.SwarmSnapshot rampToPopulation(int targetPlayers) {
        int clamped = Math.max(1, Math.min(500, targetPlayers));
        Server targetServer = server != null ? server : safeBukkitServer();
        boolean canScheduleAcrossTicks = runtime.accessor().scheduler().isPresent()
                && !isPrimaryThread(targetServer);

        while (activeSwarmActors.size() < clamped) {
            int batchEnd = Math.min(clamped, activeSwarmActors.size() + 2);
            final int startSlot = activeSwarmActors.size();
            Runnable spawnBatch = () -> {
                for (int slot = startSlot; slot < batchEnd; slot++) {
                    runtime.resetTickStartNanos();
                    boolean op = (slot & 7) == 0;
                    PersonaPolicyBotActor bot = runtime.spawnPersonaBotActor(op ? "op" : "default");
                    NmsEmbeddedPlayerSession.SpiralAnchor anchor =
                            NmsEmbeddedPlayerSession.assignSpiralAnchor(bot, slot);
                    markVirtualChunkNeighborhood(anchor.chunkX(), anchor.chunkZ());
                    BotStepRecord step = bot.stepAutonomousPolicy();
                    runtime.recordPlatformBotStep(step);
                    LiveServerPlayerSession live = LiveServerPlayerSession.trySpawn(
                            targetServer,
                            bot,
                            op,
                            1000 + slot
                    );
                    activeSwarmActors.add(bot);
                    activeSwarmSessions.add(live);
                    runtime.resetTickStartNanos();
                }
                refreshMainThreadWorldCensus(targetServer);
            };
            if (canScheduleAcrossTicks) {
                runOnMainThreadBlocking(spawnBatch);
                sleepWithStallSampling(25L, null);
            } else {
                spawnBatch.run();
            }
        }
        return buildPaperSwarmSnapshot(targetServer, activeSwarmActors.size(), 0);
    }

    @Override
    public synchronized LeafFuzzRuntime.SwarmSnapshot stepConcurrentSwarm(int churnCount) {
        if (activeSwarmActors.isEmpty()) {
            return new LeafFuzzRuntime.SwarmSnapshot(0, 0, 0, 0, 0);
        }
        Server targetServer = server != null ? server : safeBukkitServer();
        boolean canScheduleAcrossTicks = runtime.accessor().scheduler().isPresent()
                && !isPrimaryThread(targetServer);
        int toChurn = Math.max(0, Math.min(activeSwarmActors.size(), churnCount));
        final int[] bgActions = {0};

        Runnable stepBatch = () -> {
            LogAndStallSignatureOracle oracle = runtime.faultOracle();
            for (int i = 0; i < activeSwarmActors.size(); i++) {
                PersonaPolicyBotActor bot = activeSwarmActors.get(i);
                BotStepRecord step = bot.stepAutonomousPolicy();
                runtime.recordPlatformBotStep(step);
                markVirtualChunkNeighborhood(bot.x() >> 4, bot.z() >> 4);
                bgActions[0]++;
                LiveServerPlayerSession live = i < activeSwarmSessions.size() ? activeSwarmSessions.get(i) : null;
                if (live != null) {
                    live.sendMovePacket(
                            step.x() + 0.5,
                            step.y(),
                            step.z() + 0.5,
                            step.yawDeg(),
                            step.pitchDeg(),
                            oracle
                    );
                }
            }
            for (int c = 0; c < toChurn; c++) {
                int idx = Math.floorMod(swarmChurnCursor++, activeSwarmActors.size());
                LiveServerPlayerSession oldLive = idx < activeSwarmSessions.size() ? activeSwarmSessions.get(idx) : null;
                if (oldLive != null) {
                    oldLive.disconnect(oracle);
                }
                runtime.retentionScreener().recordPlayerDeparture();
                boolean op = (idx & 7) == 0;
                PersonaPolicyBotActor replacement = runtime.spawnPersonaBotActor(op ? "op" : "default");
                NmsEmbeddedPlayerSession.SpiralAnchor anchor =
                        NmsEmbeddedPlayerSession.assignSpiralAnchor(replacement, idx);
                markVirtualChunkNeighborhood(anchor.chunkX(), anchor.chunkZ());
                LiveServerPlayerSession newLive = LiveServerPlayerSession.trySpawn(
                        targetServer,
                        replacement,
                        op,
                        2000 + swarmChurnCursor
                );
                activeSwarmActors.set(idx, replacement);
                if (idx < activeSwarmSessions.size()) {
                    activeSwarmSessions.set(idx, newLive);
                }
            }
            refreshMainThreadWorldCensus(targetServer);
            runtime.resetTickStartNanos();
        };
        if (canScheduleAcrossTicks) {
            runOnMainThreadBlocking(stepBatch);
        } else {
            stepBatch.run();
        }
        return buildPaperSwarmSnapshot(targetServer, bgActions[0], toChurn);
    }

    @Override
    public synchronized LeafFuzzRuntime.SwarmSnapshot captureSnapshot() {
        Server targetServer = server != null ? server : safeBukkitServer();
        return buildPaperSwarmSnapshot(targetServer, 0, 0);
    }

    @Override
    public synchronized void teardownAll() {
        if (activeSwarmActors.isEmpty() && activeSwarmSessions.isEmpty()) {
            return;
        }
        Server targetServer = server != null ? server : safeBukkitServer();
        boolean canScheduleAcrossTicks = runtime.accessor().scheduler().isPresent()
                && !isPrimaryThread(targetServer);
        Runnable teardownTask = () -> {
            LogAndStallSignatureOracle oracle = runtime.faultOracle();
            for (LiveServerPlayerSession s : activeSwarmSessions) {
                if (s != null) {
                    s.disconnect(oracle);
                }
                runtime.retentionScreener().recordPlayerDeparture();
            }
            activeSwarmSessions.clear();
            activeSwarmActors.clear();
            virtualSwarmChunks.clear();
        };
        if (canScheduleAcrossTicks) {
            runOnMainThreadBlocking(teardownTask);
        } else {
            teardownTask.run();
        }
    }

    private void refreshMainThreadWorldCensus(Server targetServer) {
        if (targetServer == null || !isPrimaryThread(targetServer)) {
            return;
        }
        int worldChunks = 0;
        int worldEntities = 0;
        try {
            for (World w : targetServer.getWorlds()) {
                if (w == null) {
                    continue;
                }
                try {
                    org.bukkit.Chunk[] chunks = w.getLoadedChunks();
                    if (chunks != null) {
                        worldChunks += chunks.length;
                    }
                } catch (Throwable ignored) {
                }
                try {
                    List<org.bukkit.entity.Entity> ents = w.getEntities();
                    if (ents != null) {
                        worldEntities += ents.size();
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
        this.cachedMainThreadChunks = worldChunks;
        this.cachedMainThreadEntities = worldEntities;
    }

    private LeafFuzzRuntime.SwarmSnapshot buildPaperSwarmSnapshot(
            Server targetServer,
            int bgActions,
            int churned
    ) {
        int online = activeSwarmActors.size();
        int loadedChunks = Math.max(virtualSwarmChunks.size(), this.cachedMainThreadChunks);
        int entities = Math.max(online * 2, this.cachedMainThreadEntities);
        if (targetServer != null) {
            try {
                Collection<? extends Player> onlinePlayers = targetServer.getOnlinePlayers();
                if (onlinePlayers != null) {
                    online = Math.max(online, onlinePlayers.size());
                }
                if (isPrimaryThread(targetServer)) {
                    refreshMainThreadWorldCensus(targetServer);
                    loadedChunks = Math.max(loadedChunks, this.cachedMainThreadChunks);
                    entities = Math.max(entities, this.cachedMainThreadEntities);
                }
            } catch (Throwable ignored) {
            }
        }
        return new LeafFuzzRuntime.SwarmSnapshot(online, loadedChunks, entities, bgActions, churned);
    }

    private void markVirtualChunkNeighborhood(int cx, int cz) {
        for (int dx = -1; dx <= 1; dx++) {
            for (int dz = -1; dz <= 1; dz++) {
                virtualSwarmChunks.add((cx + dx) + "," + (cz + dz));
            }
        }
    }

    /**
     * Salient ("shiny / distinct") item slot discovered inside an open container menu.
     */
    record SalientSlot(
            int slot,
            String material,
            String displayName,
            int loreLines,
            double salienceScore
    ) {
        String formatSummary() {
            if (displayName != null && !displayName.isBlank()) {
                return "slot " + slot + " " + material + " (" + displayName + ")";
            }
            return "slot " + slot + " " + material;
        }
    }

    private static final class MenuExplorationState {
        private final Map<Integer, int[]> slotStats = new LinkedHashMap<>();
        private int totalClicks;

        synchronized SalientSlot selectSlotToClick(List<SalientSlot> candidates) {
            if (candidates == null || candidates.isEmpty()) {
                return null;
            }
            // 1. Curiosity / Mutation: click any salient ("shiny") slot that has never been clicked yet
            for (SalientSlot s : candidates) {
                int[] st = slotStats.computeIfAbsent(s.slot(), k -> new int[4]);
                if (st[0] == 0) {
                    st[0]++;
                    totalClicks++;
                    return s;
                }
            }
            // 2. UCB1 slot reward policy: lean toward slots that trigger world effects (+3.0)
            //    or reveal information (+1.5) while pruning inert slots (-0.6).
            SalientSlot best = candidates.get(0);
            double bestScore = Double.NEGATIVE_INFINITY;
            double logTotal = Math.log(Math.max(2.0, totalClicks + 1.0));
            for (SalientSlot s : candidates) {
                int[] st = slotStats.computeIfAbsent(s.slot(), k -> new int[4]);
                int pulls = Math.max(1, st[0]);
                double meanQ = (3.0 * st[1] + 1.5 * st[2] - 0.6 * st[3]) / pulls;
                double ucb = meanQ + 0.85 * Math.sqrt(logTotal / pulls) + 0.04 * s.salienceScore();
                if (ucb > bestScore) {
                    bestScore = ucb;
                    best = s;
                }
            }
            int[] chosenStats = slotStats.computeIfAbsent(best.slot(), k -> new int[4]);
            chosenStats[0]++;
            totalClicks++;
            return best;
        }

        synchronized void recordOutcome(int slot, boolean triggeredEffect, boolean revealedInfo) {
            int[] st = slotStats.computeIfAbsent(slot, k -> new int[4]);
            if (triggeredEffect) {
                st[1]++;
            }
            if (revealedInfo) {
                st[2]++;
            }
            if (!triggeredEffect && !revealedInfo) {
                st[3]++;
            }
        }
    }

    @Override
    public EpisodeOutcome runEpisode(List<EpisodeAction> actions) {
        if (actions == null || actions.isEmpty()) {
            return EpisodeOutcome.clean();
        }
        Server targetServer = server != null ? server : safeBukkitServer();
        LogAndStallSignatureOracle oracle = runtime.faultOracle();

        long exceptionsBefore = oracle.totalExceptionsRecorded();
        long stallsBefore = oracle.totalStallsRecorded();
        long hazardsBefore = oracle.totalHazardsRecorded();
        List<FaultSignature> beforeSigs = oracle.rankedSignatures();

        List<String> capturedMessages = new ArrayList<>();
        List<String> observedTokens = new ArrayList<>();
        Set<String> episodeCoverageTokens = new java.util.LinkedHashSet<>();
        boolean usageError = false;

        String primaryTier = actions.get(0).tier();
        PersonaPolicyBotActor bot = runtime.spawnPersonaBotActor(primaryTier);
        BotStepRecord preStep = bot.stepAutonomousPolicy();
        runtime.recordPlatformBotStep(preStep);
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
            // Enforce DEFAULT_DENYLIST safety check
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

            boolean opTier = "op".equalsIgnoreCase(action.tier()) || bot.isOp();
            String shape = action.followUpShape() != null
                    ? action.followUpShape().trim().toLowerCase(Locale.ROOT)
                    : "repeat";
            int botCount = switch (shape) {
                case "concurrent", "coop_group" -> 2;
                case "burst_swarm" -> 4;
                default -> 1;
            };
            int initialCommandsPerBot = ("repeat".equals(shape) || "concurrent".equals(shape)) ? 2 : 1;

            long t0 = System.nanoTime();
            List<LiveServerPlayerSession> liveSessions = new ArrayList<>(botCount);
            List<Player> spawnedPlayers = new ArrayList<>(botCount);
            final boolean[] dispatchFailed = {false};
            final EpisodeOutcome[] earlyFault = {null};
            final int[] epMenusOpened = {0};
            final int[] epMenuSlotsClicked = {0};
            final int[] epTeleports = {0};
            final double[] epMaxTeleportDist = {0.0};
            final int[] epInfoResponses = {0};
            final int[] totalDispatches = {0};
            final List<String> epClickedItems = new ArrayList<>();
            final String[] lastClickedMenuKey = {null};
            final int[] lastClickedMenuSlot = {-1};
            final boolean[] menuClosedAfterClick = {false};
            final boolean[] submenuRevealedAfterClick = {false};

            Runnable step1JoinAndDispatch = () -> {
                for (int bIdx = 0; bIdx < botCount; bIdx++) {
                    PersonaPolicyBotActor dispatchActor = (bIdx == 0)
                            ? bot
                            : runtime.spawnPersonaBotActor(action.tier());
                    LiveServerPlayerSession liveSession = LiveServerPlayerSession.trySpawn(
                            targetServer,
                            dispatchActor,
                            opTier,
                            bIdx
                    );
                    Player activePlayer;
                    if (liveSession != null) {
                        liveSessions.add(liveSession);
                        activePlayer = liveSession.craftPlayer();
                    } else {
                        activePlayer = createSyntheticPlayerProxy(
                                targetServer,
                                dispatchActor,
                                opTier,
                                shape,
                                capturedMessages
                        );
                    }
                    if (activePlayer != null) {
                        spawnedPlayers.add(activePlayer);
                        if (bIdx == 0 && targetServer != null) {
                            dispatchReversibleWorldMicroSkill(
                                    targetServer,
                                    activePlayer,
                                    preStep.selectedSkill(),
                                    runtime,
                                    oracle,
                                    observedTokens
                            );
                        }
                    }
                    runtime.resetTickStartNanos();
                    int cmdsForThisBot = (bIdx == 0) ? initialCommandsPerBot : 1;
                    for (int cIdx = 0; cIdx < cmdsForThisBot; cIdx++) {
                        runtime.retentionScreener().recordCommandExecution();
                        totalDispatches[0]++;
                        try {
                            if (targetServer != null && activePlayer != null) {
                                boolean ok = dispatchViaCommandMapOrServer(targetServer, activePlayer, cleanCmd);
                                if (!ok) {
                                    dispatchFailed[0] = true;
                                }
                            } else {
                                runtime.accessor().executeCommandWithCapture(cleanCmd, capturedMessages::add);
                            }
                            if (liveSession != null) {
                                liveSession.drainOutboundPackets();
                            }
                            if (bIdx == 0 && cIdx == 0 && targetServer != null && activePlayer != null) {
                                inspectAndClickSalientMenu(
                                        targetServer,
                                        activePlayer,
                                        cleanCmd,
                                        oracle,
                                        observedTokens,
                                        epMenusOpened,
                                        epMenuSlotsClicked,
                                        epClickedItems,
                                        lastClickedMenuKey,
                                        lastClickedMenuSlot,
                                        menuClosedAfterClick,
                                        submenuRevealedAfterClick
                                );
                                if (liveSession != null) {
                                    liveSession.drainOutboundPackets();
                                }
                            }
                        } catch (Throwable t) {
                            Throwable rootCause = (t instanceof CommandException && t.getCause() != null)
                                    ? t.getCause()
                                    : t;
                            FaultSignature sig = oracle.recordThrowable(rootCause, "Command dispatch: /" + cleanCmd);
                            earlyFault[0] = EpisodeOutcome.fault(
                                    sig.signatureId(),
                                    sig.suspectJar(),
                                    0.0,
                                    (System.nanoTime() - t0) / 1_000_000.0,
                                    List.of(sig.topPluginFrame())
                            );
                            return;
                        }
                    }
                }
            };

            boolean canScheduleAcrossTicks = runtime.accessor().scheduler().isPresent()
                    && !isPrimaryThread(targetServer);
            if (canScheduleAcrossTicks) {
                runOnMainThreadBlocking(step1JoinAndDispatch, episodeCoverageTokens);
                if (earlyFault[0] == null) {
                    if ("quit_lt1s".equals(shape)) {
                        sleepWithStallSampling(200L, episodeCoverageTokens);
                    } else {
                        boolean expectsAsyncEffect = menuClosedAfterClick[0]
                                || submenuRevealedAfterClick[0]
                                || isLikelyTeleportOrAsyncCommand(cleanCmd);
                        long maxWaitMs = expectsAsyncEffect ? (opTier ? 1400L : 2600L) : 320L;
                        long pollDeadline = System.currentTimeMillis() + maxWaitMs;
                        while (System.currentTimeMillis() < pollDeadline) {
                            sleepWithStallSampling(120L, episodeCoverageTokens);
                            final boolean[] settled = {false};
                            runOnMainThreadBlocking(() -> {
                                if (!liveSessions.isEmpty()) {
                                    LiveServerPlayerSession primaryLive = liveSessions.get(0);
                                    primaryLive.drainOutboundPackets();
                                    if (epMenuSlotsClicked[0] == 0
                                            && targetServer != null
                                            && primaryLive.craftPlayer() != null
                                            && hasOpenCustomContainer(primaryLive.craftPlayer())) {
                                        inspectAndClickSalientMenu(
                                                targetServer,
                                                primaryLive.craftPlayer(),
                                                cleanCmd,
                                                oracle,
                                                observedTokens,
                                                epMenusOpened,
                                                epMenuSlotsClicked,
                                                epClickedItems,
                                                lastClickedMenuKey,
                                                lastClickedMenuSlot,
                                                menuClosedAfterClick,
                                                submenuRevealedAfterClick
                                        );
                                        primaryLive.drainOutboundPackets();
                                    }
                                    double moved = primaryLive.displacementFromSpawn();
                                    if (moved >= 4.0) {
                                        settled[0] = true;
                                    }
                                }
                            }, episodeCoverageTokens);
                            if (settled[0]) {
                                sleepWithStallSampling(60L, episodeCoverageTokens);
                                break;
                            }
                        }
                    }
                }
            } else {
                step1JoinAndDispatch.run();
            }

            if (dispatchFailed[0]) {
                usageError = true;
            }
            if (earlyFault[0] != null) {
                Runnable cleanupOnFault = () -> {
                    for (LiveServerPlayerSession s : liveSessions) {
                        s.disconnect(oracle);
                        runtime.retentionScreener().recordPlayerDeparture();
                    }
                };
                if (canScheduleAcrossTicks) {
                    runOnMainThreadBlocking(cleanupOnFault);
                } else {
                    cleanupOnFault.run();
                }
                runtime.recordEpisodeObservation(
                        "/" + cleanCmd,
                        liveSessions.size(),
                        totalDispatches[0],
                        epMenusOpened[0],
                        epMenuSlotsClicked[0],
                        epClickedItems,
                        epTeleports[0],
                        epMaxTeleportDist[0],
                        epInfoResponses[0],
                        usageError
                );
                return earlyFault[0];
            }

            int prevX = bot.x();
            int prevY = bot.y();
            int prevZ = bot.z();
            BotStepRecord followStep = bot.performFollowUpBehavior(shape);
            runtime.recordPlatformBotStep(followStep);
            observedTokens.add("followup:" + followStep.selectedSkill());

            Runnable step2FollowUpAndDisconnect = () -> {
                if (!liveSessions.isEmpty()) {
                    for (LiveServerPlayerSession s : liveSessions) {
                        s.drainOutboundPackets();
                        double moved = s.displacementFromSpawn();
                        if (moved >= 4.0) {
                            epTeleports[0]++;
                            if (moved > epMaxTeleportDist[0]) {
                                epMaxTeleportDist[0] = moved;
                            }
                        }
                        epInfoResponses[0] += s.chatOrInfoPacketsSeen();
                    }
                    if (lastClickedMenuKey[0] != null && lastClickedMenuSlot[0] >= 0) {
                        MenuExplorationState mState = menuExplorationByKey.get(lastClickedMenuKey[0]);
                        if (mState != null) {
                            boolean eff = epTeleports[0] > 0 || menuClosedAfterClick[0];
                            boolean inf = submenuRevealedAfterClick[0] || epInfoResponses[0] > 0;
                            mState.recordOutcome(lastClickedMenuSlot[0], eff, inf);
                        }
                    }
                    if (epTeleports[0] > 0) {
                        int bucket = (int) Math.min(4096L, Math.max(16L, Math.round(epMaxTeleportDist[0] / 32.0) * 32L));
                        observedTokens.add("effect:teleport:" + bucket + "b");
                    }
                    if (epInfoResponses[0] > 0) {
                        observedTokens.add("info:chat_packets:" + Math.min(8, epInfoResponses[0]));
                    }
                    LiveServerPlayerSession primaryLive = liveSessions.get(0);
                    Location curLoc = primaryLive.craftPlayer() != null ? primaryLive.craftPlayer().getLocation() : null;
                    double baseX = curLoc != null ? curLoc.getX() : prevX + 0.5;
                    double baseY = curLoc != null ? curLoc.getY() : prevY;
                    double baseZ = curLoc != null ? curLoc.getZ() : prevZ + 0.5;
                    switch (shape) {
                        case "chunk_border_thrash" -> {
                            int[] offsets = {16, 0, 16, 0};
                            for (int off : offsets) {
                                primaryLive.sendMovePacket(
                                        baseX + off,
                                        baseY,
                                        baseZ,
                                        followStep.yawDeg(),
                                        followStep.pitchDeg(),
                                        oracle
                                );
                            }
                        }
                        case "move" -> primaryLive.sendMovePacket(
                                baseX + 6.0,
                                baseY,
                                baseZ + 6.0,
                                followStep.yawDeg(),
                                followStep.pitchDeg(),
                                oracle
                        );
                        case "homesteader_reroll" -> {
                            primaryLive.sendMovePacket(baseX + 8.0, baseY, baseZ + 8.0, followStep.yawDeg(), followStep.pitchDeg(), oracle);
                            runtime.retentionScreener().recordCommandExecution();
                            totalDispatches[0]++;
                            try {
                                dispatchViaCommandMapOrServer(targetServer, primaryLive.craftPlayer(), cleanCmd);
                            } catch (Throwable t) {
                                oracle.recordThrowable(t, "Follow-up homesteader_reroll command dispatch");
                            }
                            primaryLive.sendMovePacket(baseX + 12.0, baseY, baseZ + 4.0, followStep.yawDeg(), followStep.pitchDeg(), oracle);
                        }
                        case "explorer_wander" -> {
                            primaryLive.sendMovePacket(baseX + 24.0, baseY, baseZ - 15.0, followStep.yawDeg(), followStep.pitchDeg(), oracle);
                            runtime.retentionScreener().recordCommandExecution();
                            totalDispatches[0]++;
                            try {
                                dispatchViaCommandMapOrServer(targetServer, primaryLive.craftPlayer(), cleanCmd);
                            } catch (Throwable t) {
                                oracle.recordThrowable(t, "Follow-up explorer_wander command dispatch");
                            }
                            primaryLive.sendMovePacket(baseX - 7.0, baseY, baseZ + 8.0, followStep.yawDeg(), followStep.pitchDeg(), oracle);
                        }
                        case "coop_group" -> {
                            primaryLive.sendMovePacket(baseX + 8.0, baseY, baseZ + 8.0, followStep.yawDeg(), followStep.pitchDeg(), oracle);
                            if (liveSessions.size() > 1) {
                                liveSessions.get(1).sendMovePacket(baseX - 7.0, baseY, baseZ + 8.0, followStep.yawDeg(), followStep.pitchDeg(), oracle);
                            }
                        }
                        case "window_click" -> primaryLive.sendContainerClosePacket(oracle);
                        case "rejoin" -> {
                            primaryLive.disconnect(oracle);
                            runtime.retentionScreener().recordPlayerDeparture();
                            liveSessions.remove(0);
                            LiveServerPlayerSession rejoined = LiveServerPlayerSession.trySpawn(targetServer, bot, opTier, 0);
                            if (rejoined != null) {
                                liveSessions.add(0, rejoined);
                                runtime.retentionScreener().recordCommandExecution();
                                totalDispatches[0]++;
                                try {
                                    dispatchViaCommandMapOrServer(targetServer, rejoined.craftPlayer(), cleanCmd);
                                    rejoined.drainOutboundPackets();
                                } catch (Throwable t) {
                                    oracle.recordThrowable(t, "Follow-up rejoin command dispatch");
                                }
                            }
                        }
                        default -> {
                        }
                    }
                    for (LiveServerPlayerSession s : liveSessions) {
                        s.drainOutboundPackets();
                        double movedAfterFollow = s.displacementFromSpawn();
                        if (movedAfterFollow >= 4.0 && epTeleports[0] == 0) {
                            epTeleports[0]++;
                            epMaxTeleportDist[0] = movedAfterFollow;
                            observedTokens.add("effect:teleport:" + ((int) Math.round(movedAfterFollow)) + "b");
                        }
                        s.disconnect(oracle);
                        runtime.retentionScreener().recordPlayerDeparture();
                    }
                } else {
                    Player primaryPlayer = !spawnedPlayers.isEmpty()
                            ? spawnedPlayers.get(0)
                            : createSyntheticPlayerProxy(targetServer, bot, opTier, shape, capturedMessages);
                    if ("move".equals(shape)
                            || "chunk_border_thrash".equals(shape)
                            || "homesteader_reroll".equals(shape)
                            || "explorer_wander".equals(shape)
                            || "coop_group".equals(shape)) {
                        fireSyntheticMoveEvent(
                                targetServer,
                                primaryPlayer,
                                prevX,
                                prevY,
                                prevZ,
                                followStep.x(),
                                followStep.y(),
                                followStep.z(),
                                followStep.yawDeg(),
                                followStep.pitchDeg(),
                                runtime,
                                oracle
                        );
                    } else if ("window_click".equals(shape)) {
                        fireSyntheticWindowFollowUp(targetServer, primaryPlayer, runtime, oracle);
                    }
                    if (spawnedPlayers.isEmpty() && primaryPlayer != null) {
                        spawnedPlayers.add(primaryPlayer);
                    }
                    for (Player p : spawnedPlayers) {
                        fireSyntheticQuitEvent(targetServer, p, runtime, oracle);
                        runtime.retentionScreener().recordPlayerDeparture();
                    }
                }
            };

            if (canScheduleAcrossTicks) {
                runOnMainThreadBlocking(step2FollowUpAndDisconnect, episodeCoverageTokens);
            } else {
                step2FollowUpAndDisconnect.run();
            }

            if (!capturedMessages.isEmpty()) {
                epInfoResponses[0] += capturedMessages.size();
            }
            runtime.recordEpisodeObservation(
                    "/" + cleanCmd,
                    liveSessions.size(),
                    totalDispatches[0],
                    epMenusOpened[0],
                    epMenuSlotsClicked[0],
                    epClickedItems,
                    epTeleports[0],
                    epMaxTeleportDist[0],
                    epInfoResponses[0],
                    dispatchFailed[0]
            );
        }

        for (String line : capturedMessages) {
            if (line == null) {
                continue;
            }
            String low = line.toLowerCase(Locale.ROOT);
            if (low.contains("unknown command") || low.contains("usage:") || low.contains("invalid argument")) {
                usageError = true;
                break;
            }
        }

        if (!episodeCoverageTokens.isEmpty()) {
            observedTokens.addAll(episodeCoverageTokens);
        }

        if (oracle.totalExceptionsRecorded() > exceptionsBefore
                || oracle.totalStallsRecorded() > stallsBefore
                || oracle.totalHazardsRecorded() > hazardsBefore) {
            List<FaultSignature> afterSigs = oracle.rankedSignatures();
            FaultSignature triggered = selectNewestSignature(beforeSigs, afterSigs);
            if (triggered != null
                    && !"server".equalsIgnoreCase(triggered.suspectJar())
                    && !"server".equalsIgnoreCase(triggered.topPluginFrame())) {
                observedTokens.add(triggered.topPluginFrame());
                return EpisodeOutcome.fault(
                        triggered.signatureId(),
                        triggered.suspectJar(),
                        0.0,
                        triggered.maxDurationMs(),
                        observedTokens
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

    private static void fireSyntheticQuitEvent(
            Server targetServer,
            Player syntheticPlayer,
            LeafFuzzRuntime runtime,
            LogAndStallSignatureOracle oracle
    ) {
        if (targetServer == null || targetServer.getPluginManager() == null || syntheticPlayer == null) {
            return;
        }
        try {
            @SuppressWarnings({"deprecation", "removal"})
            PlayerQuitEvent quitEvent = new PlayerQuitEvent(syntheticPlayer, "");
            dispatchTargetScopedEvent(targetServer, quitEvent, runtime, oracle, "Synthetic PlayerQuitEvent follow-up exception");
        } catch (Throwable t) {
            oracle.recordThrowable(t, "Synthetic PlayerQuitEvent follow-up exception");
        }
    }

    private static void fireSyntheticMoveEvent(
            Server targetServer,
            Player syntheticPlayer,
            int fromX,
            int fromY,
            int fromZ,
            int toX,
            int toY,
            int toZ,
            float yaw,
            float pitch,
            LeafFuzzRuntime runtime,
            LogAndStallSignatureOracle oracle
    ) {
        if (targetServer == null || targetServer.getPluginManager() == null || syntheticPlayer == null) {
            return;
        }
        try {
            World world = resolveFirstWorld(targetServer);
            Location from = new Location(world, fromX + 0.5, fromY, fromZ + 0.5, yaw, pitch);
            Location to = new Location(world, toX + 0.5, toY, toZ + 0.5, yaw, pitch);
            PlayerMoveEvent moveEvent = new PlayerMoveEvent(syntheticPlayer, from, to);
            dispatchTargetScopedEvent(targetServer, moveEvent, runtime, oracle, "Synthetic PlayerMoveEvent follow-up exception");
        } catch (Throwable t) {
            oracle.recordThrowable(t, "Synthetic PlayerMoveEvent follow-up exception");
        }
    }

    private static void fireSyntheticWindowFollowUp(
            Server targetServer,
            Player syntheticPlayer,
            LeafFuzzRuntime runtime,
            LogAndStallSignatureOracle oracle
    ) {
        if (targetServer == null || targetServer.getPluginManager() == null || syntheticPlayer == null) {
            return;
        }
        try {
            InventoryView view = syntheticPlayer.getOpenInventory();
            if (view != null) {
                InventoryCloseEvent closeEvent = new InventoryCloseEvent(view);
                dispatchTargetScopedEvent(targetServer, closeEvent, runtime, oracle, "Synthetic InventoryCloseEvent follow-up exception");
            }
        } catch (Throwable t) {
            oracle.recordThrowable(t, "Synthetic InventoryCloseEvent follow-up exception");
        }
    }

    /**
     * Dispatches a synthetic follow-up event to registered listeners while isolating target plugins
     * and skipping un-primed connection-session listeners (such as {@code AsyncPlayerPreLoginEvent}
     * session managers) when they are outside the active target scope.
     */
    private static void dispatchTargetScopedEvent(
            Server targetServer,
            org.bukkit.event.Event event,
            LeafFuzzRuntime runtime,
            LogAndStallSignatureOracle oracle,
            String contextLabel
    ) {
        org.bukkit.plugin.RegisteredListener[] listeners = null;
        try {
            listeners = event.getHandlers().getRegisteredListeners();
        } catch (Throwable ignored) {
        }
        if (listeners == null || listeners.length == 0) {
            targetServer.getPluginManager().callEvent(event);
            return;
        }
        String targetFilter = runtime != null ? runtime.activeTargetFilter() : "all";
        List<String> selectors = BrigadierDispatcherInspector.parseTargetSelectors(targetFilter);
        boolean scopedTargets = !selectors.isEmpty();

        for (org.bukkit.plugin.RegisteredListener reg : listeners) {
            if (reg == null) {
                continue;
            }
            String pluginName = (reg.getPlugin() != null && reg.getPlugin().getName() != null)
                    ? reg.getPlugin().getName()
                    : "";
            String listenerCls = reg.getListener() != null ? reg.getListener().getClass().getName() : "";
            if (scopedTargets && (!pluginName.isEmpty() || !listenerCls.isEmpty())) {
                boolean matches = BrigadierDispatcherInspector.matchesTargetIdentifier(
                        pluginName,
                        listenerCls,
                        targetFilter,
                        runtime != null ? runtime.ownershipIndex() : null
                );
                if (!matches) {
                    continue;
                }
            } else if (isUnprimedConnectionSessionListener(listenerCls)) {
                continue;
            }
            try {
                reg.callEvent(event);
            } catch (Throwable t) {
                oracle.recordThrowable(t, contextLabel);
            }
        }
    }

    private static boolean isUnprimedConnectionSessionListener(String listenerCls) {
        if (listenerCls == null || listenerCls.isEmpty()) {
            return false;
        }
        String low = listenerCls.toLowerCase(Locale.ROOT);
        return low.contains("connectionlistener")
                || low.contains("loginlistener")
                || low.contains("prelogin");
    }

    private static final Player.Spigot SPIGOT_DELEGATE = new Player.Spigot();

    private static boolean dispatchViaCommandMapOrServer(
            Server targetServer,
            Player syntheticPlayer,
            String cleanCmd
    ) {
        try {
            CommandMap commandMap = targetServer.getCommandMap();
            if (commandMap != null) {
                return commandMap.dispatch(syntheticPlayer, cleanCmd);
            }
        } catch (CommandException ce) {
            throw ce;
        } catch (Throwable ignored) {
        }
        return targetServer.dispatchCommand(syntheticPlayer, cleanCmd);
    }

    /**
     * Creates a target-agnostic dynamic {@link Player} proxy backed by {@code bot} so any plugin
     * command inspecting {@code sender instanceof Player}, {@code getUniqueId()}, {@code getName()},
     * {@code getLocation()}, {@code getWorld()}, or {@code hasPermission(String)} executes cleanly
     * without synchronous chunk loads ({@code S-005}).
     */
    static Player createSyntheticPlayerProxy(
            Server server,
            PersonaPolicyBotActor bot,
            boolean op,
            List<String> capturedMessages
    ) {
        return createSyntheticPlayerProxy(server, bot, op, "repeat", capturedMessages);
    }

    static Player createSyntheticPlayerProxy(
            Server server,
            PersonaPolicyBotActor bot,
            boolean op,
            String followUpShape,
            List<String> capturedMessages
    ) {
        UUID actorId = bot.actorUuid();
        String actorName = bot.actorName();
        World firstWorld = resolveFirstWorld(server);
        InetSocketAddress address = InetSocketAddress.createUnresolved("127.0.0.1", 25565);
        Inventory dummyInventory = createDummyInventoryProxy();
        PlayerInventory dummyPlayerInventory = createDummyPlayerInventoryProxy();

        try {
            return (Player) Proxy.newProxyInstance(
                    Player.class.getClassLoader(),
                    new Class<?>[]{Player.class},
                    (proxy, method, args) -> {
                        String m = method.getName();
                        int n = method.getParameterCount();
                        if ("equals".equals(m) && n == 1) {
                            if (proxy == args[0]) {
                                return true;
                            }
                            if (args[0] instanceof Player other) {
                                return actorId.equals(other.getUniqueId());
                            }
                            return false;
                        }
                        if ("hashCode".equals(m) && n == 0) {
                            return actorId.hashCode();
                        }
                        if ("toString".equals(m) && n == 0) {
                            return "SyntheticPersonaPlayer[" + actorName + ",persona="
                                    + bot.persona().taxonomyArchetype() + ",op=" + op + "]";
                        }
                        if (("getName".equals(m) || "getDisplayName".equals(m) || "getPlayerListName".equals(m)) && n == 0) {
                            return actorName;
                        }
                        if ("getUniqueId".equals(m) && n == 0) {
                            return actorId;
                        }
                        if ("getServer".equals(m) && n == 0) {
                            return server;
                        }
                        if ("getWorld".equals(m) && n == 0) {
                            return firstWorld;
                        }
                        if (("getLocation".equals(m) || "getEyeLocation".equals(m)) && n == 0) {
                            return new Location(
                                    firstWorld,
                                    bot.x() + 0.5,
                                    "getEyeLocation".equals(m) ? bot.y() + 1.62 : bot.y(),
                                    bot.z() + 0.5,
                                    bot.yawDeg(),
                                    bot.pitchDeg()
                            );
                        }
                        if ("getLocation".equals(m) && n == 1 && args[0] instanceof Location loc) {
                            loc.setWorld(firstWorld);
                            loc.setX(bot.x() + 0.5);
                            loc.setY(bot.y());
                            loc.setZ(bot.z() + 0.5);
                            loc.setYaw(bot.yawDeg());
                            loc.setPitch(bot.pitchDeg());
                            return loc;
                        }
                        if ("teleportAsync".equals(m) && n >= 1) {
                            if (args != null && args[0] instanceof Location loc) {
                                bot.setLocation(loc.getBlockX(), loc.getBlockY(), loc.getBlockZ());
                            }
                            return CompletableFuture.completedFuture(Boolean.TRUE);
                        }
                        if ("teleport".equals(m) && n >= 1) {
                            if (args != null && args[0] instanceof Location loc) {
                                bot.setLocation(loc.getBlockX(), loc.getBlockY(), loc.getBlockZ());
                            }
                            return Boolean.TRUE;
                        }
                        if ("spigot".equals(m) && n == 0) {
                            return SPIGOT_DELEGATE;
                        }
                        if ("getInventory".equals(m) && n == 0) {
                            return dummyPlayerInventory;
                        }
                        if ("getOpenInventory".equals(m) && n == 0) {
                            return createDummyInventoryViewProxy((Player) proxy, dummyInventory, dummyPlayerInventory);
                        }
                        if ("getAddress".equals(m) && n == 0) {
                            return address;
                        }
                        if ("isOp".equals(m) && n == 0) {
                            return op;
                        }
                        if ("hasPlayedBefore".equals(m) && n == 0) {
                            return Boolean.TRUE;
                        }
                        if ("isOnline".equals(m) && n == 0) {
                            return bot.isOnline();
                        }
                        if ("isValid".equals(m) && n == 0) {
                            return bot.isOnline();
                        }
                        if ("isDead".equals(m) && n == 0) {
                            return false;
                        }
                        if (("hasPermission".equals(m) || "isPermissionSet".equals(m)) && n == 1 && args != null) {
                            return evaluateSyntheticPermission(server, op, followUpShape, args[0]);
                        }
                        if ("sendMessage".equals(m) && n >= 1 && args != null) {
                            if (capturedMessages != null) {
                                Object first = args[0];
                                if (first instanceof String s) {
                                    capturedMessages.add(s);
                                } else if (first instanceof String[] arr) {
                                    for (String s : arr) {
                                        if (s != null) {
                                            capturedMessages.add(s);
                                        }
                                    }
                                } else if (first != null) {
                                    capturedMessages.add(first.toString());
                                }
                            }
                            return null;
                        }
                        if ("getHealth".equals(m) && n == 0) {
                            return 20.0;
                        }
                        if ("getFoodLevel".equals(m) && n == 0) {
                            return 20;
                        }
                        if ("getPing".equals(m) && n == 0) {
                            return 12;
                        }
                        if ("getLocale".equals(m) && n == 0) {
                            return "en_us";
                        }
                        Class<?> ret = method.getReturnType();
                        if (ret == CompletableFuture.class) {
                            return CompletableFuture.completedFuture(null);
                        }
                        if (ret == Optional.class) {
                            return Optional.empty();
                        }
                        if (ret == List.class || ret == Collection.class) {
                            return Collections.emptyList();
                        }
                        if (ret == Set.class) {
                            return Collections.emptySet();
                        }
                        if (ret == Map.class) {
                            return Collections.emptyMap();
                        }
                        if (ret == UUID.class) {
                            return actorId;
                        }
                        if (ret == Location.class) {
                            return new Location(firstWorld, bot.x() + 0.5, bot.y(), bot.z() + 0.5, bot.yawDeg(), bot.pitchDeg());
                        }
                        if (ret == World.class) {
                            return firstWorld;
                        }
                        if (ret == Server.class) {
                            return server;
                        }
                        if (ret == boolean.class || ret == Boolean.class) {
                            return false;
                        }
                        if (ret == int.class || ret == Integer.class) {
                            return 0;
                        }
                        if (ret == long.class || ret == Long.class) {
                            return 0L;
                        }
                        if (ret == double.class || ret == Double.class) {
                            return 0.0;
                        }
                        if (ret == float.class || ret == Float.class) {
                            return 0.0f;
                        }
                        if (ret == String.class) {
                            return "";
                        }
                        return null;
                    }
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean evaluateSyntheticPermission(
            Server server,
            boolean op,
            String followUpShape,
            Object permArg
    ) {
        String permName = null;
        if (permArg instanceof String s) {
            permName = s;
        } else if (permArg instanceof Permission p) {
            permName = p.getName();
        }
        if (permName == null || permName.isBlank()) {
            return true;
        }
        String low = permName.trim().toLowerCase(Locale.ROOT);
        if (low.contains("bypass") || low.contains("nodelay") || low.contains("nocooldown")) {
            return false;
        }
        if (op) {
            return true;
        }
        if (server != null) {
            try {
                PluginManager pm = server.getPluginManager();
                if (pm != null) {
                    Permission reg = pm.getPermission(low);
                    if (reg != null && reg.getDefault() != null) {
                        return reg.getDefault().getValue(false);
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return !isAdminOrBypassPermission(low);
    }

    private static boolean isAdminOrBypassPermission(String lowPerm) {
        return lowPerm.equals("*")
                || lowPerm.contains("admin")
                || lowPerm.contains("reload")
                || lowPerm.contains("edit")
                || lowPerm.contains("settings")
                || lowPerm.contains("sudo")
                || lowPerm.contains("debug")
                || lowPerm.contains("developer")
                || lowPerm.contains("bypass")
                || lowPerm.contains("nodelay")
                || lowPerm.contains("nocooldown")
                || lowPerm.contains("staff")
                || lowPerm.endsWith(".op");
    }

    private static Inventory createDummyInventoryProxy() {
        try {
            return (Inventory) Proxy.newProxyInstance(
                    Inventory.class.getClassLoader(),
                    new Class<?>[]{Inventory.class},
                    (proxy, method, args) -> {
                        if ("getSize".equals(method.getName())) {
                            return 27;
                        }
                        Class<?> ret = method.getReturnType();
                        if (ret == boolean.class || ret == Boolean.class) return false;
                        if (ret == int.class || ret == Integer.class) return 0;
                        if (ret == List.class || ret == Collection.class) return Collections.emptyList();
                        return null;
                    }
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static PlayerInventory createDummyPlayerInventoryProxy() {
        try {
            return (PlayerInventory) Proxy.newProxyInstance(
                    PlayerInventory.class.getClassLoader(),
                    new Class<?>[]{PlayerInventory.class},
                    (proxy, method, args) -> {
                        if ("getSize".equals(method.getName())) {
                            return 36;
                        }
                        if ("getHeldItemSlot".equals(method.getName())) {
                            return 0;
                        }
                        Class<?> ret = method.getReturnType();
                        if (ret == boolean.class || ret == Boolean.class) return false;
                        if (ret == int.class || ret == Integer.class) return 0;
                        if (ret == List.class || ret == Collection.class) return Collections.emptyList();
                        return null;
                    }
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static InventoryView createDummyInventoryViewProxy(
            Player player,
            Inventory top,
            PlayerInventory bottom
    ) {
        try {
            return (InventoryView) Proxy.newProxyInstance(
                    InventoryView.class.getClassLoader(),
                    new Class<?>[]{InventoryView.class},
                    (proxy, method, args) -> {
                        String m = method.getName();
                        if ("getPlayer".equals(m)) return player;
                        if ("getTopInventory".equals(m)) return top;
                        if ("getBottomInventory".equals(m)) return bottom;
                        if ("getTitle".equals(m)) return "SyntheticContainer";
                        Class<?> ret = method.getReturnType();
                        if (ret == boolean.class || ret == Boolean.class) return false;
                        if (ret == int.class || ret == Integer.class) return 0;
                        return null;
                    }
            );
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static World resolveFirstWorld(Server server) {
        if (server == null) {
            return null;
        }
        try {
            List<World> worlds = server.getWorlds();
            if (worlds != null && !worlds.isEmpty()) {
                return worlds.get(0);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static FaultSignature selectNewestSignature(
            List<FaultSignature> before,
            List<FaultSignature> after
    ) {
        if (after == null || after.isEmpty()) {
            return null;
        }
        for (FaultSignature cand : after) {
            if ("unknown".equalsIgnoreCase(cand.suspectJar())
                    || "server".equalsIgnoreCase(cand.topPluginFrame())) {
                continue;
            }
            Optional<FaultSignature> prev = before.stream()
                    .filter(b -> b.signatureId().equals(cand.signatureId()))
                    .findFirst();
            if (prev.isEmpty() || cand.occurrences() > prev.get().occurrences()) {
                return cand;
            }
        }
        return null;
    }

    private boolean isPrimaryThread(Server targetServer) {
        if (targetServer != null) {
            try {
                return targetServer.isPrimaryThread();
            } catch (Throwable ignored) {
            }
        }
        try {
            return Bukkit.isPrimaryThread();
        } catch (Throwable ignored) {
            return true;
        }
    }

    private static boolean isLikelyTeleportOrAsyncCommand(String cleanCmd) {
        if (cleanCmd == null || cleanCmd.isBlank()) {
            return false;
        }
        String low = cleanCmd.trim().toLowerCase(Locale.ROOT);
        if (!low.contains(" ")) {
            return true; // Root command (e.g. /rtp, /wild, /spawn)
        }
        return low.contains("world=")
                || low.contains("region=")
                || low.contains("biome=")
                || low.contains("shape=")
                || low.endsWith(" gui")
                || low.endsWith(" menu")
                || low.contains("teleport");
    }

    private static boolean hasOpenCustomContainer(Player player) {
        if (player == null) {
            return false;
        }
        try {
            InventoryView view = player.getOpenInventory();
            if (view == null) {
                return false;
            }
            Inventory top = view.getTopInventory();
            if (top == null || top.getSize() <= 0) {
                return false;
            }
            InventoryType type = top.getType();
            if (type != InventoryType.CRAFTING && type != InventoryType.CREATIVE) {
                return true;
            }
            InventoryHolder holder = top.getHolder();
            return holder != null && !(holder instanceof Player);
        } catch (Throwable ignored) {
            return false;
        }
    }

    void inspectAndClickSalientMenu(
            Server targetServer,
            Player player,
            String cleanCmd,
            LogAndStallSignatureOracle oracle,
            List<String> observedTokens,
            int[] epMenusOpened,
            int[] epMenuSlotsClicked,
            List<String> epClickedItems,
            String[] lastClickedMenuKey,
            int[] lastClickedMenuSlot,
            boolean[] menuClosedAfterClick,
            boolean[] submenuRevealedAfterClick
    ) {
        if (targetServer == null || player == null || !hasOpenCustomContainer(player)) {
            return;
        }
        try {
            InventoryView view = player.getOpenInventory();
            Inventory top = view.getTopInventory();
            String beforeTitle = safeMenuTitle(view);
            String menuKey = beforeTitle + ":" + top.getSize();
            List<SalientSlot> salientSlots = rankSalientMenuSlots(top);
            epMenusOpened[0]++;
            observedTokens.add("info:menu_open:" + menuKey);
            observedTokens.add("info:menu_salient_slots:" + Math.max(1, salientSlots.size()));
            if (salientSlots.isEmpty()) {
                return;
            }
            MenuExplorationState state = menuExplorationByKey.computeIfAbsent(menuKey, k -> new MenuExplorationState());
            SalientSlot chosen = state.selectSlotToClick(salientSlots);
            if (chosen == null) {
                return;
            }
            String beforeSig = snapshotInventorySignature(top);
            int beforeIconCopies = countMatchingMenuIconInPlayerInventory(player, view, chosen);
            lastClickedMenuKey[0] = menuKey;
            lastClickedMenuSlot[0] = chosen.slot();
            epMenuSlotsClicked[0]++;
            epClickedItems.add(chosen.formatSummary());
            observedTokens.add("info:menu_click:" + chosen.material());

            InventoryClickEvent clickEvent = new InventoryClickEvent(
                    view,
                    InventoryType.SlotType.CONTAINER,
                    chosen.slot(),
                    ClickType.LEFT,
                    InventoryAction.PICKUP_ALL
            );
            targetServer.getPluginManager().callEvent(clickEvent);
            runtime.resetTickStartNanos();
            auditGuiItemExtraction(
                    player,
                    view,
                    beforeTitle,
                    chosen,
                    beforeIconCopies,
                    clickEvent.isCancelled(),
                    cleanCmd,
                    oracle,
                    observedTokens
            );

            if (!hasOpenCustomContainer(player)) {
                menuClosedAfterClick[0] = true;
                observedTokens.add("effect:menu_action:" + chosen.material());
                return;
            }
            InventoryView afterView = player.getOpenInventory();
            Inventory afterTop = afterView != null ? afterView.getTopInventory() : null;
            if (afterTop != null) {
                String afterTitle = safeMenuTitle(afterView);
                String afterSig = snapshotInventorySignature(afterTop);
                if (!Objects.equals(beforeTitle, afterTitle) || !Objects.equals(beforeSig, afterSig)) {
                    submenuRevealedAfterClick[0] = true;
                    String subKey = afterTitle + ":" + afterTop.getSize();
                    observedTokens.add("info:submenu_open:" + subKey);
                    List<SalientSlot> subSalient = rankSalientMenuSlots(afterTop);
                    if (!subSalient.isEmpty()) {
                        MenuExplorationState subState = menuExplorationByKey.computeIfAbsent(subKey, k -> new MenuExplorationState());
                        SalientSlot subChosen = subState.selectSlotToClick(subSalient);
                        if (subChosen != null) {
                            epMenuSlotsClicked[0]++;
                            epClickedItems.add("sub->" + subChosen.formatSummary());
                            InventoryClickEvent subClick = new InventoryClickEvent(
                                    afterView,
                                    InventoryType.SlotType.CONTAINER,
                                    subChosen.slot(),
                                    ClickType.LEFT,
                                    InventoryAction.PICKUP_ALL
                            );
                            targetServer.getPluginManager().callEvent(subClick);
                            runtime.resetTickStartNanos();
                            boolean subClosed = !hasOpenCustomContainer(player);
                            subState.recordOutcome(subChosen.slot(), subClosed, true);
                            if (subClosed) {
                                menuClosedAfterClick[0] = true;
                                observedTokens.add("effect:submenu_action:" + subChosen.material());
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) {
            oracle.recordThrowable(t, "Salient menu click dispatch on /" + cleanCmd);
        }
    }

    static List<SalientSlot> rankSalientMenuSlots(Inventory top) {
        if (top == null || top.getSize() <= 0) {
            return List.of();
        }
        int size = top.getSize();
        Map<String, Integer> sigFreq = new HashMap<>();
        Map<String, Integer> matFreq = new HashMap<>();
        String[] mats = new String[size];
        String[] names = new String[size];
        int[] lores = new int[size];
        boolean[] glints = new boolean[size];
        String[] sigs = new String[size];

        for (int i = 0; i < size; i++) {
            ItemStack item = top.getItem(i);
            if (item == null || item.getType() == Material.AIR) {
                continue;
            }
            String mat = item.getType().name();
            String disp = "";
            int loreCount = 0;
            boolean glint = false;
            String loreText = "";
            try {
                if (item.hasItemMeta()) {
                    ItemMeta meta = item.getItemMeta();
                    if (meta != null) {
                        if (meta.hasDisplayName()) {
                            disp = stripColorCodes(meta.getDisplayName()).trim();
                        }
                        if (meta.hasLore() && meta.getLore() != null) {
                            loreCount = meta.getLore().size();
                            loreText = stripColorCodes(String.join(" ", meta.getLore())).toLowerCase(Locale.ROOT);
                        }
                        glint = meta.hasEnchants();
                    }
                }
            } catch (Throwable ignored) {
            }
            String lowerDisp = disp.toLowerCase(Locale.ROOT);
            if (lowerDisp.contains("quick reload")
                    || lowerDisp.contains("stop server")
                    || loreText.contains("/rtp reload")
                    || loreText.contains("reloads the server")) {
                continue;
            }
            mats[i] = mat;
            names[i] = disp;
            lores[i] = loreCount;
            glints[i] = glint;
            String sig = mat + "|" + disp + "|" + loreCount;
            sigs[i] = sig;
            sigFreq.put(sig, sigFreq.getOrDefault(sig, 0) + 1);
            matFreq.put(mat, matFreq.getOrDefault(mat, 0) + 1);
        }

        List<SalientSlot> positive = new ArrayList<>();
        SalientSlot bestFallback = null;
        for (int i = 0; i < size; i++) {
            if (mats[i] == null) {
                continue;
            }
            String mat = mats[i];
            String disp = names[i];
            int loreCount = lores[i];
            int sf = sigFreq.getOrDefault(sigs[i], 1);
            int mf = matFreq.getOrDefault(mat, 1);

            double score = (120.0 / sf) + (40.0 / mf);
            if (!disp.isEmpty()) {
                score += 45.0;
            }
            if (loreCount > 0) {
                score += 25.0 + Math.min(30.0, loreCount * 6.0);
            }
            if (glints[i]) {
                score += 30.0;
            }
            boolean isFillerMaterial = mat.endsWith("_GLASS_PANE")
                    || mat.equals("IRON_BARS")
                    || mat.equals("GRAY_DYE")
                    || mat.equals("LIGHT_GRAY_DYE")
                    || mat.equals("BLACK_DYE");
            if (isFillerMaterial && (disp.isEmpty() || sf >= 2)) {
                score -= 220.0;
            }
            if (mat.equals("BARRIER")) {
                score -= 160.0;
            }
            SalientSlot slot = new SalientSlot(i, mat, disp, loreCount, score);
            if (bestFallback == null || score > bestFallback.salienceScore()) {
                bestFallback = slot;
            }
            if (score > 0.0) {
                positive.add(slot);
            }
        }
        if (positive.isEmpty() && bestFallback != null) {
            return List.of(bestFallback);
        }
        positive.sort(Comparator.comparingDouble(SalientSlot::salienceScore).reversed().thenComparingInt(SalientSlot::slot));
        return List.copyOf(positive);
    }

    private static String safeMenuTitle(InventoryView view) {
        if (view == null) {
            return "menu";
        }
        try {
            String t = stripColorCodes(view.getTitle()).trim();
            return t.isEmpty() ? view.getTopInventory().getType().name() : t;
        } catch (Throwable ignored) {
            return "menu";
        }
    }

    private static String snapshotInventorySignature(Inventory inv) {
        if (inv == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < inv.getSize(); i++) {
            ItemStack item = inv.getItem(i);
            if (item != null && item.getType() != Material.AIR) {
                sb.append(i).append(':').append(item.getType().name()).append(';');
            }
        }
        return sb.toString();
    }

    private static String stripColorCodes(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        return input.replaceAll("(?i)[§&][0-9A-FK-ORX]", "");
    }

    /**
     * Executes live server BIT self-test canaries ({@code FUZZ-LIVE-002} and {@code FUZZ-LIVE-003})
     * verifying real main-thread MSPT/stack sampling and real {@code ServerPlayer} spawn + random-slot
     * salient menu clicking on the live server.
     *
     * @param plugin owning Bukkit plugin
     * @return list of live platform BIT check results
     */
    public List<LeafFuzzBitSuite.CheckResult> runLivePlatformCanaries(Plugin plugin) {
        List<LeafFuzzBitSuite.CheckResult> out = new ArrayList<>();
        Server targetServer = this.server != null ? this.server : safeBukkitServer();

        // FUZZ-LIVE-002: Live Main-Thread MSPT & Stack Ownership Canary
        long t0 = System.nanoTime();
        try {
            double mspt = runtime.currentServerMspt();
            int jars = runtime.ownershipIndex().indexedJarCount();
            boolean ok = jars > 0 && Double.isFinite(mspt) && mspt >= 0.0;
            double dur = (System.nanoTime() - t0) / 1_000_000.0;
            out.add(new LeafFuzzBitSuite.CheckResult(
                    "FUZZ-LIVE-002",
                    "LIVE-MSPT",
                    ok,
                    String.format(
                            Locale.ROOT,
                            "Live main-thread tick & JAR ownership probe (mspt=%.2f ms, indexedJars=%d)",
                            mspt,
                            jars
                    ),
                    dur
            ));
        } catch (Throwable t) {
            double dur = (System.nanoTime() - t0) / 1_000_000.0;
            out.add(new LeafFuzzBitSuite.CheckResult("FUZZ-LIVE-002", "LIVE-MSPT", false, "Exception: " + t.getMessage(), dur));
        }

        // FUZZ-LIVE-003: Live ServerPlayer Spawn + Random-Slot Shiny Menu Click Canary
        long t1 = System.nanoTime();
        if (targetServer == null || plugin == null) {
            out.add(new LeafFuzzBitSuite.CheckResult("FUZZ-LIVE-003", "LIVE-BOT", false, "Server unavailable", 0.0));
            return out;
        }
        try {
            final int randomTargetSlot = ThreadLocalRandom.current().nextInt(27);
            final int[] clickedSlot = {-1};
            final boolean[] onlineDuringCheck = {false};
            final boolean[] offlineAfterDisconnect = {false};

            Runnable canaryTask = () -> {
                PersonaPolicyBotActor actor = runtime.spawnPersonaBotActor("default");
                LiveServerPlayerSession session = LiveServerPlayerSession.trySpawn(targetServer, actor, false, 0);
                if (session == null || session.craftPlayer() == null) {
                    return;
                }
                Player botPlayer = session.craftPlayer();
                UUID botUuid = botPlayer.getUniqueId();
                onlineDuringCheck[0] = (targetServer.getPlayer(botUuid) != null);

                Inventory canaryMenu = targetServer.createInventory(null, 27, "Canary Menu");
                ItemStack pane = new ItemStack(Material.GRAY_STAINED_GLASS_PANE);
                for (int i = 0; i < 27; i++) {
                    canaryMenu.setItem(i, pane.clone());
                }
                ItemStack shiny = new ItemStack(Material.DIAMOND);
                ItemMeta meta = shiny.getItemMeta();
                if (meta != null) {
                    meta.setDisplayName("§bShiny Canary Action");
                    meta.setLore(List.of("§7Click to trigger canary"));
                    shiny.setItemMeta(meta);
                }
                canaryMenu.setItem(randomTargetSlot, shiny);

                Listener clickListener = new Listener() {
                    @EventHandler
                    public void onClick(InventoryClickEvent e) {
                        if (e.getWhoClicked().getUniqueId().equals(botUuid)) {
                            clickedSlot[0] = e.getRawSlot();
                            e.setCancelled(true);
                            e.getWhoClicked().closeInventory();
                        }
                    }
                };
                targetServer.getPluginManager().registerEvents(clickListener, plugin);
                try {
                    botPlayer.openInventory(canaryMenu);
                    menuExplorationByKey.remove("Canary Menu:27");
                    inspectAndClickSalientMenu(
                            targetServer,
                            botPlayer,
                            "canary",
                            runtime.faultOracle(),
                            new ArrayList<>(),
                            new int[]{0},
                            new int[]{0},
                            new ArrayList<>(),
                            new String[]{null},
                            new int[]{-1},
                            new boolean[]{false},
                            new boolean[]{false}
                    );
                } finally {
                    HandlerList.unregisterAll(clickListener);
                    session.disconnect(runtime.faultOracle());
                    offlineAfterDisconnect[0] = (targetServer.getPlayer(botUuid) == null);
                }
            };

            runOnMainThreadBlocking(canaryTask);
            boolean ok = onlineDuringCheck[0]
                    && clickedSlot[0] == randomTargetSlot
                    && offlineAfterDisconnect[0];
            double dur = (System.nanoTime() - t1) / 1_000_000.0;
            out.add(new LeafFuzzBitSuite.CheckResult(
                    "FUZZ-LIVE-003",
                    "LIVE-BOT",
                    ok,
                    String.format(
                            Locale.ROOT,
                            "Live ServerPlayer + random-slot shiny menu click canary (online=%s, shinySlot=%d, clicked=%d, cleanQuit=%s)",
                            onlineDuringCheck[0],
                            randomTargetSlot,
                            clickedSlot[0],
                            offlineAfterDisconnect[0]
                    ),
                    dur
            ));
        } catch (Throwable t) {
            double dur = (System.nanoTime() - t1) / 1_000_000.0;
            out.add(new LeafFuzzBitSuite.CheckResult("FUZZ-LIVE-003", "LIVE-BOT", false, "Exception: " + t.getMessage(), dur));
        }
        return out;
    }

    private void runOnMainThreadBlocking(Runnable task) {
        runOnMainThreadBlocking(task, null);
    }

    private void runOnMainThreadBlocking(Runnable task, Collection<String> coverageOut) {
        Optional<io.github.dailystruggle.server.api.TaskScheduler> schedOpt = runtime.accessor().scheduler();
        if (schedOpt.isEmpty() || isPrimaryThread(server)) {
            task.run();
            return;
        }
        CompletableFuture<Void> fut = new CompletableFuture<>();
        schedOpt.get().runSync(() -> {
            runtime.resetTickStartNanos();
            try {
                task.run();
                fut.complete(null);
            } catch (Throwable t) {
                fut.completeExceptionally(t);
            } finally {
                runtime.resetTickStartNanos();
            }
        });
        long deadlineMs = System.currentTimeMillis() + 10_000L;
        while (!fut.isDone() && System.currentTimeMillis() < deadlineMs) {
            try {
                fut.get(4L, java.util.concurrent.TimeUnit.MILLISECONDS);
                break;
            } catch (java.util.concurrent.TimeoutException te) {
                runtime.sampleEpisodeCoverageAndStalls(coverageOut);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception ignored) {
                break;
            }
        }
    }

    private void sleepWithStallSampling(long waitMs, Collection<String> coverageOut) {
        long deadline = System.currentTimeMillis() + Math.max(15L, waitMs);
        while (System.currentTimeMillis() < deadline) {
            runtime.sampleEpisodeCoverageAndStalls(coverageOut);
            try {
                Thread.sleep(15L);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        runtime.sampleEpisodeCoverageAndStalls(coverageOut);
    }

    /**
     * Dispatches a reversible world block-break, block-place, or block-interact event when the
     * persona's autonomous policy selects a world-interaction micro-skill and the player's chunk
     * is already resident in memory ({@code S-005}), restoring the original {@link BlockData}
     * immediately in a {@code finally} block so zero permanent world modifications remain.
     */
    static void dispatchReversibleWorldMicroSkill(
            Server targetServer,
            Player activePlayer,
            String selectedSkill,
            LeafFuzzRuntime runtime,
            LogAndStallSignatureOracle oracle,
            List<String> observedTokens
    ) {
        if (targetServer == null || activePlayer == null || selectedSkill == null || selectedSkill.isBlank()) {
            return;
        }
        boolean isBreak = selectedSkill.startsWith("harvest_") || selectedSkill.startsWith("dig_");
        boolean isPlace = selectedSkill.startsWith("place_");
        boolean isInteract = selectedSkill.startsWith("interact_");
        if (!isBreak && !isPlace && !isInteract) {
            return;
        }
        try {
            Location loc = activePlayer.getLocation();
            if (loc == null || loc.getWorld() == null) {
                return;
            }
            World world = loc.getWorld();
            int bx = loc.getBlockX() + 1;
            int bz = loc.getBlockZ();
            if (!world.isChunkLoaded(bx >> 4, bz >> 4)) {
                return;
            }
            int by = Math.max(world.getMinHeight() + 1, Math.min(world.getMaxHeight() - 2, loc.getBlockY()));
            Block targetBlock = world.getBlockAt(bx, by, bz);
            if (targetBlock == null) {
                return;
            }
            BlockData savedData = targetBlock.getBlockData() != null ? targetBlock.getBlockData().clone() : null;
            try {
                if (isBreak) {
                    BlockBreakEvent breakEv = new BlockBreakEvent(targetBlock, activePlayer);
                    dispatchTargetScopedEvent(
                            targetServer,
                            breakEv,
                            runtime,
                            oracle,
                            "Synthetic BlockBreakEvent micro-skill (" + selectedSkill + ")"
                    );
                    runtime.recordBlockSkillExecution();
                    observedTokens.add(breakEv.isCancelled()
                            ? "info:block_break_cancelled:" + selectedSkill
                            : "effect:block_break:" + selectedSkill);
                } else if (isPlace) {
                    Block against = world.getBlockAt(bx, Math.max(world.getMinHeight(), by - 1), bz);
                    BlockState replacedState = targetBlock.getState();
                    ItemStack held = new ItemStack(Material.COBBLESTONE, 1);
                    BlockPlaceEvent placeEv = new BlockPlaceEvent(
                            targetBlock,
                            replacedState,
                            against,
                            held,
                            activePlayer,
                            true,
                            EquipmentSlot.HAND
                    );
                    dispatchTargetScopedEvent(
                            targetServer,
                            placeEv,
                            runtime,
                            oracle,
                            "Synthetic BlockPlaceEvent micro-skill (" + selectedSkill + ")"
                    );
                    runtime.recordBlockSkillExecution();
                    observedTokens.add(placeEv.isCancelled()
                            ? "info:block_place_cancelled:" + selectedSkill
                            : "effect:block_place:" + selectedSkill);
                } else {
                    PlayerInteractEvent interactEv = new PlayerInteractEvent(
                            activePlayer,
                            Action.RIGHT_CLICK_BLOCK,
                            new ItemStack(Material.STICK, 1),
                            targetBlock,
                            BlockFace.UP,
                            EquipmentSlot.HAND
                    );
                    dispatchTargetScopedEvent(
                            targetServer,
                            interactEv,
                            runtime,
                            oracle,
                            "Synthetic PlayerInteractEvent micro-skill (" + selectedSkill + ")"
                    );
                    runtime.recordBlockSkillExecution();
                    observedTokens.add("effect:block_interact:" + selectedSkill);
                }
            } finally {
                if (savedData != null) {
                    try {
                        targetBlock.setBlockData(savedData, false);
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    static int countMatchingMenuIconInPlayerInventory(
            Player player,
            InventoryView view,
            SalientSlot chosen
    ) {
        if (player == null || chosen == null || chosen.displayName() == null || chosen.displayName().isBlank()) {
            return 0;
        }
        int total = 0;
        try {
            PlayerInventory inv = player.getInventory();
            if (inv != null && inv.getContents() != null) {
                for (ItemStack stack : inv.getContents()) {
                    if (matchesMenuIcon(stack, chosen)) {
                        total += Math.max(1, stack.getAmount());
                    }
                }
            }
            if (view != null) {
                ItemStack cursor = view.getCursor();
                if (matchesMenuIcon(cursor, chosen)) {
                    total += Math.max(1, cursor.getAmount());
                }
            }
        } catch (Throwable ignored) {
        }
        return total;
    }

    private static boolean matchesMenuIcon(ItemStack stack, SalientSlot chosen) {
        if (stack == null || stack.getType() == Material.AIR || !stack.getType().name().equals(chosen.material())) {
            return false;
        }
        if (!stack.hasItemMeta()) {
            return false;
        }
        ItemMeta meta = stack.getItemMeta();
        if (meta == null || !meta.hasDisplayName()) {
            return false;
        }
        String disp = stripColorCodes(meta.getDisplayName()).trim();
        return disp.equalsIgnoreCase(chosen.displayName());
    }

    static void auditGuiItemExtraction(
            Player player,
            InventoryView view,
            String menuTitle,
            SalientSlot chosen,
            int beforeIconCopies,
            boolean clickCancelled,
            String cleanCmd,
            LogAndStallSignatureOracle oracle,
            List<String> observedTokens
    ) {
        if (player == null || chosen == null || oracle == null) {
            return;
        }
        try {
            if (player.isOp()) {
                return;
            }
            int afterIconCopies = countMatchingMenuIconInPlayerInventory(player, view, chosen);
            if (afterIconCopies > beforeIconCopies && clickCancelled) {
                String safeTitle = (menuTitle == null || menuTitle.isBlank())
                        ? "CustomMenu"
                        : menuTitle.replaceAll("[^A-Za-z0-9_]", "");
                if (safeTitle.isEmpty()) {
                    safeTitle = "CustomMenu";
                }
                String suspectJar = (cleanCmd != null && !cleanCmd.isBlank())
                        ? cleanCmd.split("\\s+")[0].replace("/", "")
                        : "plugin";
                oracle.recordCustomHazard(
                        "gui-item-leak",
                        "GuiMenu." + safeTitle + ".slot" + chosen.slot(),
                        suspectJar,
                        afterIconCopies - beforeIconCopies,
                        "Cancelled GUI click leaked menu icon '" + chosen.formatSummary()
                                + "' into unprivileged player inventory in '" + menuTitle + "'"
                );
                if (observedTokens != null) {
                    observedTokens.add("hazard:gui-item-leak:" + safeTitle + ":" + chosen.slot());
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static Server safeBukkitServer() {
        try {
            return Bukkit.getServer();
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Live NMS {@code ServerPlayer} + Netty {@code EmbeddedChannel} {@code Connection} session
     * registered in {@code PlayerList} via {@code placeNewPlayer} so {@code Bukkit.getPlayer(uuid)},
     * {@code Bukkit.getOnlinePlayers()}, chunk tracking, and Netty packet pipelines see a real
     * online player during the episode.
     */
    private static final class LiveServerPlayerSession {
        private final Object playerList;
        private final Object serverPlayer;
        private final Player craftPlayer;
        private final Object embeddedChannel;
        private final boolean opGranted;
        private final String spawnWorldName;
        private final double spawnX;
        private final double spawnY;
        private final double spawnZ;
        private int chatOrInfoPackets;
        private int teleportPacketsAfterJoin;
        private boolean joinDrainDone;
        private boolean disconnected;

        private LiveServerPlayerSession(
                Object playerList,
                Object serverPlayer,
                Player craftPlayer,
                Object embeddedChannel,
                boolean opGranted
        ) {
            this.playerList = playerList;
            this.serverPlayer = serverPlayer;
            this.craftPlayer = craftPlayer;
            this.embeddedChannel = embeddedChannel;
            this.opGranted = opGranted;
            Location loc = craftPlayer != null ? craftPlayer.getLocation() : null;
            this.spawnWorldName = (loc != null && loc.getWorld() != null) ? loc.getWorld().getName() : "world";
            this.spawnX = loc != null ? loc.getX() : 0.0;
            this.spawnY = loc != null ? loc.getY() : 64.0;
            this.spawnZ = loc != null ? loc.getZ() : 0.0;
        }

        private static final java.util.concurrent.atomic.AtomicBoolean LOGGED_SPAWN_ERROR =
                new java.util.concurrent.atomic.AtomicBoolean(false);

        Player craftPlayer() {
            return craftPlayer;
        }

        int chatOrInfoPacketsSeen() {
            return chatOrInfoPackets;
        }

        double displacementFromSpawn() {
            if (craftPlayer == null) {
                return 0.0;
            }
            try {
                Location cur = craftPlayer.getLocation();
                if (cur == null) {
                    return 0.0;
                }
                String curWorld = cur.getWorld() != null ? cur.getWorld().getName() : spawnWorldName;
                if (!Objects.equals(curWorld, spawnWorldName)) {
                    return 1024.0;
                }
                double dx = cur.getX() - spawnX;
                double dz = cur.getZ() - spawnZ;
                double horiz = Math.hypot(dx, dz);
                if (horiz >= 4.0) {
                    return horiz;
                }
                if (teleportPacketsAfterJoin > 0) {
                    double dy = Math.abs(cur.getY() - spawnY);
                    return Math.max(horiz, dy >= 4.0 ? dy : 0.0);
                }
                return horiz;
            } catch (Throwable ignored) {
                return 0.0;
            }
        }

        static LiveServerPlayerSession trySpawn(
                Server targetServer,
                PersonaPolicyBotActor bot,
                boolean op,
                int botIndex
        ) {
            if (targetServer == null || bot == null) {
                return null;
            }
            try {
                Object mcServer = targetServer.getClass().getMethod("getServer").invoke(targetServer);
                if (mcServer == null) {
                    return null;
                }
                ClassLoader cl = mcServer.getClass().getClassLoader();
                Class<?> mcServerCls = Class.forName("net.minecraft.server.MinecraftServer", true, cl);
                Object overworld = mcServerCls.getMethod("overworld").invoke(mcServer);
                Object playerList = mcServerCls.getMethod("getPlayerList").invoke(mcServer);
                if (overworld == null || playerList == null) {
                    return null;
                }

                Class<?> serverLevelCls = Class.forName("net.minecraft.server.level.ServerLevel", true, cl);
                Class<?> playerListCls = Class.forName("net.minecraft.server.players.PlayerList", true, cl);
                Class<?> gameProfileCls = Class.forName("com.mojang.authlib.GameProfile", true, cl);
                Class<?> clientInfoCls = Class.forName("net.minecraft.server.level.ClientInformation", true, cl);
                Class<?> serverPlayerCls = Class.forName("net.minecraft.server.level.ServerPlayer", true, cl);
                Class<?> packetFlowCls = Class.forName("net.minecraft.network.protocol.PacketFlow", true, cl);
                Class<?> connectionCls = Class.forName("net.minecraft.network.Connection", true, cl);
                Class<?> cookieCls = Class.forName("net.minecraft.server.network.CommonListenerCookie", true, cl);
                Class<?> embeddedChannelCls = Class.forName("io.netty.channel.embedded.EmbeddedChannel", true, cl);
                Class<?> channelPipelineCls = Class.forName("io.netty.channel.ChannelPipeline", true, cl);

                String safeName = bot.actorName(botIndex);
                UUID botUuid = (botIndex == 0)
                        ? bot.actorUuid()
                        : UUID.nameUUIDFromBytes(("leaffuzz-peer-" + safeName + "-" + bot.actorUuid()).getBytes(java.nio.charset.StandardCharsets.UTF_8));

                Object gameProfile = gameProfileCls.getConstructor(UUID.class, String.class).newInstance(botUuid, safeName);
                Object clientInfo = clientInfoCls.getMethod("createDefault").invoke(null);
                Object serverPlayer = serverPlayerCls
                        .getConstructor(mcServerCls, serverLevelCls, gameProfileCls, clientInfoCls)
                        .newInstance(mcServer, overworld, gameProfile, clientInfo);

                try {
                    org.bukkit.World defaultWorld = !targetServer.getWorlds().isEmpty()
                            ? targetServer.getWorlds().get(0)
                            : null;
                    double targetX = bot.x() + 0.5;
                    double targetY = bot.y();
                    double targetZ = bot.z() + 0.5;
                    if (defaultWorld != null) {
                        int cx = ((int) Math.floor(targetX)) >> 4;
                        int cz = ((int) Math.floor(targetZ)) >> 4;
                        if (!defaultWorld.isChunkLoaded(cx, cz)) {
                            Location spawnLoc = defaultWorld.getSpawnLocation();
                            int offsetX = ((botIndex % 5) - 2) * 4;
                            int offsetZ = (((botIndex / 5) % 5) - 2) * 4;
                            int candX = spawnLoc.getBlockX() + offsetX;
                            int candZ = spawnLoc.getBlockZ() + offsetZ;
                            if (defaultWorld.isChunkLoaded(candX >> 4, candZ >> 4)) {
                                targetX = candX + 0.5;
                                targetY = Math.max(64.0, spawnLoc.getY());
                                targetZ = candZ + 0.5;
                            } else {
                                targetX = spawnLoc.getBlockX() + 0.5;
                                targetY = Math.max(64.0, spawnLoc.getY());
                                targetZ = spawnLoc.getBlockZ() + 0.5;
                            }
                        }
                    }
                    serverPlayerCls.getMethod("setPos", double.class, double.class, double.class)
                            .invoke(serverPlayer, targetX, targetY, targetZ);
                } catch (Throwable ignored) {
                }

                Object serverboundFlow = packetFlowCls.getField("SERVERBOUND").get(null);
                Object connection = connectionCls.getConstructor(packetFlowCls).newInstance(serverboundFlow);
                Object channel = embeddedChannelCls.getConstructor().newInstance();
                Object pipeline = embeddedChannelCls.getMethod("pipeline").invoke(channel);

                Class<?> channelHandlerCls = Class.forName("io.netty.channel.ChannelHandler", true, cl);
                Class<?> inboundUnconfigCls = Class.forName("net.minecraft.network.UnconfiguredPipelineHandler$Inbound", true, cl);
                java.lang.reflect.Method addLast = channelPipelineCls.getMethod("addLast", String.class, channelHandlerCls);
                addLast.invoke(pipeline, "inbound_config", inboundUnconfigCls.getConstructor().newInstance());
                connectionCls.getMethod("configurePacketHandler", channelPipelineCls)
                        .invoke(connection, pipeline);
                connectionCls.getField("channel").set(connection, channel);
                connectionCls.getField("address").set(connection, new InetSocketAddress("127.0.0.1", 25565 + botIndex));

                Object cookie = cookieCls.getMethod("createInitial", gameProfileCls, boolean.class)
                        .invoke(null, gameProfile, false);

                playerListCls
                        .getMethod("placeNewPlayer", connectionCls, serverPlayerCls, cookieCls)
                        .invoke(playerList, connection, serverPlayer, cookie);

                Object bukkitEntity = serverPlayerCls.getMethod("getBukkitEntity").invoke(serverPlayer);
                if (!(bukkitEntity instanceof Player craftPlayer)) {
                    return null;
                }
                if (op) {
                    craftPlayer.setOp(true);
                }
                LiveServerPlayerSession session = new LiveServerPlayerSession(
                        playerList,
                        serverPlayer,
                        craftPlayer,
                        channel,
                        op
                );
                session.drainOutboundPackets();
                session.joinDrainDone = true;
                return session;
            } catch (Throwable t) {
                if (LOGGED_SPAWN_ERROR.compareAndSet(false, true)) {
                    Throwable cause = (t instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() != null)
                            ? ite.getCause()
                            : t;
                    try {
                        targetServer.getLogger().warning("[LeafFuzz] LiveServerPlayerSession fallback: " + cause);
                    } catch (Throwable ignored) {
                    }
                }
                return null;
            }
        }

        void sendMovePacket(
                double x,
                double y,
                double z,
                float yaw,
                float pitch,
                LogAndStallSignatureOracle oracle
        ) {
            if (disconnected) {
                return;
            }
            try {
                if (craftPlayer != null && craftPlayer.getWorld() != null) {
                    org.bukkit.World w = craftPlayer.getWorld();
                    Location cur = craftPlayer.getLocation();
                    if (cur != null) {
                        double dx = Math.max(-3.5, Math.min(3.5, x - cur.getX()));
                        double dz = Math.max(-3.5, Math.min(3.5, z - cur.getZ()));
                        double candX = cur.getX() + dx;
                        double candZ = cur.getZ() + dz;
                        int cx = ((int) Math.floor(candX)) >> 4;
                        int cz = ((int) Math.floor(candZ)) >> 4;
                        if (w.isChunkLoaded(cx, cz)) {
                            x = candX;
                            y = cur.getY();
                            z = candZ;
                        } else {
                            x = cur.getX();
                            y = cur.getY();
                            z = cur.getZ();
                        }
                    }
                }
                ClassLoader cl = serverPlayer.getClass().getClassLoader();
                Object listener = resolvePacketListener();
                if (listener == null) {
                    return;
                }
                Class<?> posRotCls = Class.forName(
                        "net.minecraft.network.protocol.game.ServerboundMovePlayerPacket$PosRot",
                        true,
                        cl
                );
                Class<?> movePktCls = Class.forName(
                        "net.minecraft.network.protocol.game.ServerboundMovePlayerPacket",
                        true,
                        cl
                );
                Object pkt = posRotCls.getConstructor(
                        double.class,
                        double.class,
                        double.class,
                        float.class,
                        float.class,
                        boolean.class,
                        boolean.class
                ).newInstance(x, y, z, yaw, pitch, true, false);
                listener.getClass().getMethod("handleMovePlayer", movePktCls).invoke(listener, pkt);
                drainOutboundPackets();
            } catch (Throwable t) {
                Throwable cause = (t instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() != null)
                        ? ite.getCause()
                        : t;
                oracle.recordThrowable(cause, "ServerboundMovePlayerPacket$PosRot follow-up exception");
            }
        }

        void sendContainerClosePacket(LogAndStallSignatureOracle oracle) {
            if (disconnected) {
                return;
            }
            try {
                ClassLoader cl = serverPlayer.getClass().getClassLoader();
                Object listener = resolvePacketListener();
                if (listener == null) {
                    return;
                }
                Class<?> closePktCls = Class.forName(
                        "net.minecraft.network.protocol.game.ServerboundContainerClosePacket",
                        true,
                        cl
                );
                Object pkt = closePktCls.getConstructor(int.class).newInstance(0);
                listener.getClass().getMethod("handleContainerClose", closePktCls).invoke(listener, pkt);
                drainOutboundPackets();
            } catch (Throwable t) {
                Throwable cause = (t instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() != null)
                        ? ite.getCause()
                        : t;
                oracle.recordThrowable(cause, "ServerboundContainerClosePacket follow-up exception");
            }
        }

        void drainOutboundPackets() {
            if (embeddedChannel == null) {
                return;
            }
            try {
                java.lang.reflect.Method readOutbound = embeddedChannel.getClass().getMethod("readOutbound");
                Object msg;
                int guard = 0;
                while ((msg = readOutbound.invoke(embeddedChannel)) != null && guard++ < 512) {
                    String clsName = msg.getClass().getSimpleName();
                    if (joinDrainDone) {
                        if (clsName.contains("SystemChat")
                                || clsName.contains("DisguisedChat")
                                || clsName.contains("PlayerChat")
                                || clsName.contains("ActionBar")
                                || clsName.contains("SetTitle")
                                || clsName.contains("BossEvent")
                                || clsName.contains("OpenBook")) {
                            chatOrInfoPackets++;
                        }
                    }
                    if (clsName.contains("PlayerPosition")) {
                        if (joinDrainDone) {
                            teleportPacketsAfterJoin++;
                        }
                        confirmTeleportPacket(msg);
                    }
                    try {
                        Class<?> refCountedCls = Class.forName(
                                "io.netty.util.ReferenceCounted",
                                false,
                                embeddedChannel.getClass().getClassLoader()
                        );
                        if (refCountedCls.isInstance(msg)) {
                            refCountedCls.getMethod("release").invoke(msg);
                        }
                    } catch (Throwable ignored) {
                    }
                }
                embeddedChannel.getClass().getMethod("releaseOutbound").invoke(embeddedChannel);
            } catch (Throwable ignored) {
            }
        }

        private void confirmTeleportPacket(Object positionPacket) {
            try {
                int tpId = -1;
                for (String mName : new String[]{"id", "getId"}) {
                    try {
                        Object res = positionPacket.getClass().getMethod(mName).invoke(positionPacket);
                        if (res instanceof Integer i) {
                            tpId = i;
                            break;
                        }
                    } catch (NoSuchMethodException ignored) {
                    }
                }
                if (tpId < 0) {
                    return;
                }
                Object listener = resolvePacketListener();
                if (listener == null) {
                    return;
                }
                ClassLoader cl = serverPlayer.getClass().getClassLoader();
                Class<?> acceptCls = Class.forName(
                        "net.minecraft.network.protocol.game.ServerboundAcceptTeleportationPacket",
                        true,
                        cl
                );
                Object acceptPkt = acceptCls.getConstructor(int.class).newInstance(tpId);
                listener.getClass().getMethod("handleAcceptTeleportPacket", acceptCls).invoke(listener, acceptPkt);
            } catch (Throwable ignored) {
            }
        }

        void disconnect(LogAndStallSignatureOracle oracle) {
            if (disconnected) {
                return;
            }
            disconnected = true;
            try {
                if (opGranted && craftPlayer != null) {
                    craftPlayer.setOp(false);
                }
            } catch (Throwable ignored) {
            }
            try {
                Class<?> serverPlayerCls = Class.forName(
                        "net.minecraft.server.level.ServerPlayer",
                        true,
                        serverPlayer.getClass().getClassLoader()
                );
                playerList.getClass().getMethod("remove", serverPlayerCls).invoke(playerList, serverPlayer);
            } catch (Throwable t) {
                Throwable cause = (t instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() != null)
                        ? ite.getCause()
                        : t;
                oracle.recordThrowable(cause, "PlayerList#remove follow-up exception");
            }
            try {
                if (embeddedChannel != null) {
                    embeddedChannel.getClass().getMethod("releaseOutbound").invoke(embeddedChannel);
                    embeddedChannel.getClass().getMethod("releaseInbound").invoke(embeddedChannel);
                }
            } catch (Throwable ignored) {
            }
        }

        private Object resolvePacketListener() {
            try {
                return serverPlayer.getClass().getField("connection").get(serverPlayer);
            } catch (Throwable ignored) {
                return null;
            }
        }
    }
}
