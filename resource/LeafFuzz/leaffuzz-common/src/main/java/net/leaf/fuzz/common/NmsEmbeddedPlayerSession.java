package net.leaf.fuzz.common;

import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Cross-platform reflective NMS {@code ServerPlayer} + Netty {@code EmbeddedChannel} session and
 * Archimedean spiral coordinate allocator for Paper, Folia, Fabric, and NeoForge
 * ({@code ADR-115}, {@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Spawns real server-side {@code ServerPlayer} entities via {@code PlayerList#placeNewPlayer}
 * at deterministic golden-angle Archimedean spiral coordinates without synchronous main-thread
 * chunk I/O ({@code S-005}), enabling 100-player concurrent chunk-ticket, entity-tracking, and
 * command/movement survival verification across all supported mod and plugin platforms.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-002
 * @trace S-004
 * @trace S-005
 */
public final class NmsEmbeddedPlayerSession {

    /** Golden angle in radians ({@code pi * (3 - sqrt(5))}) for uniform 2D spiral dispersion. */
    private static final double GOLDEN_ANGLE_RAD = 2.39996322972865332;

    /** Default inter-bot spiral radial stride in blocks (3 chunks). */
    public static final int DEFAULT_SPIRAL_STRIDE_BLOCKS = 48;

    private static final AtomicBoolean LOGGED_SPAWN_FALLBACK = new AtomicBoolean(false);

    /**
     * Immutable 3D block coordinate assigned along the Archimedean spiral.
     *
     * @param x      block X coordinate
     * @param y      block Y coordinate
     * @param z      block Z coordinate
     * @param chunkX chunk X coordinate ({@code x >> 4})
     * @param chunkZ chunk Z coordinate ({@code z >> 4})
     */
    public record SpiralAnchor(int x, int y, int z, int chunkX, int chunkZ) {
    }

    /**
     * Snapshot of live server population, loaded chunks, and tracked entities.
     *
     * @param onlinePlayers   online players reported by the server or active swarm roster
     * @param loadedChunks    loaded chunks across server worlds
     * @param trackedEntities tracked entities across server worlds
     */
    public record WorldCensus(int onlinePlayers, int loadedChunks, int trackedEntities) {
    }

    private final Object mcServer;
    private final Object playerList;
    private final Object serverPlayer;
    private final Object embeddedChannel;
    private final PersonaPolicyBotActor botActor;
    private final boolean opGranted;
    private final double spawnX;
    private final double spawnY;
    private final double spawnZ;
    private int chatOrInfoPackets;
    private int teleportPacketsAfterJoin;
    private boolean joinDrainDone;
    private boolean disconnected;

    private NmsEmbeddedPlayerSession(
            Object mcServer,
            Object playerList,
            Object serverPlayer,
            Object embeddedChannel,
            PersonaPolicyBotActor botActor,
            boolean opGranted,
            double spawnX,
            double spawnY,
            double spawnZ
    ) {
        this.mcServer = mcServer;
        this.playerList = playerList;
        this.serverPlayer = serverPlayer;
        this.embeddedChannel = embeddedChannel;
        this.botActor = botActor;
        this.opGranted = opGranted;
        this.spawnX = spawnX;
        this.spawnY = spawnY;
        this.spawnZ = spawnZ;
    }

    /**
     * Computes a deterministic golden-angle Archimedean spiral anchor for {@code slotIndex}
     * without touching world chunk storage ({@code S-005}).
     *
     * @param slotIndex    zero-based bot slot index in {@code [0, N)}
     * @param strideBlocks radial spacing in blocks (clamped to {@code >= 16})
     * @return spiral block and chunk coordinates at {@code Y = 64}
     */
    public static SpiralAnchor computeSpiralAnchor(int slotIndex, int strideBlocks) {
        int idx = Math.max(0, slotIndex);
        int stride = Math.max(16, strideBlocks);
        if (idx == 0) {
            return new SpiralAnchor(16, 64, -16, 1, -1);
        }
        double radius = stride * Math.sqrt(idx);
        double theta = idx * GOLDEN_ANGLE_RAD;
        int x = (int) Math.round(radius * Math.cos(theta));
        int z = (int) Math.round(radius * Math.sin(theta));
        return new SpiralAnchor(x, 64, z, x >> 4, z >> 4);
    }

    /**
     * Positions {@code bot} at the deterministic Archimedean spiral anchor for {@code slotIndex}.
     *
     * @param bot       persona bot actor to position
     * @param slotIndex zero-based roster slot index
     * @return assigned {@link SpiralAnchor}
     */
    public static SpiralAnchor assignSpiralAnchor(PersonaPolicyBotActor bot, int slotIndex) {
        Objects.requireNonNull(bot, "bot");
        SpiralAnchor anchor = computeSpiralAnchor(slotIndex, DEFAULT_SPIRAL_STRIDE_BLOCKS);
        bot.setLocation(anchor.x(), anchor.y(), anchor.z());
        return anchor;
    }

    /**
     * Attempts to spawn a live NMS {@code ServerPlayer} backed by a Netty {@code EmbeddedChannel}
     * on the given Mojang-mapped {@code net.minecraft.server.MinecraftServer} instance.
     *
     * @param mcServer Mojang-mapped {@code MinecraftServer} instance (Fabric, NeoForge, or Paper)
     * @param bot      persona bot actor
     * @param op       whether operator privileges are requested
     * @param botIndex roster slot index
     * @return spawned session, or {@code null} if the runtime environment lacks NMS classes
     */
    public static NmsEmbeddedPlayerSession trySpawnOnMinecraftServer(
            Object mcServer,
            PersonaPolicyBotActor bot,
            boolean op,
            int botIndex
    ) {
        if (mcServer == null || bot == null) {
            return null;
        }
        try {
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

            String baseName = bot.actorName() != null
                    ? bot.actorName().replaceAll("[^a-zA-Z0-9_]", "")
                    : "FuzzBot";
            if (baseName.length() > 11) {
                baseName = baseName.substring(0, 11);
            }
            String safeName = (botIndex <= 0) ? baseName : (baseName + "_" + botIndex);
            if (safeName.length() > 16) {
                safeName = safeName.substring(0, 16);
            }
            UUID botUuid = (botIndex <= 0)
                    ? bot.actorUuid()
                    : UUID.nameUUIDFromBytes(
                            ("leaffuzz-swarm-" + botIndex + "-" + safeName + "-" + bot.actorUuid())
                                    .getBytes(StandardCharsets.UTF_8)
                    );

            Object gameProfile = gameProfileCls.getConstructor(UUID.class, String.class)
                    .newInstance(botUuid, safeName);
            Object clientInfo = clientInfoCls.getMethod("createDefault").invoke(null);
            Object serverPlayer = serverPlayerCls
                    .getConstructor(mcServerCls, serverLevelCls, gameProfileCls, clientInfoCls)
                    .newInstance(mcServer, overworld, gameProfile, clientInfo);

            double sx = bot.x() + 0.5;
            double sy = bot.y();
            double sz = bot.z() + 0.5;
            try {
                serverPlayerCls.getMethod("setPos", double.class, double.class, double.class)
                        .invoke(serverPlayer, sx, sy, sz);
            } catch (Throwable ignored) {
            }

            Object serverboundFlow = packetFlowCls.getField("SERVERBOUND").get(null);
            Object connection = connectionCls.getConstructor(packetFlowCls).newInstance(serverboundFlow);
            Object channel = embeddedChannelCls.getConstructor().newInstance();
            Object pipeline = embeddedChannelCls.getMethod("pipeline").invoke(channel);

            Class<?> channelHandlerCls = Class.forName("io.netty.channel.ChannelHandler", true, cl);
            Class<?> inboundUnconfigCls = Class.forName(
                    "net.minecraft.network.UnconfiguredPipelineHandler$Inbound",
                    true,
                    cl
            );
            Method addLast = channelPipelineCls.getMethod("addLast", String.class, channelHandlerCls);
            addLast.invoke(pipeline, "inbound_config", inboundUnconfigCls.getConstructor().newInstance());
            connectionCls.getMethod("configurePacketHandler", channelPipelineCls)
                    .invoke(connection, pipeline);
            connectionCls.getField("channel").set(connection, channel);
            connectionCls.getField("address").set(
                    connection,
                    new InetSocketAddress("127.0.0.1", 26000 + Math.floorMod(botIndex, 16000))
            );

            Object cookie = cookieCls.getMethod("createInitial", gameProfileCls, boolean.class)
                    .invoke(null, gameProfile, false);
            playerListCls.getMethod("placeNewPlayer", connectionCls, serverPlayerCls, cookieCls)
                    .invoke(playerList, connection, serverPlayer, cookie);

            NmsEmbeddedPlayerSession session = new NmsEmbeddedPlayerSession(
                    mcServer,
                    playerList,
                    serverPlayer,
                    channel,
                    bot,
                    op,
                    sx,
                    sy,
                    sz
            );
            session.drainOutboundPackets();
            session.joinDrainDone = true;
            return session;
        } catch (Throwable t) {
            LOGGED_SPAWN_FALLBACK.compareAndSet(false, true);
            return null;
        }
    }

    public Object serverPlayer() {
        return serverPlayer;
    }

    public PersonaPolicyBotActor botActor() {
        return botActor;
    }

    public boolean isOpGranted() {
        return opGranted;
    }

    public boolean isDisconnected() {
        return disconnected;
    }

    public int chatOrInfoPacketsSeen() {
        return chatOrInfoPackets;
    }

    /**
     * Creates a Brigadier {@code CommandSourceStack} bound to this live {@code ServerPlayer}
     * entity so player-only commands ({@code source.getPlayerOrException()}) execute against a
     * real world entity on Fabric and NeoForge.
     *
     * @return {@code CommandSourceStack} instance, or {@code null} on failure
     */
    public Object createCommandSourceStack() {
        if (serverPlayer == null || disconnected) {
            return null;
        }
        try {
            Object source = serverPlayer.getClass().getMethod("createCommandSourceStack").invoke(serverPlayer);
            if (source == null) {
                return null;
            }
            try {
                source = source.getClass().getMethod("withSuppressedOutput").invoke(source);
            } catch (Throwable ignored) {
            }
            if (opGranted) {
                try {
                    source = source.getClass().getMethod("withPermission", int.class).invoke(source, 4);
                } catch (NoSuchMethodException e) {
                    try {
                        ClassLoader cl = source.getClass().getClassLoader();
                        Class<?> permSetCls = Class.forName(
                                "net.minecraft.server.permissions.PermissionSet",
                                true,
                                cl
                        );
                        Class<?> lvlSetCls = Class.forName(
                                "net.minecraft.server.permissions.LevelBasedPermissionSet",
                                true,
                                cl
                        );
                        Object ownerPerm = lvlSetCls.getField("OWNER").get(null);
                        source = source.getClass().getMethod("withPermission", permSetCls)
                                .invoke(source, ownerPerm);
                    } catch (Throwable ignored) {
                    }
                }
            }
            return source;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Sends a {@code ServerboundMovePlayerPacket$PosRot} packet to the player's packet listener,
     * updating chunk tracking and firing platform movement hooks.
     */
    public void sendMovePacket(
            double x,
            double y,
            double z,
            float yaw,
            float pitch,
            LogAndStallSignatureOracle oracle
    ) {
        if (disconnected || serverPlayer == null) {
            return;
        }
        try {
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
            if (botActor != null) {
                botActor.setLocation((int) Math.floor(x), (int) Math.floor(y), (int) Math.floor(z));
            }
            drainOutboundPackets();
        } catch (Throwable t) {
            if (oracle != null) {
                Throwable cause = (t instanceof InvocationTargetException ite && ite.getCause() != null)
                        ? ite.getCause()
                        : t;
                oracle.recordThrowable(cause, "ServerboundMovePlayerPacket$PosRot exception");
            }
        }
    }

    /**
     * Drains outbound packets queued in the {@code EmbeddedChannel}, confirming server teleports
     * via {@code ServerboundAcceptTeleportationPacket} and releasing Netty {@code ReferenceCounted}
     * buffers so chunk/entity packets do not leak direct memory.
     */
    public void drainOutboundPackets() {
        if (embeddedChannel == null) {
            return;
        }
        try {
            Method readOutbound = embeddedChannel.getClass().getMethod("readOutbound");
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

    /**
     * Returns the horizontal (or vertical teleport) displacement in blocks from the bot's spawn
     * coordinates.
     */
    public double displacementFromSpawn() {
        if (serverPlayer == null) {
            return 0.0;
        }
        try {
            double curX = ((Number) serverPlayer.getClass().getMethod("getX").invoke(serverPlayer)).doubleValue();
            double curY = ((Number) serverPlayer.getClass().getMethod("getY").invoke(serverPlayer)).doubleValue();
            double curZ = ((Number) serverPlayer.getClass().getMethod("getZ").invoke(serverPlayer)).doubleValue();
            double horiz = Math.hypot(curX - spawnX, curZ - spawnZ);
            if (horiz >= 4.0) {
                return horiz;
            }
            if (teleportPacketsAfterJoin > 0) {
                double dy = Math.abs(curY - spawnY);
                return Math.max(horiz, dy >= 4.0 ? dy : 0.0);
            }
            return horiz;
        } catch (Throwable ignored) {
            return 0.0;
        }
    }

    /**
     * Removes the {@code ServerPlayer} from {@code PlayerList} and releases all Netty channel
     * buffers ({@code S-002}).
     */
    public void disconnect(LogAndStallSignatureOracle oracle) {
        if (disconnected) {
            return;
        }
        disconnected = true;
        try {
            Class<?> serverPlayerCls = Class.forName(
                    "net.minecraft.server.level.ServerPlayer",
                    true,
                    serverPlayer.getClass().getClassLoader()
            );
            playerList.getClass().getMethod("remove", serverPlayerCls).invoke(playerList, serverPlayer);
        } catch (Throwable t) {
            if (oracle != null) {
                Throwable cause = (t instanceof InvocationTargetException ite && ite.getCause() != null)
                        ? ite.getCause()
                        : t;
                oracle.recordThrowable(cause, "PlayerList#remove exception");
            }
        }
        try {
            if (embeddedChannel != null) {
                embeddedChannel.getClass().getMethod("releaseOutbound").invoke(embeddedChannel);
                embeddedChannel.getClass().getMethod("releaseInbound").invoke(embeddedChannel);
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Samples online player count, loaded chunk count, and tracked entity count from a
     * Mojang-mapped {@code MinecraftServer} without loading any chunks ({@code S-005}).
     */
    public static WorldCensus sampleWorldCensus(Object mcServer, int fallbackOnlineBots) {
        int online = Math.max(0, fallbackOnlineBots);
        int chunks = 0;
        int entities = 0;
        if (mcServer == null) {
            return new WorldCensus(online, 0, 0);
        }
        try {
            Object playerList = mcServer.getClass().getMethod("getPlayerList").invoke(mcServer);
            if (playerList != null) {
                Object cnt = playerList.getClass().getMethod("getPlayerCount").invoke(playerList);
                if (cnt instanceof Number n) {
                    online = Math.max(online, n.intValue());
                }
            }
            Object levelsObj = mcServer.getClass().getMethod("getAllLevels").invoke(mcServer);
            if (levelsObj instanceof Iterable<?> levels) {
                for (Object level : levels) {
                    if (level == null) {
                        continue;
                    }
                    try {
                        Object chunkSource = level.getClass().getMethod("getChunkSource").invoke(level);
                        if (chunkSource != null) {
                            Object cCnt = chunkSource.getClass().getMethod("getLoadedChunksCount").invoke(chunkSource);
                            if (cCnt instanceof Number n) {
                                chunks += Math.max(0, n.intValue());
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                    try {
                        Object entityIter = level.getClass().getMethod("getAllEntities").invoke(level);
                        if (entityIter instanceof Iterable<?> it) {
                            for (Object ignored : it) {
                                entities++;
                            }
                        }
                    } catch (Throwable ignored) {
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return new WorldCensus(online, chunks, Math.max(online, entities));
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

    /**
     * Reusable {@link LeafFuzzRuntime.SwarmRosterController} backed by
     * {@link NmsEmbeddedPlayerSession} for Mojang-mapped servers (Fabric and NeoForge).
     */
    public static final class NmsSwarmRosterController implements LeafFuzzRuntime.SwarmRosterController {
        private final LeafFuzzRuntime runtime;
        private final java.util.function.Supplier<Object> mcServerSupplier;
        private final java.util.List<PersonaPolicyBotActor> activeActors = new java.util.ArrayList<>();
        private final java.util.List<NmsEmbeddedPlayerSession> activeSessions = new java.util.ArrayList<>();
        private final java.util.Set<String> activeChunks = new java.util.LinkedHashSet<>();
        private int churnCursor;

        public NmsSwarmRosterController(
                LeafFuzzRuntime runtime,
                java.util.function.Supplier<Object> mcServerSupplier
        ) {
            this.runtime = Objects.requireNonNull(runtime, "runtime");
            this.mcServerSupplier = Objects.requireNonNull(mcServerSupplier, "mcServerSupplier");
        }

        @Override
        public synchronized LeafFuzzRuntime.SwarmSnapshot rampToPopulation(int targetPlayers) {
            int clamped = Math.max(1, Math.min(500, targetPlayers));
            Object mcServer = mcServerSupplier.get();
            while (activeActors.size() < clamped) {
                int slot = activeActors.size();
                boolean op = (slot & 7) == 0;
                PersonaPolicyBotActor bot = runtime.spawnPersonaBotActor(op ? "op" : "default");
                SpiralAnchor anchor = assignSpiralAnchor(bot, slot);
                markChunkNeighborhood(anchor.chunkX(), anchor.chunkZ());
                PersonaPolicyBotActor.BotStepRecord step = bot.stepAutonomousPolicy();
                runtime.recordPlatformBotStep(step);
                NmsEmbeddedPlayerSession live = trySpawnOnMinecraftServer(mcServer, bot, op, 1000 + slot);
                activeActors.add(bot);
                activeSessions.add(live);
            }
            runtime.resetTickStartNanos();
            WorldCensus census = sampleWorldCensus(mcServer, activeActors.size());
            return new LeafFuzzRuntime.SwarmSnapshot(
                    Math.max(activeActors.size(), census.onlinePlayers()),
                    Math.max(activeChunks.size(), census.loadedChunks()),
                    Math.max(activeActors.size() * 2, census.trackedEntities()),
                    activeActors.size(),
                    0
            );
        }

        @Override
        public synchronized LeafFuzzRuntime.SwarmSnapshot stepConcurrentSwarm(int churnCount) {
            if (activeActors.isEmpty()) {
                return new LeafFuzzRuntime.SwarmSnapshot(0, 0, 0, 0, 0);
            }
            Object mcServer = mcServerSupplier.get();
            LogAndStallSignatureOracle oracle = runtime.faultOracle();
            int actions = 0;
            for (int i = 0; i < activeActors.size(); i++) {
                PersonaPolicyBotActor bot = activeActors.get(i);
                PersonaPolicyBotActor.BotStepRecord step = bot.stepAutonomousPolicy();
                runtime.recordPlatformBotStep(step);
                markChunkNeighborhood(bot.x() >> 4, bot.z() >> 4);
                actions++;
                NmsEmbeddedPlayerSession live = i < activeSessions.size() ? activeSessions.get(i) : null;
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
            int toChurn = Math.max(0, Math.min(activeActors.size(), churnCount));
            for (int c = 0; c < toChurn; c++) {
                int idx = Math.floorMod(churnCursor++, activeActors.size());
                NmsEmbeddedPlayerSession oldLive = idx < activeSessions.size() ? activeSessions.get(idx) : null;
                if (oldLive != null) {
                    oldLive.disconnect(oracle);
                }
                runtime.retentionScreener().recordPlayerDeparture();
                boolean op = (idx & 7) == 0;
                PersonaPolicyBotActor replacement = runtime.spawnPersonaBotActor(op ? "op" : "default");
                SpiralAnchor anchor = assignSpiralAnchor(replacement, idx);
                markChunkNeighborhood(anchor.chunkX(), anchor.chunkZ());
                NmsEmbeddedPlayerSession newLive = trySpawnOnMinecraftServer(
                        mcServer,
                        replacement,
                        op,
                        2000 + churnCursor
                );
                activeActors.set(idx, replacement);
                if (idx < activeSessions.size()) {
                    activeSessions.set(idx, newLive);
                }
            }
            runtime.resetTickStartNanos();
            WorldCensus census = sampleWorldCensus(mcServer, activeActors.size());
            return new LeafFuzzRuntime.SwarmSnapshot(
                    Math.max(activeActors.size(), census.onlinePlayers()),
                    Math.max(activeChunks.size(), census.loadedChunks()),
                    Math.max(activeActors.size() * 2, census.trackedEntities()),
                    actions,
                    toChurn
            );
        }

        @Override
        public synchronized LeafFuzzRuntime.SwarmSnapshot captureSnapshot() {
            Object mcServer = mcServerSupplier.get();
            WorldCensus census = sampleWorldCensus(mcServer, activeActors.size());
            return new LeafFuzzRuntime.SwarmSnapshot(
                    Math.max(activeActors.size(), census.onlinePlayers()),
                    Math.max(activeChunks.size(), census.loadedChunks()),
                    Math.max(activeActors.size() * 2, census.trackedEntities()),
                    0,
                    0
            );
        }

        @Override
        public synchronized void teardownAll() {
            LogAndStallSignatureOracle oracle = runtime.faultOracle();
            for (NmsEmbeddedPlayerSession s : activeSessions) {
                if (s != null) {
                    s.disconnect(oracle);
                }
                runtime.retentionScreener().recordPlayerDeparture();
            }
            activeSessions.clear();
            activeActors.clear();
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

    private Object resolvePacketListener() {
        try {
            return serverPlayer.getClass().getField("connection").get(serverPlayer);
        } catch (Throwable ignored) {
            return null;
        }
    }
}
