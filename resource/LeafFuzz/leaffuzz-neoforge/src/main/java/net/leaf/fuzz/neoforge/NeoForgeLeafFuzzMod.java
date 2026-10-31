package net.leaf.fuzz.neoforge;

import io.github.dailystruggle.rtp.neoforge.v26_1_R1.server.NeoForgeModServerAccessor;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.fuzz.common.NmsEmbeddedPlayerSession;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor;
import net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.BotStepRecord;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.MinecraftServer;
import net.minecraft.world.phys.Vec2;
import net.minecraft.world.phys.Vec3;
import net.neoforged.fml.common.Mod;
import net.neoforged.neoforge.common.NeoForge;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import net.neoforged.neoforge.event.server.ServerStartedEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/**
 * NeoForge mod entry point for {@code LeafFuzz}, delegating platform services to
 * {@link NeoForgeModServerAccessor} and domain lifecycle to {@link LeafFuzzRuntime}
 * ({@code leaffuzz-ADR-001}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 */
@Mod("leaffuzz")
public final class NeoForgeLeafFuzzMod {

    private final AtomicReference<Object> activeDispatcher = new AtomicReference<>();
    private final AtomicReference<MinecraftServer> activeServer = new AtomicReference<>();
    private final LeafFuzzRuntime runtime;

    public NeoForgeLeafFuzzMod() {
        NeoForgeModServerAccessor accessor =
                new NeoForgeModServerAccessor("LeafFuzz", Path.of("config", "leaffuzz"));
        accessor.registerEvents();
        NeoForge.EVENT_BUS.addListener(
                (RegisterCommandsEvent event) -> activeDispatcher.set(event.getDispatcher())
        );
        NeoForge.EVENT_BUS.addListener(
                (ServerStartedEvent event) -> {
                    activeServer.set(event.getServer());
                    if (event.getServer() != null && event.getServer().getCommands() != null) {
                        activeDispatcher.set(event.getServer().getCommands().getDispatcher());
                    }
                }
        );
        this.runtime = new LeafFuzzRuntime(accessor);
        this.runtime.setBrigadierDispatcherSupplier(activeDispatcher::get);
        this.runtime.setPlatformEpisodeRunner(actions -> runNeoForgePersonaEpisode(accessor, actions));
        this.runtime.setPlatformSwarmController(
                new NmsEmbeddedPlayerSession.NmsSwarmRosterController(this.runtime, activeServer::get)
        );
        this.runtime.start();
        NeoForge.EVENT_BUS.addListener(
                (ServerStoppingEvent event) -> {
                    activeServer.set(null);
                    if (this.runtime != null) {
                        this.runtime.close();
                    }
                }
        );
        accessor.logger().info("LeafFuzz (NeoForge) initialized. Run /fuzz check <mod|all> for a 4-stage QC pass.");
    }

    private EpisodeOutcome runNeoForgePersonaEpisode(
            NeoForgeModServerAccessor accessor,
            List<EpisodeAction> actions
    ) {
        if (actions == null || actions.isEmpty()) {
            return EpisodeOutcome.clean();
        }
        long exceptionsBefore = runtime.faultOracle().totalExceptionsRecorded();
        long stallsBefore = runtime.faultOracle().totalStallsRecorded();
        List<String> capturedOutput = new ArrayList<>();
        List<String> observedTokens = new ArrayList<>();
        boolean usageError = false;

        PersonaPolicyBotActor bot = runtime.spawnPersonaBotActor(actions.get(0).tier());
        BotStepRecord preStep = bot.stepAutonomousPolicy();
        runtime.recordPlatformBotStep(preStep);
        observedTokens.add("persona:" + bot.persona().taxonomyArchetype());
        observedTokens.add("skill:" + preStep.selectedSkill());

        for (EpisodeAction action : actions) {
            String cleanCmd = bot.prepareCommandForDispatch(action.commandLine());
            if (cleanCmd.isEmpty()) {
                continue;
            }
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
            MinecraftServer srv = activeServer.get();
            boolean opTier = "op".equalsIgnoreCase(action.tier()) || bot.isOp();
            NmsEmbeddedPlayerSession liveSession =
                    NmsEmbeddedPlayerSession.trySpawnOnMinecraftServer(srv, bot, opTier, 0);
            int teleportsConfirmed = 0;
            double maxTeleportDist = 0.0;
            int infoResponses = 0;
            try {
                for (int i = 0; i < dispatches; i++) {
                    runtime.retentionScreener().recordCommandExecution();
                    try {
                        if (srv != null && srv.getCommands() != null) {
                            Object playerSrc = liveSession != null ? liveSession.createCommandSourceStack() : null;
                            CommandSourceStack baseSource = (playerSrc instanceof CommandSourceStack css)
                                    ? css
                                    : srv.createCommandSourceStack()
                                            .withPosition(new Vec3(bot.x() + 0.5, bot.y(), bot.z() + 0.5))
                                            .withRotation(new Vec2(bot.pitchDeg(), bot.yawDeg()))
                                            .withSuppressedOutput();
                            srv.getCommands().performPrefixedCommand(baseSource, cleanCmd);
                            if (liveSession != null) {
                                liveSession.drainOutboundPackets();
                            }
                        } else {
                            accessor.executeCommandWithCapture(cleanCmd, capturedOutput::add);
                        }
                    } catch (Throwable t) {
                        FaultSignature sig = runtime.faultOracle().recordThrowable(t, "Command dispatch: /" + cleanCmd);
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
                runtime.recordPlatformBotStep(followStep);
                observedTokens.add("followup:" + followStep.selectedSkill());
                if (liveSession != null) {
                    liveSession.sendMovePacket(
                            followStep.x() + 0.5,
                            followStep.y(),
                            followStep.z() + 0.5,
                            followStep.yawDeg(),
                            followStep.pitchDeg(),
                            runtime.faultOracle()
                    );
                    double moved = liveSession.displacementFromSpawn();
                    if (moved >= 4.0) {
                        teleportsConfirmed++;
                        maxTeleportDist = moved;
                    }
                    infoResponses += liveSession.chatOrInfoPacketsSeen();
                    NmsEmbeddedPlayerSession.WorldCensus census =
                            NmsEmbeddedPlayerSession.sampleWorldCensus(srv, 1);
                    runtime.recordSwarmTelemetry(
                            census.onlinePlayers(),
                            census.loadedChunks(),
                            census.trackedEntities()
                    );
                }
                if (!followStep.online()) {
                    accessor.dispatchingPlayerLifecycleHook().fireQuit(bot.actorUuid());
                } else {
                    accessor.dispatchingPlayerLifecycleHook().fireJoin(bot.actorUuid());
                }
            } finally {
                if (liveSession != null) {
                    liveSession.disconnect(runtime.faultOracle());
                    runtime.retentionScreener().recordPlayerDeparture();
                }
            }
            runtime.recordEpisodeObservation(
                    "/" + cleanCmd,
                    1,
                    dispatches,
                    0,
                    0,
                    List.of(),
                    teleportsConfirmed,
                    maxTeleportDist,
                    infoResponses + capturedOutput.size(),
                    false
            );
        }

        for (String line : capturedOutput) {
            String low = line.toLowerCase(Locale.ROOT);
            if (low.contains("unknown command") || low.contains("usage:") || low.contains("invalid argument")) {
                usageError = true;
                break;
            }
        }

        if (runtime.faultOracle().totalExceptionsRecorded() > exceptionsBefore
                || runtime.faultOracle().totalStallsRecorded() > stallsBefore) {
            List<FaultSignature> ranked = runtime.faultOracle().rankedSignatures();
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

        return new EpisodeOutcome(false, null, null, 0.0, 0.0, observedTokens, usageError);
    }
}
