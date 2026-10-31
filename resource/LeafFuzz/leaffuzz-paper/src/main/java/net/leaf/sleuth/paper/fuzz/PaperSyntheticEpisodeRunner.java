package net.leaf.sleuth.paper.fuzz;

import io.github.dailystruggle.server.api.TaskHandle;
import io.github.dailystruggle.server.api.TaskScheduler;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;
import net.leaf.sleuth.common.fuzz.DualAudienceMitigationReport;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.fuzz.NodeBandit;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;
import net.leaf.sleuth.common.resource.ClassRetentionScreener;
import org.bukkit.Bukkit;
import org.bukkit.Server;
import org.bukkit.command.CommandSender;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.function.Consumer;
import java.util.function.DoubleSupplier;
import java.util.function.Supplier;

/**
 * Paper and Folia synthetic episode runner that dispatches command and lifecycle follow-up
 * shapes ({@code quit_lt1s}, {@code quit_delay}, {@code repeat}, {@code concurrent},
 * {@code window_click}) via {@link TaskScheduler} without synchronous chunk loads or reflection
 * ({@code S-005}, {@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-005
 */
public final class PaperSyntheticEpisodeRunner implements SleuthServerFuzzer.EpisodeRunner {

    private final Server server;
    private final Supplier<JarClassOwnershipIndex> ownershipIndexSupplier;
    private final LogAndStallSignatureOracle faultOracle;
    private final ClassRetentionScreener retentionScreener;
    private final DoubleSupplier currentMsptSupplier;
    private volatile SleuthServerFuzzer activeFuzzer;
    private volatile TaskHandle campaignTask;

    public PaperSyntheticEpisodeRunner(
            Server server,
            Supplier<JarClassOwnershipIndex> ownershipIndexSupplier,
            LogAndStallSignatureOracle faultOracle,
            ClassRetentionScreener retentionScreener,
            DoubleSupplier currentMsptSupplier
    ) {
        this.server = server;
        this.ownershipIndexSupplier = Objects.requireNonNull(ownershipIndexSupplier, "ownershipIndexSupplier");
        this.faultOracle = Objects.requireNonNull(faultOracle, "faultOracle");
        this.retentionScreener = Objects.requireNonNull(retentionScreener, "retentionScreener");
        this.currentMsptSupplier = currentMsptSupplier != null ? currentMsptSupplier : () -> 0.0;
    }

    /**
     * Starts a tick-paced QA calibration campaign using {@link TaskScheduler#runSyncTimer}.
     */
    public synchronized SleuthServerFuzzer startScheduledCampaign(
            TaskScheduler scheduler,
            Collection<String> tiers,
            int maxEpisodes,
            Consumer<List<DualAudienceMitigationReport>> onComplete
    ) {
        stopCampaign();
        Server targetServer = server != null ? server : safeBukkitServer();
        JarClassOwnershipIndex idx = ownershipIndexSupplier.get();
        if (idx == null) {
            idx = JarClassOwnershipIndex.empty();
        }
        CommandAuditReport audit = PaperCommandTreeInspector.auditLiveServer(targetServer, List.of(), idx);
        CommandTree tree = audit.commandTree();

        SleuthServerFuzzer fuzzer = new SleuthServerFuzzer(
                tree,
                idx,
                tiers != null && !tiers.isEmpty() ? tiers : List.of("default"),
                NodeBandit.DEFAULT_FOLLOW_UP_SHAPES,
                new Random(1L)
        );
        int budget = Math.max(1, maxEpisodes);
        fuzzer.setTargetEpisodes(budget);
        fuzzer.setActive(true);
        this.activeFuzzer = fuzzer;

        if (scheduler == null || fuzzer.bandit().armCount() == 0) {
            fuzzer.setActive(false);
            if (onComplete != null) {
                onComplete.accept(fuzzer.findings());
            }
            return fuzzer;
        }

        this.campaignTask = scheduler.runSyncTimer(() -> {
            if (!fuzzer.isActive() || fuzzer.episodesCompleted() >= budget) {
                stopCampaign();
                if (onComplete != null) {
                    onComplete.accept(fuzzer.findings());
                }
                return;
            }
            try {
                fuzzer.runSingleEpisode(this);
            } catch (Throwable t) {
                faultOracle.recordThrowable(t, "Synthetic episode runner exception");
            }
            if (fuzzer.episodesCompleted() >= budget) {
                stopCampaign();
                if (onComplete != null) {
                    onComplete.accept(fuzzer.findings());
                }
            }
        }, 2L, 4L);

        return fuzzer;
    }

    public synchronized void stopCampaign() {
        TaskHandle task = this.campaignTask;
        this.campaignTask = null;
        if (task != null) {
            try {
                task.cancel();
            } catch (Throwable ignored) {
            }
        }
        SleuthServerFuzzer fuzzer = this.activeFuzzer;
        if (fuzzer != null) {
            fuzzer.stop();
        }
    }

    public SleuthServerFuzzer activeFuzzer() {
        return activeFuzzer;
    }

    @Override
    public EpisodeOutcome runEpisode(List<EpisodeAction> actions) {
        if (actions == null || actions.isEmpty()) {
            return EpisodeOutcome.clean();
        }
        Server targetServer = server != null ? server : safeBukkitServer();

        long exceptionsBefore = faultOracle.totalExceptionsRecorded();
        long stallsBefore = faultOracle.totalStallsRecorded();
        List<FaultSignature> beforeSigs = faultOracle.rankedSignatures();

        boolean anyUsageError = false;
        List<String> touchedClasses = new ArrayList<>();

        for (EpisodeAction action : actions) {
            String rawCmd = action.commandLine();
            if (rawCmd == null || rawCmd.isBlank()) {
                continue;
            }
            String cmdNoSlash = rawCmd.startsWith("/") ? rawCmd.substring(1).trim() : rawCmd.trim();
            if (cmdNoSlash.isEmpty()) {
                continue;
            }
            boolean opTier = "op".equalsIgnoreCase(action.tier());
            String shape = action.followUpShape() != null
                    ? action.followUpShape().toLowerCase(Locale.ROOT)
                    : "repeat";

            int dispatchCount = switch (shape) {
                case "repeat" -> 2;
                case "concurrent" -> 3;
                default -> 1;
            };

            for (int i = 0; i < dispatchCount; i++) {
                boolean dispatched = dispatchSyntheticCommand(targetServer, cmdNoSlash, opTier);
                if (!dispatched) {
                    anyUsageError = true;
                }
            }

            if ("quit_lt1s".equals(shape) || "quit_delay".equals(shape)) {
                retentionScreener.recordPlayerDeparture();
            } else {
                retentionScreener.recordCommandExecution();
            }
        }

        long exceptionsAfter = faultOracle.totalExceptionsRecorded();
        long stallsAfter = faultOracle.totalStallsRecorded();
        double currentMspt = currentMsptSupplier.getAsDouble();
        double msptExcess = Math.max(0.0, currentMspt - 20.0);

        if (exceptionsAfter > exceptionsBefore || stallsAfter > stallsBefore) {
            List<FaultSignature> afterSigs = faultOracle.rankedSignatures();
            FaultSignature triggered = selectNewestSignature(beforeSigs, afterSigs);
            if (triggered != null) {
                if (!"server".equals(triggered.topPluginFrame())) {
                    touchedClasses.add(triggered.topPluginFrame());
                }
                return EpisodeOutcome.fault(
                        triggered.signatureId(),
                        triggered.suspectJar(),
                        0.0,
                        Math.max(msptExcess, triggered.maxDurationMs()),
                        touchedClasses
                );
            }
        }

        List<ClassRetentionFinding> retentionFindings = retentionScreener.latestFindings();
        if (!retentionFindings.isEmpty()) {
            ClassRetentionFinding topLeak = retentionFindings.get(0);
            touchedClasses.add(topLeak.className());
            return EpisodeOutcome.fault(
                    "leak:" + topLeak.className(),
                    topLeak.owningJar(),
                    topLeak.slopePerEvent(),
                    msptExcess,
                    touchedClasses
            );
        }

        return new EpisodeOutcome(
                false,
                null,
                null,
                0.0,
                msptExcess,
                touchedClasses,
                anyUsageError
        );
    }

    private boolean dispatchSyntheticCommand(Server targetServer, String cmdNoSlash, boolean opTier) {
        if (targetServer == null) {
            return false;
        }
        try {
            CommandSender sender = PaperCommandTreeInspector.createTierSender(
                    targetServer,
                    targetServer.getPluginManager(),
                    opTier
            );
            return targetServer.dispatchCommand(sender, cmdNoSlash);
        } catch (Throwable t) {
            faultOracle.recordThrowable(t, "Command dispatch exception for /" + cmdNoSlash);
            return false;
        }
    }

    private static FaultSignature selectNewestSignature(
            List<FaultSignature> before,
            List<FaultSignature> after
    ) {
        if (after == null || after.isEmpty()) {
            return null;
        }
        for (FaultSignature cand : after) {
            Optional<FaultSignature> prev = before.stream()
                    .filter(b -> b.signatureId().equals(cand.signatureId()))
                    .findFirst();
            if (prev.isEmpty() || cand.occurrences() > prev.get().occurrences()) {
                return cand;
            }
        }
        return after.get(0);
    }

    private static Server safeBukkitServer() {
        try {
            return Bukkit.getServer();
        } catch (Throwable ignored) {
            return null;
        }
    }
}
