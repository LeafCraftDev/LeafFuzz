package net.leaf.fuzz.common.command;

import io.github.dailystruggle.commandsapi.common.CommandParameter;
import io.github.dailystruggle.commandsapi.common.CommandsAPI;
import io.github.dailystruggle.commandsapi.common.CommandsAPICommand;
import io.github.dailystruggle.commandsapi.common.localCommands.TreeCommand;
import io.github.dailystruggle.menu.api.MenuBindingSupport;
import io.github.dailystruggle.menu.api.MenuDescriptor;
import io.github.dailystruggle.rtp.common.bit.config.atlas.BytecodeCausalGraphScanner.ClaimDeliveryFinding;
import io.github.dailystruggle.server.api.BookMenuSpec;
import io.github.dailystruggle.server.api.ServerAccessor;
import net.leaf.fuzz.common.BrigadierDispatcherInspector;
import net.leaf.fuzz.common.LeafFuzzConfig;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.fuzz.common.LeafFuzzScorecardReport;
import net.leaf.fuzz.common.ui.LeafFuzzMenuBuilder;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandAuditReport;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.LeastPrivilegeFinding;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignState;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignStatus;
import net.leaf.sleuth.common.fuzz.JarClassOwnershipIndex;
import net.leaf.sleuth.common.fuzz.LogAndStallSignatureOracle.FaultSignature;
import net.leaf.sleuth.common.resource.ClassRetentionFinding;
import net.leaf.sleuth.common.resource.ClassRetentionScreener;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.logging.Level;

/**
 * Platform-neutral {@code /fuzz} (aliases {@code /leaffuzz}, {@code /qc}) command tree built on
 * {@link CommandsAPI} ({@code commands-api-ADR-001}, {@code commands-api-ADR-002}, {@code leaffuzz-ADR-001}).
 *
 * <p>Root parameters ({@code target=}, {@code episodes=}, {@code players=}, {@code stage=}) allow direct execution via
 * {@code /fuzz target=RTP episodes=24 players=100}, while keeping the top-level subcommand surface concise (5 subcommands):
 * <ul>
 *   <li>{@code /fuzz check [target=<plugin|mod|A,B|all>] [episodes=<n>] [players=<1..500>] [stage=<all|commands|fuzz|faults|leaks|snapshot>]}</li>
 *   <li>{@code /fuzz report} — Open the interactive in-game Book scorecard (also triggered by bare {@code /fuzz})</li>
 *   <li>{@code /fuzz reset [scope=<all|faults|leaks|campaign>]} — Clear recorded fault signatures, GC checkpoints, or campaign state</li>
 *   <li>{@code /fuzz test} — Run {@code [FUZZ bit]} PBIT/CBIT/IBIT self-tests off-thread</li>
 *   <li>{@code /fuzz reload} — Validate and hot-reload {@code config.yml} and {@code messages.yml}</li>
 * </ul>
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy commands-api-ADR-001
 * @governedBy commands-api-ADR-002
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-002
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-004
 * @trace S-005
 * @trace S-007
 */
public final class LeafFuzzCommand implements TreeCommand {

    private static final Set<String> VALID_STAGES = Set.of(
            "all", "commands", "fuzz", "faults", "leaks", "claims", "snapshot"
    );
    private static final Set<String> VALID_RESET_SCOPES = Set.of(
            "all", "faults", "leaks", "campaign"
    );

    private final String name;
    private final ServerAccessor accessor;
    private final LeafFuzzRuntime runtime;
    private final LeafFuzzMenuBuilder menuBuilder = new LeafFuzzMenuBuilder();
    private final CheckSub checkSub;
    private final ReportSub reportSub;
    private final Map<String, CommandParameter> parameterLookup = new ConcurrentHashMap<>();
    private final Map<String, CommandsAPICommand> commandLookup = new ConcurrentHashMap<>();

    public LeafFuzzCommand(String name, ServerAccessor accessor, LeafFuzzRuntime runtime) {
        this.name = (name == null || name.isBlank()) ? "fuzz" : name.trim();
        this.accessor = Objects.requireNonNull(accessor, "accessor");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
        this.checkSub = new CheckSub(this);
        this.reportSub = new ReportSub(this);

        // Attach root-level parameters so `/fuzz target=RTP episodes=24 players=100` works directly like `/rtp`
        addParameter("target", createTargetParameter());
        addParameter("episodes", createEpisodesParameter());
        addParameter("players", createPlayersParameter());
        addParameter("stage", createStageParameter());

        // 5 core subcommands
        addSubCommand(this.checkSub);
        addSubCommand(this.reportSub);
        addSubCommand(new ResetSub(this));
        addSubCommand(new TestSub(this));
        addSubCommand(new ReloadSub(this));
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String permission() {
        return "leaffuzz.admin";
    }

    @Override
    public String description() {
        return "Cross-platform in-JVM QC, command-tree fuzzing, and post-GC memory leak screener.";
    }

    @Override
    public CommandsAPICommand parent() {
        return null;
    }

    @Override
    public long avgTime() {
        return 0L;
    }

    @Override
    public Map<String, CommandParameter> getParameterLookup() {
        return parameterLookup;
    }

    @Override
    public Map<String, CommandsAPICommand> getCommandLookup() {
        return commandLookup;
    }

    @Override
    public void msgNoPermission(UUID callerId, String permission) {
        LeafFuzzConfig cfg = runtime.config();
        String msg = cfg.messages().noPermission();
        accessor.log(Level.WARNING, "[LeafFuzz] " + msg + " (" + permission + ")");
        sendReply(callerId, msg, true);
    }

    @Override
    public void msgBadParameter(UUID callerId, String parameterName, String parameterValue) {
        LeafFuzzConfig cfg = runtime.config();
        String msg = cfg.messages().badParameter()
                .replace("[param]", String.valueOf(parameterName))
                .replace("[value]", String.valueOf(parameterValue));
        accessor.log(Level.WARNING, "[LeafFuzz] " + msg);
        sendReply(callerId, msg, true);
    }

    @Override
    public void msgInvalidCommand(UUID callerId, String argument) {
        LeafFuzzConfig cfg = runtime.config();
        String msg = cfg.messages().invalidCommand().replace("[arg]", String.valueOf(argument));
        accessor.log(Level.WARNING, "[LeafFuzz] " + msg);
        sendReply(callerId, msg, true);
    }

    @Override
    public java.util.concurrent.CompletableFuture<Boolean> onCommand(
            UUID callerId,
            java.util.function.Predicate<String> permissionCheckMethod,
            Consumer<String> messageMethod,
            String[] args
    ) {
        return TreeCommand.super.onCommand(
                callerId,
                permissionCheckMethod,
                messageMethod,
                normalizePositionalCheckArgs(args),
                0,
                null
        );
    }

    private static String[] normalizePositionalCheckArgs(String[] args) {
        if (args == null || args.length < 2 || !"check".equalsIgnoreCase(args[0])) {
            return args;
        }
        String[] copy = args.clone();
        if (!copy[1].contains("=") && !"help".equalsIgnoreCase(copy[1])) {
            copy[1] = "target=" + copy[1];
            if (copy.length >= 3 && !copy[2].contains("=")) {
                try {
                    Integer.parseInt(copy[2].trim());
                    copy[2] = "episodes=" + copy[2].trim();
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return copy;
    }

    @Override
    public boolean onCommand(
            UUID callerId,
            Map<String, List<String>> parameterValues,
            CommandsAPICommand nextCommand
    ) {
        if (nextCommand != null) {
            return true;
        }
        if (parameterValues != null && !parameterValues.isEmpty()) {
            return checkSub.onCommand(callerId, parameterValues, null);
        }
        return reportSub.onCommand(callerId, parameterValues, null);
    }

    private void sendReply(UUID callerId, String message, boolean error) {
        String prefix = runtime.config().messages().prefix();
        sendRawLine(callerId, prefix + message, error);
    }

    private void sendRawLine(UUID callerId, String line, boolean error) {
        UUID effectiveId = callerId != null ? callerId : CommandsAPI.serverId;
        Consumer<String> fallback = msg -> accessor.sendMessage(effectiveId, msg, error);
        CommandsAPI.messageMethodFor(effectiveId, fallback).accept(line);
    }

    private CommandParameter createTargetParameter() {
        return new CommandParameter("leaffuzz.admin", "Target plugin/mod name or 'all'", (u, v) -> true) {
            @Override
            public Set<String> values() {
                return candidateTargetNames();
            }
        };
    }

    private CommandParameter createEpisodesParameter() {
        return new CommandParameter(
                "leaffuzz.admin",
                "Number of UCB1 fuzz episodes (1..100000)",
                (u, v) -> {
                    try {
                        int n = Integer.parseInt(v.trim());
                        return n >= 1 && n <= 100_000;
                    } catch (Exception e) {
                        return false;
                    }
                }
        ) {
            @Override
            public Set<String> values() {
                return Set.of("24", "100", "250", "1000", "5000", "7200");
            }
        };
    }

    private CommandParameter createPlayersParameter() {
        return new CommandParameter(
                "leaffuzz.admin",
                "Concurrent player roster size (1..500 or 'auto'/'ramp' to ramp until unstable)",
                (u, v) -> {
                    if (v == null || v.isBlank()) {
                        return false;
                    }
                    String trimmed = v.trim().toLowerCase(Locale.ROOT);
                    if ("auto".equals(trimmed) || "ramp".equals(trimmed)) {
                        return true;
                    }
                    try {
                        int n = Integer.parseInt(trimmed);
                        return n >= 1 && n <= 500;
                    } catch (Exception e) {
                        return false;
                    }
                }
        ) {
            @Override
            public Set<String> values() {
                return Set.of("auto", "ramp", "1", "10", "25", "50", "100", "200");
            }
        };
    }

    private CommandParameter createStageParameter() {
        return new CommandParameter(
                "leaffuzz.admin",
                "QC stage: all, commands, fuzz, faults, leaks, claims, or snapshot",
                (u, v) -> v != null && VALID_STAGES.contains(v.trim().toLowerCase(Locale.ROOT))
        ) {
            @Override
            public Set<String> values() {
                return VALID_STAGES;
            }
        };
    }

    private Set<String> candidateTargetNames() {
        Set<String> out = new LinkedHashSet<>();
        out.add("all");
        for (JarClassOwnershipIndex.JarDescriptor desc : runtime.ownershipIndex().descriptors().values()) {
            out.add(desc.pluginId());
            out.add(desc.jarName());
        }
        return out;
    }

    private abstract class BaseSub implements TreeCommand {
        private final String subName;
        private final String perm;
        private final String desc;
        private final CommandsAPICommand parent;
        private final Map<String, CommandParameter> params = new ConcurrentHashMap<>();
        private final Map<String, CommandsAPICommand> subs = new ConcurrentHashMap<>();

        BaseSub(String subName, String perm, String desc, CommandsAPICommand parent) {
            this.subName = subName;
            this.perm = perm;
            this.desc = desc;
            this.parent = parent;
        }

        @Override
        public String name() {
            return subName;
        }

        @Override
        public String permission() {
            return perm;
        }

        @Override
        public String description() {
            return desc;
        }

        @Override
        public CommandsAPICommand parent() {
            return parent;
        }

        @Override
        public long avgTime() {
            return 0L;
        }

        @Override
        public Map<String, CommandParameter> getParameterLookup() {
            return params;
        }

        @Override
        public Map<String, CommandsAPICommand> getCommandLookup() {
            return subs;
        }

        @Override
        public void msgNoPermission(UUID callerId, String permission) {
            LeafFuzzCommand.this.msgNoPermission(callerId, permission);
        }

        @Override
        public void msgBadParameter(UUID callerId, String parameterName, String parameterValue) {
            LeafFuzzCommand.this.msgBadParameter(callerId, parameterName, parameterValue);
        }

        @Override
        public void msgInvalidCommand(UUID callerId, String argument) {
            LeafFuzzCommand.this.msgInvalidCommand(callerId, argument);
        }
    }

    private final class CheckSub extends BaseSub {
        CheckSub(CommandsAPICommand parent) {
            super(
                    "check",
                    "leaffuzz.admin",
                    "Run the 4-stage automated QC pass (or a specific stage via stage=).",
                    parent
            );
            addParameter("target", createTargetParameter());
            addParameter("episodes", createEpisodesParameter());
            addParameter("players", createPlayersParameter());
            addParameter("stage", createStageParameter());
        }

        @Override
        public boolean onCommand(
                UUID callerId,
                Map<String, List<String>> parameterValues,
                CommandsAPICommand nextCommand
        ) {
            if (nextCommand != null) {
                return true;
            }
            String target = joinedParam(parameterValues, "target", "all");
            String stage = firstParam(parameterValues, "stage", "all").toLowerCase(Locale.ROOT);
            int episodes = parseIntParam(parameterValues, "episodes", runtime.config().defaultEpisodes());
            int players = parsePlayersParam(parameterValues, runtime.config().defaultPlayers());

            return switch (stage) {
                case "commands" -> executeCommandsStage(callerId, target);
                case "faults" -> executeFaultsStage(callerId, target);
                case "leaks" -> executeLeaksScreenStage(callerId, target);
                case "claims" -> executeClaimsStage(callerId, target);
                case "snapshot" -> executeLeaksSnapshotStage(callerId);
                default -> executeFullQcPass(callerId, target, episodes, players);
            };
        }

        private boolean executeFullQcPass(UUID callerId, String target, int episodes, int players) {
            if (!runtime.checkRunning().compareAndSet(false, true)) {
                sendReply(callerId, runtime.config().messages().busy(), true);
                return true;
            }
            if (accessor.scheduler().isPresent()) {
                String playerDesc = players < 0
                        ? "auto-ramp to instability (up to 100 players)"
                        : Math.max(1, players) + " concurrent player(s)";
                sendReply(
                        callerId,
                        "&7Running 4-stage QC check for [&a" + target + "&7] (&f" + episodes
                                + " &7episodes, &b" + playerDesc
                                + " &7across tick-paced batches + post-GC retention screen)...",
                        false
                );
            }
            try {
                runtime.runQcCheckAsync(target, episodes, players, card -> {
                    try {
                        String safeTarget = card.targetName().replaceAll("[^a-zA-Z0-9._-]", "_").toLowerCase(Locale.ROOT);
                        Path reportPath = accessor.getRootFolder().resolve("reports").resolve(safeTarget + "-qc-report.md");
                        for (String line : card.formatChatLines(runtime.config().messages().prefix(), reportPath)) {
                            sendRawLine(callerId, line, false);
                        }
                        if (callerId != null && (callerId.getMostSignificantBits() != 0L || callerId.getLeastSignificantBits() != 0L)) {
                            try {
                                accessor.sendInteractiveLine(callerId, BookMenuSpec.Line.of(
                                        BookMenuSpec.Fragment.plain(runtime.config().messages().prefix()),
                                        BookMenuSpec.Fragment.runCommand(
                                                "&a&l[📖 Open Book Scorecard]",
                                                "&eOpen interactive parchment book report\n&a/" + name + " report",
                                                "/" + name + " report"
                                        ),
                                        BookMenuSpec.Fragment.plain(" "),
                                        BookMenuSpec.Fragment.runCommand(
                                                "&b&l[↻ Re-Run Check]",
                                                "&eRe-run 4-stage QC check for &f" + card.targetName() + "\n&a/" + name + " check target=" + card.targetName(),
                                                "/" + name + " check target=" + card.targetName()
                                        )
                                ));
                            } catch (Throwable ex) {
                                accessor.log(Level.FINE, "[LeafFuzz] Interactive prompt fallback: " + ex.getMessage(), ex);
                            }
                        }
                    } finally {
                        runtime.checkRunning().set(false);
                    }
                });
            } catch (Throwable t) {
                runtime.checkRunning().set(false);
                throw t;
            }
            return true;
        }

        private boolean executeCommandsStage(UUID callerId, String target) {
            CommandAuditReport report = runtime.auditCommandSurface(target);
            int totalNodes = report.totalNodes();
            long defaultVisible = report.defaultTierNodes();
            List<LeastPrivilegeFinding> findings = report.findings();
            sendReply(
                    callerId,
                    "&fCommand Audit [&a" + target + "&f]: &a" + totalNodes + " &7nodes (&e"
                            + defaultVisible + " &7default-visible, &c" + findings.size() + " &7least-privilege findings)",
                    false
            );
            for (int i = 0; i < Math.min(8, findings.size()); i++) {
                LeastPrivilegeFinding f = findings.get(i);
                sendReply(
                        callerId,
                        "  &e[!] &f/" + f.nodeId() + " &7(" + f.suspectPluginOrJar() + ", " + f.findingKind()
                                + ") -> &f" + f.remediationCommand(),
                        false
                );
            }
            return true;
        }

        private boolean executeFaultsStage(UUID callerId, String target) {
            List<FaultSignature> ranked = runtime.faultOracle().rankedSignatures();
            List<FaultSignature> filtered = new ArrayList<>();
            for (FaultSignature sig : ranked) {
                if (BrigadierDispatcherInspector.matchesTargetIdentifier(
                        sig.suspectJar(),
                        sig.topPluginFrame(),
                        target,
                        runtime.ownershipIndex()
                )) {
                    filtered.add(sig);
                }
            }
            sendReply(
                    callerId,
                    "&fAttributed Fault Signatures [&a" + target + "&f]: &e" + filtered.size()
                            + " &7(exceptions=" + runtime.faultOracle().totalExceptionsRecorded()
                            + ", stalls=" + runtime.faultOracle().totalStallsRecorded() + ")",
                    false
            );
            for (int i = 0; i < Math.min(8, filtered.size()); i++) {
                FaultSignature sig = filtered.get(i);
                sendReply(
                        callerId,
                        "  &c[" + sig.kind() + "] &f" + sig.signatureId()
                                + " &7(owner=" + sig.suspectJar() + ", count=" + sig.occurrences() + ")",
                        false
                );
            }
            return true;
        }

        private boolean executeLeaksScreenStage(UUID callerId, String target) {
            ClassRetentionScreener screener = runtime.retentionScreener();
            int cps = screener.checkpointCount();
            List<ClassRetentionFinding> findings = cps >= ClassRetentionScreener.MIN_CHECKPOINTS
                    ? screener.screenClassGrowth()
                    : screener.latestFindings();
            List<ClassRetentionFinding> filtered = new ArrayList<>();
            for (ClassRetentionFinding f : findings) {
                if (BrigadierDispatcherInspector.matchesTargetIdentifier(
                        f.owningJar(),
                        f.className(),
                        target,
                        runtime.ownershipIndex()
                )) {
                    filtered.add(f);
                }
            }
            sendReply(
                    callerId,
                    "&fPost-GC Retention Screen [&a" + target + "&f]: &e" + cps + " &7checkpoints, &c"
                            + filtered.size() + " &7Bonferroni-significant leaking classes",
                    false
            );
            if (cps < ClassRetentionScreener.MIN_CHECKPOINTS) {
                sendReply(
                        callerId,
                        "&7Need at least &e" + ClassRetentionScreener.MIN_CHECKPOINTS
                                + " &7checkpoints for OLS regression (run &a/" + name + " check stage=snapshot&7).",
                        false
                );
            }
            for (int i = 0; i < Math.min(8, filtered.size()); i++) {
                ClassRetentionFinding f = filtered.get(i);
                sendReply(
                        callerId,
                        String.format(
                                Locale.ROOT,
                                "  &c[LEAK] &f%s &7(jar=%s, slope=+%.2f/%s, R²=%.3f, p=%.2e)",
                                f.className(),
                                f.owningJar(),
                                f.slopePerEvent(),
                                f.eventBasis(),
                                f.rSquared(),
                                f.pValue()
                        ),
                        false
                );
            }
            return true;
        }

        private boolean executeClaimsStage(UUID callerId, String target) {
            List<ClaimDeliveryFinding> findings = runtime.auditClaimDelivery(target);
            sendReply(
                    callerId,
                    "&fFirst-Order & Second-Order Claim Delivery Audit [&a" + target + "&f]: &e"
                            + findings.size() + " &7finding(s)",
                    false
            );
            for (int i = 0; i < Math.min(8, findings.size()); i++) {
                ClaimDeliveryFinding f = findings.get(i);
                sendReply(
                        callerId,
                        "  &e[" + f.confidenceTier().name() + " " + f.confidencePercent()
                                + "%] &7(Order " + f.order() + " - " + f.kind().name()
                                + ") &fClaims: &7" + f.claims()
                                + " &f-> Does Not Deliver: &c" + f.doesNotDeliver(),
                        false
                );
                if (!f.llmExplanation().isEmpty()) {
                    sendReply(callerId, "    &b[AST Explanation] &7" + f.llmExplanation(), false);
                }
            }
            return true;
        }

        private boolean executeLeaksSnapshotStage(UUID callerId) {
            ClassRetentionScreener screener = runtime.retentionScreener();
            if (screener.isSnapshotBusy()) {
                sendReply(callerId, runtime.config().messages().busy(), true);
                return true;
            }
            if (accessor.scheduler().isEmpty()) {
                msgBadParameter(callerId, "stage", "snapshot (async scheduler unavailable)");
                return true;
            }
            sendReply(callerId, "&7Capturing post-GC class histogram off-thread...", false);
            accessor.scheduler().get().runAsync(() -> {
                try {
                    ClassRetentionScreener.HistogramCheckpoint cp = screener.captureLiveSnapshot(
                            "manual-" + (screener.checkpointCount() + 1)
                    );
                    accessor.scheduler().get().runSync(() -> sendReply(
                            callerId,
                            String.format(
                                    Locale.ROOT,
                                    "&aCaptured checkpoint #%d (%d classes, OldGen=%.1f MB, departures=%d, commands=%d).",
                                    screener.checkpointCount(),
                                    cp.classCounts().size(),
                                    cp.oldGenAfterGcMb(),
                                    cp.cumulativeDepartures(),
                                    cp.cumulativeCommands()
                            ),
                            false
                    ));
                } catch (Exception e) {
                    accessor.log(Level.WARNING, "[LeafFuzz] Snapshot capture error: " + e.getMessage(), e);
                    accessor.scheduler().get().runSync(() -> msgBadParameter(callerId, "stage", "snapshot (" + e.getMessage() + ")"));
                }
            });
            return true;
        }
    }

    private final class ReportSub extends BaseSub {
        ReportSub(CommandsAPICommand parent) {
            super(
                    "report",
                    "leaffuzz.admin",
                    "Open the interactive in-game Book scorecard for the latest QC check.",
                    parent
            );
        }

        @Override
        public boolean onCommand(
                UUID callerId,
                Map<String, List<String>> parameterValues,
                CommandsAPICommand nextCommand
        ) {
            if (nextCommand != null) {
                return true;
            }
            MenuDescriptor book = menuBuilder.buildScorecardBook(runtime);
            UUID viewerId = callerId != null ? callerId : CommandsAPI.serverId;
            try {
                accessor.renderBookOrChat(viewerId, MenuBindingSupport.toBookMenuSpec(book));
            } catch (Throwable t) {
                LeafFuzzScorecardReport card = runtime.latestScorecard();
                if (card != null) {
                    for (String line : card.formatChatLines(runtime.config().messages().prefix(), null)) {
                        sendRawLine(viewerId, line, false);
                    }
                } else {
                    sendReply(viewerId, "&7No QC scorecard has been generated yet. Run &a/" + name + " check target=<PluginOrMod>&7.", false);
                }
            }
            return true;
        }
    }

    private final class ResetSub extends BaseSub {
        ResetSub(CommandsAPICommand parent) {
            super(
                    "reset",
                    "leaffuzz.admin",
                    "Clear recorded fault signatures, post-GC leak checkpoints, or campaign state.",
                    parent
            );
            addParameter(
                    "scope",
                    new CommandParameter(
                            "leaffuzz.admin",
                            "Scope to reset: all, faults, leaks, or campaign",
                            (u, v) -> v != null && VALID_RESET_SCOPES.contains(v.trim().toLowerCase(Locale.ROOT))
                    ) {
                        @Override
                        public Set<String> values() {
                            return VALID_RESET_SCOPES;
                        }
                    }
            );
        }

        @Override
        public boolean onCommand(
                UUID callerId,
                Map<String, List<String>> parameterValues,
                CommandsAPICommand nextCommand
        ) {
            if (nextCommand != null) {
                return true;
            }
            if (runtime.checkRunning().get()) {
                sendReply(callerId, runtime.config().messages().busy(), true);
                return true;
            }
            String scope = firstParam(parameterValues, "scope", "all").toLowerCase(Locale.ROOT);
            boolean resetFaults = "all".equals(scope) || "faults".equals(scope);
            boolean resetLeaks = "all".equals(scope) || "leaks".equals(scope);
            boolean resetCampaign = "all".equals(scope) || "campaign".equals(scope);

            if (resetFaults) {
                runtime.faultOracle().clear();
            }
            if (resetLeaks) {
                runtime.retentionScreener().reset();
            }
            int restoredJars = 0;
            if (resetCampaign) {
                FuzzCampaignStateStore store = runtime.campaignStateStore();
                Optional<CampaignState> cur = store.load();
                if (cur.isPresent()) {
                    try {
                        store.save(cur.get().withStatus(CampaignStatus.ABORTED, System.currentTimeMillis()));
                    } catch (Exception e) {
                        accessor.log(Level.WARNING, "[LeafFuzz] Failed to reset campaign state", e);
                    }
                }
                for (Path dir : LeafFuzzRuntime.resolveArchiveDirectories(accessor.getRootFolder())) {
                    try {
                        restoredJars += store.abortAndRestore(dir).size();
                    } catch (Exception ignored) {
                    }
                }
            }
            sendReply(
                    callerId,
                    "&aReset complete &7(scope=&f" + scope + "&7, restored archives=&f" + restoredJars + "&7).",
                    false
            );
            return true;
        }
    }

    private final class TestSub extends BaseSub {
        TestSub(CommandsAPICommand parent) {
            super("test", "leaffuzz.admin", "Run [FUZZ bit] PBIT/CBIT/IBIT self-tests.", parent);
        }

        @Override
        public boolean onCommand(
                UUID callerId,
                Map<String, List<String>> parameterValues,
                CommandsAPICommand nextCommand
        ) {
            if (runtime.checkRunning().get()) {
                sendReply(callerId, runtime.config().messages().busy(), true);
                return true;
            }
            String prefix = runtime.config().messages().prefix();
            accessor.scheduler().ifPresentOrElse(
                    s -> s.runAsync(() -> {
                        List<String> lines = runtime.bitSuite().executeAllAndFormat(prefix);
                        s.runSync(() -> {
                            for (String line : lines) {
                                sendRawLine(callerId, line, false);
                            }
                        });
                    }),
                    () -> {
                        for (String line : runtime.bitSuite().executeAllAndFormat(prefix)) {
                            sendRawLine(callerId, line, false);
                        }
                    }
            );
            return true;
        }
    }

    private final class ReloadSub extends BaseSub {
        ReloadSub(CommandsAPICommand parent) {
            super("reload", "leaffuzz.admin", "Validate and reload config.yml and messages.yml.", parent);
        }

        @Override
        public boolean onCommand(
                UUID callerId,
                Map<String, List<String>> parameterValues,
                CommandsAPICommand nextCommand
        ) {
            List<String> errors = runtime.reloadAndValidate();
            if (errors.isEmpty()) {
                sendReply(callerId, runtime.config().messages().reloadSuccess(), false);
            } else {
                sendReply(
                        callerId,
                        runtime.config().messages().reloadFailed().replace("[errors]", String.join("; ", errors)),
                        true
                );
            }
            return true;
        }
    }

    private static String joinedParam(Map<String, List<String>> params, String key, String fallback) {
        if (params == null) {
            return fallback;
        }
        List<String> vals = params.get(key);
        if (vals == null || vals.isEmpty()) {
            return fallback;
        }
        List<String> nonBlank = new ArrayList<>(vals.size());
        for (String v : vals) {
            if (v != null && !v.isBlank()) {
                nonBlank.add(v.trim());
            }
        }
        return nonBlank.isEmpty() ? fallback : String.join(",", nonBlank);
    }

    private static String firstParam(Map<String, List<String>> params, String key, String fallback) {
        if (params == null) {
            return fallback;
        }
        List<String> vals = params.get(key);
        if (vals == null || vals.isEmpty() || vals.get(0) == null || vals.get(0).isBlank()) {
            return fallback;
        }
        return vals.get(0).trim();
    }

    private static int parseIntParam(Map<String, List<String>> params, String key, int fallback) {
        String raw = firstParam(params, key, null);
        if (raw == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static int parsePlayersParam(Map<String, List<String>> params, int fallback) {
        String raw = firstParam(params, "players", null);
        if (raw == null) {
            return fallback;
        }
        String low = raw.trim().toLowerCase(Locale.ROOT);
        if ("auto".equals(low) || "ramp".equals(low)) {
            return LeafFuzzRuntime.AUTO_RAMP_PLAYERS;
        }
        try {
            return Integer.parseInt(low);
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }
}
