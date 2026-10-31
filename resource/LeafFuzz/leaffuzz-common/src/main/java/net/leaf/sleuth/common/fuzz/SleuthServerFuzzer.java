package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.Denylist;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.SequenceStep;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.NumericBisectionResult;
import net.leaf.sleuth.common.fuzz.NodeBandit.ArmKey;
import net.leaf.sleuth.common.fuzz.NodeBandit.EpisodeFeedback;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * In-JVM QA calibration and stress-test engine coordinating {@link NodeBandit} UCB1 exploration,
 * {@link NumericBoundaryLadder} boundary argument cycling, {@link FuzzActionShrinker} delta-debugging
 * trace minimization ({@code ddmin} + {@code bisectNumericArg}), and {@link DualAudienceMitigationReport}
 * synthesis ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * <p>Pure Java 17 with zero platform imports ({@code ADR-129}); platform adapters (such as
 * {@code PaperSyntheticEpisodeRunner}) supply the {@link EpisodeRunner} callback that dispatches
 * synthetic commands and lifecycle follow-up shapes on the server scheduler.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-004
 * @trace S-005
 */
public final class SleuthServerFuzzer {

    /**
     * Outcome of executing a single episode action sequence against the target environment.
     *
     * @param reproduced        whether a fault (exception, stall, or class retention leak) occurred
     * @param signatureId       triggered fault/leak signature ID (e.g. {@code "leak:pkg.Class"} or {@code "exc:..."})
     * @param suspectJar        attributed plugin JAR from {@link JarClassOwnershipIndex}
     * @param classGrowthDelta  retained class instance growth observed during the episode
     * @param msptExcess        excess MSPT above baseline observed during the episode
     * @param observedClasses   newly touched classes or stack frames for novelty scoring
     * @param usageError        whether the command was rejected as a syntax/usage error
     */
    public record EpisodeOutcome(
            boolean reproduced,
            String signatureId,
            String suspectJar,
            double classGrowthDelta,
            double msptExcess,
            List<String> observedClasses,
            boolean usageError
    ) {
        public EpisodeOutcome {
            observedClasses = observedClasses == null ? List.of() : List.copyOf(observedClasses);
        }

        public static EpisodeOutcome clean() {
            return new EpisodeOutcome(false, null, null, 0.0, 0.0, List.of(), false);
        }

        public static EpisodeOutcome cleanWithNovelty(Collection<String> observedClasses) {
            return new EpisodeOutcome(false, null, null, 0.0, 0.0,
                    observedClasses != null ? List.copyOf(observedClasses) : List.of(), false);
        }

        public static EpisodeOutcome fault(
                String signatureId,
                String suspectJar,
                double classGrowthDelta,
                double msptExcess,
                Collection<String> observedClasses
        ) {
            return new EpisodeOutcome(
                    true,
                    signatureId,
                    suspectJar,
                    classGrowthDelta,
                    msptExcess,
                    observedClasses != null ? List.copyOf(observedClasses) : List.of(),
                    false
            );
        }
    }

    /**
     * Platform-neutral callback that executes a candidate sequence of {@link EpisodeAction}s
     * and returns its {@link EpisodeOutcome}.
     */
    @FunctionalInterface
    public interface EpisodeRunner extends Function<List<EpisodeAction>, EpisodeOutcome> {
        EpisodeOutcome runEpisode(List<EpisodeAction> actions);

        @Override
        default EpisodeOutcome apply(List<EpisodeAction> actions) {
            return runEpisode(actions);
        }
    }

    private static final List<String> UNVISITED_CYCLE_SHAPES = List.of(
            "window_click",
            "repeat",
            "explorer_wander",
            "homesteader_reroll",
            "quit_lt1s",
            "burst_swarm",
            "chunk_border_thrash"
    );
    private static final List<String> MENU_EXPLORE_SHAPES = List.of(
            "window_click",
            "repeat",
            "explorer_wander",
            "homesteader_reroll",
            "rejoin",
            "quit_lt1s"
    );
    private static final List<String> LEAK_CONFIRM_SHAPES = List.of(
            "quit_lt1s",
            "burst_swarm",
            "rejoin",
            "chunk_border_thrash",
            "rejoin",
            "quit_lt1s"
    );

    private final CommandTree commandTree;
    private final JarClassOwnershipIndex ownershipIndex;
    private final NodeBandit bandit;
    private final Denylist denylist;
    private final Map<String, Integer> ladderCursorByNode = new LinkedHashMap<>();
    private final Map<String, Integer> nodePulls = new LinkedHashMap<>();
    private final Map<String, Integer> nodeSalientSlots = new LinkedHashMap<>();
    private final java.util.Set<String> nodeStalled = new java.util.LinkedHashSet<>();
    private final java.util.Set<String> nodeLeaked = new java.util.LinkedHashSet<>();
    private final List<DualAudienceMitigationReport> findings = new CopyOnWriteArrayList<>();
    private final Map<String, DualAudienceMitigationReport> findingsBySignature = new LinkedHashMap<>();
    private final AtomicBoolean active = new AtomicBoolean(false);
    private final AtomicInteger episodesCompleted = new AtomicInteger(0);
    private volatile int targetEpisodes;

    public SleuthServerFuzzer(
            CommandTree commandTree,
            JarClassOwnershipIndex ownershipIndex,
            Collection<String> tiers,
            Collection<String> followUpShapes,
            Random rng
    ) {
        this.commandTree = Objects.requireNonNull(commandTree, "commandTree");
        this.ownershipIndex = ownershipIndex != null ? ownershipIndex : JarClassOwnershipIndex.empty();
        this.bandit = new NodeBandit(
                commandTree,
                tiers,
                NodeBandit.DEFAULT_BUDGET_SHARE,
                NodeBandit.DEFAULT_EXPLORATION_C,
                followUpShapes,
                rng != null ? rng : new Random(1L)
        );
        this.denylist = commandTree.denylistEntries().isEmpty()
                ? new Denylist(CommandSurfaceAuditor.DEFAULT_DENYLIST)
                : new Denylist(commandTree.denylistEntries());
    }

    /**
     * Selects the next arm using node-first coverage scheduling (guaranteeing every unvisited
     * executable node at least 1 pull, typed argument nodes up to 3 boundary-ladder pulls, and
     * leaking nodes up to 6 confirmation pulls before UCB1 bandit selection) and synthesizes a
     * concrete {@link EpisodeAction}.
     *
     * @return synthesized {@link EpisodeAction}
     */
    public synchronized EpisodeAction nextEpisodeAction() {
        ArmKey arm = selectScheduledOrBanditArm();
        nodePulls.put(arm.nodeId(), nodePulls.getOrDefault(arm.nodeId(), 0) + 1);
        CommandNode node = commandTree.nodes().get(arm.nodeId());
        String commandLine = synthesizeCommandLine(node, arm.nodeId());
        String tier = (node != null && node.isDefaultVisible()) ? "default" : "op";
        return new EpisodeAction(commandLine, arm.followUpShape(), arm.nodeId(), tier);
    }

    private ArmKey selectScheduledOrBanditArm() {
        List<CommandNode> activeExec = commandTree.executableAllowedNodes();
        int epIdx = episodesCompleted.get();
        List<String> availShapes = bandit.shapes();
        String fallbackShape = availShapes.isEmpty() ? "repeat" : availShapes.get(0);

        // 1. If a previously visited node revealed a menu with multiple salient ("shiny") slots,
        //    mutate across those salient slots first so every distinct menu button is exercised.
        for (Map.Entry<String, Integer> entry : nodeSalientSlots.entrySet()) {
            String menuNid = entry.getKey();
            int salientCount = Math.min(6, Math.max(2, entry.getValue()));
            int pulls = nodePulls.getOrDefault(menuNid, 0);
            if (pulls > 0 && pulls < salientCount && bandit.armStats(menuNid, fallbackShape) != null) {
                String desiredShape = MENU_EXPLORE_SHAPES.get(Math.floorMod(pulls, MENU_EXPLORE_SHAPES.size()));
                String shape = availShapes.contains(desiredShape) ? desiredShape : fallbackShape;
                return new ArmKey(menuNid, shape);
            }
        }

        // 2. Guarantee every unvisited core command/subcommand/argument node (rank <= 3) gets at least 1 pull first
        List<CommandNode> unvisitedCore = new ArrayList<>();
        List<CommandNode> unvisitedParamMutations = new ArrayList<>();
        for (CommandNode n : activeExec) {
            if (nodePulls.getOrDefault(n.nodeId(), 0) == 0 && bandit.armStats(n.nodeId(), fallbackShape) != null) {
                if (nodePriorityRank(n) <= 3) {
                    unvisitedCore.add(n);
                } else {
                    unvisitedParamMutations.add(n);
                }
            }
        }
        if (!unvisitedCore.isEmpty()) {
            sortNodesByPriority(unvisitedCore);
            CommandNode chosenNode = unvisitedCore.get(0);
            String desiredShape = ("argument".equals(chosenNode.kind()) && chosenNode.nodeId().contains("scan"))
                    ? "quit_delay"
                    : UNVISITED_CYCLE_SHAPES.get(Math.floorMod(epIdx, UNVISITED_CYCLE_SHAPES.size()));
            String shape = availShapes.contains(desiredShape) ? desiredShape : fallbackShape;
            return new ArmKey(chosenNode.nodeId(), shape);
        }

        // 3. Give typed argument nodes up to 3 pulls across NumericBoundaryLadder if not yet faulted
        for (CommandNode n : activeExec) {
            int pulls = nodePulls.getOrDefault(n.nodeId(), 0);
            if ("argument".equals(n.kind())
                    && pulls < 3
                    && !nodeStalled.contains(n.nodeId())
                    && !nodeLeaked.contains(n.nodeId())
                    && bandit.armStats(n.nodeId(), fallbackShape) != null) {
                String desiredShape = (pulls == 1) ? "explorer_wander" : "quit_delay";
                String shape = availShapes.contains(desiredShape) ? desiredShape : fallbackShape;
                return new ArmKey(n.nodeId(), shape);
            }
        }

        // 4. Give leaking nodes up to 6 confirmation pulls across LEAK_CONFIRM_SHAPES
        for (String leakNid : nodeLeaked) {
            int pulls = nodePulls.getOrDefault(leakNid, 0);
            if (pulls < 6 && bandit.armStats(leakNid, fallbackShape) != null) {
                String desiredShape = LEAK_CONFIRM_SHAPES.get(Math.min(pulls, LEAK_CONFIRM_SHAPES.size() - 1));
                String shape = availShapes.contains(desiredShape) ? desiredShape : fallbackShape;
                return new ArmKey(leakNid, shape);
            }
        }

        // 5. Interleave UCB1 bandit exploitation of learned high-reward commands/shapes (67% of pulls)
        //    with curiosity exploration of unvisited param=value mutations (33% of pulls).
        if (!unvisitedParamMutations.isEmpty() && Math.floorMod(epIdx, 3) == 0) {
            sortNodesByPriority(unvisitedParamMutations);
            CommandNode chosenNode = unvisitedParamMutations.get(0);
            String desiredShape = UNVISITED_CYCLE_SHAPES.get(Math.floorMod(epIdx, UNVISITED_CYCLE_SHAPES.size()));
            String shape = availShapes.contains(desiredShape) ? desiredShape : fallbackShape;
            return new ArmKey(chosenNode.nodeId(), shape);
        }

        return bandit.selectArm();
    }

    private static void sortNodesByPriority(List<CommandNode> list) {
        list.sort((a, b) -> {
            int ra = nodePriorityRank(a);
            int rb = nodePriorityRank(b);
            if (ra != rb) return Integer.compare(ra, rb);
            int la = a.nodeId().length();
            int lb = b.nodeId().length();
            if (la != lb) return Integer.compare(la, lb);
            return a.nodeId().compareTo(b.nodeId());
        });
    }

    private static int nodePriorityRank(CommandNode node) {
        String id = node.nodeId();
        if (!id.contains(" ")) {
            String owner = node.owningPlugin();
            if (owner != null && !owner.isBlank()) {
                String ownerLow = owner.trim().toLowerCase(java.util.Locale.ROOT);
                String idLow = id.trim().toLowerCase(java.util.Locale.ROOT);
                if (ownerLow.equals(idLow) || ownerLow.startsWith(idLow + "-") || ownerLow.contains(idLow)) {
                    return 0; // Primary root command matching plugin identity
                }
            }
            return 1; // Other root command or alias
        }
        if ("argument".equals(node.kind())) {
            return 2; // Typed argument node
        }
        if (!id.contains("=")) {
            return 3; // Core subcommand literal (e.g. "rtp gui", "rtp info")
        }
        return 4; // Parameter completion literal (e.g. "rtp world=world")
    }

    /**
     * Synthesizes a concrete command line for {@code node} using the next value on its
     * {@link NumericBoundaryLadder}.
     *
     * @param node   command node (nullable if resolved by {@code nodeId})
     * @param nodeId canonical command node ID
     * @return concrete command string starting with {@code "/"}
     */
    public synchronized String synthesizeCommandLine(CommandNode node, String nodeId) {
        CommandNode resolved = node != null ? node : (nodeId != null ? commandTree.nodes().get(nodeId) : null);
        if (resolved == null) {
            String raw = nodeId != null ? nodeId.trim() : "help";
            return raw.startsWith("/") ? raw : "/" + raw;
        }

        List<String> ladderTokens = NumericBoundaryLadder.candidateTokensForNode(resolved);
        int cursor = ladderCursorByNode.getOrDefault(resolved.nodeId(), 0);
        String chosenArgToken = ladderTokens.get(Math.floorMod(cursor, ladderTokens.size()));
        ladderCursorByNode.put(resolved.nodeId(), cursor + 1);

        StringBuilder sb = new StringBuilder("/");
        sb.append(resolved.rootId());
        if (!resolved.steps().isEmpty()) {
            for (SequenceStep step : resolved.steps()) {
                sb.append(' ');
                if ("argument".equals(step.kind())) {
                    sb.append(chosenArgToken);
                } else {
                    sb.append(step.name());
                }
            }
        } else {
            String[] parts = resolved.nodeId().trim().split("\\s+");
            for (int i = 1; i < parts.length; i++) {
                sb.append(' ');
                if (parts[i].startsWith("<") && parts[i].endsWith(">")) {
                    sb.append(chosenArgToken);
                } else {
                    sb.append(parts[i]);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Runs a synchronous multi-episode exploration and minimization campaign against {@code runner}.
     *
     * @param maxEpisodes maximum number of UCB1 episodes to execute
     * @param runner      episode execution callback
     * @return immutable list of minimized {@link DualAudienceMitigationReport} findings
     */
    public List<DualAudienceMitigationReport> runCampaign(int maxEpisodes, EpisodeRunner runner) {
        Objects.requireNonNull(runner, "runner");
        int budget = Math.max(1, maxEpisodes);
        active.set(true);
        targetEpisodes = budget;
        try {
            for (int ep = 0; ep < budget && active.get(); ep++) {
                runSingleEpisode(runner);
            }
        } finally {
            active.set(false);
        }
        return findings();
    }

    /**
     * Executes a single UCB1 episode against {@code runner}, updating {@link NodeBandit} rewards
     * and automatically running {@link #minimizeAndRecordFinding} if a fault or leak reproduces.
     *
     * @param runner episode runner callback
     * @return optional new or updated {@link DualAudienceMitigationReport} if the episode triggered a fault
     */
    public Optional<DualAudienceMitigationReport> runSingleEpisode(EpisodeRunner runner) {
        Objects.requireNonNull(runner, "runner");
        EpisodeAction action = nextEpisodeAction();
        if (denylist.isDeniedCommandLine(action.commandLine(), commandTree)) {
            episodesCompleted.incrementAndGet();
            return Optional.empty();
        }
        List<EpisodeAction> trace = List.of(action);
        EpisodeOutcome outcome = runner.runEpisode(trace);
        episodesCompleted.incrementAndGet();

        String resolvedNodeId = action.nodeId() != null ? action.nodeId() : action.commandLine();
        double infoAndEffectBonus = 0.0;
        for (String tok : outcome.observedClasses()) {
            if (tok == null) {
                continue;
            }
            if (tok.startsWith("info:menu_salient_slots:")) {
                try {
                    int slots = Integer.parseInt(tok.substring("info:menu_salient_slots:".length()).trim());
                    if (slots > 1) {
                        synchronized (this) {
                            nodeSalientSlots.put(resolvedNodeId, Math.max(nodeSalientSlots.getOrDefault(resolvedNodeId, 0), slots));
                        }
                    }
                } catch (NumberFormatException ignored) {
                }
            }
            if (tok.startsWith("info:")) {
                infoAndEffectBonus += 1.5;
            } else if (tok.startsWith("effect:")) {
                infoAndEffectBonus += 3.0;
            }
        }

        bandit.update(
                resolvedNodeId,
                action.followUpShape(),
                new EpisodeFeedback(
                        (outcome.reproduced() ? 5.0 : 0.0) + Math.min(12.0, infoAndEffectBonus),
                        0.0,
                        outcome.observedClasses(),
                        outcome.classGrowthDelta(),
                        0.0,
                        outcome.msptExcess(),
                        outcome.reproduced() ? 1 : 0,
                        outcome.usageError()
                )
        );

        if (!outcome.reproduced()) {
            return Optional.empty();
        }
        return Optional.of(minimizeAndRecordFinding(trace, outcome, runner));
    }

    /**
     * Minimizes an arbitrary multi-step failing trace using {@link FuzzActionShrinker#ddmin}
     * followed by {@link FuzzActionShrinker#bisectNumericArg}, attributes the culprit JAR via
     * {@link JarClassOwnershipIndex}, and records a {@link DualAudienceMitigationReport}.
     *
     * @param initialTrace multi-step episode trace that triggered {@code initialOutcome}
     * @param initialOutcome initial fault/leak outcome
     * @param runner       episode runner used to verify candidate shrinks and numeric bisections
     * @return minimized {@link DualAudienceMitigationReport}
     */
    public synchronized DualAudienceMitigationReport minimizeAndRecordFinding(
            List<EpisodeAction> initialTrace,
            EpisodeOutcome initialOutcome,
            EpisodeRunner runner
    ) {
        Objects.requireNonNull(initialTrace, "initialTrace");
        Objects.requireNonNull(initialOutcome, "initialOutcome");
        Objects.requireNonNull(runner, "runner");

        String targetSig = initialOutcome.signatureId() != null && !initialOutcome.signatureId().isBlank()
                ? initialOutcome.signatureId()
                : "fault:reproduced";

        Predicate<List<EpisodeAction>> reproducesSameSignature = candidate -> {
            if (candidate == null || candidate.isEmpty()) {
                return false;
            }
            for (EpisodeAction act : candidate) {
                if (denylist.isDeniedCommandLine(act.commandLine(), commandTree)) {
                    return false;
                }
            }
            EpisodeOutcome res = runner.runEpisode(candidate);
            if (!res.reproduced()) {
                return false;
            }
            return res.signatureId() == null
                    || res.signatureId().isBlank()
                    || targetSig.equals(res.signatureId());
        };

        List<EpisodeAction> ddminTrace = FuzzActionShrinker.ddmin(initialTrace, reproducesSameSignature);

        CommandNode primaryNode = null;
        for (EpisodeAction act : ddminTrace) {
            if (act.nodeId() != null && commandTree.nodes().containsKey(act.nodeId())) {
                primaryNode = commandTree.nodes().get(act.nodeId());
                break;
            }
        }

        NumericBisectionResult bisected = FuzzActionShrinker.bisectNumericArg(
                ddminTrace,
                primaryNode,
                commandTree,
                denylist,
                null,
                reproducesSameSignature
        );

        List<EpisodeAction> finalActions = bisected.minimizedActions();
        List<String> minimalCommands = new ArrayList<>(finalActions.size());
        String followUp = "repeat";
        for (int i = 0; i < finalActions.size(); i++) {
            EpisodeAction act = finalActions.get(i);
            minimalCommands.add(act.commandLine());
            if (i == finalActions.size() - 1 && act.followUpShape() != null && !act.followUpShape().isBlank()) {
                followUp = act.followUpShape();
            }
        }

        String suspectJar = resolveSuspectJar(initialOutcome, primaryNode);
        DualAudienceMitigationReport report = DualAudienceMitigationReport.build(
                targetSig,
                suspectJar,
                minimalCommands,
                followUp,
                bisected.thresholdSummary(),
                primaryNode,
                commandTree
        );

        DualAudienceMitigationReport existing = findingsBySignature.put(targetSig, report);
        if (existing != null) {
            findings.remove(existing);
        }
        findings.add(report);
        return report;
    }

    private String resolveSuspectJar(EpisodeOutcome outcome, CommandNode node) {
        if (outcome.suspectJar() != null
                && !outcome.suspectJar().isBlank()
                && !"server".equalsIgnoreCase(outcome.suspectJar())
                && !"unknown".equalsIgnoreCase(outcome.suspectJar())) {
            return outcome.suspectJar();
        }
        if (!outcome.observedClasses().isEmpty()) {
            Optional<String> fromFrames = ownershipIndex.firstSuspectJar(outcome.observedClasses());
            if (fromFrames.isPresent()) {
                return fromFrames.get();
            }
        }
        if (node != null && node.owningPlugin() != null && !node.owningPlugin().isBlank()) {
            return node.owningPlugin();
        }
        return outcome.suspectJar() != null && !outcome.suspectJar().isBlank() ? outcome.suspectJar() : "server";
    }

    public CommandTree commandTree() {
        return commandTree;
    }

    public JarClassOwnershipIndex ownershipIndex() {
        return ownershipIndex;
    }

    public NodeBandit bandit() {
        return bandit;
    }

    public boolean isActive() {
        return active.get();
    }

    public void setActive(boolean active) {
        this.active.set(active);
    }

    public void stop() {
        this.active.set(false);
    }

    public int episodesCompleted() {
        return episodesCompleted.get();
    }

    public int targetEpisodes() {
        return targetEpisodes;
    }

    public void setTargetEpisodes(int targetEpisodes) {
        this.targetEpisodes = Math.max(0, targetEpisodes);
    }

    public List<DualAudienceMitigationReport> findings() {
        return Collections.unmodifiableList(new ArrayList<>(findings));
    }
}
