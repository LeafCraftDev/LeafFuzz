package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;

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

/**
 * Tier-stratified UCB1 multi-armed bandit scheduler over {@code (nodeId, followUpShape)} pairs
 * with novelty bonuses for newly observed heap classes or stack frames ({@code ADR-125},
 * {@code leafsleuth-ADR-006}).
 *
 * <p>Stratifies pull budget so {@code default}-tier command nodes receive
 * {@link #defaultBudgetShare()} (default {@code 0.75}) of pulls when both {@code default} and
 * {@code op} tiers are active, preventing a large administrative command tree from starving
 * player-facing command coverage.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-004
 */
public final class NodeBandit {

    /** Default exploration constant {@code c = sqrt(2)}. */
    public static final double DEFAULT_EXPLORATION_C = 1.414;

    /** Default pull budget share allocated to {@code default}-visible command arms ({@code 0.75}). */
    public static final double DEFAULT_BUDGET_SHARE = 0.75;

    /** Canonical lifecycle follow-up shapes exercised in-JVM. */
    public static final List<String> DEFAULT_FOLLOW_UP_SHAPES = List.of(
            "quit_lt1s",
            "quit_delay",
            "repeat",
            "homesteader_reroll",
            "rejoin",
            "coop_group",
            "explorer_wander",
            "concurrent",
            "window_click",
            "burst_swarm",
            "chunk_border_thrash"
    );

    /**
     * Identifier for a single bandit arm {@code (nodeId, followUpShape)}.
     *
     * @param nodeId        canonical command node ID
     * @param followUpShape follow-up lifecycle shape (e.g. {@code "quit_lt1s"}, {@code "repeat"})
     */
    public record ArmKey(String nodeId, String followUpShape) {
        public ArmKey {
            Objects.requireNonNull(nodeId, "nodeId");
            Objects.requireNonNull(followUpShape, "followUpShape");
        }
    }

    /**
     * Mutable statistics tracked for a single {@link ArmKey}.
     */
    public static final class BanditArmStats {
        private final String nodeId;
        private final String followUpShape;
        private final String minTier;
        private int pulls;
        private double totalReward;
        private int noveltyHits;
        private double harmTotal;
        private int usageErrors;
        private double maxMsptExcess;
        private double lastMsptExcess;

        public BanditArmStats(String nodeId, String followUpShape, String minTier) {
            this.nodeId = Objects.requireNonNull(nodeId, "nodeId");
            this.followUpShape = Objects.requireNonNull(followUpShape, "followUpShape");
            this.minTier = (minTier == null || minTier.isBlank()) ? "default" : minTier;
        }

        public String nodeId() {
            return nodeId;
        }

        public String followUpShape() {
            return followUpShape;
        }

        public String minTier() {
            return minTier;
        }

        public int pulls() {
            return pulls;
        }

        public double totalReward() {
            return totalReward;
        }

        public double meanReward() {
            return pulls > 0 ? totalReward / pulls : 0.0;
        }

        public int noveltyHits() {
            return noveltyHits;
        }

        public double harmTotal() {
            return harmTotal;
        }

        public int usageErrors() {
            return usageErrors;
        }

        public double maxMsptExcess() {
            return maxMsptExcess;
        }

        public double lastMsptExcess() {
            return lastMsptExcess;
        }
    }

    /**
     * Telemetry feedback from a single episode execution used to update an arm's UCB1 reward.
     *
     * @param explicitReward  optional base reward override
     * @param noveltyBonus    explicit novelty bonus
     * @param observedClasses classes or stack frames observed during the episode (for automatic novelty)
     * @param classGrowth     retained class instance growth delta
     * @param tickGapExcessMs peak tick gap excess in milliseconds
     * @param msptExcess      continuous MSPT excess above baseline
     * @param faultCount      exceptions or stalls triggered during the episode
     * @param usageError      whether the command failed with a syntax/usage rejection
     */
    public record EpisodeFeedback(
            double explicitReward,
            double noveltyBonus,
            Collection<String> observedClasses,
            double classGrowth,
            double tickGapExcessMs,
            double msptExcess,
            int faultCount,
            boolean usageError
    ) {
        public static EpisodeFeedback of(
                double classGrowth,
                double msptExcess,
                int faultCount,
                Collection<String> observedClasses,
                boolean usageError
        ) {
            return new EpisodeFeedback(
                    0.0,
                    0.0,
                    observedClasses != null ? List.copyOf(observedClasses) : List.of(),
                    classGrowth,
                    0.0,
                    msptExcess,
                    faultCount,
                    usageError
            );
        }
    }

    private final CommandTree tree;
    private final List<String> activeTiers;
    private final double defaultBudgetShare;
    private final double explorationC;
    private final Random rng;
    private final List<String> shapes;
    private final Map<ArmKey, BanditArmStats> arms = new LinkedHashMap<>();
    private final Map<String, double[]> nodeRewardTotals = new LinkedHashMap<>();
    private final List<ArmKey> defaultArms = new ArrayList<>();
    private final List<ArmKey> opArms = new ArrayList<>();
    private final Set<String> seenNoveltyTokens = new LinkedHashSet<>();
    private int totalPulls;
    private int defaultPulls;
    private int opPulls;

    public NodeBandit(CommandTree tree) {
        this(tree, List.of("default"), DEFAULT_BUDGET_SHARE, DEFAULT_EXPLORATION_C, DEFAULT_FOLLOW_UP_SHAPES, new Random(1L));
    }

    public NodeBandit(
            CommandTree tree,
            Collection<String> tiers,
            double defaultBudgetShare,
            double explorationC,
            Collection<String> followUpShapes,
            Random rng
    ) {
        this.tree = Objects.requireNonNull(tree, "tree");
        this.activeTiers = normalizeTiers(tiers);
        this.defaultBudgetShare = Math.min(1.0, Math.max(0.0, defaultBudgetShare));
        this.explorationC = Double.isFinite(explorationC) && explorationC >= 0.0 ? explorationC : DEFAULT_EXPLORATION_C;
        this.rng = rng != null ? rng : new Random(1L);
        this.shapes = normalizeShapes(followUpShapes);

        for (CommandNode node : tree.executableAllowedNodes()) {
            if (!isVisibleInActiveTiers(node, this.activeTiers)) {
                continue;
            }
            String mTier = node.isDefaultVisible() ? "default" : "op";
            for (String shape : this.shapes) {
                ArmKey key = new ArmKey(node.nodeId(), shape);
                BanditArmStats stats = new BanditArmStats(node.nodeId(), shape, mTier);
                arms.put(key, stats);
                if ("default".equals(mTier)) {
                    defaultArms.add(key);
                } else {
                    opArms.add(key);
                }
            }
        }
    }

    /**
     * Selects the next {@link ArmKey} using tier-stratified UCB1 and increments its pull counter.
     *
     * @return chosen {@code (nodeId, followUpShape)} arm
     */
    public ArmKey selectArm() {
        String stratum;
        List<ArmKey> pool;
        if (!defaultArms.isEmpty() && !opArms.isEmpty()) {
            if (rng.nextDouble() < defaultBudgetShare) {
                stratum = "default";
                pool = defaultArms;
            } else {
                stratum = "op";
                pool = opArms;
            }
        } else if (!defaultArms.isEmpty()) {
            stratum = "default";
            pool = defaultArms;
        } else if (!opArms.isEmpty()) {
            stratum = "op";
            pool = opArms;
        } else {
            throw new IllegalStateException("NodeBandit has no allowed executable command arms for active tiers " + activeTiers);
        }

        int stratumTotal = "default".equals(stratum) ? defaultPulls : opPulls;
        double bestScore = Double.NEGATIVE_INFINITY;
        List<ArmKey> bestCandidates = new ArrayList<>();

        for (ArmKey key : pool) {
            BanditArmStats stats = arms.get(key);
            double score = ucbScore(stats, stratumTotal);
            if (score > bestScore + 1e-12) {
                bestScore = score;
                bestCandidates.clear();
                bestCandidates.add(key);
            } else if (Math.abs(score - bestScore) <= 1e-12) {
                bestCandidates.add(key);
            }
        }

        ArmKey chosen = bestCandidates.size() == 1
                ? bestCandidates.get(0)
                : bestCandidates.get(rng.nextInt(bestCandidates.size()));

        BanditArmStats chosenStats = arms.get(chosen);
        chosenStats.pulls += 1;
        totalPulls += 1;
        if ("default".equals(stratum)) {
            defaultPulls += 1;
        } else {
            opPulls += 1;
        }
        return chosen;
    }

    /**
     * Updates the UCB1 reward and novelty statistics for {@code (nodeId, followUpShape)}.
     *
     * @param nodeId        command node ID
     * @param followUpShape follow-up lifecycle shape
     * @param feedback      episode telemetry feedback
     * @return computed scalar reward added to the arm
     */
    public double update(String nodeId, String followUpShape, EpisodeFeedback feedback) {
        Objects.requireNonNull(nodeId, "nodeId");
        Objects.requireNonNull(followUpShape, "followUpShape");
        Objects.requireNonNull(feedback, "feedback");

        ArmKey key = new ArmKey(nodeId, followUpShape);
        BanditArmStats stats = arms.computeIfAbsent(key, k -> {
            CommandNode node = tree.nodes().get(nodeId);
            String mTier = (node != null && node.isDefaultVisible()) ? "default" : "op";
            BanditArmStats created = new BanditArmStats(nodeId, followUpShape, mTier);
            if ("default".equals(mTier)) {
                defaultArms.add(k);
            } else {
                opArms.add(k);
            }
            return created;
        });

        if (stats.pulls == 0) {
            stats.pulls = 1;
            totalPulls += 1;
            if ("default".equals(stats.minTier)) {
                defaultPulls += 1;
            } else {
                opPulls += 1;
            }
        }

        int newTokens = 0;
        if (feedback.observedClasses() != null) {
            for (String token : feedback.observedClasses()) {
                if (token != null && !token.isBlank() && seenNoveltyTokens.add(token.trim())) {
                    newTokens++;
                }
            }
        }
        double novelty = Math.max(0.0, feedback.noveltyBonus()) + (newTokens * 0.5);

        double effMsptExcess = Math.max(0.0, feedback.msptExcess());
        stats.lastMsptExcess = effMsptExcess;
        if (effMsptExcess > stats.maxMsptExcess) {
            stats.maxMsptExcess = effMsptExcess;
        }

        double harmComponent = Math.max(0.0, feedback.classGrowth()) / 50.0
                + Math.max(0.0, feedback.tickGapExcessMs()) / 500.0
                + Math.min(4.0, effMsptExcess / 5.0)
                + 2.0 * Math.max(0, feedback.faultCount());

        double computed = feedback.explicitReward() + novelty + harmComponent;
        if (feedback.usageError()) {
            computed -= 0.25;
            stats.usageErrors += 1;
        }
        if (novelty > 0.0 || newTokens > 0) {
            stats.noveltyHits += Math.max(1, newTokens > 0 ? newTokens : (int) Math.round(novelty));
        }
        stats.harmTotal += harmComponent;
        stats.totalReward += computed;
        double[] nodeTotals = nodeRewardTotals.computeIfAbsent(nodeId, k -> new double[2]);
        nodeTotals[0] += 1.0;
        nodeTotals[1] += computed;
        return computed;
    }

    /**
     * Convenience overload for updating an arm with scalar reward, novelty, class growth, and MSPT excess.
     *
     * @param nodeId        command node ID
     * @param followUpShape follow-up shape
     * @param reward        explicit base reward
     * @param novelty       novelty bonus
     * @param classGrowth   retained class instance growth
     * @param msptExcess    excess MSPT
     * @param usageError    whether a usage error occurred
     * @return computed total reward for this update
     */
    public double update(
            String nodeId,
            String followUpShape,
            double reward,
            double novelty,
            double classGrowth,
            double msptExcess,
            boolean usageError
    ) {
        return update(nodeId, followUpShape, new EpisodeFeedback(
                reward,
                novelty,
                List.of(),
                classGrowth,
                0.0,
                msptExcess,
                0,
                usageError
        ));
    }

    private double ucbScore(BanditArmStats stats, int stratumTotal) {
        double logTerm = Math.log(Math.max(2.0, stratumTotal + 2.0));
        if (stats.pulls <= 0) {
            double[] nodeTotals = nodeRewardTotals.get(stats.nodeId);
            double nodePrior = (nodeTotals != null && nodeTotals[0] > 0.0 && nodeTotals[1] > 0.0)
                    ? 0.80 * (nodeTotals[1] / nodeTotals[0])
                    : 0.0;
            return nodePrior + explorationC * Math.sqrt(logTerm);
        }
        return stats.meanReward() + explorationC * Math.sqrt(logTerm / stats.pulls);
    }

    /**
     * Returns the top learned {@link BanditArmStats} ranked by mean reward and pull count.
     */
    public List<BanditArmStats> topLearnedArms(int limit) {
        List<BanditArmStats> visited = new ArrayList<>();
        for (BanditArmStats st : arms.values()) {
            if (st.pulls > 0) {
                visited.add(st);
            }
        }
        visited.sort((a, b) -> {
            int c = Double.compare(b.totalReward, a.totalReward);
            if (c != 0) return c;
            return Integer.compare(b.pulls, a.pulls);
        });
        return visited.subList(0, Math.min(Math.max(1, limit), visited.size()));
    }

    public CommandTree tree() {
        return tree;
    }

    public List<String> activeTiers() {
        return activeTiers;
    }

    public double defaultBudgetShare() {
        return defaultBudgetShare;
    }

    public List<String> shapes() {
        return shapes;
    }

    public int totalPulls() {
        return totalPulls;
    }

    public int defaultPulls() {
        return defaultPulls;
    }

    public int opPulls() {
        return opPulls;
    }

    public int armCount() {
        return arms.size();
    }

    public Map<ArmKey, BanditArmStats> arms() {
        return Collections.unmodifiableMap(arms);
    }

    public BanditArmStats armStats(String nodeId, String followUpShape) {
        return arms.get(new ArmKey(nodeId, followUpShape));
    }

    public Set<String> seenNoveltyTokens() {
        return Collections.unmodifiableSet(seenNoveltyTokens);
    }

    private static boolean isVisibleInActiveTiers(CommandNode node, List<String> activeTiers) {
        for (String t : activeTiers) {
            if (node.tiers().contains(t) || t.equalsIgnoreCase(node.minTier())) {
                return true;
            }
        }
        return false;
    }

    private static List<String> normalizeTiers(Collection<String> tiers) {
        if (tiers == null || tiers.isEmpty()) {
            return List.of("default");
        }
        List<String> out = new ArrayList<>();
        for (String raw : tiers) {
            if (raw != null && !raw.isBlank()) {
                String clean = raw.trim().toLowerCase(Locale.ROOT);
                if (!out.contains(clean)) {
                    out.add(clean);
                }
            }
        }
        return out.isEmpty() ? List.of("default") : Collections.unmodifiableList(out);
    }

    private static List<String> normalizeShapes(Collection<String> shapes) {
        if (shapes == null || shapes.isEmpty()) {
            return DEFAULT_FOLLOW_UP_SHAPES;
        }
        List<String> out = new ArrayList<>();
        for (String s : shapes) {
            if (s != null && !s.isBlank()) {
                String clean = s.trim();
                if (!out.contains(clean)) {
                    out.add(clean);
                }
            }
        }
        return out.isEmpty() ? DEFAULT_FOLLOW_UP_SHAPES : Collections.unmodifiableList(out);
    }
}
