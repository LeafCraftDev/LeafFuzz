package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandTree;
import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.Denylist;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

/**
 * Zeller's delta-debugging ({@code ddmin}) action sequence minimizer and binary numeric argument
 * bisector ({@code bisectNumericArg}) for reducing multi-step stress traces down to 1-minimal
 * reproducers and exact numeric boundary thresholds ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-004
 */
public final class FuzzActionShrinker {

    private static final int FLOAT_BISECTION_STEPS = 16;

    private FuzzActionShrinker() {
    }

    /**
     * Single step in an episode trace combining a command invocation and a lifecycle follow-up shape.
     *
     * @param commandLine   executed command line (e.g. {@code "/rtp radius 1024"})
     * @param followUpShape follow-up lifecycle shape (e.g. {@code "quit_lt1s"}, {@code "repeat"})
     * @param nodeId        optional canonical command node ID (e.g. {@code "rtp radius <n>"})
     * @param tier          permission tier ({@code "default"} or {@code "op"})
     */
    public record EpisodeAction(
            String commandLine,
            String followUpShape,
            String nodeId,
            String tier
    ) {
        public EpisodeAction {
            commandLine = commandLine == null ? "" : commandLine.trim();
            followUpShape = (followUpShape == null || followUpShape.isBlank()) ? "repeat" : followUpShape.trim();
            nodeId = (nodeId == null || nodeId.isBlank()) ? null : nodeId.trim();
            tier = (tier == null || tier.isBlank()) ? "default" : tier.trim().toLowerCase(Locale.ROOT);
        }

        public static EpisodeAction of(String commandLine, String followUpShape) {
            return new EpisodeAction(commandLine, followUpShape, null, "default");
        }

        public static EpisodeAction of(String commandLine, String followUpShape, String nodeId) {
            return new EpisodeAction(commandLine, followUpShape, nodeId, "default");
        }

        public EpisodeAction withCommandLine(String updatedCommandLine) {
            return new EpisodeAction(updatedCommandLine, followUpShape, nodeId, tier);
        }
    }

    /**
     * Outcome of binary-searching a numeric command argument for its minimal threshold.
     *
     * @param minimizedActions updated action trace with the bisected numeric argument substituted
     * @param thresholdSummary formatted threshold clause (e.g. {@code "n >= 256"}), if a numeric arg was bisected
     * @param thresholdValue   numeric threshold value, or {@code null}
     */
    public record NumericBisectionResult(
            List<EpisodeAction> minimizedActions,
            Optional<String> thresholdSummary,
            Number thresholdValue
    ) {
        public NumericBisectionResult {
            minimizedActions = minimizedActions == null ? List.of() : List.copyOf(minimizedActions);
            thresholdSummary = thresholdSummary == null ? Optional.empty() : thresholdSummary;
        }
    }

    /**
     * Zeller's delta debugging ({@code ddmin}): computes a 1-minimal sublist (preserving order)
     * for which {@code test.test(candidate)} still holds.
     *
     * @param items initial failing sequence
     * @param test  reproduction predicate (assumed to hold on {@code items})
     * @param <T>   element type
     * @return immutable 1-minimal sublist
     */
    public static <T> List<T> ddmin(List<T> items, Predicate<List<T>> test) {
        Objects.requireNonNull(items, "items");
        Objects.requireNonNull(test, "test");
        if (items.size() <= 1) {
            return List.copyOf(items);
        }

        Map<List<T>, Boolean> memo = new LinkedHashMap<>();
        Predicate<List<T>> cachedTest = candidate -> {
            List<T> key = List.copyOf(candidate);
            Boolean prev = memo.get(key);
            if (prev != null) {
                return prev;
            }
            boolean result = test.test(key);
            memo.put(key, result);
            return result;
        };

        List<T> cur = new ArrayList<>(items);
        int n = 2;
        while (cur.size() >= 2) {
            int size = Math.max(1, cur.size() / n);
            List<List<T>> chunks = new ArrayList<>();
            for (int i = 0; i < cur.size(); i += size) {
                chunks.add(new ArrayList<>(cur.subList(i, Math.min(cur.size(), i + size))));
            }

            boolean reducedToChunk = false;
            for (List<T> chunk : chunks) {
                if (chunk.size() < cur.size() && cachedTest.test(chunk)) {
                    cur = chunk;
                    n = 2;
                    reducedToChunk = true;
                    break;
                }
            }
            if (reducedToChunk) {
                continue;
            }

            boolean reducedToComplement = false;
            for (int i = 0; i < chunks.size(); i++) {
                List<T> complement = new ArrayList<>(cur.size());
                for (int j = 0; j < chunks.size(); j++) {
                    if (j != i) {
                        complement.addAll(chunks.get(j));
                    }
                }
                if (!complement.isEmpty() && cachedTest.test(complement)) {
                    cur = complement;
                    n = Math.max(n - 1, 2);
                    reducedToComplement = true;
                    break;
                }
            }
            if (reducedToComplement) {
                continue;
            }

            if (n >= cur.size()) {
                break;
            }
            n = Math.min(cur.size(), n * 2);
        }
        return Collections.unmodifiableList(cur);
    }

    /**
     * Binary-searches a numeric argument token in {@code actions} to isolate the minimal
     * reproducing value while enforcing {@code denylist} safety checks on every candidate command.
     *
     * @param actions      minimized or raw episode action sequence
     * @param node         optional target {@link CommandNode} providing argument name, parser, and bounds
     * @param tree         optional {@link CommandTree} for denylist and node resolution
     * @param denylist     optional {@link Denylist} (defaults to {@code tree} denylist or {@link CommandSurfaceAuditor#DEFAULT_DENYLIST})
     * @param passingValue optional known passing baseline value (defaults to {@code 0} or {@code 1} within bounds)
     * @param reproduces   predicate testing whether a candidate action trace still reproduces the finding
     * @return {@link NumericBisectionResult} with the bisected action trace and threshold summary
     */
    public static NumericBisectionResult bisectNumericArg(
            List<EpisodeAction> actions,
            CommandNode node,
            CommandTree tree,
            Denylist denylist,
            Number passingValue,
            Predicate<List<EpisodeAction>> reproduces
    ) {
        Objects.requireNonNull(reproduces, "reproduces");
        if (actions == null || actions.isEmpty()) {
            return new NumericBisectionResult(List.of(), Optional.empty(), null);
        }
        List<EpisodeAction> baseActions = List.copyOf(actions);
        Denylist activeDeny = denylist != null
                ? denylist
                : (tree != null && !tree.denylistEntries().isEmpty()
                        ? new Denylist(tree.denylistEntries())
                        : new Denylist(CommandSurfaceAuditor.DEFAULT_DENYLIST));

        CommandNode argNode = resolveNumericArgNode(node, tree, baseActions);
        if (argNode != null && argNode.denied()) {
            return new NumericBisectionResult(baseActions, Optional.empty(), null);
        }

        int targetActionIdx = -1;
        int targetTokenIdx = -1;
        boolean leadingSlash = false;
        List<String> cmdTokens = List.of();
        Double parsedFail = null;
        boolean tokenHasDecimal = false;

        int expectedTokenIdx = computeExpectedNumericTokenIndex(argNode, tree);

        for (int aIdx = 0; aIdx < baseActions.size(); aIdx++) {
            String rawCmd = baseActions.get(aIdx).commandLine();
            if (rawCmd == null || rawCmd.isBlank()) {
                continue;
            }
            boolean hasSlash = rawCmd.startsWith("/");
            String clean = hasSlash ? rawCmd.substring(1).trim() : rawCmd.trim();
            String[] split = clean.split("\\s+");
            if (split.length < 2) {
                continue;
            }
            int chosenTok = -1;
            if (expectedTokenIdx > 0 && expectedTokenIdx < split.length && parseNumericToken(split[expectedTokenIdx]) != null) {
                chosenTok = expectedTokenIdx;
            } else {
                for (int tIdx = split.length - 1; tIdx >= 1; tIdx--) {
                    if (parseNumericToken(split[tIdx]) != null) {
                        chosenTok = tIdx;
                        break;
                    }
                }
            }
            if (chosenTok > 0) {
                targetActionIdx = aIdx;
                targetTokenIdx = chosenTok;
                leadingSlash = hasSlash;
                cmdTokens = List.of(split);
                String tokStr = split[chosenTok];
                parsedFail = parseNumericToken(tokStr);
                tokenHasDecimal = tokStr.contains(".");
                break;
            }
        }

        if (targetActionIdx < 0 || targetTokenIdx <= 0 || parsedFail == null) {
            return new NumericBisectionResult(baseActions, Optional.empty(), null);
        }

        String origCmd = (leadingSlash ? "/" : "") + String.join(" ", cmdTokens);
        if (activeDeny.isDeniedCommandLine(origCmd, tree)) {
            return new NumericBisectionResult(baseActions, Optional.empty(), null);
        }

        String parserKind = argNode != null
                ? CommandSurfaceAuditor.normalizeParserKind(argNode.parser())
                : (tokenHasDecimal ? "double" : "integer");
        boolean isFloat = "float".equals(parserKind) || "double".equals(parserKind);
        String paramName = resolveParamName(argNode, targetTokenIdx, cmdTokens);
        Map<String, Object> props = argNode != null ? argNode.properties() : Map.of();

        final int actionIndex = targetActionIdx;
        final int tokenIndex = targetTokenIdx;
        final boolean slashPrefix = leadingSlash;
        final List<String> baseCmdTokens = cmdTokens;

        if (isFloat) {
            double failF = parsedFail;
            double loF = extractDoubleProp(props, "min", Math.min(0.0, failF));
            double passF;
            if (passingValue != null) {
                passF = passingValue.doubleValue();
            } else if (loF <= 1.0 && 1.0 <= failF) {
                passF = Math.max(loF, loF >= 1.0 ? 1.0 : 0.0);
            } else {
                passF = loF;
            }

            if (Math.abs(failF - passF) <= 1e-9) {
                String tok = NumericBoundaryLadder.formatDoubleToken(failF);
                return new NumericBisectionResult(baseActions, Optional.of(paramName + " >= " + tok), failF);
            }

            List<EpisodeAction> passCandidate = substituteValue(
                    baseActions, actionIndex, tokenIndex, slashPrefix, baseCmdTokens,
                    NumericBoundaryLadder.formatDoubleToken(passF)
            );
            String passCmd = passCandidate.get(actionIndex).commandLine();
            if (!activeDeny.isDeniedCommandLine(passCmd, tree) && reproduces.test(passCandidate)) {
                String tok = NumericBoundaryLadder.formatDoubleToken(passF);
                return new NumericBisectionResult(passCandidate, Optional.of(paramName + " >= " + tok), passF);
            }

            double lowF = Math.min(passF, failF);
            double highF = Math.max(passF, failF);
            double bestF = failF;
            List<EpisodeAction> bestTrace = baseActions;

            for (int step = 0; step < FLOAT_BISECTION_STEPS; step++) {
                double midF = Math.round(((lowF + highF) / 2.0) * 10_000.0) / 10_000.0;
                if (Math.abs(midF - lowF) <= 1e-6 || Math.abs(midF - highF) <= 1e-6) {
                    break;
                }
                List<EpisodeAction> cand = substituteValue(
                        baseActions, actionIndex, tokenIndex, slashPrefix, baseCmdTokens,
                        NumericBoundaryLadder.formatDoubleToken(midF)
                );
                String candCmd = cand.get(actionIndex).commandLine();
                boolean ok = !activeDeny.isDeniedCommandLine(candCmd, tree) && reproduces.test(cand);
                if (failF >= passF) {
                    if (ok) {
                        bestF = midF;
                        bestTrace = cand;
                        highF = midF;
                    } else {
                        lowF = midF;
                    }
                } else {
                    if (ok) {
                        bestF = midF;
                        bestTrace = cand;
                        lowF = midF;
                    } else {
                        highF = midF;
                    }
                }
            }
            String op = failF >= passF ? ">=" : "<=";
            String formatted = NumericBoundaryLadder.formatDoubleToken(bestF);
            return new NumericBisectionResult(bestTrace, Optional.of(paramName + " " + op + " " + formatted), bestF);
        }

        int failI = (int) Math.round(parsedFail);
        int loI = extractIntProp(props, "min", Math.min(0, failI));
        int passI;
        if (passingValue != null) {
            passI = (int) Math.round(passingValue.doubleValue());
        } else if (loI <= 1 && 1 <= failI) {
            passI = Math.max(loI, loI >= 1 ? 1 : 0);
        } else {
            passI = loI;
        }

        if (failI == passI) {
            return new NumericBisectionResult(baseActions, Optional.of(paramName + " >= " + failI), failI);
        }

        Map<Integer, Boolean> intMemo = new LinkedHashMap<>();
        Map<Integer, List<EpisodeAction>> traceMemo = new LinkedHashMap<>();

        Predicate<Integer> evalInt = val -> {
            Boolean cached = intMemo.get(val);
            if (cached != null) {
                return cached;
            }
            List<EpisodeAction> cand = substituteValue(
                    baseActions, actionIndex, tokenIndex, slashPrefix, baseCmdTokens,
                    Integer.toString(val)
            );
            traceMemo.put(val, cand);
            String candCmd = cand.get(actionIndex).commandLine();
            if (activeDeny.isDeniedCommandLine(candCmd, tree)) {
                intMemo.put(val, false);
                return false;
            }
            boolean ok = reproduces.test(cand);
            intMemo.put(val, ok);
            return ok;
        };

        if (evalInt.test(passI)) {
            return new NumericBisectionResult(
                    traceMemo.getOrDefault(passI, baseActions),
                    Optional.of(paramName + " >= " + passI),
                    passI
            );
        }

        int bestI = failI;
        List<EpisodeAction> bestTrace = substituteValue(
                baseActions, actionIndex, tokenIndex, slashPrefix, baseCmdTokens,
                Integer.toString(failI)
        );

        if (failI > passI) {
            int low = passI + 1;
            int high = failI;
            while (low <= high) {
                int mid = low + ((high - low) >>> 1);
                if (evalInt.test(mid)) {
                    bestI = mid;
                    bestTrace = traceMemo.getOrDefault(mid, bestTrace);
                    high = mid - 1;
                } else {
                    low = mid + 1;
                }
            }
            return new NumericBisectionResult(bestTrace, Optional.of(paramName + " >= " + bestI), bestI);
        } else {
            int low = failI;
            int high = passI - 1;
            while (low <= high) {
                int mid = low + ((high - low) >>> 1);
                if (evalInt.test(mid)) {
                    bestI = mid;
                    bestTrace = traceMemo.getOrDefault(mid, bestTrace);
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }
            return new NumericBisectionResult(bestTrace, Optional.of(paramName + " <= " + bestI), bestI);
        }
    }

    private static List<EpisodeAction> substituteValue(
            List<EpisodeAction> baseActions,
            int targetActionIdx,
            int targetTokenIdx,
            boolean slashPrefix,
            List<String> baseCmdTokens,
            String formattedValue
    ) {
        List<String> updatedTokens = new ArrayList<>(baseCmdTokens);
        updatedTokens.set(targetTokenIdx, formattedValue);
        String newCmd = (slashPrefix ? "/" : "") + String.join(" ", updatedTokens);

        String rootLower = baseCmdTokens.get(0).toLowerCase(Locale.ROOT);
        List<EpisodeAction> out = new ArrayList<>(baseActions.size());
        for (int i = 0; i < baseActions.size(); i++) {
            EpisodeAction act = baseActions.get(i);
            if (i == targetActionIdx) {
                out.add(act.withCommandLine(newCmd));
            } else {
                String rc = act.commandLine();
                boolean hs = rc.startsWith("/");
                String clean = hs ? rc.substring(1).trim() : rc.trim();
                String[] ct = clean.isEmpty() ? new String[0] : clean.split("\\s+");
                if (ct.length > targetTokenIdx
                        && ct[0].toLowerCase(Locale.ROOT).equals(rootLower)
                        && parseNumericToken(ct[targetTokenIdx]) != null) {
                    ct[targetTokenIdx] = formattedValue;
                    out.add(act.withCommandLine((hs ? "/" : "") + String.join(" ", ct)));
                } else {
                    out.add(act);
                }
            }
        }
        return Collections.unmodifiableList(out);
    }

    private static CommandNode resolveNumericArgNode(
            CommandNode node,
            CommandTree tree,
            List<EpisodeAction> actions
    ) {
        if (node != null && "argument".equals(node.kind())) {
            return node;
        }
        if (node != null && tree != null) {
            for (String childId : node.children()) {
                CommandNode child = tree.nodes().get(childId);
                if (child != null && "argument".equals(child.kind())) {
                    return child;
                }
            }
        }
        if (tree != null) {
            for (EpisodeAction act : actions) {
                if (act.nodeId() != null) {
                    CommandNode byId = tree.nodes().get(act.nodeId());
                    if (byId != null) {
                        return byId;
                    }
                }
            }
        }
        return node;
    }

    private static int computeExpectedNumericTokenIndex(CommandNode argNode, CommandTree tree) {
        if (argNode == null) {
            return -1;
        }
        if (!argNode.steps().isEmpty()) {
            for (int i = argNode.steps().size() - 1; i >= 0; i--) {
                if ("argument".equals(argNode.steps().get(i).kind())) {
                    return i + 1;
                }
            }
            return argNode.steps().size();
        }
        String[] parts = argNode.nodeId().trim().split("\\s+");
        for (int i = parts.length - 1; i >= 1; i--) {
            if (parts[i].startsWith("<") && parts[i].endsWith(">")) {
                return i;
            }
        }
        return parts.length > 1 ? parts.length - 1 : -1;
    }

    private static String resolveParamName(CommandNode argNode, int targetTokenIdx, List<String> cmdTokens) {
        if (argNode != null) {
            if ("argument".equals(argNode.kind()) && argNode.name() != null && !argNode.name().isBlank()) {
                return stripAngleBrackets(argNode.name());
            }
            int stepIdx = targetTokenIdx - 1;
            if (stepIdx >= 0 && stepIdx < argNode.steps().size()) {
                String stepName = argNode.steps().get(stepIdx).name();
                if (stepName != null && !stepName.isBlank()) {
                    return stripAngleBrackets(stepName);
                }
            }
            String[] nodeParts = argNode.nodeId().trim().split("\\s+");
            if (targetTokenIdx >= 1 && targetTokenIdx < nodeParts.length) {
                String tok = stripAngleBrackets(nodeParts[targetTokenIdx]);
                if (!tok.isEmpty()) {
                    return tok;
                }
            }
        }
        if (targetTokenIdx >= 2 && targetTokenIdx - 1 < cmdTokens.size()) {
            String prev = cmdTokens.get(targetTokenIdx - 1);
            if (parseNumericToken(prev) == null) {
                return stripAngleBrackets(prev);
            }
        }
        return "value";
    }

    private static String stripAngleBrackets(String raw) {
        if (raw == null) {
            return "value";
        }
        String s = raw.trim();
        while (s.startsWith("<")) {
            s = s.substring(1).trim();
        }
        while (s.endsWith(">")) {
            s = s.substring(0, s.length() - 1).trim();
        }
        return s.isEmpty() ? "value" : s;
    }

    private static Double parseNumericToken(String token) {
        if (token == null || token.isBlank()) {
            return null;
        }
        try {
            double d = Double.parseDouble(token.trim());
            return Double.isFinite(d) ? d : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static int extractIntProp(Map<String, Object> props, String key, int defaultValue) {
        if (props == null || !props.containsKey(key)) {
            return defaultValue;
        }
        Object v = props.get(key);
        if (v instanceof Number n) {
            return n.intValue();
        }
        if (v instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    private static double extractDoubleProp(Map<String, Object> props, String key, double defaultValue) {
        if (props == null || !props.containsKey(key)) {
            return defaultValue;
        }
        Object v = props.get(key);
        if (v instanceof Number n) {
            double d = n.doubleValue();
            return Double.isFinite(d) ? d : defaultValue;
        }
        if (v instanceof String s) {
            try {
                double d = Double.parseDouble(s.trim());
                return Double.isFinite(d) ? d : defaultValue;
            } catch (NumberFormatException ignored) {
                return defaultValue;
            }
        }
        return defaultValue;
    }
}
