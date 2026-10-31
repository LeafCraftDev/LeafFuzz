package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.CommandSurfaceAuditor.CommandNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Deterministic numeric boundary and magnitude ladder generator producing deduplicated, sorted
 * probe values across {@code [min, -1, 0, 1, 16, 64, 256, 1024, min(max, cap), max]}
 * ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * <p>Used during automated QA calibration episodes to exercise integer and floating-point command
 * arguments across zero, negative, power-of-two, and boundary extremes before binary bisection.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-004
 */
public final class NumericBoundaryLadder {

    /** Default magnitude cap applied before the upper bound extreme ({@code 4096}). */
    public static final int DEFAULT_CAP = 4096;

    /** Canonical base interior ladder points ({@code [-1, 0, 1, 16, 64, 256, 1024]}). */
    public static final List<Integer> BASE_LADDER_POINTS = List.of(-1, 0, 1, 16, 64, 256, 1024);

    private NumericBoundaryLadder() {
    }

    /**
     * Generates a sorted, deduplicated integer boundary ladder clamped to {@code [min, max]}
     * with default cap {@link #DEFAULT_CAP}.
     *
     * @param min optional lower bound (defaults to {@link Integer#MIN_VALUE})
     * @param max optional upper bound (defaults to {@link Integer#MAX_VALUE})
     * @return immutable sorted list of integer probe points
     */
    public static List<Integer> integerLadder(Integer min, Integer max) {
        return integerLadder(min, max, DEFAULT_CAP);
    }

    /**
     * Generates a sorted, deduplicated integer boundary ladder clamped to {@code [min, max]}.
     *
     * @param min optional lower bound (defaults to {@link Integer#MIN_VALUE})
     * @param max optional upper bound (defaults to {@link Integer#MAX_VALUE})
     * @param cap magnitude cap point included when within {@code [min, max]}
     * @return immutable sorted list of integer probe points
     */
    public static List<Integer> integerLadder(Integer min, Integer max, int cap) {
        int effMin = min != null ? min : Integer.MIN_VALUE;
        int effMax = max != null ? max : Integer.MAX_VALUE;
        if (effMin > effMax) {
            int tmp = effMin;
            effMin = effMax;
            effMax = tmp;
        }
        int clampedCap = Math.min(effMax, Math.max(effMin, cap));
        Set<Integer> sorted = new TreeSet<>();
        sorted.add(effMin);
        for (int p : BASE_LADDER_POINTS) {
            if (p >= effMin && p <= effMax) {
                sorted.add(p);
            }
        }
        if (clampedCap >= effMin && clampedCap <= effMax) {
            sorted.add(clampedCap);
        }
        sorted.add(effMax);
        return Collections.unmodifiableList(new ArrayList<>(sorted));
    }

    /**
     * Generates a sorted, deduplicated floating-point boundary ladder clamped to {@code [min, max]}.
     *
     * @param min optional lower bound (defaults to {@code -cap})
     * @param max optional upper bound (defaults to {@code +cap})
     * @param cap magnitude cap point
     * @return immutable sorted list of double probe points
     */
    public static List<Double> doubleLadder(Double min, Double max, double cap) {
        double effCap = (Double.isFinite(cap) && cap > 0.0) ? cap : DEFAULT_CAP;
        double effMin = (min != null && Double.isFinite(min)) ? min : -effCap;
        double effMax = (max != null && Double.isFinite(max)) ? max : effCap;
        if (effMin > effMax) {
            double tmp = effMin;
            effMin = effMax;
            effMax = tmp;
        }
        double clampedCap = Math.min(effMax, Math.max(effMin, effCap));
        List<Double> raw = new ArrayList<>();
        raw.add(effMin);
        for (int p : BASE_LADDER_POINTS) {
            raw.add((double) p);
        }
        raw.add(clampedCap);
        raw.add(effMax);
        Collections.sort(raw);

        Set<Double> dedup = new LinkedHashSet<>();
        for (double val : raw) {
            if (val >= effMin - 1e-9 && val <= effMax + 1e-9) {
                double clamped = Math.min(effMax, Math.max(effMin, Math.round(val * 1_000_000.0) / 1_000_000.0));
                if (clamped == -0.0) {
                    clamped = 0.0;
                }
                dedup.add(clamped);
            }
        }
        return Collections.unmodifiableList(new ArrayList<>(dedup));
    }

    /**
     * Extracts formatted string candidate values for a command argument node from its parser
     * and properties map.
     *
     * @param node command node
     * @return immutable list of candidate argument tokens
     */
    public static List<String> candidateTokensForNode(CommandNode node) {
        if (node == null) {
            return List.of("1");
        }
        String kind = CommandSurfaceAuditor.normalizeParserKind(node.parser());
        Map<String, Object> props = node.properties();
        if ("float".equals(kind) || "double".equals(kind)) {
            Double lo = extractDoubleProp(props, "min");
            Double hi = extractDoubleProp(props, "max");
            List<Double> vals = doubleLadder(lo, hi, DEFAULT_CAP);
            List<String> out = new ArrayList<>(vals.size());
            for (double d : vals) {
                out.add(formatDoubleToken(d));
            }
            return Collections.unmodifiableList(out);
        }
        if ("integer".equals(kind) || "long".equals(kind) || "time".equals(kind)) {
            Integer lo = extractIntProp(props, "min");
            Integer hi = extractIntProp(props, "max");
            List<Integer> vals = integerLadder(lo, hi, DEFAULT_CAP);
            List<String> out = new ArrayList<>(vals.size());
            for (int v : vals) {
                out.add(Integer.toString(v));
            }
            return Collections.unmodifiableList(out);
        }
        if ("bool".equals(kind)) {
            return List.of("true", "false");
        }
        if ("dimension".equals(kind) || "world".equals(kind)) {
            return List.of("world", "world_nether", "world_the_end", "invalid_world_fuzz");
        }
        if ("game_profile".equals(kind) || "entity".equals(kind) || "player".equals(kind)) {
            return List.of("SleuthBot", "@p", "Notch", "invalid_player_fuzz");
        }
        if ("uuid".equals(kind)) {
            return List.of("00000000-0000-0000-0000-000000000000", "invalid-uuid-fuzz");
        }
        if ("item_stack".equals(kind) || "block_state".equals(kind)) {
            return List.of("stone", "diamond_sword", "air", "invalid_material_fuzz");
        }
        return List.of("1", "16", "64", "256", "1024");
    }

    /**
     * Formats a floating-point value cleanly for command argument substitution.
     *
     * @param value numeric value
     * @return formatted token
     */
    public static String formatDoubleToken(double value) {
        double rounded = Math.round(value * 10_000.0) / 10_000.0;
        if (Math.abs(rounded - Math.rint(rounded)) < 1e-9) {
            return String.format(Locale.ROOT, "%.1f", rounded);
        }
        String s = Double.toString(rounded);
        return s;
    }

    private static Integer extractIntProp(Map<String, Object> props, String key) {
        if (props == null || !props.containsKey(key)) {
            return null;
        }
        Object v = props.get(key);
        if (v instanceof Number n) {
            long l = n.longValue();
            if (l < Integer.MIN_VALUE) {
                return Integer.MIN_VALUE;
            }
            if (l > Integer.MAX_VALUE) {
                return Integer.MAX_VALUE;
            }
            return (int) l;
        }
        if (v instanceof String s) {
            try {
                return Integer.parseInt(s.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static Double extractDoubleProp(Map<String, Object> props, String key) {
        if (props == null || !props.containsKey(key)) {
            return null;
        }
        Object v = props.get(key);
        if (v instanceof Number n) {
            double d = n.doubleValue();
            return Double.isFinite(d) ? d : null;
        }
        if (v instanceof String s) {
            try {
                double d = Double.parseDouble(s.trim());
                return Double.isFinite(d) ? d : null;
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }
}
