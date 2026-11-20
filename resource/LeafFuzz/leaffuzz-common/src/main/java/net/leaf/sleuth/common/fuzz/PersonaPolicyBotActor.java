package net.leaf.sleuth.common.fuzz;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * In-JVM synthetic persona bot actor and 256-byte {@code Int8[16x16]} policy genome evaluator
 * ({@code ADR-125}, {@code leaffuzz-ADR-001}, {@code leafsleuth-ADR-002}, {@code leafsleuth-ADR-006}).
 *
 * <p>Consumes a portable {@link PersonaProfile} ({@code sleuth_persona_v1} Amiibo-style
 * behavioral genome) and supports both:
 * <ul>
 *   <li><b>Autonomous Policy Mode:</b> Evaluates the 256-byte {@code Int8[16x16]} policy matrix
 *       against the 16-feature {@code Int8} state context vector using Q10 fixed-point base-2
 *       softmax ({@link #selectPolicyActionInt}) to step through {@link #POLICY_MICRO_SKILLS}
 *       ({@code rtp_or_anchor}, {@code step_toward_anchor}, {@code step_away_anchor},
 *       {@code harvest_nearest}, {@code craft_basics}, {@code interact_nearest},
 *       {@code deposit_or_trade}, etc.) and build realistic player state preconditions.</li>
 *   <li><b>Directed Fuzzer Manipulation Mode:</b> Executes fuzzed command lines as a synthetic
 *       player in either {@code default} or {@code op} permission tier, rewrites aliases when
 *       applicable, and drives lifecycle/spatial follow-up behaviors ({@code quit_lt1s},
 *       {@code quit_delay}, {@code move}, {@code chunk_border_thrash}, {@code window_click},
 *       {@code repeat}, {@code concurrent}).</li>
 * </ul>
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leaffuzz-ADR-001
 * @governedBy leafsleuth-ADR-002
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-BIO-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-005
 */
public final class PersonaPolicyBotActor {

    /** Number of signed 8-bit state features in the policy context vector. */
    public static final int POLICY_NUM_FEATURES = 16;

    /** Number of compositional gameplay micro-skills in the policy action space. */
    public static final int POLICY_NUM_ACTIONS = 16;

    /** Byte length of the flattened {@code Int8[16x16]} policy weight matrix. */
    public static final int POLICY_WEIGHT_BYTES = POLICY_NUM_FEATURES * POLICY_NUM_ACTIONS;

    /** Canonical 16 local state/inventory feature names for the {@code Int8[16]} context vector. */
    public static final List<String> POLICY_FEATURE_NAMES = List.of(
            "bias",
            "enclosed_horiz",
            "roof_cover",
            "floor_solid",
            "light_deficit",
            "depth_norm",
            "inv_building",
            "inv_wood_raw",
            "inv_torches",
            "inv_functional",
            "inv_ores_val",
            "near_log_or_ore",
            "near_container",
            "anchor_dist",
            "stalled_steps",
            "trait_role"
    );

    /** Canonical 16 compositional gameplay micro-skills evaluated by the 256-byte policy genome. */
    public static final List<String> POLICY_MICRO_SKILLS = List.of(
            "noop_wait",
            "rtp_or_anchor",
            "step_toward_anchor",
            "step_away_anchor",
            "harvest_nearest",
            "dig_stair_down",
            "dig_tunnel_fwd",
            "craft_basics",
            "place_wall_ring",
            "place_roof_cell",
            "place_pillar_or_bridge",
            "place_torch_if_dark",
            "place_utility",
            "place_redstone_link",
            "interact_nearest",
            "deposit_or_trade"
    );

    /** 16-entry Q10 fixed-point fractional {@code 2^(r/16)} lookup table ({@code 1024..1961}). */
    private static final int[] EXP2_FRAC_LUT = {
            1024, 1070, 1117, 1166, 1218, 1272, 1328, 1387,
            1448, 1512, 1579, 1649, 1722, 1798, 1878, 1961
    };

    /** Prebaked 256-byte {@code Int8[16x16]} policy genomes trained via cross-entropy method. */
    public static final Map<String, String> PREBAKED_POLICY_BASE64 = Map.of(
            "house", "6v/69Prw9/z//fkIBf36+wb5/wH4Aev/9P0F/wP//AD8/Pf+A//5BQYE+gEHJAP8+wIGCvD89Pv+DgH+BQHzAhUB+ff39Pz6CAEBNfL89/fs/vX++AYH+vwG/QH78AL6/P0ADwIH+fQGCgUA+QH8BfUE8vwGBQEl9PcC+v/89AML//bx+wgtA/oDB/n5+AL5/jH6///6Lfb49/D9/f37+/cE8vz89/78AQHzDQT7APkCB/79I/sH+h7//fYJ+wj/BgX+AggF9vn1PgP9/u77/PD7AAL3CwX0CQLw+AMECwIEAAD8//YB+Pz/9vsL9+8J9AEFDAT3APkBAPb5/P/3+A==",
            "mineshaft", "BQPxA+74+vUA+v74/f/3+w/1/gMF+/4H9P/u9gb4CPv5APT5Bv/8Afn9K/v+LfYH/vn8/wH++/wBBwD4AAf8//cFAPT8JQECAQL5I/X+/fof/+8K+Qf5+/MJAv3vAPL59foDBgci//72Bvj4AgH7+/z3+u35AQElAvoi+PoF+QL4//Xy/AL7B/0D+gkE/ggH/gUGCgT8+PQH+/YEAf/6CPv89fUA+AH5//T5A/X+9fwD/v0FIgv98hr5+vj49/oD9/P39/n0+/YDBAYD9v0G//kHAfb6/f77AQPv/gD+Dfr5/fYG++/qBA32+P0F/PwIBAIE8QX7A/UC8/36+QUB+w==",
            "caving", "9QL7Be36+PXzAPb2+gX78gbt+gb0//AB9An0///2CwP8AvcEBgL/AAAE/+sCJ/gH9fj9AQ0G/wL7Bfzt/v7/+/72/vX7K/gJCAH5I/L+7vEO9f0AAf33BPUA9Pj87/0GJ//+APMp+Qf+//4I+gXu8/bq+/UM/gYn9P0x/vsE9QIE9xH69AQF/vH0+v0ABP8I//0F+AkE+/3+BvQB/AMAA/z7+P348hQF/AEB8PT69fj98QABGvz/BR779AH+9/r9+uj/8AT0Bv0CAf7x+gX9+/H7+/vxA/vzA//8/vz1Avz6/gL98/b2AP3u+QL78AL//f/88vn5/AL0+wT88Qf49w==",
            "villager", "+v/+//r69PnxDQL46PwFAAH2BQLuA/kGA/v6BfQA/wL1+fz7+f/6//sL9QD6IO7w/QIIBQL99woM/fkDAPEB+AD+/Q39AvsIBgD1LQsB8/8F9wX8AP3sCAAK9fkA/PcLBfoJCAMA//wAAAP99gjxAvD3/v0A+vU29P8N+vj7AgT++AcH/vgA/wDw/wT9//j0+fX4Cvz6BwP5/PL4/fIE8uz1/wD4+PkHAPkB8wX7///19wD/I/b5BB/9/v8C9/oL//8B9fsAAwf7LfH9DQPwBfn1/fT4Bv/5Cfv/Bfj8//gEAPX49uz//ez1+PUv8wL+AQDu/ff58/kE/wEHMwb7Ag==",
            "shop", "CAPw//359QkB/vgHA////Qb8/AUI/QADAfkHAv3///wB/QDw+vj9AwX79gP6G/P49fkDDfgI8v8DAv7+AP/1/wL+9/8E/AH7FAj4MgL+9uL/8/3/BAH0/v0HBgT3+/v79fMNAv769foLCwj4/Av//gH6/fsC9vUs+gL3/QD8+v0AAPkD/fkBAPv99AT8AfsC9wL7//r1AgL/9fb9AvYA+/f7B/UI+f/9+/v7DP/89wAD9PwCMPn+AST/BfYEAQEPEQL8/fD29Ab8NAkG/P34AP7xCPQB/vn+BAXx//r+BvgMBwID/fnz/Or/9/4KAPYu/wADBgEBBQUF+P8AKgDzBw==",
            "machine", "APn4/QD49vv8//v+BAYD/An5Afz2/PkECAYFBgMC//kAAPzzBgEFBwn8+v35KAMH+PwGB/MFAwL/AfTy/gXuAib/7O8BAgH/Bvz8K/7r/AXwB/UBAAEBBQbr/wQI8v8U9AH8/vj79fj8EAoF8gL///b9+gj8Av0b9f0F/gb9+/4JBQIB/vUKBv8C/Pn/AfwABQ0F+P399/X6CfsG+vn+Bf8I/P/0+vj8APr7AfD+Cf33/AXzI+8JAh72+/b9Av7z9Af1AwH7Bfr6CP/88/j+9yvyBBADBPb6BAQA+v0BDfsD/wEI//f//AT3AwEpAgcCBvoL8wQE/ff9BfUE+gn2+A==",
            "explorer", "9v36+/wD8vz8D/X//QQC/hb9Bvrs//sG/+cD/gEBAAL9A/X3Af7+/wD6/gb6GezxIgIMBvcA+QYF/v//Afj5A/oC9AQA8fn++wD1KgH69AX19/r8Af/3C/8F+fz//fwB+/77C/wF/gf8CgL89AH6AfIB+v73/vQn9ggu/gL+BPcAAf/4A/jy+/r//gL4+fUD+Qj4CQHxCgH89PX9/Pj8+/P///0C+gQA9AH+/wf9+fr1/QAAIvID/CL8Af8J8vELCQYC9PEE9AP/AwDzCPv5AvXvAfb4BPrz/vb/Bvv3AfgFAP8A/fgE/O4C8/8AMfb9/fzv/PT19QEE+fX9ASz9+g==",
            "diamond", "9AH1/fz39foA+//89vQB/f/4/fX5/wEK+P0E8/gG/gP/9gH9+PcG8/f7+O/yKAT7DgH19v74/QHxAf3xAPz/NATy+/b0+f74BgP7MgQEAgUD8fgACP7yAQH3+QT2Bv7A/fv+8fsx+f74+fr8+frvq/cA+fz0+wMsAQQ+/fz8Afvz9fzuBP/6BPz6+wH7BwL2+/X7BPP7//z6APoLAAf6DgLy9/QHBwL9/PgD+AEL/vb9AQHyJ/z5BSX19gL88/H9/v398v75BQPxJwb8/P3+7ADz9fv76wL+CP/8/wHpAQH+//v7Afz1/PUD9/gF//86/vz68vr69fcH/AL0Jv78QA=="
    );

    private static final int[][] CARDINAL_DIRS = {
            {1, 0},
            {0, 1},
            {-1, 0},
            {0, -1}
    };

    private static final int[] HUMAN_CADENCE_JITTER_PCT = {-26, 24, -18, 28, -22, 16, -14, 12};

    private static final Pattern JSON_STRING_FIELD = Pattern.compile("\"([a-zA-Z0-9_]+)\"\\s*:\\s*\"([^\"]*)\"");
    private static final Pattern JSON_NUMBER_FIELD = Pattern.compile("\"([a-zA-Z0-9_]+)\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");
    private static final Pattern JSON_BOOL_FIELD = Pattern.compile("\"([a-zA-Z0-9_]+)\"\\s*:\\s*(true|false)");

    /**
     * Portable generative persona profile and pretrained 256-byte {@code Int8[16x16]} policy
     * genome ({@code sleuth_persona_v1}).
     *
     * @param accountId               player UUID
     * @param playerName              player display name
     * @param banned                  whether the account is marked banned
     * @param expectedSolver          classified camera look solver regime
     * @param mouseGcdDeg             primary mouse sensitivity GCD step in degrees
     * @param turnJerkDeg             mean angular jerk in degrees/tick^2
     * @param angularSpeedDeg         mean angular turn speed in degrees/tick
     * @param clickMeanMs             mean inter-click interval in milliseconds
     * @param clickCv                 click interval coefficient of variation
     * @param physCountsPerTick       median physical mouse counts per tick
     * @param pathCurvature           mean 2D camera path curvature
     * @param pitchYawAnisotropy      pitch-to-yaw rotation anisotropy ratio
     * @param turnWhileRunningRate    fraction of turns executed while sprinting/running
     * @param strafeTurnRate          fraction of running turns executed while strafing
     * @param airborneTurnRate        fraction of turns executed while airborne
     * @param fittsInterceptMs        2D Fitts's Law container click intercept in milliseconds
     * @param fittsSlopeMsPerBit      2D Fitts's Law container index-of-difficulty slope in ms/bit
     * @param wpmMean                 typing burst cadence mean in words per minute
     * @param wpmStd                  typing burst cadence standard deviation in words per minute
     * @param hotbarSlots             ordered dominant hotbar slot cycle (1..3 slots in {@code [0, 8]})
     * @param goalLoop                ordered dominant gameplay state loop
     * @param goalTransitions         flattened {@code 7x7} gameplay Markov transition matrix
     * @param chunkX                  representative visited chunk X coordinate
     * @param chunkZ                  representative visited chunk Z coordinate
     * @param preferredCommandAliases map from command family to preferred alias
     * @param taxonomyArchetype       dominant fuzzer player-taxonomy scenario archetype
     * @param taxonomyWeights         normalized probability weights over fuzzer scenario shapes
     * @param pretrainedPolicyWeights 256-byte {@code Int8[16x16]} policy weight matrix
     */
    public record PersonaProfile(
            UUID accountId,
            String playerName,
            boolean banned,
            String expectedSolver,
            double mouseGcdDeg,
            double turnJerkDeg,
            double angularSpeedDeg,
            double clickMeanMs,
            double clickCv,
            double physCountsPerTick,
            double pathCurvature,
            double pitchYawAnisotropy,
            double turnWhileRunningRate,
            double strafeTurnRate,
            double airborneTurnRate,
            double fittsInterceptMs,
            double fittsSlopeMsPerBit,
            double wpmMean,
            double wpmStd,
            List<Integer> hotbarSlots,
            List<String> goalLoop,
            long[] goalTransitions,
            int chunkX,
            int chunkZ,
            Map<String, String> preferredCommandAliases,
            String taxonomyArchetype,
            Map<String, Double> taxonomyWeights,
            byte[] pretrainedPolicyWeights
    ) {
        public PersonaProfile {
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(playerName, "playerName");
            Objects.requireNonNull(expectedSolver, "expectedSolver");
            hotbarSlots = (hotbarSlots == null || hotbarSlots.isEmpty()) ? List.of(0, 1, 2) : List.copyOf(hotbarSlots);
            goalLoop = (goalLoop == null || goalLoop.isEmpty())
                    ? List.of("MINING", "BUILDING", "CRAFTING")
                    : List.copyOf(goalLoop);
            goalTransitions = goalTransitions == null ? new long[49] : goalTransitions.clone();
            preferredCommandAliases = preferredCommandAliases == null
                    ? Map.of()
                    : Collections.unmodifiableMap(new LinkedHashMap<>(preferredCommandAliases));
            taxonomyArchetype = taxonomyArchetype == null ? "explorer_wander" : taxonomyArchetype;
            taxonomyWeights = taxonomyWeights == null
                    ? Map.of()
                    : Collections.unmodifiableMap(new LinkedHashMap<>(taxonomyWeights));
            pretrainedPolicyWeights = pretrainedPolicyWeights == null
                    ? new byte[POLICY_WEIGHT_BYTES]
                    : pretrainedPolicyWeights.clone();
        }

        @Override
        public long[] goalTransitions() {
            return goalTransitions.clone();
        }

        @Override
        public byte[] pretrainedPolicyWeights() {
            return pretrainedPolicyWeights.clone();
        }

        /** Returns the 256-byte {@code Int8[16x16]} pretrained policy weights encoded as Base64. */
        public String pretrainedPolicyBase64() {
            return Base64.getEncoder().encodeToString(pretrainedPolicyWeights);
        }

        /** Serializes this persona profile into a single-line JSON record ({@code sleuth_persona_v1}). */
        public String toJsonLine() {
            StringBuilder sb = new StringBuilder(1024);
            sb.append("{\"schema\":\"sleuth_persona_v1\"");
            sb.append(",\"account_id\":\"").append(accountId).append('"');
            sb.append(",\"id\":\"").append(escapeJson(playerName)).append('"');
            sb.append(",\"player_name\":\"").append(escapeJson(playerName)).append('"');
            sb.append(",\"banned\":").append(banned);
            sb.append(",\"expected_solver\":\"").append(escapeJson(expectedSolver)).append('"');
            sb.append(",\"mouse_gcd_deg\":").append(String.format(Locale.ROOT, "%.4f", mouseGcdDeg));
            sb.append(",\"turn_jerk_deg\":").append(String.format(Locale.ROOT, "%.4f", turnJerkDeg));
            sb.append(",\"angular_speed_deg\":").append(String.format(Locale.ROOT, "%.4f", angularSpeedDeg));
            sb.append(",\"click_mean_ms\":").append(String.format(Locale.ROOT, "%.2f", clickMeanMs));
            sb.append(",\"click_cv\":").append(String.format(Locale.ROOT, "%.4f", clickCv));
            sb.append(",\"phys_counts_per_tick\":").append(String.format(Locale.ROOT, "%.2f", physCountsPerTick));
            sb.append(",\"path_curvature\":").append(String.format(Locale.ROOT, "%.4f", pathCurvature));
            sb.append(",\"pitch_yaw_anisotropy\":").append(String.format(Locale.ROOT, "%.4f", pitchYawAnisotropy));
            sb.append(",\"turn_while_running_rate\":").append(String.format(Locale.ROOT, "%.4f", turnWhileRunningRate));
            sb.append(",\"strafe_turn_rate\":").append(String.format(Locale.ROOT, "%.4f", strafeTurnRate));
            sb.append(",\"airborne_turn_rate\":").append(String.format(Locale.ROOT, "%.4f", airborneTurnRate));
            sb.append(",\"fitts_intercept_ms\":").append(String.format(Locale.ROOT, "%.2f", fittsInterceptMs));
            sb.append(",\"fitts_slope_ms_per_bit\":").append(String.format(Locale.ROOT, "%.2f", fittsSlopeMsPerBit));
            sb.append(",\"wpm_mean\":").append(String.format(Locale.ROOT, "%.2f", wpmMean));
            sb.append(",\"wpm_std\":").append(String.format(Locale.ROOT, "%.2f", wpmStd));
            sb.append(",\"chunk_x\":").append(chunkX);
            sb.append(",\"chunk_z\":").append(chunkZ);
            sb.append(",\"taxonomy_archetype\":\"").append(escapeJson(taxonomyArchetype)).append('"');
            sb.append(",\"pretrained_policy_b64\":\"").append(pretrainedPolicyBase64()).append("\"}");
            return sb.toString();
        }

        private static String escapeJson(String s) {
            return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    /**
     * Outcome of a single autonomous or fuzzer-directed bot step.
     *
     * @param stepIndex       monotonic step index for this bot
     * @param selectedSkill   micro-skill or follow-up behavior executed
     * @param skillIndex      policy skill index in {@code [0, 15]} (or {@code -1} for direct follow-up)
     * @param x               updated block X coordinate
     * @param y               updated block Y coordinate
     * @param z               updated block Z coordinate
     * @param yawDeg          updated camera yaw in degrees
     * @param pitchDeg        updated camera pitch in degrees
     * @param hotbarSlot      selected hotbar slot in {@code [0, 8]}
     * @param clickDelayMs    cadence interval in milliseconds derived from persona biometrics
     * @param online          whether the synthetic bot remains online after the step
     */
      public record BotStepRecord(
              int stepIndex,
              String selectedSkill,
              int skillIndex,
              int x,
              int y,
              int z,
              float yawDeg,
              float pitchDeg,
              int hotbarSlot,
              int clickDelayMs,
              boolean online
      ) {
          /** Returns {@code true} if the selected micro-skill is a spatial exploration action. */
          public boolean isExplorationSkill() {
              if (selectedSkill == null) {
                  return false;
              }
              return switch (selectedSkill) {
                  case "rtp_or_anchor", "step_toward_anchor", "step_away_anchor" -> true;
                  default -> false;
              };
          }

          /** Returns {@code true} if the selected micro-skill breaks or mines blocks. */
          public boolean isMiningSkill() {
              if (selectedSkill == null) {
                  return false;
              }
              return switch (selectedSkill) {
                  case "harvest_nearest", "dig_stair_down", "dig_tunnel_fwd" -> true;
                  default -> false;
              };
          }

          /** Returns {@code true} if the selected micro-skill places construction or utility blocks. */
          public boolean isBuildingSkill() {
              if (selectedSkill == null) {
                  return false;
              }
              return switch (selectedSkill) {
                  case "place_wall_ring",
                          "place_roof_cell",
                          "place_pillar_or_bridge",
                          "place_torch_if_dark",
                          "place_utility",
                          "place_redstone_link" -> true;
                  default -> false;
              };
          }

          /** Returns {@code true} if the selected micro-skill mutates world blocks (mining or building). */
          public boolean isWorldMutationSkill() {
              return isMiningSkill() || isBuildingSkill();
          }

          /**
           * Returns the deterministic relative block offset {@code {dx, dy, dz}} targeted by this
           * step's mining or building micro-skill.
           */
          public int[] targetBlockOffset() {
              int ringIdx = Math.floorMod(stepIndex, RING_OFFSETS_12.length);
              int[] ring = RING_OFFSETS_12[ringIdx];
              if (selectedSkill == null) {
                  return new int[]{1, 0, 0};
              }
              return switch (selectedSkill) {
                  case "dig_stair_down" -> new int[]{ring[0], -1, ring[1]};
                  case "dig_tunnel_fwd", "harvest_nearest" -> new int[]{ring[0], 0, ring[1]};
                  case "place_roof_cell" -> new int[]{ring[0], 2, ring[1]};
                  case "place_pillar_or_bridge" -> new int[]{0, -1, 0};
                  default -> new int[]{ring[0], 0, ring[1]};
              };
          }
      }

      private static final int[][] RING_OFFSETS_12 = {
              {-2, -1}, {-2, 0}, {-2, 1},
              {2, -1}, {2, 0}, {2, 1},
              {-1, -2}, {0, -2}, {1, -2},
              {-1, 2}, {0, 2}, {1, 2}
      };

      private final PersonaProfile persona;
      private final String permissionTier;
      private final byte[] policyWeights;
      private final int initialSeed;
      private int rngState;

      private volatile int x;
      private volatile int y;
      private volatile int z;
      private int anchorX;
      private int anchorY;
      private int anchorZ;
      private volatile int yawIdx;
      private volatile float yawDeg;
      private volatile float pitchDeg;
      private int hotbarCursor;
      private volatile int currentHotbarSlot;
      private int stepCount;
      private int awayLegStep;
      private int awayLegLength = 2;
      private int awayTurnCount;
      private int stepsSinceProgress;
    private int rtpCount;
    private int logsCount;
    private int planksCount;
    private int cobbleCount;
    private int torchesCount;
    private int utilitiesCount;
    private int oresCount;
    private volatile boolean containerOpen;
    private volatile boolean online = true;
    private final Set<String> chunksExplored = new LinkedHashSet<>();
    private final List<BotStepRecord> stepHistory = new ArrayList<>();
    private final List<String> executedCommands = new ArrayList<>();

    /**
     * Creates a synthetic bot actor backed by {@code persona} and operating at {@code permissionTier}.
     *
     * @param persona        pretrained persona genome
     * @param permissionTier {@code "default"} or {@code "op"}
     * @param seed           deterministic PRNG seed
     */
    public PersonaPolicyBotActor(PersonaProfile persona, String permissionTier, int seed) {
        this.persona = Objects.requireNonNull(persona, "persona");
        this.permissionTier = (permissionTier == null || permissionTier.isBlank())
                ? "default"
                : permissionTier.trim().toLowerCase(Locale.ROOT);
        this.policyWeights = persona.pretrainedPolicyWeights();
        this.initialSeed = seed != 0 ? seed : (persona.accountId().hashCode() != 0 ? persona.accountId().hashCode() : 1337);
        this.rngState = this.initialSeed;
        this.x = persona.chunkX() << 4;
        this.y = 64;
        this.z = persona.chunkZ() << 4;
        this.anchorX = this.x;
        this.anchorY = this.y;
        this.anchorZ = this.z;
        this.currentHotbarSlot = persona.hotbarSlots().isEmpty() ? 0 : Math.floorMod(persona.hotbarSlots().get(0), 9);
        this.chunksExplored.add((this.x >> 4) + "," + (this.z >> 4));
    }

    /**
     * Evaluates the 256-byte {@code Int8[16x16]} policy matrix against the 16-byte {@code Int8[16]}
     * context vector using integer dot products and Q10 fixed-point base-2 LUT softmax.
     *
     * @param weightsInt8    256-byte {@code Int8[16x16]} policy weights
     * @param ctxInt8        16-byte {@code Int8[16]} context vector
     * @param tempShift      softmax temperature shift in {@code [4, 16]} (default {@code 10})
     * @param unsignedRandom 32-bit unsigned random draw (interpreted via {@code Integer.toUnsignedLong})
     * @param outLogits      optional {@code int[16]} buffer receiving raw dot-product logits
     * @return chosen action index in {@code [0, 15]}
     */
    public static int selectPolicyActionInt(
            byte[] weightsInt8,
            byte[] ctxInt8,
            int tempShift,
            int unsignedRandom,
            int[] outLogits
    ) {
        Objects.requireNonNull(weightsInt8, "weightsInt8");
        Objects.requireNonNull(ctxInt8, "ctxInt8");
        if (weightsInt8.length < POLICY_WEIGHT_BYTES) {
            throw new IllegalArgumentException("weightsInt8 must have 256 bytes, got " + weightsInt8.length);
        }
        if (ctxInt8.length < POLICY_NUM_FEATURES) {
            throw new IllegalArgumentException("ctxInt8 must have 16 bytes, got " + ctxInt8.length);
        }
        int[] logits = (outLogits != null && outLogits.length >= POLICY_NUM_ACTIONS)
                ? outLogits
                : new int[POLICY_NUM_ACTIONS];
        int shift = Math.max(4, Math.min(16, tempShift > 0 ? tempShift : 10));
        int maxLogit = Integer.MIN_VALUE / 2;

        for (int a = 0; a < POLICY_NUM_ACTIONS; a++) {
            int acc = 0;
            int row = a << 4;
            for (int f = 0; f < POLICY_NUM_FEATURES; f++) {
                acc += (int) weightsInt8[row + f] * (int) ctxInt8[f];
            }
            logits[a] = acc;
            if (acc > maxLogit) {
                maxLogit = acc;
            }
        }

        int[] weights = new int[POLICY_NUM_ACTIONS];
        long totalWeight = 0L;
        for (int a = 0; a < POLICY_NUM_ACTIONS; a++) {
            int diff = (logits[a] - maxLogit) >> (shift - 4);
            int w;
            if (diff <= -240) {
                w = 1;
            } else {
                int negDiff = Math.max(0, -diff);
                int oct = negDiff >> 4;
                int rem = negDiff & 15;
                int base = EXP2_FRAC_LUT[15 - rem];
                int shifted = oct >= 31 ? 0 : (base >> oct);
                w = Math.max(1, shifted);
            }
            weights[a] = w;
            totalWeight += w;
        }

        long r = Long.remainderUnsigned(Integer.toUnsignedLong(unsignedRandom), Math.max(1L, totalWeight));
        for (int a = 0; a < POLICY_NUM_ACTIONS; a++) {
            r -= weights[a];
            if (r < 0L) {
                return a;
            }
        }
        return POLICY_NUM_ACTIONS - 1;
    }

    /**
     * Computes the current 16-element signed {@code Int8} state context vector {@code c_t} in {@code [-127, 127]}.
     *
     * @return 16-byte context vector
     */
    public synchronized byte[] computeContextInt8() {
        byte[] ctx = new byte[POLICY_NUM_FEATURES];
        ctx[0] = 127; // bias (+1.0 in Q7)
        int enclosed = Math.min(4, planksCount >> 2);
        ctx[1] = clampInt8((enclosed * 64) - 127);
        ctx[2] = clampInt8(-127 + Math.min(8, planksCount) * 32);
        ctx[3] = 127; // solid floor
        int effLight = Math.min(15, 4 + torchesCount * 5);
        ctx[4] = clampInt8((7 - effLight) * 18);
        int depth = Math.max(0, 64 - y);
        ctx[5] = clampInt8(depth * 2);
        ctx[6] = intSatRatio(planksCount + cobbleCount, 32);
        ctx[7] = intSatRatio(logsCount, 12);
        ctx[8] = intSatRatio(torchesCount, 8);
        ctx[9] = intSatRatio(utilitiesCount, 4);
        ctx[10] = intSatRatio(oresCount, 12);
        ctx[11] = (logsCount < 8 || y < 56) ? (byte) 96 : (byte) -64;
        ctx[12] = (containerOpen || utilitiesCount > 0) ? (byte) 96 : (byte) -64;
        int distAnchor = Math.abs(x - anchorX) + Math.abs(z - anchorZ);
        ctx[13] = intSatRatio(distAnchor, 16);
        ctx[14] = intSatRatio(stepsSinceProgress, 8);
        ctx[15] = "op".equals(permissionTier) ? (byte) 64 : (byte) 16;
        return ctx;
    }

    /**
     * Advances the bot by one autonomous episode step, computing the 16-feature context vector,
     * sampling an action via {@link #selectPolicyActionInt(byte[], byte[], int, int, int[])},
     * and executing the chosen micro-skill from {@link #POLICY_MICRO_SKILLS}.
     *
     * @return record of the executed micro-skill and updated bot kinematics
     */
    public synchronized BotStepRecord stepAutonomousPolicy() {
        if (!online) {
            online = true;
        }
        byte[] ctx = computeContextInt8();
        int actionIdx = selectPolicyActionInt(policyWeights, ctx, 10, nextUint32(), null);
        return executeMicroSkillByIndex(actionIdx);
    }

    /**
     * Directly manipulates the bot to execute a specific micro-skill index in {@code [0, 15]}.
     *
     * @param skillIdx index into {@link #POLICY_MICRO_SKILLS}
     * @return record of the executed micro-skill and updated bot kinematics
     */
      public synchronized BotStepRecord executeMicroSkillByIndex(int skillIdx) {
          int clampedIdx = Math.floorMod(skillIdx, POLICY_MICRO_SKILLS.size());
          String skill = POLICY_MICRO_SKILLS.get(clampedIdx);
          int[] dir = CARDINAL_DIRS[yawIdx & 3];
          boolean progressed = false;

          switch (skill) {
              case "rtp_or_anchor" -> {
                  rtpCount++;
                  double radius = 32.0 * Math.sqrt(rtpCount);
                  double theta = (rtpCount + (initialSeed & 15)) * 2.39996322972865332;
                  x += (int) Math.round(radius * Math.cos(theta));
                  z += (int) Math.round(radius * Math.sin(theta));
                  anchorX = x;
                  anchorY = y;
                  anchorZ = z;
                  awayLegStep = 0;
                  awayLegLength = 2;
                  awayTurnCount = 0;
                  chunksExplored.add((x >> 4) + "," + (z >> 4));
                  progressed = true;
              }
              case "step_toward_anchor" -> {
                  int dx = Integer.compare(anchorX, x) * 4;
                  int dz = Integer.compare(anchorZ, z) * 4;
                  x += dx;
                  z += dz;
                  chunksExplored.add((x >> 4) + "," + (z >> 4));
                  progressed = (dx != 0 || dz != 0);
              }
              case "step_away_anchor" -> {
                  x += dir[0] * 8;
                  z += dir[1] * 8;
                  awayLegStep++;
                  if (awayLegStep >= awayLegLength) {
                      awayLegStep = 0;
                      yawIdx = (yawIdx + 1) & 3;
                      awayTurnCount++;
                      if ((awayTurnCount & 1) == 0) {
                          awayLegLength = Math.min(32, awayLegLength + 1);
                      }
                  }
                  progressed = chunksExplored.add((x >> 4) + "," + (z >> 4));
              }
              case "harvest_nearest" -> {
                x += dir[0];
                z += dir[1];
                cobbleCount += 3;
                oresCount += 1;
                progressed = true;
            }
            case "craft_basics" -> {
                if (logsCount > 0) {
                    logsCount--;
                    planksCount += 4;
                }
                torchesCount += 2;
                utilitiesCount += 1;
                progressed = true;
            }
            case "place_wall_ring", "place_roof_cell", "place_pillar_or_bridge" -> {
                if (planksCount > 0) {
                    planksCount--;
                } else if (cobbleCount > 0) {
                    cobbleCount--;
                }
                progressed = true;
            }
            case "place_torch_if_dark" -> {
                if (torchesCount > 0) {
                    torchesCount--;
                }
                progressed = true;
            }
            case "place_utility", "place_redstone_link" -> {
                if (utilitiesCount > 0) {
                    utilitiesCount--;
                }
                containerOpen = true;
                progressed = true;
            }
            case "interact_nearest", "deposit_or_trade" -> {
                containerOpen = !containerOpen;
                progressed = true;
            }
            default -> {
                // noop_wait
            }
        }

        if (progressed) {
            stepsSinceProgress = 0;
        } else {
            stepsSinceProgress++;
        }
        return advanceBiometricKinematics(skill, clampedIdx);
    }

    /**
     * Manipulates the bot to prepare and record a fuzzed command line, substituting any
     * persona-preferred root command alias when applicable and expanding {@code {self}} to the
     * bot's player name.
     *
     * @param rawCommandLine raw command line from {@link SleuthServerFuzzer}
     * @return normalized command string without leading slash ready for platform dispatch
     */
    public synchronized String prepareCommandForDispatch(String rawCommandLine) {
        if (!online) {
            online = true;
        }
        String raw = rawCommandLine == null ? "" : rawCommandLine.trim();
        String noSlash = raw.startsWith("/") ? raw.substring(1).trim() : raw;
        if (noSlash.isEmpty()) {
            return "";
        }
        String substituted = noSlash.replace("{self}", persona.playerName());
        int spaceIdx = substituted.indexOf(' ');
        String rootCmd = spaceIdx > 0 ? substituted.substring(0, spaceIdx) : substituted;
        String rest = spaceIdx > 0 ? substituted.substring(spaceIdx) : "";
        String preferred = persona.preferredCommandAliases().get(rootCmd.toLowerCase(Locale.ROOT));
        String finalCmd = (preferred != null && !preferred.isBlank() && !preferred.contains(" "))
                ? (preferred.startsWith("/") ? preferred.substring(1) : preferred) + rest
                : substituted;
        executedCommands.add("/" + finalCmd);
        advanceBiometricKinematics("command:" + rootCmd.toLowerCase(Locale.ROOT), 1);
        return finalCmd;
    }

    /**
     * Executes a follow-up lifecycle shape after command dispatch ({@code quit_lt1s}, {@code quit_delay},
     * {@code move}, {@code explorer_wander}, {@code chunk_border_thrash}, {@code world_switch},
     * {@code window_click}, {@code repeat}, {@code concurrent}).
     *
     * @param followUpShape follow-up shape identifier
     * @return record of the executed follow-up behavior and resulting bot state
     */
    public synchronized BotStepRecord performFollowUpBehavior(String followUpShape) {
        String shape = (followUpShape == null || followUpShape.isBlank())
                ? "repeat"
                : followUpShape.trim().toLowerCase(Locale.ROOT);
        switch (shape) {
            case "quit_lt1s", "quit_delay" -> {
                online = false;
                containerOpen = false;
                return advanceBiometricKinematics(shape, -1);
            }
            case "move", "explorer_wander" -> {
                int[] dir = CARDINAL_DIRS[yawIdx & 3];
                x += dir[0] * 3;
                z += dir[1] * 3;
                yawIdx = (yawIdx + 1) & 3;
                chunksExplored.add((x >> 4) + "," + (z >> 4));
                return advanceBiometricKinematics(shape, 3);
            }
            case "chunk_border_thrash" -> {
                // Step directly across a 16-block chunk boundary
                int localX = Math.floorMod(x, 16);
                x += (localX >= 8) ? (16 - localX + 1) : -(localX + 1);
                chunksExplored.add((x >> 4) + "," + (z >> 4));
                return advanceBiometricKinematics(shape, 3);
            }
            case "window_click" -> {
                containerOpen = true;
                return advanceBiometricKinematics(shape, 14);
            }
            default -> {
                return advanceBiometricKinematics(shape, 0);
            }
        }
    }

    private synchronized BotStepRecord advanceBiometricKinematics(String skillName, int skillIdx) {
        int step = this.stepCount++;
        double gcd = Math.max(0.01, persona.mouseGcdDeg());
        int yawSteps = Math.max(1, (int) Math.round(persona.angularSpeedDeg() / gcd));
        int sign = ((step + yawIdx) & 1) == 0 ? 1 : -1;
        this.yawDeg = normalizeYaw(this.yawDeg + (float) (sign * yawSteps * gcd));
        double rawPitch = this.pitchDeg + (sign * gcd * persona.pitchYawAnisotropy() * 2.0);
        this.pitchDeg = (float) Math.max(-89.0, Math.min(89.0, rawPitch));

        List<Integer> slots = persona.hotbarSlots();
        if (!slots.isEmpty()) {
            hotbarCursor = (hotbarCursor + 1) % slots.size();
            currentHotbarSlot = Math.floorMod(slots.get(hotbarCursor), 9);
        }

        int jitterPct = HUMAN_CADENCE_JITTER_PCT[step & 7];
        int baseClickMs = (int) Math.round(persona.clickMeanMs());
        int clickDelayMs = Math.max(35, baseClickMs + (baseClickMs * jitterPct) / 100);

        BotStepRecord rec = new BotStepRecord(
                step,
                skillName,
                skillIdx,
                x,
                y,
                z,
                yawDeg,
                pitchDeg,
                currentHotbarSlot,
                clickDelayMs,
                online
        );
        stepHistory.add(rec);
        return rec;
    }

    private static float normalizeYaw(float yaw) {
        float y = yaw % 360.0f;
        if (y >= 180.0f) {
            y -= 360.0f;
        } else if (y < -180.0f) {
            y += 360.0f;
        }
        return y;
    }

    private int nextUint32() {
        int state = (this.rngState += 0x6D2B79F5);
        int t = (state ^ (state >>> 15)) * (1 | state);
        t = (t + ((t ^ (t >>> 7)) * (61 | t))) ^ t;
        return t ^ (t >>> 14);
    }

    private static byte clampInt8(int v) {
        return (byte) Math.max(-127, Math.min(127, v));
    }

    private static byte intSatRatio(int count, int cap) {
        int c = Math.max(0, count);
        int m = Math.max(1, cap);
        if (c >= m) {
            return 127;
        }
        int num = (c * 254) - (((c * c) / m) * 127);
        return clampInt8(num / m);
    }

    /**
     * Decodes a Base64-encoded 256-byte {@code Int8[16x16]} policy genome.
     *
     * @param base64 Base64 string or prebaked preset name ({@code "explorer"}, {@code "house"}, etc.)
     * @return 256-byte policy weight array
     */
    public static byte[] decodePolicyWeightsBase64(String base64) {
        if (base64 == null || base64.isBlank()) {
            return new byte[POLICY_WEIGHT_BYTES];
        }
        String trimmed = base64.trim();
        String resolved = PREBAKED_POLICY_BASE64.getOrDefault(trimmed.toLowerCase(Locale.ROOT), trimmed);
        try {
            byte[] decoded = Base64.getDecoder().decode(resolved);
            if (decoded.length == POLICY_WEIGHT_BYTES) {
                byte[] clamped = new byte[POLICY_WEIGHT_BYTES];
                for (int i = 0; i < POLICY_WEIGHT_BYTES; i++) {
                    clamped[i] = clampInt8(decoded[i]);
                }
                return clamped;
            }
        } catch (IllegalArgumentException ignored) {
        }
        return new byte[POLICY_WEIGHT_BYTES];
    }

    /**
     * Returns the built-in catalog of 8 orthogonal {@link PersonaProfile} archetypes
     * covering diverse player behavior loops, motor kinematics, and 256-byte policy genomes.
     *
     * @return immutable list of 8 built-in persona profiles
     */
    public static List<PersonaProfile> defaultPersonaCatalog() {
        return DEFAULT_CATALOG;
    }

    /**
     * Selects a deterministic persona profile for {@code episodeIndex} from {@code customCatalog}
     * (if non-empty) or {@link #defaultPersonaCatalog()}.
     *
     * @param customCatalog optional custom loaded personas
     * @param episodeIndex  episode or actor index
     * @return selected {@link PersonaProfile}
     */
    public static PersonaProfile selectPersonaForEpisode(
            List<PersonaProfile> customCatalog,
            int episodeIndex
    ) {
        List<PersonaProfile> pool = (customCatalog != null && !customCatalog.isEmpty())
                ? customCatalog
                : DEFAULT_CATALOG;
        return pool.get(Math.floorMod(episodeIndex, pool.size()));
    }

    /**
     * Parses a single {@code sleuth_persona_v1} JSON line produced by
     * {@link PersonaProfile#toJsonLine()} back into a {@link PersonaProfile}.
     *
     * @param jsonLine single-line JSON object
     * @return parsed {@link PersonaProfile}, or {@code null} if blank/invalid
     */
    public static PersonaProfile fromJsonLine(String jsonLine) {
        if (jsonLine == null || jsonLine.isBlank()) {
            return null;
        }
        String trimmed = jsonLine.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
            return null;
        }
        Map<String, String> strings = new LinkedHashMap<>();
        Matcher sm = JSON_STRING_FIELD.matcher(trimmed);
        while (sm.find()) {
            strings.put(sm.group(1), sm.group(2));
        }
        Map<String, Double> numbers = new LinkedHashMap<>();
        Matcher nm = JSON_NUMBER_FIELD.matcher(trimmed);
        while (nm.find()) {
            try {
                numbers.put(nm.group(1), Double.parseDouble(nm.group(2)));
            } catch (NumberFormatException ignored) {
            }
        }
        boolean banned = false;
        Matcher bm = JSON_BOOL_FIELD.matcher(trimmed);
        while (bm.find()) {
            if ("banned".equals(bm.group(1))) {
                banned = Boolean.parseBoolean(bm.group(2));
            }
        }

        String playerName = strings.getOrDefault("player_name", strings.getOrDefault("id", "LF_Bot0"));
        UUID accountId;
        try {
            String rawUuid = strings.get("account_id");
            accountId = rawUuid != null
                    ? UUID.fromString(rawUuid)
                    : UUID.nameUUIDFromBytes(("leaffuzz-persona:" + playerName).getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            accountId = UUID.nameUUIDFromBytes(("leaffuzz-persona:" + playerName).getBytes(StandardCharsets.UTF_8));
        }

        String solver = strings.getOrDefault("expected_solver", "HUMAN_QUANTIZED_GCD");
        double mouseGcd = numbers.getOrDefault("mouse_gcd_deg", 0.15);
        double turnJerk = numbers.getOrDefault("turn_jerk_deg", 1.8);
        double angularSpeed = numbers.getOrDefault("angular_speed_deg", 3.5);
        double clickMean = numbers.getOrDefault("click_mean_ms", 160.0);
        double clickCv = numbers.getOrDefault("click_cv", 0.21);
        double physCounts = numbers.getOrDefault("phys_counts_per_tick", 8.0);
        double curvature = numbers.getOrDefault("path_curvature", 0.25);
        double anisotropy = numbers.getOrDefault("pitch_yaw_anisotropy", 0.45);
        double runTurn = numbers.getOrDefault("turn_while_running_rate", 0.60);
        double strafeTurn = numbers.getOrDefault("strafe_turn_rate", 0.40);
        double airborneTurn = numbers.getOrDefault("airborne_turn_rate", 0.20);
        double fittsIntercept = numbers.getOrDefault("fitts_intercept_ms", 110.0);
        double fittsSlope = numbers.getOrDefault("fitts_slope_ms_per_bit", 85.0);
        double wpmMean = numbers.getOrDefault("wpm_mean", 55.0);
        double wpmStd = numbers.getOrDefault("wpm_std", 12.0);
        int chunkX = numbers.getOrDefault("chunk_x", 16.0).intValue();
        int chunkZ = numbers.getOrDefault("chunk_z", -12.0).intValue();
        String archetype = strings.getOrDefault("taxonomy_archetype", "explorer_wander");
        byte[] weights = decodePolicyWeightsBase64(strings.getOrDefault("pretrained_policy_b64", "explorer"));

        return new PersonaProfile(
                accountId,
                playerName,
                banned,
                solver,
                mouseGcd,
                turnJerk,
                angularSpeed,
                clickMean,
                clickCv,
                physCounts,
                curvature,
                anisotropy,
                runTurn,
                strafeTurn,
                airborneTurn,
                fittsIntercept,
                fittsSlope,
                wpmMean,
                wpmStd,
                List.of(0, 1, 2),
                List.of("MINING", "BUILDING", "CRAFTING"),
                new long[49],
                chunkX,
                chunkZ,
                Map.of(),
                archetype,
                Map.of(archetype, 1.0),
                weights
        );
    }

    /**
     * Loads all {@link PersonaProfile} records from a {@code sleuth_persona_v1} JSONL file
     * if it exists, falling back to {@link #defaultPersonaCatalog()} when absent or empty.
     *
     * @param jsonlFile path to {@code personas.jsonl}
     * @return immutable list of loaded or default persona profiles
     */
    public static List<PersonaProfile> loadPersonasOrDefault(Path jsonlFile) {
        if (jsonlFile != null && Files.isRegularFile(jsonlFile)) {
            try {
                List<String> lines = Files.readAllLines(jsonlFile, StandardCharsets.UTF_8);
                List<PersonaProfile> parsed = new ArrayList<>();
                for (String line : lines) {
                    PersonaProfile p = fromJsonLine(line);
                    if (p != null) {
                        parsed.add(p);
                    }
                }
                if (!parsed.isEmpty()) {
                    return List.copyOf(parsed);
                }
            } catch (IOException ignored) {
            }
        }
        return DEFAULT_CATALOG;
    }

    public PersonaProfile persona() {
        return persona;
    }

    public UUID actorUuid() {
        return UUID.nameUUIDFromBytes(
                ("leaffuzz-bot:" + persona.accountId() + ":" + permissionTier + ":" + initialSeed)
                        .getBytes(StandardCharsets.UTF_8)
        );
    }

    public synchronized void setLocation(int newX, int newY, int newZ) {
        this.x = newX;
        this.y = newY;
        this.z = newZ;
        this.chunksExplored.add((newX >> 4) + "," + (newZ >> 4));
    }

    public String actorName() {
        return actorName(0);
    }

    /**
     * Formats a Minecraft-valid ({@code <= 16} chars, {@code [a-zA-Z0-9_]}) bot username
     * by abbreviating the persona stem before attaching the permission tier suffix
     * ({@code _p} or {@code _op}) and optional swarm slot suffix ({@code _<botIndex>}).
     *
     * @param botIndex swarm slot index ({@code <= 0} omits the index suffix)
     * @return abbreviated username guaranteed to fit within 16 characters without cutting off suffixes
     */
    public String actorName(int botIndex) {
        String tierSuffix = "op".equals(permissionTier) ? "_op" : "_p";
        String indexSuffix = botIndex > 0 ? ("_" + botIndex) : "";
        String suffix = tierSuffix + indexSuffix;
        if (suffix.length() >= 15) {
            suffix = suffix.substring(0, 15);
        }
        int maxStem = Math.max(1, 16 - suffix.length());
        String stem = abbreviateStem(persona.playerName(), maxStem);
        return stem + suffix;
    }

    static String abbreviateStem(String rawName, int maxStem) {
        String cleaned = rawName == null ? "" : rawName.replaceAll("[^a-zA-Z0-9_]", "");
        while (cleaned.startsWith("_")) {
            cleaned = cleaned.substring(1);
        }
        while (cleaned.endsWith("_")) {
            cleaned = cleaned.substring(0, cleaned.length() - 1);
        }
        if (cleaned.isEmpty()) {
            cleaned = "LF_Bot";
        }
        if (cleaned.length() <= maxStem) {
            return cleaned;
        }
        String compact = cleaned
                .replaceFirst("^(?i)LeafFuzz_?", "LF_")
                .replaceFirst("^(?i)LeafSleuth_?", "LS_")
                .replaceFirst("^(?i)Leaf_?", "LF_")
                .replaceFirst("^(?i)Fuzz_?", "FZ_")
                .replaceAll("_+", "_");
        if (compact.length() > maxStem) {
            StringBuilder sb = new StringBuilder(compact);
            for (int i = sb.length() - 1; i >= 1 && sb.length() > maxStem; i--) {
                char c = sb.charAt(i);
                char prev = sb.charAt(i - 1);
                if ((c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') && prev != '_') {
                    sb.deleteCharAt(i);
                }
            }
            compact = sb.toString();
        }
        if (compact.length() > maxStem) {
            compact = compact.substring(0, maxStem);
        }
        while (compact.length() > 1 && compact.endsWith("_")) {
            compact = compact.substring(0, compact.length() - 1);
        }
        return compact;
    }

    public String permissionTier() {
        return permissionTier;
    }

    public boolean isOp() {
        return "op".equals(permissionTier);
    }

    public int x() {
        return x;
    }

    public int y() {
        return y;
    }

    public int z() {
        return z;
    }

    public float yawDeg() {
        return yawDeg;
    }

    public float pitchDeg() {
        return pitchDeg;
    }

    public int currentHotbarSlot() {
        return currentHotbarSlot;
    }

    public boolean isOnline() {
        return online;
    }

    public boolean isContainerOpen() {
        return containerOpen;
    }
      public synchronized Set<String> chunksExplored() {
          return Set.copyOf(chunksExplored);
      }

      public synchronized int chunksExploredCount() {
          return chunksExplored.size();
      }

      public synchronized List<BotStepRecord> stepHistory() {
          return List.copyOf(stepHistory);
      }

      public synchronized List<String> executedCommands() {
          return List.copyOf(executedCommands);
      }

      private static final List<PersonaProfile> DEFAULT_CATALOG = buildDefaultCatalog();

      private static List<PersonaProfile> buildDefaultCatalog() {
        return List.of(
                createBuiltinPersona(
                        0, "LF_Explr", 0.065, 1.2, 85.0, 0.85, 0.70, 0.35,
                        List.of(0, 1, 2), List.of("COMMAND_CHAT", "MINING", "BUILDING"),
                        16, -12, "explorer_wander", "explorer"
                ),
                createBuiltinPersona(
                        1, "LF_Stead", 0.105, 2.3, 140.0, 0.20, 0.10, 0.05,
                        List.of(3, 4, 5), List.of("BUILDING", "CONTAINER_SORT", "COMMAND_CHAT"),
                        32, -24, "homesteader_reroll", "house"
                ),
                createBuiltinPersona(
                        2, "LF_Miner", 0.165, 4.3, 225.0, 0.65, 0.45, 0.20,
                        List.of(6, 7, 8), List.of("MINING", "CRAFTING", "BUILDING"),
                        48, -36, "chunk_border_thrash", "mineshaft"
                ),
                createBuiltinPersona(
                        3, "LF_Craft", 0.255, 8.0, 355.0, 0.92, 0.82, 0.55,
                        List.of(0, 4, 8), List.of("CRAFTING", "CONTAINER_SORT", "MINING"),
                        64, -48, "window_click", "shop"
                ),
                createBuiltinPersona(
                        4, "LF_Sort", 0.375, 14.5, 540.0, 0.12, 0.05, 0.02,
                        List.of(1, 5, 6), List.of("CONTAINER_SORT", "BUILDING", "COMBAT"),
                        80, -60, "window_click", "villager"
                ),
                createBuiltinPersona(
                        5, "LF_Run", 0.082, 1.7, 110.0, 0.75, 0.58, 0.28,
                        List.of(2, 3, 7), List.of("COMMAND_CHAT", "MINING", "CONTAINER_SORT"),
                        96, -72, "burst_swarm", "caving"
                ),
                createBuiltinPersona(
                        6, "LF_Rdstn", 0.132, 3.2, 178.0, 0.30, 0.18, 0.08,
                        List.of(2, 1, 0), List.of("CRAFTING", "BUILDING", "AFK"),
                        112, -84, "repeat", "machine"
                ),
                createBuiltinPersona(
                        7, "LF_Delvr", 0.205, 5.8, 280.0, 0.88, 0.76, 0.48,
                        List.of(5, 4, 3), List.of("COMBAT", "MINING", "COMMAND_CHAT"),
                        128, -96, "explorer_wander", "diamond"
                )
        );
    }

    private static PersonaProfile createBuiltinPersona(
            int index,
            String name,
            double mouseGcd,
            double turnJerk,
            double clickMeanMs,
            double runTurnRate,
            double strafeTurnRate,
            double airborneTurnRate,
            List<Integer> hotbarSlots,
            List<String> goalLoop,
            int chunkX,
            int chunkZ,
            String taxonomyArchetype,
            String presetPolicyKey
    ) {
        UUID uuid = UUID.nameUUIDFromBytes(("leaffuzz-persona-catalog:" + index + ":" + name).getBytes(StandardCharsets.UTF_8));
        byte[] weights = decodePolicyWeightsBase64(presetPolicyKey);
        return new PersonaProfile(
                uuid,
                name,
                false,
                "HUMAN_QUANTIZED_GCD",
                mouseGcd,
                turnJerk,
                Math.max(1.5, mouseGcd * 24.0),
                clickMeanMs,
                0.21,
                Math.max(2.0, 24.0),
                0.25,
                0.45,
                runTurnRate,
                strafeTurnRate,
                airborneTurnRate,
                110.0,
                85.0,
                58.0,
                12.0,
                hotbarSlots,
                goalLoop,
                new long[49],
                chunkX,
                chunkZ,
                Map.of(),
                taxonomyArchetype,
                Map.of(taxonomyArchetype, 1.0),
                weights
        );
    }
}
