package net.leaf.sleuth.common.fuzz;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Persistent YAML state store ({@code plugins/LeafSleuth/fuzz-campaign.yml}) and crash-safe
 * {@code .jar.sleuth-disabled} restoration manifest for multi-boot QA calibration campaigns
 * ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * <p>Writes the rename manifest to {@code fuzz-campaign.yml} before renaming any candidate
 * plugin archive to {@code <Plugin>.jar.sleuth-disabled}, and restores all disabled archives
 * on campaign completion, abort, or crash recovery when the retry budget is exceeded.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-005
 * @trace S-005
 */
public final class FuzzCampaignStateStore {

    /** Default campaign state file name inside {@code plugins/LeafSleuth/}. */
    public static final String DEFAULT_STATE_FILE_NAME = "fuzz-campaign.yml";

    /** Suffix appended to temporarily isolated plugin JARs during multi-boot bisection. */
    public static final String DISABLED_JAR_SUFFIX = ".sleuth-disabled";

    /** Default maximum restart retry budget before automatic crash-recovery abort. */
    public static final int DEFAULT_MAX_RESTART_RETRIES = 3;

    private static final Logger LOGGER = Logger.getLogger(FuzzCampaignStateStore.class.getName());

    /**
     * Lifecycle state of a persisted QA calibration campaign.
     */
    public enum CampaignStatus {
        IDLE,
        RUNNING,
        AWAITING_RESTART_RESUME,
        COMPLETED,
        ABORTED;

        public static CampaignStatus parse(String raw, CampaignStatus fallback) {
            if (raw == null || raw.isBlank()) {
                return fallback;
            }
            String clean = raw.trim().toUpperCase(Locale.ROOT).replace('-', '_');
            for (CampaignStatus status : values()) {
                if (status.name().equals(clean)) {
                    return status;
                }
            }
            return fallback;
        }
    }

    /**
     * Immutable snapshot of a QA calibration campaign persisted in {@code fuzz-campaign.yml}.
     *
     * @param campaignId           unique campaign identifier
     * @param status               current campaign status
     * @param restartStrategy      active {@link RestartStrategy}
     * @param completedEpisodes    number of episodes completed so far
     * @param targetEpisodes       total episode budget
     * @param restartRetries       number of restart resumes performed
     * @param maxRestartRetries    maximum allowed restart retries before crash-recovery abort
     * @param activeTiers          active permission tiers (e.g. {@code ["default"]})
     * @param disabledPluginJars   manifest of plugin JAR file names currently renamed to {@code .jar.sleuth-disabled}
     * @param discoveredSignatures deduplicated fault/leak signature IDs discovered so far
     * @param updatedAtEpochMs     epoch milliseconds of last checkpoint write
     */
    public record CampaignState(
            String campaignId,
            CampaignStatus status,
            RestartStrategy restartStrategy,
            int completedEpisodes,
            int targetEpisodes,
            int restartRetries,
            int maxRestartRetries,
            List<String> activeTiers,
            List<String> disabledPluginJars,
            List<String> discoveredSignatures,
            long updatedAtEpochMs
    ) {
        public CampaignState {
            campaignId = (campaignId == null || campaignId.isBlank()) ? "default-campaign" : campaignId.trim();
            status = status == null ? CampaignStatus.IDLE : status;
            restartStrategy = restartStrategy == null ? RestartStrategy.NONE : restartStrategy;
            completedEpisodes = Math.max(0, completedEpisodes);
            targetEpisodes = Math.max(0, targetEpisodes);
            restartRetries = Math.max(0, restartRetries);
            maxRestartRetries = Math.max(1, maxRestartRetries);
            activeTiers = activeTiers == null || activeTiers.isEmpty() ? List.of("default") : List.copyOf(activeTiers);
            disabledPluginJars = disabledPluginJars == null ? List.of() : List.copyOf(disabledPluginJars);
            discoveredSignatures = discoveredSignatures == null ? List.of() : List.copyOf(discoveredSignatures);
        }

        public CampaignState withStatus(CampaignStatus newStatus, long nowMs) {
            return new CampaignState(
                    campaignId,
                    newStatus,
                    restartStrategy,
                    completedEpisodes,
                    targetEpisodes,
                    restartRetries,
                    maxRestartRetries,
                    activeTiers,
                    disabledPluginJars,
                    discoveredSignatures,
                    nowMs
            );
        }

        public CampaignState withDisabledJars(Collection<String> jars, long nowMs) {
            return new CampaignState(
                    campaignId,
                    status,
                    restartStrategy,
                    completedEpisodes,
                    targetEpisodes,
                    restartRetries,
                    maxRestartRetries,
                    activeTiers,
                    jars != null ? List.copyOf(jars) : List.of(),
                    discoveredSignatures,
                    nowMs
            );
        }

        public CampaignState withIncrementedRetry(CampaignStatus newStatus, long nowMs) {
            return new CampaignState(
                    campaignId,
                    newStatus,
                    restartStrategy,
                    completedEpisodes,
                    targetEpisodes,
                    restartRetries + 1,
                    maxRestartRetries,
                    activeTiers,
                    disabledPluginJars,
                    discoveredSignatures,
                    nowMs
            );
        }
    }

    private final Path stateFilePath;

    public FuzzCampaignStateStore(Path stateFilePath) {
        this.stateFilePath = Objects.requireNonNull(stateFilePath, "stateFilePath");
    }

    public static FuzzCampaignStateStore forDataFolder(Path pluginDataFolder) {
        Objects.requireNonNull(pluginDataFolder, "pluginDataFolder");
        return new FuzzCampaignStateStore(pluginDataFolder.resolve(DEFAULT_STATE_FILE_NAME));
    }

    public Path stateFilePath() {
        return stateFilePath;
    }

    /**
     * Saves {@code state} to {@code fuzz-campaign.yml}.
     *
     * @param state campaign state to persist
     * @throws IOException if writing fails
     */
    public synchronized void save(CampaignState state) throws IOException {
        Objects.requireNonNull(state, "state");
        Path parent = stateFilePath.getParent();
        if (parent != null && !Files.exists(parent)) {
            Files.createDirectories(parent);
        }
        String yaml = serializeYaml(state);
        Files.writeString(stateFilePath, yaml, StandardCharsets.UTF_8);
    }

    /**
     * Loads the persisted {@link CampaignState} from {@code fuzz-campaign.yml} if it exists.
     *
     * @return loaded {@link CampaignState}, or {@link Optional#empty()} if no state file exists
     */
    public synchronized Optional<CampaignState> load() {
        if (!Files.isRegularFile(stateFilePath)) {
            return Optional.empty();
        }
        try {
            String text = Files.readString(stateFilePath, StandardCharsets.UTF_8);
            return Optional.of(deserializeYaml(text));
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "[LeafSleuth] Failed to read campaign state from " + stateFilePath, e);
            return Optional.empty();
        }
    }

    /**
     * Writes the rename manifest to {@code fuzz-campaign.yml} first, then renames each candidate
     * {@code <Plugin>.jar} in {@code pluginsDir} to {@code <Plugin>.jar.sleuth-disabled}.
     *
     * @param baseState        current campaign state
     * @param pluginsDir       {@code plugins/} directory
     * @param candidateJars    JAR file names to disable for bisection
     * @return updated {@link CampaignState} recording all disabled JARs
     * @throws IOException if checkpointing or renaming fails
     */
    public synchronized CampaignState disableJarsForBisection(
            CampaignState baseState,
            Path pluginsDir,
            Collection<String> candidateJars
    ) throws IOException {
        Objects.requireNonNull(baseState, "baseState");
        Objects.requireNonNull(pluginsDir, "pluginsDir");
        Set<String> normalizedJars = new LinkedHashSet<>(baseState.disabledPluginJars());
        if (candidateJars != null) {
            for (String jar : candidateJars) {
                if (jar != null && !jar.isBlank()) {
                    String name = Path.of(jar.trim()).getFileName().toString();
                    if (!name.toLowerCase(Locale.ROOT).startsWith("leafsleuth")) {
                        normalizedJars.add(name);
                    }
                }
            }
        }

        // Write manifest BEFORE renaming any files so crash recovery always knows what was disabled
        CampaignState manifestWritten = baseState.withDisabledJars(normalizedJars, System.currentTimeMillis());
        save(manifestWritten);

        for (String jarName : normalizedJars) {
            Path activeJar = pluginsDir.resolve(jarName);
            Path disabledJar = pluginsDir.resolve(jarName + DISABLED_JAR_SUFFIX);
            if (Files.isRegularFile(activeJar) && !Files.exists(disabledJar)) {
                Files.move(activeJar, disabledJar, StandardCopyOption.REPLACE_EXISTING);
            }
        }
        return manifestWritten;
    }

    /**
     * Restores all {@code *.jar.sleuth-disabled} archives in {@code pluginsDir} back to their
     * original {@code *.jar} names and updates {@code fuzz-campaign.yml}.
     *
     * @param pluginsDir {@code plugins/} directory
     * @return immutable list of restored JAR file names
     */
    public synchronized List<String> restoreDisabledJars(Path pluginsDir) {
        List<String> restored = new ArrayList<>();
        Optional<CampaignState> loadedOpt = load();

        if (pluginsDir != null && Files.isDirectory(pluginsDir)) {
            if (loadedOpt.isPresent()) {
                for (String jarName : loadedOpt.get().disabledPluginJars()) {
                    if (restoreSingleJar(pluginsDir, jarName)) {
                        restored.add(jarName);
                    }
                }
            }
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(pluginsDir, "*" + DISABLED_JAR_SUFFIX)) {
                for (Path disabledPath : stream) {
                    String fileName = disabledPath.getFileName().toString();
                    String origName = fileName.substring(0, fileName.length() - DISABLED_JAR_SUFFIX.length());
                    if (restoreSingleJar(pluginsDir, origName) && !restored.contains(origName)) {
                        restored.add(origName);
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "[LeafSleuth] Failed to scan plugins directory for disabled JARs: " + pluginsDir, e);
            }
        }

        if (loadedOpt.isPresent()) {
            CampaignState cleared = loadedOpt.get().withDisabledJars(List.of(), System.currentTimeMillis());
            try {
                save(cleared);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "[LeafSleuth] Failed to update campaign state after restoring JARs", e);
            }
        }
        return Collections.unmodifiableList(restored);
    }

    /**
     * Marks any persisted campaign as {@link CampaignStatus#ABORTED} and restores all
     * {@code .jar.sleuth-disabled} files in {@code pluginsDir}.
     *
     * @param pluginsDir {@code plugins/} directory
     * @return list of restored JAR file names
     */
    public synchronized List<String> abortAndRestore(Path pluginsDir) {
        List<String> restored = restoreDisabledJars(pluginsDir);
        Optional<CampaignState> loadedOpt = load();
        if (loadedOpt.isPresent()) {
            CampaignState aborted = loadedOpt.get()
                    .withDisabledJars(List.of(), System.currentTimeMillis())
                    .withStatus(CampaignStatus.ABORTED, System.currentTimeMillis());
            try {
                save(aborted);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "[LeafSleuth] Failed to persist ABORTED campaign state", e);
            }
        }
        return restored;
    }

    private static boolean restoreSingleJar(Path pluginsDir, String jarName) {
        if (jarName == null || jarName.isBlank()) {
            return false;
        }
        Path disabledPath = pluginsDir.resolve(jarName + DISABLED_JAR_SUFFIX);
        Path activePath = pluginsDir.resolve(jarName);
        if (!Files.isRegularFile(disabledPath)) {
            return false;
        }
        try {
            Files.move(disabledPath, activePath, StandardCopyOption.REPLACE_EXISTING);
            return true;
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "[LeafSleuth] Failed to restore disabled plugin JAR " + disabledPath, e);
            return false;
        }
    }

    static String serializeYaml(CampaignState s) {
        StringBuilder sb = new StringBuilder();
        sb.append("# LeafSleuth QA Calibration Campaign Resume State\n");
        sb.append("campaignId: ").append(quoteYaml(s.campaignId())).append('\n');
        sb.append("status: ").append(s.status().name()).append('\n');
        sb.append("restartStrategy: ").append(s.restartStrategy().name()).append('\n');
        sb.append("completedEpisodes: ").append(s.completedEpisodes()).append('\n');
        sb.append("targetEpisodes: ").append(s.targetEpisodes()).append('\n');
        sb.append("restartRetries: ").append(s.restartRetries()).append('\n');
        sb.append("maxRestartRetries: ").append(s.maxRestartRetries()).append('\n');
        sb.append("updatedAtEpochMs: ").append(s.updatedAtEpochMs()).append('\n');
        appendYamlList(sb, "activeTiers", s.activeTiers());
        appendYamlList(sb, "disabledPluginJars", s.disabledPluginJars());
        appendYamlList(sb, "discoveredSignatures", s.discoveredSignatures());
        return sb.toString();
    }

    static CampaignState deserializeYaml(String yamlText) {
        String campaignId = "default-campaign";
        CampaignStatus status = CampaignStatus.IDLE;
        RestartStrategy strategy = RestartStrategy.NONE;
        int completedEpisodes = 0;
        int targetEpisodes = 0;
        int restartRetries = 0;
        int maxRestartRetries = DEFAULT_MAX_RESTART_RETRIES;
        long updatedAtEpochMs = 0L;
        List<String> activeTiers = new ArrayList<>();
        List<String> disabledPluginJars = new ArrayList<>();
        List<String> discoveredSignatures = new ArrayList<>();

        if (yamlText != null && !yamlText.isBlank()) {
            String[] lines = yamlText.split("\\R");
            String currentListKey = null;
            for (String rawLine : lines) {
                String trimmed = rawLine.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                if (trimmed.startsWith("- ") && currentListKey != null) {
                    String item = unquoteYaml(trimmed.substring(2).trim());
                    if (!item.isEmpty()) {
                        switch (currentListKey) {
                            case "activeTiers" -> activeTiers.add(item);
                            case "disabledPluginJars" -> disabledPluginJars.add(item);
                            case "discoveredSignatures" -> discoveredSignatures.add(item);
                            default -> {
                            }
                        }
                    }
                    continue;
                }
                int colon = trimmed.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String key = trimmed.substring(0, colon).trim();
                String val = trimmed.substring(colon + 1).trim();
                if (val.isEmpty() || "[]".equals(val)) {
                    currentListKey = key;
                    continue;
                }
                currentListKey = null;
                String cleanVal = unquoteYaml(val);
                switch (key) {
                    case "campaignId" -> campaignId = cleanVal;
                    case "status" -> status = CampaignStatus.parse(cleanVal, CampaignStatus.IDLE);
                    case "restartStrategy" -> {
                        RestartStrategy parsed = RestartStrategy.parseOrNullForAuto(cleanVal);
                        strategy = parsed != null ? parsed : RestartStrategy.NONE;
                    }
                    case "completedEpisodes" -> completedEpisodes = parseIntSafe(cleanVal, 0);
                    case "targetEpisodes" -> targetEpisodes = parseIntSafe(cleanVal, 0);
                    case "restartRetries" -> restartRetries = parseIntSafe(cleanVal, 0);
                    case "maxRestartRetries" -> maxRestartRetries = parseIntSafe(cleanVal, DEFAULT_MAX_RESTART_RETRIES);
                    case "updatedAtEpochMs" -> updatedAtEpochMs = parseLongSafe(cleanVal, 0L);
                    default -> {
                    }
                }
            }
        }

        return new CampaignState(
                campaignId,
                status,
                strategy,
                completedEpisodes,
                targetEpisodes,
                restartRetries,
                maxRestartRetries,
                activeTiers,
                disabledPluginJars,
                discoveredSignatures,
                updatedAtEpochMs
        );
    }

    private static void appendYamlList(StringBuilder sb, String key, List<String> items) {
        if (items == null || items.isEmpty()) {
            sb.append(key).append(": []\n");
            return;
        }
        sb.append(key).append(":\n");
        for (String item : items) {
            sb.append("  - ").append(quoteYaml(item)).append('\n');
        }
    }

    private static String quoteYaml(String raw) {
        if (raw == null) {
            return "\"\"";
        }
        String escaped = raw.replace("\\", "\\\\").replace("\"", "\\\"");
        return "\"" + escaped + "\"";
    }

    private static String unquoteYaml(String raw) {
        if (raw == null) {
            return "";
        }
        String s = raw.trim();
        if (s.length() >= 2 && ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'")))) {
            s = s.substring(1, s.length() - 1).replace("\\\"", "\"").replace("\\\\", "\\");
        }
        return s.trim();
    }

    private static int parseIntSafe(String s, int fallback) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static long parseLongSafe(String s, long fallback) {
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }
}
