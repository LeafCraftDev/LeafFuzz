package net.leaf.fuzz.common;

import io.github.dailystruggle.bytecode.LlmConfigDocSynthesizer.LlmHookConfig;
import io.github.dailystruggle.bytecode.LlmConfigDocSynthesizer.Provider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Platform-neutral configuration and configurable user-facing messages for {@code LeafFuzz}
 * ({@code leaffuzz-ADR-001}, {@code REQ-RTP-F-013}, {@code S-007}).
 *
 * @param defaultEpisodes            default episode count for {@code /fuzz check} (default {@code 250})
 * @param defaultPlayers             default concurrent player roster size for {@code /fuzz check} (default {@code 1}, up to {@code 500})
 * @param slowTickThresholdMs        slow-tick MSPT threshold for main-thread stall capture (default {@code 100.0})
 * @param requireDisposableForAll    whether {@code /fuzz check all} requires {@code .bench-disposable}
 * @param restartStrategy            configured restart strategy ({@code "AUTO"}, {@code "NONE"}, {@code "SPIGOT_RESTART"}, {@code "SUPERVISOR_STOP"})
 * @param maxRestartRetries          maximum multi-boot campaign restart retries (default {@code 3})
 * @param extraDenylist              extra command patterns excluded from fuzzing
 * @param messages                   configurable operator feedback messages ({@code S-007})
 * @param llmAudit                   optional AST-grounded LLM fault explainer and causal chain audit config
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-007
 */
public record LeafFuzzConfig(
        int defaultEpisodes,
        int defaultPlayers,
        double slowTickThresholdMs,
        boolean requireDisposableForAll,
        String restartStrategy,
        int maxRestartRetries,
        List<String> extraDenylist,
        Messages messages,
        LlmAuditConfig llmAudit
) {
    /**
     * Optional subscribed LLM configuration for AST-grounded fault explanations and advisory
     * second-order causal chain auditing ({@code corpus-atlas-ADR-001}, {@code corpus-atlas-ADR-002}).
     *
     * @param enabled            whether LLM fault explanation / semantic causal audit is enabled
     * @param provider           provider identifier ({@code "OFF"}, {@code "GEMINI"}, {@code "OPENAI_COMPATIBLE"}, {@code "ANTHROPIC"}, {@code "OLLAMA"})
     * @param model              model identifier (e.g. {@code "gemini-2.5-flash"})
     * @param endpoint           custom HTTP endpoint, or empty for provider default
     * @param apiKeyEnv          environment variable holding the API key (default {@code "GEMINI_API_KEY"})
     * @param explainFuzzFaults  whether to attach AST-grounded root-cause explanations to proven faults
     * @param maxChainsPerTarget maximum causal chains or findings sent to the LLM per target
     */
    public record LlmAuditConfig(
            boolean enabled,
            String provider,
            String model,
            String endpoint,
            String apiKeyEnv,
            boolean explainFuzzFaults,
            int maxChainsPerTarget
    ) {
        public LlmAuditConfig {
            provider = (provider == null || provider.isBlank()) ? "OFF" : provider.trim().toUpperCase(Locale.ROOT);
            model = (model == null || model.isBlank()) ? "gemini-2.5-flash" : model.trim();
            endpoint = endpoint == null ? "" : endpoint.trim();
            apiKeyEnv = (apiKeyEnv == null || apiKeyEnv.isBlank()) ? "GEMINI_API_KEY" : apiKeyEnv.trim();
            maxChainsPerTarget = Math.max(1, Math.min(32, maxChainsPerTarget));
        }

        public static LlmAuditConfig defaults() {
            return new LlmAuditConfig(false, "OFF", "gemini-2.5-flash", "", "GEMINI_API_KEY", true, 6);
        }

        public LlmHookConfig toLlmHookConfig() {
            if (!enabled) {
                return new LlmHookConfig(Provider.OFF, model, "", "", 11434, "", apiKeyEnv, 6_000, 240);
            }
            Provider prov;
            try {
                prov = Provider.valueOf(provider);
            } catch (IllegalArgumentException ignored) {
                prov = Provider.OFF;
            }
            String effEndpoint = endpoint;
            if (effEndpoint.isEmpty()) {
                effEndpoint = switch (prov) {
                    case GEMINI -> "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent";
                    case ANTHROPIC -> "https://api.anthropic.com/v1/messages";
                    case OPENAI_COMPATIBLE -> "https://api.openai.com/v1/chat/completions";
                    case OLLAMA, OFF -> "http://127.0.0.1:11434/v1/chat/completions";
                };
            }
            return new LlmHookConfig(
                    prov,
                    model,
                    effEndpoint,
                    "",
                    11434,
                    "",
                    apiKeyEnv,
                    6_000,
                    240
            );
        }
    }
    /**
     * Configurable command feedback messages satisfying {@code S-007}.
     *
     * @param prefix         chat/console message prefix
     * @param noPermission   permission-denied message template
     * @param badParameter   invalid parameter message template
     * @param invalidCommand unknown subcommand message template
     * @param busy           busy / in-progress message template
     * @param reloadSuccess  configuration reload success message
     * @param reloadFailed   configuration reload failure message template
     */
    public record Messages(
            String prefix,
            String noPermission,
            String badParameter,
            String invalidCommand,
            String busy,
            String reloadSuccess,
            String reloadFailed
    ) {
        public Messages {
            prefix = (prefix == null || prefix.isBlank()) ? "&8[&2LeafFuzz&8] &r" : prefix;
            noPermission = (noPermission == null || noPermission.isBlank())
                    ? "&cYou do not have permission to run this LeafFuzz command."
                    : noPermission;
            badParameter = (badParameter == null || badParameter.isBlank())
                    ? "&cInvalid parameter '[param]': '[value]'."
                    : badParameter;
            invalidCommand = (invalidCommand == null || invalidCommand.isBlank())
                    ? "&cUnknown subcommand '[arg]'. Use /fuzz help."
                    : invalidCommand;
            busy = (busy == null || busy.isBlank())
                    ? "&eA diagnostic snapshot or fuzz pass is already running; please wait."
                    : busy;
            reloadSuccess = (reloadSuccess == null || reloadSuccess.isBlank())
                    ? "&aLeafFuzz configuration and messages reloaded."
                    : reloadSuccess;
            reloadFailed = (reloadFailed == null || reloadFailed.isBlank())
                    ? "&cLeafFuzz reload failed: [errors]"
                    : reloadFailed;
        }

        public static Messages defaults() {
            return new Messages(
                    "&8[&2LeafFuzz&8] &r",
                    "&cYou do not have permission to run this LeafFuzz command.",
                    "&cInvalid parameter '[param]': '[value]'.",
                    "&cUnknown subcommand '[arg]'. Use /fuzz help.",
                    "&eA diagnostic snapshot or fuzz pass is already running; please wait.",
                    "&aLeafFuzz configuration and messages reloaded.",
                    "&cLeafFuzz reload failed: [errors]"
            );
        }
    }

    public LeafFuzzConfig(
            int defaultEpisodes,
            double slowTickThresholdMs,
            boolean requireDisposableForAll,
            String restartStrategy,
            int maxRestartRetries,
            List<String> extraDenylist,
            Messages messages,
            LlmAuditConfig llmAudit
    ) {
        this(
                defaultEpisodes,
                1,
                slowTickThresholdMs,
                requireDisposableForAll,
                restartStrategy,
                maxRestartRetries,
                extraDenylist,
                messages,
                llmAudit
        );
    }

    public LeafFuzzConfig(
            int defaultEpisodes,
            double slowTickThresholdMs,
            boolean requireDisposableForAll,
            String restartStrategy,
            int maxRestartRetries,
            List<String> extraDenylist,
            Messages messages
    ) {
        this(
                defaultEpisodes,
                1,
                slowTickThresholdMs,
                requireDisposableForAll,
                restartStrategy,
                maxRestartRetries,
                extraDenylist,
                messages,
                LlmAuditConfig.defaults()
        );
    }

    public LeafFuzzConfig {
        defaultEpisodes = Math.max(1, Math.min(100_000, defaultEpisodes));
        defaultPlayers = (defaultPlayers == LeafFuzzRuntime.AUTO_RAMP_PLAYERS)
                ? LeafFuzzRuntime.AUTO_RAMP_PLAYERS
                : Math.max(1, Math.min(500, defaultPlayers));
        slowTickThresholdMs = (Double.isFinite(slowTickThresholdMs) && slowTickThresholdMs >= 10.0)
                ? slowTickThresholdMs
                : 100.0;
        restartStrategy = (restartStrategy == null || restartStrategy.isBlank()) ? "AUTO" : restartStrategy.trim();
        maxRestartRetries = Math.max(1, Math.min(20, maxRestartRetries));
        extraDenylist = extraDenylist == null ? List.of() : List.copyOf(extraDenylist);
        messages = messages != null ? messages : Messages.defaults();
        llmAudit = llmAudit != null ? llmAudit : LlmAuditConfig.defaults();
    }

    public static LeafFuzzConfig defaults() {
        return new LeafFuzzConfig(
                250,
                1,
                100.0,
                true,
                "AUTO",
                3,
                List.of(),
                Messages.defaults(),
                LlmAuditConfig.defaults()
        );
    }

    /**
     * Loads {@code config.yml} and {@code messages.yml} from {@code rootFolder}, writing defaults
     * if absent.
     *
     * @param rootFolder plugin or mod configuration directory
     * @return loaded {@link LeafFuzzConfig}
     */
    public static LeafFuzzConfig load(Path rootFolder) {
        if (rootFolder == null) {
            return defaults();
        }
        try {
            Files.createDirectories(rootFolder);
            Path configPath = rootFolder.resolve("config.yml");
            if (!Files.exists(configPath)) {
                Files.writeString(configPath, defaultConfigYaml(), StandardCharsets.UTF_8);
            }
            Path messagesPath = rootFolder.resolve("messages.yml");
            if (!Files.exists(messagesPath)) {
                Files.writeString(messagesPath, defaultMessagesYaml(), StandardCharsets.UTF_8);
            }
            String configText = Files.readString(configPath, StandardCharsets.UTF_8);
            String messagesText = Files.readString(messagesPath, StandardCharsets.UTF_8);
            return parse(configText, messagesText);
        } catch (IOException ignored) {
            return defaults();
        }
    }

    /**
     * Validates {@code config.yml} and {@code messages.yml} in {@code rootFolder}.
     *
     * @param rootFolder plugin or mod configuration directory
     * @return list of validation error strings (empty if valid)
     */
    public static List<String> validateDirectory(Path rootFolder) {
        if (rootFolder == null || !Files.isDirectory(rootFolder)) {
            return List.of();
        }
        List<String> errors = new ArrayList<>();
        Path configPath = rootFolder.resolve("config.yml");
        if (Files.isRegularFile(configPath)) {
            try {
                String text = Files.readString(configPath, StandardCharsets.UTF_8);
                int episodes = parseIntScalar(text, "defaultEpisodes", 250);
                if (episodes <= 0 || episodes > 100_000) {
                    errors.add("config.yml:defaultEpisodes must be in [1, 100000]");
                }
                String rawPlayers = parseStringScalar(text, "defaultPlayers", "1");
                String trimmedPlayers = rawPlayers == null ? "1" : rawPlayers.trim().toLowerCase(Locale.ROOT);
                if (!"auto".equals(trimmedPlayers) && !"ramp".equals(trimmedPlayers)) {
                    int players = parseIntScalar(text, "defaultPlayers", -999);
                    if (players <= 0 || players > 500) {
                        errors.add("config.yml:defaultPlayers must be in [1, 500] or 'auto'/'ramp'");
                    }
                }
                double threshold = parseDoubleScalar(text, "slowTickThresholdMs", 100.0);
                if (!Double.isFinite(threshold) || threshold < 10.0) {
                    errors.add("config.yml:slowTickThresholdMs must be >= 10.0");
                }
            } catch (IOException e) {
                errors.add("config.yml: " + e.getMessage());
            }
        }
        return Collections.unmodifiableList(errors);
    }

    static LeafFuzzConfig parse(String configYaml, String messagesYaml) {
        int episodes = parseIntScalar(configYaml, "defaultEpisodes", 250);
        int players = parsePlayersScalar(configYaml, "defaultPlayers", 1);
        double slowTickMs = parseDoubleScalar(configYaml, "slowTickThresholdMs", 100.0);
        boolean requireDisposable = parseBooleanScalar(configYaml, "requireDisposableForAll", true);
        String strategy = parseStringScalar(configYaml, "restartStrategy", "AUTO");
        int maxRetries = parseIntScalar(configYaml, "maxRestartRetries", 3);
        List<String> extraDeny = parseListItems(configYaml, "extraDenylist");

        Messages defMsg = Messages.defaults();
        Messages msgs = new Messages(
                parseStringScalar(messagesYaml, "prefix", defMsg.prefix()),
                parseStringScalar(messagesYaml, "noPermission", defMsg.noPermission()),
                parseStringScalar(messagesYaml, "badParameter", defMsg.badParameter()),
                parseStringScalar(messagesYaml, "invalidCommand", defMsg.invalidCommand()),
                parseStringScalar(messagesYaml, "busy", defMsg.busy()),
                parseStringScalar(messagesYaml, "reloadSuccess", defMsg.reloadSuccess()),
                parseStringScalar(messagesYaml, "reloadFailed", defMsg.reloadFailed())
        );

        LlmAuditConfig defLlm = LlmAuditConfig.defaults();
        LlmAuditConfig llmCfg = new LlmAuditConfig(
                parseBooleanScalar(configYaml, "llmAuditEnabled", defLlm.enabled()),
                parseStringScalar(configYaml, "llmProvider", defLlm.provider()),
                parseStringScalar(configYaml, "llmModel", defLlm.model()),
                parseStringScalar(configYaml, "llmEndpoint", defLlm.endpoint()),
                parseStringScalar(configYaml, "llmApiKeyEnv", defLlm.apiKeyEnv()),
                parseBooleanScalar(configYaml, "explainFuzzFaults", defLlm.explainFuzzFaults()),
                parseIntScalar(configYaml, "maxChainsPerTarget", defLlm.maxChainsPerTarget())
        );

        return new LeafFuzzConfig(
                episodes,
                players,
                slowTickMs,
                requireDisposable,
                strategy,
                maxRetries,
                extraDeny,
                msgs,
                llmCfg
        );
    }

    private static String defaultConfigYaml() {
        return """
                # LeafFuzz - Cross-Platform In-JVM QC, Fuzzing & Memory-Leak Screener
                # Works across Paper, Spigot, Folia, Fabric, and NeoForge.
                check:
                  defaultEpisodes: 250
                  defaultPlayers: 1
                  slowTickThresholdMs: 100.0
                  requireDisposableForAll: true
                  extraDenylist: []

                campaign:
                  restartStrategy: "AUTO"
                  maxRestartRetries: 3

                llmAudit:
                  llmAuditEnabled: false
                  llmProvider: "OFF"
                  llmModel: "gemini-2.5-flash"
                  llmEndpoint: ""
                  llmApiKeyEnv: "GEMINI_API_KEY"
                  explainFuzzFaults: true
                  maxChainsPerTarget: 6
                """;
    }

    private static String defaultMessagesYaml() {
        return """
                # LeafFuzz Configurable Operator Feedback Messages
                prefix: "&8[&2LeafFuzz&8] &r"
                noPermission: "&cYou do not have permission to run this LeafFuzz command."
                badParameter: "&cInvalid parameter '[param]': '[value]'."
                invalidCommand: "&cUnknown subcommand '[arg]'. Use /fuzz help."
                busy: "&eA diagnostic snapshot or fuzz pass is already running; please wait."
                reloadSuccess: "&aLeafFuzz configuration and messages reloaded."
                reloadFailed: "&cLeafFuzz reload failed: [errors]"
                """;
    }

    private static String parseStringScalar(String yaml, String key, String fallback) {
        if (yaml == null || yaml.isBlank()) {
            return fallback;
        }
        String prefix = key + ":";
        for (String rawLine : yaml.split("\\R")) {
            String trimmed = rawLine.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            if (trimmed.startsWith(prefix)) {
                String val = trimmed.substring(prefix.length()).trim();
                int comment = val.indexOf(" #");
                if (comment >= 0) {
                    val = val.substring(0, comment).trim();
                }
                if (val.length() >= 2
                        && ((val.startsWith("\"") && val.endsWith("\""))
                                || (val.startsWith("'") && val.endsWith("'")))) {
                    val = val.substring(1, val.length() - 1);
                }
                return val.isEmpty() ? fallback : val;
            }
        }
        return fallback;
    }

    private static int parseIntScalar(String yaml, String key, int fallback) {
        String raw = parseStringScalar(yaml, key, null);
        if (raw == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static int parsePlayersScalar(String yaml, String key, int fallback) {
        String raw = parseStringScalar(yaml, key, null);
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

    private static double parseDoubleScalar(String yaml, String key, double fallback) {
        String raw = parseStringScalar(yaml, key, null);
        if (raw == null) {
            return fallback;
        }
        try {
            return Double.parseDouble(raw.trim());
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static boolean parseBooleanScalar(String yaml, String key, boolean fallback) {
        String raw = parseStringScalar(yaml, key, null);
        if (raw == null) {
            return fallback;
        }
        if ("true".equalsIgnoreCase(raw.trim())) {
            return true;
        }
        if ("false".equalsIgnoreCase(raw.trim())) {
            return false;
        }
        return fallback;
    }

    private static List<String> parseListItems(String yaml, String key) {
        if (yaml == null || yaml.isBlank()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        String prefix = key + ":";
        String[] lines = yaml.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (!trimmed.startsWith(prefix)) {
                continue;
            }
            String rest = trimmed.substring(prefix.length()).trim();
            if ("[]".equals(rest)) {
                return List.of();
            }
            for (int j = i + 1; j < lines.length; j++) {
                String sub = lines[j].trim();
                if (sub.isEmpty() || sub.startsWith("#")) {
                    continue;
                }
                if (!sub.startsWith("-")) {
                    break;
                }
                String item = sub.substring(1).trim();
                if (item.length() >= 2
                        && ((item.startsWith("\"") && item.endsWith("\""))
                                || (item.startsWith("'") && item.endsWith("'")))) {
                    item = item.substring(1, item.length() - 1).trim();
                }
                if (!item.isEmpty()) {
                    out.add(item);
                }
            }
            break;
        }
        return out;
    }
}
