package net.leaf.sleuth.paper.fuzz;

import io.github.dailystruggle.server.api.ServerAccessor;
import io.github.dailystruggle.server.api.TaskScheduler;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignState;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignStatus;
import net.leaf.sleuth.common.fuzz.RestartStrategy;
import org.bukkit.Bukkit;
import org.bukkit.Server;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Host-aware JVM restart strategy detector and post-boot campaign resume coordinator for
 * Paper, Folia, and Pterodactyl environments ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * <p>Auto-detection priority:
 * <ol>
 *   <li>Explicit configuration override ({@code fuzz.restartStrategy}) when not {@code "AUTO"}.</li>
 *   <li>{@link RestartStrategy#SUPERVISOR_STOP} when Pterodactyl environment variables
 *       ({@code P_SERVER_UUID} or {@code PTERODACTYL_*}) are present.</li>
 *   <li>{@link RestartStrategy#NONE} when running on Folia ({@link ServerAccessor#isFolia()}),
 *       where {@code Bukkit.spigot().restart()} throws {@link UnsupportedOperationException}.</li>
 *   <li>{@link RestartStrategy#SPIGOT_RESTART} on Paper/Spigot when {@code spigot.yml}
 *       {@code settings.restart-script} points to an existing file on disk.</li>
 *   <li>{@link RestartStrategy#NONE} otherwise.</li>
 * </ol>
 *
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-005
 * @trace S-005
 */
public final class PaperRestartCoordinator {

    /** Post-boot settle delay in ticks before resuming a multi-boot campaign ({@code 100L}). */
    public static final long POST_BOOT_SETTLE_TICKS = 100L;

    private static final Logger LOGGER = Logger.getLogger(PaperRestartCoordinator.class.getName());

    private final FuzzCampaignStateStore stateStore;
    private final Path pluginsDir;
    private final Path serverRootDir;
    private final RestartStrategy resolvedStrategy;
    private final boolean folia;

    public PaperRestartCoordinator(
            FuzzCampaignStateStore stateStore,
            Path pluginsDir,
            Path serverRootDir,
            boolean isFolia,
            String configuredStrategy,
            Map<String, String> environment
    ) {
        this.stateStore = Objects.requireNonNull(stateStore, "stateStore");
        this.pluginsDir = pluginsDir;
        this.serverRootDir = serverRootDir;
        this.folia = isFolia;
        this.resolvedStrategy = detectRestartStrategy(
                isFolia,
                serverRootDir,
                configuredStrategy,
                environment != null ? environment : System.getenv()
        );
    }

    /**
     * Auto-detects the appropriate {@link RestartStrategy} for the current server host.
     *
     * @param isFolia            whether the server is running Folia regional threading
     * @param serverRootDir      server root directory containing {@code spigot.yml}
     * @param configuredStrategy optional {@code fuzz.restartStrategy} setting from {@code config.yml}
     * @param environment        process environment variables
     * @return resolved {@link RestartStrategy}
     */
    public static RestartStrategy detectRestartStrategy(
            boolean isFolia,
            Path serverRootDir,
            String configuredStrategy,
            Map<String, String> environment
    ) {
        RestartStrategy explicit = RestartStrategy.parseOrNullForAuto(configuredStrategy);
        if (explicit != null) {
            // Never allow SPIGOT_RESTART on Folia where Spigot#restart() throws UnsupportedOperationException
            if (isFolia && explicit == RestartStrategy.SPIGOT_RESTART) {
                return RestartStrategy.NONE;
            }
            return explicit;
        }
        if (hasPterodactylEnvironment(environment)) {
            return RestartStrategy.SUPERVISOR_STOP;
        }
        if (isFolia) {
            return RestartStrategy.NONE;
        }
        if (hasExistingSpigotRestartScript(serverRootDir)) {
            return RestartStrategy.SPIGOT_RESTART;
        }
        return RestartStrategy.NONE;
    }

    /**
     * Checks whether Pterodactyl panel/Wings environment variables ({@code P_SERVER_UUID} or
     * {@code PTERODACTYL_*}) are present in {@code environment}.
     *
     * @param environment environment variable map
     * @return {@code true} if Pterodactyl container environment is detected
     */
    public static boolean hasPterodactylEnvironment(Map<String, String> environment) {
        if (environment == null || environment.isEmpty()) {
            return false;
        }
        String uuid = environment.get("P_SERVER_UUID");
        if (uuid != null && !uuid.isBlank()) {
            return true;
        }
        for (Map.Entry<String, String> entry : environment.entrySet()) {
            String key = entry.getKey();
            String val = entry.getValue();
            if (key != null
                    && key.toUpperCase(Locale.ROOT).startsWith("PTERODACTYL_")
                    && val != null
                    && !val.isBlank()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether {@code spigot.yml} in {@code serverRootDir} defines a
     * {@code restart-script} setting pointing to an existing regular file.
     *
     * @param serverRootDir server root directory
     * @return {@code true} if {@code spigot.yml} has an existing {@code restart-script}
     */
    public static boolean hasExistingSpigotRestartScript(Path serverRootDir) {
        if (serverRootDir == null || !Files.isDirectory(serverRootDir)) {
            return false;
        }
        Path spigotYml = serverRootDir.resolve("spigot.yml");
        if (!Files.isRegularFile(spigotYml)) {
            return false;
        }
        try {
            String content = Files.readString(spigotYml, StandardCharsets.UTF_8);
            for (String line : content.split("\\R")) {
                String trimmed = line.trim();
                if (trimmed.startsWith("restart-script:")) {
                    String rawPath = trimmed.substring("restart-script:".length()).trim();
                    int comment = rawPath.indexOf('#');
                    if (comment >= 0) {
                        rawPath = rawPath.substring(0, comment).trim();
                    }
                    if ((rawPath.startsWith("\"") && rawPath.endsWith("\""))
                            || (rawPath.startsWith("'") && rawPath.endsWith("'"))) {
                        if (rawPath.length() >= 2) {
                            rawPath = rawPath.substring(1, rawPath.length() - 1).trim();
                        }
                    }
                    if (rawPath.isEmpty()) {
                        return false;
                    }
                    Path resolved = serverRootDir.resolve(rawPath).normalize();
                    return Files.isRegularFile(resolved);
                }
            }
        } catch (IOException ignored) {
        }
        return false;
    }

    /**
     * Evaluates persisted campaign state on plugin boot (off-thread via {@link TaskScheduler}),
     * restoring any orphaned {@code .jar.sleuth-disabled} files if the campaign is aborted,
     * completed, or exceeded its retry budget, or scheduling a 100-tick post-boot resume when
     * {@link CampaignStatus#AWAITING_RESTART_RESUME} is active.
     *
     * @param scheduler      Folia/Paper scheduler
     * @param resumeCallback callback invoked on the main thread after 100 ticks when resuming
     */
    public void handleBootRecoveryAndResume(
            TaskScheduler scheduler,
            Consumer<CampaignState> resumeCallback
    ) {
        if (scheduler == null) {
            performRecoveryCheckSync(null, resumeCallback);
            return;
        }
        scheduler.runAsync(() -> performRecoveryCheckSync(scheduler, resumeCallback));
    }

    /**
     * Performs synchronous state recovery check (suitable for background threads and unit tests).
     *
     * @param scheduler      optional scheduler for scheduling the 100-tick settle callback
     * @param resumeCallback callback receiving the resumed {@link CampaignState}
     * @return updated {@link CampaignState} if a state file was present
     */
    public Optional<CampaignState> performRecoveryCheckSync(
            TaskScheduler scheduler,
            Consumer<CampaignState> resumeCallback
    ) {
        Optional<CampaignState> opt = stateStore.load();
        if (opt.isEmpty()) {
            // Even without a state file, restore any orphaned .jar.sleuth-disabled files
            if (pluginsDir != null) {
                stateStore.restoreDisabledJars(pluginsDir);
            }
            return Optional.empty();
        }
        CampaignState state = opt.get();
        if (state.status() == CampaignStatus.ABORTED
                || state.status() == CampaignStatus.COMPLETED
                || state.status() == CampaignStatus.IDLE) {
            if (!state.disabledPluginJars().isEmpty() && pluginsDir != null) {
                stateStore.restoreDisabledJars(pluginsDir);
            }
            return Optional.of(state);
        }

        if (state.restartRetries() >= state.maxRestartRetries()) {
            LOGGER.warning("[LeafSleuth] Campaign " + state.campaignId()
                    + " exceeded maxRestartRetries (" + state.maxRestartRetries()
                    + "); aborting and restoring disabled plugin JARs.");
            stateStore.abortAndRestore(pluginsDir);
            return stateStore.load();
        }

        if (state.status() == CampaignStatus.AWAITING_RESTART_RESUME) {
            CampaignState resumed = state.withIncrementedRetry(CampaignStatus.RUNNING, System.currentTimeMillis());
            try {
                stateStore.save(resumed);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "[LeafSleuth] Failed to save resumed campaign state", e);
            }
            if (resumeCallback != null) {
                if (scheduler != null) {
                    scheduler.runSyncDelayed(() -> resumeCallback.accept(resumed), POST_BOOT_SETTLE_TICKS);
                } else {
                    resumeCallback.accept(resumed);
                }
            }
            return Optional.of(resumed);
        }
        return Optional.of(state);
    }

    /**
     * Checkpoints {@code state} as {@link CampaignStatus#AWAITING_RESTART_RESUME} and triggers
     * the configured {@link RestartStrategy} if multi-boot restarts are supported.
     *
     * @param state  campaign state to checkpoint before restart
     * @param server Bukkit/Paper server instance
     * @return {@code true} if a restart/shutdown was initiated, {@code false} if {@link RestartStrategy#NONE}
     */
    public boolean checkpointAndTriggerRestart(CampaignState state, Server server) {
        Objects.requireNonNull(state, "state");
        if (resolvedStrategy == RestartStrategy.NONE || (folia && resolvedStrategy == RestartStrategy.SPIGOT_RESTART)) {
            return false;
        }
        CampaignState awaiting = state.withStatus(CampaignStatus.AWAITING_RESTART_RESUME, System.currentTimeMillis());
        try {
            stateStore.save(awaiting);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "[LeafSleuth] Refusing to trigger restart because campaign state could not be saved", e);
            return false;
        }

        if (resolvedStrategy == RestartStrategy.EXTERNAL_HARNESS) {
            return true;
        }
        Server targetServer = server != null ? server : safeBukkitServer();
        if (targetServer == null) {
            return false;
        }
        if (resolvedStrategy == RestartStrategy.SPIGOT_RESTART && !folia) {
            try {
                invokeSpigotRestart(targetServer);
                return true;
            } catch (Throwable t) {
                LOGGER.log(Level.WARNING, "[LeafSleuth] Spigot restart failed; falling back to single-boot mode", t);
                return false;
            }
        }
        if (resolvedStrategy == RestartStrategy.SUPERVISOR_STOP) {
            try {
                targetServer.shutdown();
                return true;
            } catch (Throwable t) {
                LOGGER.log(Level.WARNING, "[LeafSleuth] Supervisor shutdown failed", t);
                return false;
            }
        }
        return false;
    }

    public FuzzCampaignStateStore stateStore() {
        return stateStore;
    }

    public Path pluginsDir() {
        return pluginsDir;
    }

    public Path serverRootDir() {
        return serverRootDir;
    }

    public RestartStrategy resolvedStrategy() {
        return resolvedStrategy;
    }

    public boolean isFolia() {
        return folia;
    }

    @SuppressWarnings({"deprecation", "removal"})
    private static void invokeSpigotRestart(Server targetServer) {
        targetServer.spigot().restart();
    }

    private static Server safeBukkitServer() {
        try {
            return Bukkit.getServer();
        } catch (Throwable ignored) {
            return null;
        }
    }
}
