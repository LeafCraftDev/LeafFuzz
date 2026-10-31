package net.leaf.sleuth.paper.fuzz;

import org.bukkit.Server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/**
 * Staging environment opt-in check for active in-JVM QA calibration campaigns
 * ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * <p>Requires both a disposable-staging marker file ({@code plugins/LeafSleuth/.bench-disposable}
 * or server-root {@code .bench-disposable}) and offline mode ({@code online-mode=false}) before
 * {@code /sleuth fuzz start} is permitted to execute synthetic command episodes.
 *
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-004
 */
public final class DisposableServerSafetyGate {

    /** Marker file name indicating an explicitly designated disposable/staging server environment. */
    public static final String DISPOSABLE_MARKER_FILE = ".bench-disposable";

    private static final List<String> ROOT_MARKER_FILES = List.of(
            ".bench-disposable",
            "bench-loop.sh",
            "no-restart-script.sh"
    );

    private DisposableServerSafetyGate() {
    }

    /**
     * Result of evaluating the staging safety gate.
     *
     * @param allowed whether active stress episodes are permitted to run
     * @param reason  human-readable status or rejection explanation
     */
    public record GateDecision(boolean allowed, String reason) {
        public GateDecision {
            Objects.requireNonNull(reason, "reason");
        }
    }

    /**
     * Evaluates whether the server environment satisfies staging opt-in requirements.
     *
     * @param pluginDataFolder {@code plugins/LeafSleuth} data directory
     * @param server           Bukkit/Paper server instance (nullable in headless tests)
     * @return {@link GateDecision} indicating whether active episodes are permitted
     */
    public static GateDecision verify(Path pluginDataFolder, Server server) {
        boolean onlineMode = true;
        if (server != null) {
            try {
                onlineMode = server.getOnlineMode();
            } catch (Throwable ignored) {
                onlineMode = true;
            }
        }
        return verify(pluginDataFolder, onlineMode);
    }

    /**
     * Evaluates whether {@code pluginDataFolder} and {@code onlineMode} satisfy staging opt-in requirements.
     *
     * @param pluginDataFolder {@code plugins/LeafSleuth} data directory
     * @param onlineMode       whether {@code online-mode=true} is active on the server
     * @return {@link GateDecision} indicating whether active episodes are permitted
     */
    public static GateDecision verify(Path pluginDataFolder, boolean onlineMode) {
        if (!hasDisposableMarker(pluginDataFolder)) {
            return new GateDecision(
                    false,
                    "Missing staging opt-in marker (create plugins/LeafSleuth/.bench-disposable on a disposable staging server)."
            );
        }
        if (onlineMode) {
            return new GateDecision(
                    false,
                    "Staging stress runner requires online-mode=false in server.properties (current online-mode=true)."
            );
        }
        return new GateDecision(true, "Staging opt-in verified (.bench-disposable present and online-mode=false).");
    }

    /**
     * Checks whether {@code plugins/LeafSleuth/.bench-disposable} or a server-root disposable
     * marker exists.
     *
     * @param pluginDataFolder {@code plugins/LeafSleuth} directory
     * @return {@code true} if a disposable marker file exists
     */
    public static boolean hasDisposableMarker(Path pluginDataFolder) {
        if (pluginDataFolder == null) {
            return false;
        }
        Path absData = pluginDataFolder.toAbsolutePath();
        if (Files.isRegularFile(absData.resolve(DISPOSABLE_MARKER_FILE))) {
            return true;
        }
        Path pluginsDir = absData.getParent();
        Path serverRoot = pluginsDir != null ? pluginsDir.getParent() : null;
        if (serverRoot != null) {
            for (String marker : ROOT_MARKER_FILES) {
                if (Files.isRegularFile(serverRoot.resolve(marker))) {
                    return true;
                }
            }
        }
        return false;
    }
}
