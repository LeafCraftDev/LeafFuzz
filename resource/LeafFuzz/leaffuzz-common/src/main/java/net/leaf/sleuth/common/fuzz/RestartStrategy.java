package net.leaf.sleuth.common.fuzz;

import java.util.Locale;

/**
 * Host JVM restart capability strategy for multi-boot QA calibration and JAR bisection campaigns
 * ({@code ADR-125}, {@code leafsleuth-ADR-006}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy ADR-129
 * @governedBy leafsleuth-ADR-006
 * @trace REQ-SLEUTH-FUZZ-005
 */
public enum RestartStrategy {
    /**
     * Default on Folia or when no restart script or external supervisor is configured;
     * runs 100% of in-JVM discovery, {@link JarClassOwnershipIndex} attribution, and command
     * {@code ddmin} shrinking within a single boot without stopping the server.
     */
    NONE,

    /**
     * Paper/Spigot with a valid, existing {@code spigot.yml -> settings.restart-script} file
     * (never selected automatically on Folia where {@code Spigot#restart()} throws
     * {@link UnsupportedOperationException}).
     */
    SPIGOT_RESTART,

    /**
     * Pterodactyl ({@code P_SERVER_UUID} / {@code PTERODACTYL_*}) or container process supervisor
     * that automatically restarts the JVM after a clean {@code Server#shutdown()}.
     */
    SUPERVISOR_STOP,

    /**
     * Driven externally by {@code scripts/bench_fuzz_server.py}.
     */
    EXTERNAL_HARNESS;

    /**
     * Parses a configuration string into a {@link RestartStrategy}, returning {@code null}
     * if {@code raw} is {@code null}, blank, or {@code "AUTO"} so auto-detection can run.
     *
     * @param raw configuration value
     * @return explicit {@link RestartStrategy}, or {@code null} for {@code "AUTO"}
     */
    public static RestartStrategy parseOrNullForAuto(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String clean = raw.trim().toUpperCase(Locale.ROOT).replace('-', '_');
        if ("AUTO".equals(clean) || "DEFAULT".equals(clean)) {
            return null;
        }
        for (RestartStrategy strategy : values()) {
            if (strategy.name().equals(clean)) {
                return strategy;
            }
        }
        return null;
    }

    /**
     * Returns whether this strategy supports multi-boot JVM restarts.
     *
     * @return {@code true} if restarts are supported
     */
    public boolean supportsMultiBootRestart() {
        return this != NONE;
    }
}
