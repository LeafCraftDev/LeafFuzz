package net.leaf.fuzz.common;

import java.util.UUID;

/**
 * Platform-neutral factory for synthetic Brigadier command sources and typed command execution
 * callbacks used by {@link LeafFuzzRuntime} when dispatching commands against a live Brigadier
 * {@code CommandDispatcher} ({@code ADR-125}, {@code leaffuzz-ADR-001}).
 *
 * <p>Operates with zero reflection and zero platform or mod-loader imports.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 */
public final class BrigadierSyntheticSourceFactory {

    /**
     * Typed command-execution interface for custom Brigadier dispatchers or test harnesses.
     */
    @FunctionalInterface
    public interface BrigadierExecutableDispatcher {
        int execute(String input, Object source) throws Exception;
    }

    private BrigadierSyntheticSourceFactory() {
    }

    /**
     * Creates a synthetic Brigadier command source for the given bot actor.
     *
     * @param sourceType expected command source parameter type
     * @param actorUuid  synthetic bot UUID
     * @param actorName  synthetic bot name
     * @param op         whether the synthetic bot is in the {@code op} tier (permission level 4)
     * @param x          synthetic bot block X
     * @param y          synthetic bot block Y
     * @param z          synthetic bot block Z
     * @return synthetic source instance
     */
    public static SyntheticCommandSourceStub createSource(
            Class<?> sourceType,
            UUID actorUuid,
            String actorName,
            boolean op,
            int x,
            int y,
            int z
    ) {
        if (sourceType == null) {
            return null;
        }
        int permLevel = op ? 4 : 0;
        return new SyntheticCommandSourceStub(actorUuid, actorName, op, permLevel, x, y, z);
    }

    /**
     * Value-object command source stub used when a Brigadier dispatcher accepts
     * {@code CommandDispatcher<Object>} or {@link SyntheticCommandSourceStub}.
     *
     * @param actorUuid       synthetic bot UUID
     * @param actorName       synthetic bot name
     * @param op              whether the bot is op
     * @param permissionLevel Brigadier permission level ({@code 0} or {@code 4})
     * @param x               block X
     * @param y               block Y
     * @param z               block Z
     */
    public record SyntheticCommandSourceStub(
            UUID actorUuid,
            String actorName,
            boolean op,
            int permissionLevel,
            int x,
            int y,
            int z
    ) {
        public boolean hasPermission(int level) {
            return permissionLevel >= level;
        }

        public boolean hasPermissionLevel(int level) {
            return permissionLevel >= level;
        }
    }
}
