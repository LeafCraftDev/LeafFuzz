package net.leaf.sleuth.paper.fuzz;

import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignState;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignStatus;
import net.leaf.sleuth.common.fuzz.RestartStrategy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link PaperRestartCoordinator} and {@link DisposableServerSafetyGate}
 * ({@code REQ-SLEUTH-FUZZ-004}, {@code REQ-SLEUTH-FUZZ-005}, {@code leafsleuth-ADR-006}).
 */
class PaperRestartCoordinatorTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-005: PaperRestartCoordinator selects NONE on Folia, SPIGOT_RESTART on Paper with restart-script, and SUPERVISOR_STOP on Pterodactyl")
    void autoDetectsRestartStrategyAcrossFoliaPaperAndPterodactyl(@TempDir Path serverRoot) throws IOException {
        Path startScript = serverRoot.resolve("start.sh");
        Files.writeString(startScript, "#!/bin/sh\n", StandardCharsets.UTF_8);
        Files.writeString(
                serverRoot.resolve("spigot.yml"),
                "settings:\n  restart-script: ./start.sh\n",
                StandardCharsets.UTF_8
        );

        // 1. Folia without Pterodactyl -> NONE (even if spigot.yml has restart-script)
        assertEquals(
                RestartStrategy.NONE,
                PaperRestartCoordinator.detectRestartStrategy(true, serverRoot, "AUTO", Map.of())
        );

        // 2. Folia with explicit SPIGOT_RESTART override -> clamped to NONE for safety
        assertEquals(
                RestartStrategy.NONE,
                PaperRestartCoordinator.detectRestartStrategy(true, serverRoot, "SPIGOT_RESTART", Map.of())
        );

        // 3. Paper (!isFolia) with existing restart-script -> SPIGOT_RESTART
        assertEquals(
                RestartStrategy.SPIGOT_RESTART,
                PaperRestartCoordinator.detectRestartStrategy(false, serverRoot, "AUTO", Map.of())
        );

        // 4. Pterodactyl environment (P_SERVER_UUID) -> SUPERVISOR_STOP
        assertEquals(
                RestartStrategy.SUPERVISOR_STOP,
                PaperRestartCoordinator.detectRestartStrategy(
                        true,
                        serverRoot,
                        "AUTO",
                        Map.of("P_SERVER_UUID", "a1b2c3d4-e5f6")
                )
        );

        // 5. Paper without existing restart-script -> NONE
        Files.deleteIfExists(startScript);
        assertEquals(
                RestartStrategy.NONE,
                PaperRestartCoordinator.detectRestartStrategy(false, serverRoot, "AUTO", Map.of())
        );
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-005: PaperRestartCoordinator resumes AWAITING_RESTART_RESUME and aborts/restores when retry budget is exceeded")
    void bootRecoveryResumesWithinBudgetAndRestoresOnRetryExhaustion(@TempDir Path serverRoot) throws IOException {
        Path pluginsDir = serverRoot.resolve("plugins");
        Path dataFolder = pluginsDir.resolve("LeafSleuth");
        Files.createDirectories(dataFolder);

        FuzzCampaignStateStore store = FuzzCampaignStateStore.forDataFolder(dataFolder);
        PaperRestartCoordinator coordinator = new PaperRestartCoordinator(
                store,
                pluginsDir,
                serverRoot,
                false,
                "SUPERVISOR_STOP",
                Map.of("P_SERVER_UUID", "test-uuid")
        );

        CampaignState awaiting = new CampaignState(
                "resume-test",
                CampaignStatus.AWAITING_RESTART_RESUME,
                RestartStrategy.SUPERVISOR_STOP,
                8,
                24,
                0,
                2,
                List.of("default"),
                List.of(),
                List.of(),
                1730000010000L
        );
        store.save(awaiting);

        AtomicReference<CampaignState> resumedRef = new AtomicReference<>();
        coordinator.performRecoveryCheckSync(null, resumedRef::set);

        assertNotNull(resumedRef.get());
        assertEquals(CampaignStatus.RUNNING, resumedRef.get().status());
        assertEquals(1, resumedRef.get().restartRetries());

        // Now simulate exceeding maxRestartRetries with a disabled JAR present
        Path disabledJar = pluginsDir.resolve("LagPlugin.jar.sleuth-disabled");
        Files.writeString(disabledJar, "binary", StandardCharsets.UTF_8);
        CampaignState exhausted = new CampaignState(
                "resume-test",
                CampaignStatus.AWAITING_RESTART_RESUME,
                RestartStrategy.SUPERVISOR_STOP,
                16,
                24,
                2,
                2,
                List.of("default"),
                List.of("LagPlugin.jar"),
                List.of(),
                1730000020000L
        );
        store.save(exhausted);

        AtomicReference<CampaignState> secondResumeRef = new AtomicReference<>();
        coordinator.performRecoveryCheckSync(null, secondResumeRef::set);

        assertEquals(null, secondResumeRef.get(), "Must not resume when retry budget is exhausted");
        assertTrue(Files.isRegularFile(pluginsDir.resolve("LagPlugin.jar")), "Must restore .jar.sleuth-disabled on abort");
        assertFalse(Files.exists(disabledJar));
        assertEquals(CampaignStatus.ABORTED, store.load().orElseThrow().status());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: DisposableServerSafetyGate fails closed when marker is missing or online-mode=true")
    void disposableSafetyGateFailsClosedOnProductionServers(@TempDir Path serverRoot) throws IOException {
        Path dataFolder = serverRoot.resolve("plugins").resolve("LeafSleuth");
        Files.createDirectories(dataFolder);

        assertFalse(DisposableServerSafetyGate.verify(dataFolder, false).allowed());

        Files.writeString(dataFolder.resolve(".bench-disposable"), "disposable\n", StandardCharsets.UTF_8);
        assertFalse(
                DisposableServerSafetyGate.verify(dataFolder, true).allowed(),
                "Must reject when online-mode=true even if .bench-disposable exists"
        );
        assertTrue(
                DisposableServerSafetyGate.verify(dataFolder, false).allowed(),
                "Must allow when .bench-disposable exists and online-mode=false"
        );
    }
}
