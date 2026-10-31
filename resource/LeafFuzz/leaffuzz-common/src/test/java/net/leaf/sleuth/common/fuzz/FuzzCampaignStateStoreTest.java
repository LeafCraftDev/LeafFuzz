package net.leaf.sleuth.common.fuzz;

import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignState;
import net.leaf.sleuth.common.fuzz.FuzzCampaignStateStore.CampaignStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link FuzzCampaignStateStore} and {@link RestartStrategy}
 * ({@code REQ-SLEUTH-FUZZ-005}, {@code leafsleuth-ADR-006}).
 */
class FuzzCampaignStateStoreTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-005: FuzzCampaignStateStore round-trips fuzz-campaign.yml across all fields")
    void roundTripsCampaignStateYaml(@TempDir Path tempDir) throws IOException {
        Path dataFolder = tempDir.resolve("plugins").resolve("LeafSleuth");
        FuzzCampaignStateStore store = FuzzCampaignStateStore.forDataFolder(dataFolder);

        CampaignState initial = new CampaignState(
                "qa-campaign-01",
                CampaignStatus.AWAITING_RESTART_RESUME,
                RestartStrategy.SUPERVISOR_STOP,
                12,
                36,
                1,
                3,
                List.of("default", "op"),
                List.of("SuspectPlugin.jar"),
                List.of("leak:com.example.SuspectSession", "exc:java.lang.NullPointerException:com.example.Suspect.run"),
                1730000000000L
        );

        store.save(initial);
        assertTrue(Files.isRegularFile(store.stateFilePath()));

        Optional<CampaignState> loadedOpt = store.load();
        assertTrue(loadedOpt.isPresent());
        CampaignState loaded = loadedOpt.get();
        assertEquals("qa-campaign-01", loaded.campaignId());
        assertEquals(CampaignStatus.AWAITING_RESTART_RESUME, loaded.status());
        assertEquals(RestartStrategy.SUPERVISOR_STOP, loaded.restartStrategy());
        assertEquals(12, loaded.completedEpisodes());
        assertEquals(36, loaded.targetEpisodes());
        assertEquals(1, loaded.restartRetries());
        assertEquals(3, loaded.maxRestartRetries());
        assertEquals(List.of("default", "op"), loaded.activeTiers());
        assertEquals(List.of("SuspectPlugin.jar"), loaded.disabledPluginJars());
        assertEquals(2, loaded.discoveredSignatures().size());
        assertEquals(1730000000000L, loaded.updatedAtEpochMs());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-005: disableJarsForBisection writes manifest and abortAndRestore restores .jar.sleuth-disabled files")
    void disablesAndRestoresCandidateJarsCrashSafely(@TempDir Path tempDir) throws IOException {
        Path pluginsDir = tempDir.resolve("plugins");
        Path dataFolder = pluginsDir.resolve("LeafSleuth");
        Files.createDirectories(dataFolder);

        Path pluginA = pluginsDir.resolve("PluginA.jar");
        Path pluginB = pluginsDir.resolve("PluginB.jar");
        Path selfJar = pluginsDir.resolve("LeafSleuth-1.0.jar");
        Files.writeString(pluginA, "jar-a", StandardCharsets.UTF_8);
        Files.writeString(pluginB, "jar-b", StandardCharsets.UTF_8);
        Files.writeString(selfJar, "self", StandardCharsets.UTF_8);

        FuzzCampaignStateStore store = FuzzCampaignStateStore.forDataFolder(dataFolder);
        CampaignState baseState = new CampaignState(
                "bisect-01",
                CampaignStatus.RUNNING,
                RestartStrategy.SPIGOT_RESTART,
                4,
                16,
                0,
                3,
                List.of("default"),
                List.of(),
                List.of(),
                1730000005000L
        );

        CampaignState updated = store.disableJarsForBisection(
                baseState,
                pluginsDir,
                List.of("PluginA.jar", "LeafSleuth-1.0.jar")
        );

        // LeafSleuth self JAR must never be disabled
        assertEquals(List.of("PluginA.jar"), updated.disabledPluginJars());
        assertFalse(Files.exists(pluginA));
        assertTrue(Files.isRegularFile(pluginsDir.resolve("PluginA.jar.sleuth-disabled")));
        assertTrue(Files.isRegularFile(selfJar));

        // Also simulate an orphaned .jar.sleuth-disabled file from an unexpected crash
        Path orphanDisabled = pluginsDir.resolve("OrphanPlugin.jar.sleuth-disabled");
        Files.writeString(orphanDisabled, "orphan", StandardCharsets.UTF_8);

        List<String> restored = store.abortAndRestore(pluginsDir);
        assertTrue(restored.contains("PluginA.jar"));
        assertTrue(restored.contains("OrphanPlugin.jar"));
        assertTrue(Files.isRegularFile(pluginA));
        assertTrue(Files.isRegularFile(pluginsDir.resolve("OrphanPlugin.jar")));
        assertFalse(Files.exists(pluginsDir.resolve("PluginA.jar.sleuth-disabled")));
        assertFalse(Files.exists(orphanDisabled));

        CampaignState afterAbort = store.load().orElseThrow();
        assertEquals(CampaignStatus.ABORTED, afterAbort.status());
        assertTrue(afterAbort.disabledPluginJars().isEmpty());
    }
}
