package net.leaf.fuzz.paper;

import io.github.dailystruggle.server.api.ServerAccessor;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.fuzz.common.LeafFuzzScorecardReport;
import net.leaf.sleuth.common.fuzz.FuzzActionShrinker.EpisodeAction;
import net.leaf.sleuth.common.fuzz.SleuthServerFuzzer.EpisodeOutcome;
import net.leaf.sleuth.paper.fuzz.PaperCommandTreeInspector;
import org.bukkit.Server;
import org.bukkit.command.Command;
import org.bukkit.command.CommandMap;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.bukkit.event.Event;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.plugin.PluginManager;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Paper/Folia integration test for {@code LeafFuzz} verifying {@link PaperCommandTreeInspector}
 * integration with {@link LeafFuzzRuntime}.
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace S-005
 */
class LeafFuzzPaperIntegrationTest {

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-003 & REQ-SLEUTH-FUZZ-004: PaperCommandTreeInspector feeds LeafFuzzRuntime and flags unguarded default-tier commands")
    void paperCommandTreeInspectorIntegratesWithLeafFuzzRuntime(@TempDir Path tempDir) {
        CommandMap commandMap = mock(CommandMap.class);
        Command exposedCmd = new Command("myplugin", "Test plugin", "/myplugin <status|reload|delete>", List.of()) {
            @Override
            public boolean execute(CommandSender sender, String commandLabel, String[] args) {
                return true;
            }
        };
        exposedCmd.setPermission(null);
        when(commandMap.getKnownCommands()).thenReturn(Map.of(
                "myplugin", exposedCmd,
                "myplugin:myplugin", exposedCmd
        ));

        Server mockServer = mock(Server.class);
        when(mockServer.getCommandMap()).thenReturn(commandMap);

        ServerAccessor accessor = new ServerAccessor() {
            @Override
            public String getServerVersion() {
                return "1.21.4-R0.1-SNAPSHOT";
            }

            @Override
            public String getPlatform() {
                return "paper";
            }

            @Override
            public Integer getServerIntVersion() {
                return 21;
            }

            @Override
            public void log(Level level, String message) {
            }

            @Override
            public void log(Level level, String message, Throwable throwable) {
            }

            @Override
            public Path getRootFolder() {
                return tempDir;
            }

            @Override
            public void sendMessage(UUID playerId, String message, boolean error) {
            }
        };

        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        runtime.setPlatformCommandGraphSupplier(() -> PaperCommandTreeInspector.inspectTierCommandGraphs(mockServer));

        LeafFuzzScorecardReport report = runtime.runQcCheck("myplugin", 6);
        assertEquals(LeafFuzzScorecardReport.Verdict.WARN, report.stage1CommandSurfaceVerdict());
        assertFalse(report.leastPrivilegeFindings().isEmpty());
        assertTrue(
                report.leastPrivilegeFindings().stream().anyMatch(f -> "myplugin reload".equals(f.nodeId())),
                "Expected unguarded /myplugin reload to be flagged in Stage 1"
        );
        assertTrue(Files.isRegularFile(tempDir.resolve("reports").resolve("myplugin-qc-report.md")));
        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-BIO-001 & REQ-SLEUTH-FUZZ-004: LeafFuzzPaperEpisodeRunner dispatches commands as synthetic Player and fires PlayerQuitEvent and PlayerMoveEvent follow-ups")
    void paperEpisodeRunnerDispatchesPersonaPlayerCommandsAndFollowUpEvents(@TempDir Path tempDir) {
        Server mockServer = mock(Server.class);
        PluginManager mockPm = mock(PluginManager.class);
        when(mockServer.getPluginManager()).thenReturn(mockPm);
        when(mockServer.getWorlds()).thenReturn(List.of());

        List<Player> commandPlayerSenders = new ArrayList<>();
        List<String> commandStrings = new ArrayList<>();
        List<Event> firedEvents = new ArrayList<>();

        when(mockServer.dispatchCommand(any(CommandSender.class), anyString())).thenAnswer(inv -> {
            CommandSender sender = inv.getArgument(0);
            String cmdLine = inv.getArgument(1);
            if (sender instanceof Player p) {
                commandPlayerSenders.add(p);
                commandStrings.add(cmdLine);
                return true;
            }
            return false;
        });

        doAnswer(inv -> {
            Event ev = inv.getArgument(0);
            firedEvents.add(ev);
            return null;
        }).when(mockPm).callEvent(any(Event.class));

        ServerAccessor accessor = new ServerAccessor() {
            @Override
            public String getServerVersion() {
                return "1.21.4-R0.1-SNAPSHOT";
            }

            @Override
            public String getPlatform() {
                return "paper";
            }

            @Override
            public Integer getServerIntVersion() {
                return 21;
            }

            @Override
            public void log(Level level, String message) {
            }

            @Override
            public void log(Level level, String message, Throwable throwable) {
            }

            @Override
            public Path getRootFolder() {
                return tempDir;
            }

            @Override
            public void sendMessage(UUID playerId, String message, boolean error) {
            }
        };

        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        LeafFuzzPaperEpisodeRunner runner = new LeafFuzzPaperEpisodeRunner(mockServer, runtime);

        EpisodeOutcome quitOutcome = runner.runEpisode(List.of(
                new EpisodeAction("/targetplugin warp 64", "quit_lt1s", "targetplugin warp <n>", "default")
        ));
        assertFalse(quitOutcome.reproduced());
        assertEquals(1, commandPlayerSenders.size());
        assertEquals("targetplugin warp 64", commandStrings.get(0));
        assertFalse(commandPlayerSenders.get(0).isOp());
        assertTrue(firedEvents.stream().anyMatch(e -> e instanceof PlayerQuitEvent));
        assertEquals(1L, runtime.retentionScreener().totalDepartures());

        EpisodeOutcome moveOutcome = runner.runEpisode(List.of(
                new EpisodeAction("/targetplugin admin 256", "chunk_border_thrash", "targetplugin admin <n>", "op")
        ));
        assertFalse(moveOutcome.reproduced());
        assertEquals(2, commandPlayerSenders.size());
        assertTrue(commandPlayerSenders.get(1).isOp());
        assertTrue(firedEvents.stream().anyMatch(e -> e instanceof PlayerMoveEvent));
        assertFalse(runtime.recentBotSteps().isEmpty());

        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: dispatchTargetScopedEvent isolates target listeners and skips unprimed connection listeners")
    void dispatchTargetScopedEventIsolatesTargetsAndSkipsConnectionListeners(@TempDir Path tempDir) throws Exception {
        Server mockServer = mock(Server.class);
        PluginManager mockPm = mock(PluginManager.class);
        when(mockServer.getPluginManager()).thenReturn(mockPm);
        when(mockServer.getWorlds()).thenReturn(List.of());

        ServerAccessor accessor = new ServerAccessor() {
            @Override
            public String getServerVersion() {
                return "1.21.4-R0.1-SNAPSHOT";
            }

            @Override
            public String getPlatform() {
                return "paper";
            }

            @Override
            public Integer getServerIntVersion() {
                return 21;
            }

            @Override
            public void log(Level level, String message) {
            }

            @Override
            public void log(Level level, String message, Throwable throwable) {
            }

            @Override
            public Path getRootFolder() {
                return tempDir;
            }

            @Override
            public void sendMessage(UUID playerId, String message, boolean error) {
            }
        };

        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        java.lang.reflect.Method helper = LeafFuzzPaperEpisodeRunner.class.getDeclaredMethod(
                "isUnprimedConnectionSessionListener",
                String.class
        );
        helper.setAccessible(true);
        assertTrue((Boolean) helper.invoke(null, "me.lucko.luckperms.bukkit.listeners.BukkitConnectionListener"));
        assertTrue((Boolean) helper.invoke(null, "com.example.auth.PreLoginListener"));
        assertFalse((Boolean) helper.invoke(null, "me.superischroma.betterrtp.player.PlayerJoinListener"));
        runtime.close();
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: rankSalientMenuSlots prioritizes distinct shiny items over filler panes and barriers")
    void rankSalientMenuSlotsPrioritizesShinyItemsOverFillerPanes() {
        org.bukkit.inventory.Inventory mockInv = mock(org.bukkit.inventory.Inventory.class);
        when(mockInv.getSize()).thenReturn(27);
        for (int i = 0; i < 27; i++) {
            org.bukkit.inventory.ItemStack item = mock(org.bukkit.inventory.ItemStack.class);
            if (i == 11) {
                when(item.getType()).thenReturn(org.bukkit.Material.GRASS_BLOCK);
                when(item.hasItemMeta()).thenReturn(true);
                org.bukkit.inventory.meta.ItemMeta meta = mock(org.bukkit.inventory.meta.ItemMeta.class);
                when(meta.hasDisplayName()).thenReturn(true);
                when(meta.getDisplayName()).thenReturn("§aOverworld");
                when(meta.hasLore()).thenReturn(true);
                when(meta.getLore()).thenReturn(List.of("§7Click to teleport"));
                when(item.getItemMeta()).thenReturn(meta);
            } else if (i == 15) {
                when(item.getType()).thenReturn(org.bukkit.Material.OAK_SAPLING);
                when(item.hasItemMeta()).thenReturn(true);
                org.bukkit.inventory.meta.ItemMeta meta = mock(org.bukkit.inventory.meta.ItemMeta.class);
                when(meta.hasDisplayName()).thenReturn(true);
                when(meta.getDisplayName()).thenReturn("§2Select Biome...");
                when(meta.hasLore()).thenReturn(true);
                when(meta.getLore()).thenReturn(List.of("§7Open biome sub-menu"));
                when(item.getItemMeta()).thenReturn(meta);
            } else if (i == 22) {
                when(item.getType()).thenReturn(org.bukkit.Material.BARRIER);
                when(item.hasItemMeta()).thenReturn(false);
            } else {
                when(item.getType()).thenReturn(org.bukkit.Material.GRAY_STAINED_GLASS_PANE);
                when(item.hasItemMeta()).thenReturn(false);
            }
            when(mockInv.getItem(i)).thenReturn(item);
        }

        List<LeafFuzzPaperEpisodeRunner.SalientSlot> salient =
                LeafFuzzPaperEpisodeRunner.rankSalientMenuSlots(mockInv);
        assertEquals(2, salient.size());
        assertEquals(11, salient.get(0).slot());
        assertEquals("GRASS_BLOCK", salient.get(0).material());
        assertEquals(15, salient.get(1).slot());
        assertEquals("OAK_SAPLING", salient.get(1).material());
    }

    @Test
    @DisplayName("REQ-SLEUTH-FUZZ-004: dispatchReversibleWorldMicroSkill fires BlockBreakEvent and restores BlockData, and auditGuiItemExtraction flags leaked menu icons")
    void reversibleWorldMicroSkillAndGuiItemConservationWorkCleanly(@TempDir Path tempDir) {
        Server mockServer = mock(Server.class);
        PluginManager mockPm = mock(PluginManager.class);
        when(mockServer.getPluginManager()).thenReturn(mockPm);

        org.bukkit.World mockWorld = mock(org.bukkit.World.class);
        when(mockWorld.isChunkLoaded(0, 0)).thenReturn(true);
        when(mockWorld.getMinHeight()).thenReturn(-64);
        when(mockWorld.getMaxHeight()).thenReturn(320);

        org.bukkit.block.Block mockBlock = mock(org.bukkit.block.Block.class);
        org.bukkit.block.data.BlockData mockData = mock(org.bukkit.block.data.BlockData.class);
        when(mockData.clone()).thenReturn(mockData);
        when(mockBlock.getBlockData()).thenReturn(mockData);
        when(mockWorld.getBlockAt(1, 64, 0)).thenReturn(mockBlock);

        Player mockPlayer = mock(Player.class);
        when(mockPlayer.getLocation()).thenReturn(new org.bukkit.Location(mockWorld, 0.5, 64.0, 0.5));
        when(mockPlayer.isOp()).thenReturn(false);

        List<Event> fired = new ArrayList<>();
        doAnswer(inv -> {
            fired.add(inv.getArgument(0));
            return null;
        }).when(mockPm).callEvent(any(Event.class));

        ServerAccessor accessor = new ServerAccessor() {
            @Override
            public String getServerVersion() {
                return "1.21.4";
            }

            @Override
            public String getPlatform() {
                return "paper";
            }

            @Override
            public Integer getServerIntVersion() {
                return 21;
            }

            @Override
            public void log(Level level, String message) {
            }

            @Override
            public void log(Level level, String message, Throwable throwable) {
            }

            @Override
            public Path getRootFolder() {
                return tempDir;
            }

            @Override
            public void sendMessage(UUID playerId, String message, boolean error) {
            }
        };

        LeafFuzzRuntime runtime = new LeafFuzzRuntime(accessor);
        runtime.load();
        List<String> tokens = new ArrayList<>();

        LeafFuzzPaperEpisodeRunner.dispatchReversibleWorldMicroSkill(
                mockServer,
                mockPlayer,
                "harvest_nearest",
                runtime,
                runtime.faultOracle(),
                tokens
        );
        assertTrue(tokens.contains("effect:block_break:harvest_nearest"));
        org.mockito.Mockito.verify(mockBlock).setBlockData(mockData, false);

        // Now verify GUI menu icon leak detection when a cancelled GUI click leaves the icon in the player's inventory
        org.bukkit.inventory.PlayerInventory mockPlayerInv = mock(org.bukkit.inventory.PlayerInventory.class);
        org.bukkit.inventory.ItemStack leakedIcon = mock(org.bukkit.inventory.ItemStack.class);
        when(leakedIcon.getType()).thenReturn(org.bukkit.Material.DIAMOND);
        when(leakedIcon.getAmount()).thenReturn(1);
        when(leakedIcon.hasItemMeta()).thenReturn(true);
        org.bukkit.inventory.meta.ItemMeta iconMeta = mock(org.bukkit.inventory.meta.ItemMeta.class);
        when(iconMeta.hasDisplayName()).thenReturn(true);
        when(iconMeta.getDisplayName()).thenReturn("§bRandom teleport");
        when(leakedIcon.getItemMeta()).thenReturn(iconMeta);
        when(mockPlayerInv.getContents()).thenReturn(new org.bukkit.inventory.ItemStack[]{leakedIcon});
        when(mockPlayer.getInventory()).thenReturn(mockPlayerInv);

        LeafFuzzPaperEpisodeRunner.SalientSlot chosen = new LeafFuzzPaperEpisodeRunner.SalientSlot(
                22, "DIAMOND", "Random teleport", 1, 200.0
        );
        LeafFuzzPaperEpisodeRunner.auditGuiItemExtraction(
                mockPlayer,
                null,
                "Teleport Menu",
                chosen,
                0,
                true,
                "/rtp menu",
                runtime.faultOracle(),
                tokens
        );
        assertEquals(1L, runtime.faultOracle().totalHazardsRecorded());
        LeafFuzzPaperEpisodeRunner runner = new LeafFuzzPaperEpisodeRunner(mockServer, runtime);
        LeafFuzzRuntime.SwarmSnapshot swarmSnap = runner.rampToPopulation(12);
        assertEquals(12, swarmSnap.onlinePlayers());
        for (int s = 0; s < 6; s++) {
            runner.stepConcurrentSwarm(0);
        }
        assertTrue(
                runtime.recentBotSteps().stream().anyMatch(
                        net.leaf.sleuth.common.fuzz.PersonaPolicyBotActor.BotStepRecord::isWorldMutationSkill
                ),
                "Paper stepConcurrentSwarm must execute mining/building bot micro-skills"
        );
        runner.teardownAll();
        runtime.close();
    }

    @Test
    @DisplayName("S-005: leaffuzz-paper source files never call synchronous getChunkAt or loadChunk")
    void leaffuzzPaperNeverCallsSynchronousChunkLoad() throws IOException {
        Path srcMain = Paths.get("src", "main", "java");
        assertTrue(Files.exists(srcMain));
        try (Stream<Path> walk = Files.walk(srcMain)) {
            List<Path> files = walk.filter(p -> p.toString().endsWith(".java")).toList();
            assertFalse(files.isEmpty());
            for (Path file : files) {
                String source = Files.readString(file, StandardCharsets.UTF_8);
                assertFalse(
                        source.contains(".getChunkAt(") || source.contains(".loadChunk("),
                        () -> "S-005 violation in " + file
                );
            }
        }
    }
}
