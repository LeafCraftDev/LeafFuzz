package net.leaf.fuzz.paper;

import io.github.dailystruggle.rtp.bukkitplatform.server.BukkitPluginServerAccessor;
import net.leaf.fuzz.common.LeafFuzzRuntime;
import net.leaf.sleuth.paper.fuzz.PaperCommandTreeInspector;
import net.leaf.sleuth.paper.fuzz.PaperRestartCoordinator;
import org.bukkit.plugin.java.JavaPlugin;

import java.nio.file.Path;

/**
 * Paper / Spigot / Folia plugin entry point for {@code LeafFuzz}, delegating platform services
 * to {@link BukkitPluginServerAccessor}, live Bukkit/Brigadier command-tree extraction to
 * {@link PaperCommandTreeInspector}, and domain lifecycle to {@link LeafFuzzRuntime}
 * ({@code leaffuzz-ADR-001}).
 *
 * @governedBy ADR-115
 * @governedBy ADR-125
 * @governedBy leaffuzz-ADR-001
 * @trace REQ-SLEUTH-FUZZ-003
 * @trace REQ-SLEUTH-FUZZ-004
 * @trace REQ-SLEUTH-FUZZ-005
 * @trace S-005
 */
public final class PaperLeafFuzzPlugin extends JavaPlugin {

    private BukkitPluginServerAccessor accessor;
    private LeafFuzzRuntime runtime;
    private PaperRestartCoordinator restartCoordinator;

    @Override
    public void onLoad() {
        if (!getDataFolder().exists()) {
            getDataFolder().mkdirs();
        }
        this.accessor = new BukkitPluginServerAccessor(this, "leaffuzz");
        this.runtime = new LeafFuzzRuntime(this.accessor);
        this.runtime.load();
    }

    @Override
    public void onEnable() {
        if (this.accessor == null || this.runtime == null) {
            this.accessor = new BukkitPluginServerAccessor(this, "leaffuzz");
            this.runtime = new LeafFuzzRuntime(this.accessor);
            this.runtime.load();
        }
        this.accessor.registerEvents();
        this.runtime.setPlatformCommandGraphSupplier(
                () -> PaperCommandTreeInspector.inspectTierCommandGraphs(getServer())
        );
        LeafFuzzPaperEpisodeRunner episodeRunner = new LeafFuzzPaperEpisodeRunner(getServer(), this.runtime);
        this.runtime.setPlatformEpisodeRunner(episodeRunner);
        this.runtime.setPlatformMsptSupplier(() -> {
            try {
                java.lang.reflect.Method m = getServer().getClass().getMethod("getAverageTickTime");
                Object res = m.invoke(getServer());
                if (res instanceof Number n) {
                    return n.doubleValue();
                }
            } catch (Throwable ignored) {
            }
            return 0.0;
        });
        this.runtime.bitSuite().setLiveCheckSupplier(() -> episodeRunner.runLivePlatformCanaries(this));
        this.runtime.start();

        Path dataDir = getDataFolder().toPath().toAbsolutePath();
        Path pluginsDir = dataDir.getParent();
        Path serverRoot = pluginsDir != null ? pluginsDir.getParent() : null;
        boolean isFolia = "folia".equalsIgnoreCase(this.accessor.getPlatform());
        this.restartCoordinator = new PaperRestartCoordinator(
                this.runtime.campaignStateStore(),
                pluginsDir,
                serverRoot,
                isFolia,
                this.runtime.config().restartStrategy(),
                System.getenv()
        );
        this.accessor.scheduler().ifPresent(
                sched -> this.restartCoordinator.handleBootRecoveryAndResume(
                        sched,
                        resumed -> this.runtime.runQcCheck("all", Math.max(1, resumed.targetEpisodes() - resumed.completedEpisodes()))
                )
        );
        registerWithLeafConfigWorkspaceIfPresent();
        getLogger().info("LeafFuzz (Paper/Folia) enabled. Run /fuzz check <PluginName|all> to run a 4-stage QC pass.");
    }

    private void registerWithLeafConfigWorkspaceIfPresent() {
        try {
            org.bukkit.plugin.Plugin leafConfig = getServer().getPluginManager().getPlugin("LeafConfig");
            if (leafConfig != null && leafConfig.isEnabled()) {
                var runtimeGetter = leafConfig.getClass().getMethod("runtime");
                Object cfgRuntime = runtimeGetter.invoke(leafConfig);
                if (cfgRuntime != null) {
                    var ingestMethod = cfgRuntime.getClass().getMethod("ingestPeerWorkspaceExtension", Object.class);
                    ingestMethod.invoke(cfgRuntime, this.runtime);
                }
            }
        } catch (Throwable ex) {
            getLogger().log(java.util.logging.Level.WARNING, "[LeafFuzz] Failed to register Plugin UML workspace tab with LeafConfig", ex);
        }
    }

    @Override
    public void onDisable() {
        if (this.runtime != null) {
            this.runtime.close();
        }
    }

    public LeafFuzzRuntime runtime() {
        return runtime;
    }

    public PaperRestartCoordinator restartCoordinator() {
        return restartCoordinator;
    }
}
