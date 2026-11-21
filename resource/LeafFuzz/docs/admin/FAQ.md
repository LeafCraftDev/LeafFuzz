# LeafFuzz — Frequently Asked Questions (FAQ)

## Does LeafFuzz work on Minecraft 26.3 as well as 26.2 and 1.21.x?
Yes. **LeafFuzz supports Minecraft `1.21.x`, `26.1`, `26.2`, and `26.3`** across **Paper**, **Folia**, **Spigot**, **Fabric**, and **NeoForge**. Both in-server `/fuzz check` auditing and standalone `swarm` mode work on `26.2` and `26.3`. See [SUPPORT_MATRIX.md](../dev/SUPPORT_MATRIX.md).

## How do I fuzz a specific plugin and read the report?
On a disposable test server, run `/fuzz check <PluginName>` (or `/fuzz check <PluginName> episodes=200`). When the run finishes, view the summary in-game with `/fuzz report <PluginName>` or open `plugins/LeafFuzz/reports/<PluginName>-qc-report.md`.

## Where do I configure `slowTickThresholdMs` and `defaultEpisodes`?
Edit `plugins/LeafFuzz/config.yml` (`slowTickThresholdMs`, `defaultEpisodes`, `seed`) and run `/fuzz reload`. See [CONFIGURATION.md](CONFIGURATION.md).

## What diagnostics should I share if `/fuzz` crashes or freezes?
Run `/fuzz status` and `/fuzz test`, attach `plugins/LeafFuzz/reports/<target>-qc-report.md`, and upload your `logs/latest.log` to <https://mclo.gs/>.
