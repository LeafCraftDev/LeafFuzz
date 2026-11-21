# LeafFuzz Support Matrix

Canonical platform, Minecraft version, Java runtime, and execution mode compatibility matrix for **LeafFuzz** (autonomous in-server quality-control fuzzer & standalone multi-bot `swarm` harness).

---

## Minecraft Version & Platform Compatibility (1.21.x – 26.3)

Yes — **LeafFuzz supports Minecraft `1.21.x` (`1.21.1`–`1.21.11`), `26.1`, `26.2`, and `26.3`** across Paper, Folia, Spigot, Purpur, Fabric, and NeoForge.

| Platform / Loader | Supported Minecraft Versions | Java Requirement | Supported Modes (`/fuzz check` & `swarm`) | Status |
|---|---|---|---|---|
| **Paper / Purpur / Pufferfish** | `1.21.x`, `26.1`, `26.2`, `26.3` | Java 21+ | In-server `/fuzz check <plugin>`, `/fuzz test`, `/fuzz stress`, and external `swarm` target | **Tier-1 Supported** |
| **Folia** | `1.21.x`, `26.1`, `26.2`, `26.3` | Java 21+ | Region-thread invariant auditing (`F-001..F-003`), MSPT/tick-stall detection, `/fuzz check` | **Tier-1 Supported** |
| **Spigot / CraftBukkit** | `1.21.x`, `26.1`, `26.2`, `26.3` | Java 21+ | Command grammar fuzzing, permission matrix probing, config round-trip checks | **Supported** |
| **Fabric / NeoForge** | `1.21.x`, `26.1`, `26.2`, `26.3` | Java 21+ | Standalone `LeafFuzz` CLI `swarm` protocol harness & RCON/console fault monitor | **Supported** |

---

## Execution Mode Matrix

| Mode | Invocation | Target Environment | Capabilities |
|---|---|---|---|
| **In-Server Plugin Audit (`/fuzz check`)** | `/fuzz check <PluginName>` (`episodes=<n>`) | Disposable staging/test Paper, Folia, or Spigot server (`1.21.x`–`26.3`) | Introspects target JAR commands, permissions, listeners, and YAML schemas; runs property-based command & event episodes; writes `plugins/LeafFuzz/reports/<target>-qc-report.md` |
| **Built-In Self-Test (`/fuzz test`)** | `/fuzz test` | Any staging server | Runs `PBIT`/`CBIT`/`IBIT` self-tests (`[FUZZ bit]`) verifying sandbox guards, tick-stall watchdogs, and report writers |
| **Standalone Multi-Bot Swarm (`swarm`)** | `java -jar LeafFuzz.jar swarm --target <host:port>` | Local/containerized disposable devstack (`1.21.x`–`26.3`) | Spawns synthetic protocol bots exercising concurrent commands, chunk boundary crossings, and packet edge cases |
