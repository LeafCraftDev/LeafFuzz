# Commands & Permissions Reference (`LeafFuzz`)

`LeafFuzz` registers `/fuzz` alongside aliases `/leaffuzz` and `/qc`. All commands use explicit `name=value` parameter syntax (`CommandsAPI`, `commands-api-ADR-001`) and work identically on `Paper`, `Spigot`, `Purpur`, `Folia`, `Fabric`, and `NeoForge`.

---

## Root Command & Subcommands (5 Subcommands)

| Command | Parameters | Default Permission | Description |
|---|---|---|---|
| `/fuzz` | `[target=<Plugin\|Mod\|A,B\|all>] [episodes=<1..100000>] [players=<auto\|ramp\|1..500>] [stage=<all\|commands\|fuzz\|faults\|leaks\|claims\|snapshot>]` | `leaffuzz.admin` (`op`) | With no parameters, opens the interactive in-game written-book scorecard (`/fuzz report`). When `target=`, `episodes=`, `players=`, or `stage=` is provided (for example `/fuzz players=auto` or `/fuzz target=RTP episodes=24`), runs `/fuzz check` directly. |
| `/fuzz check` | `[target=<Plugin\|Mod\|A,B\|all>] [episodes=<1..100000>] [players=<auto\|ramp\|1..500>] [stage=<all\|commands\|fuzz\|faults\|leaks\|claims\|snapshot>]` | `leaffuzz.admin` (`op`) | Runs the 5-stage automated QC pass (`stage=all`, default) with a concurrent player roster dispersed across an Archimedean spiral (`players=100` or `players=auto` to ramp until the server becomes unstable) or a specific stage (`stage=commands`, `stage=fuzz`, `stage=faults`, `stage=leaks`, `stage=claims`, `stage=snapshot`) and writes status-leading `reports/<target>-qc-report.md`, `reports/<target>-qc-data.yml`, and `reports/<target>-qc-data.json` for BuiltByBit / Modrinth moderation evidence. Also accepts positional shorthand `/fuzz check <Target> [episodes]`. |
| `/fuzz report` | *(none)* | `leaffuzz.admin` (`op`) | Opens the interactive in-game written-book scorecard (`LeafFuzzMenuBuilder`) for the latest QC check, or prints a formatted chat scorecard on console. |
| `/fuzz reset` | `[scope=<all\|faults\|leaks\|campaign>]` | `leaffuzz.admin` (`op`) | Clears recorded exception/stall/hazard signatures (`faults`), post-GC histogram checkpoints (`leaks`), and/or persisted campaign state and `.jar.sleuth-disabled` archives (`campaign`). Defaults to `scope=all`. |
| `/fuzz test` | *(none)* | `leaffuzz.admin` (`op`) | Executes all `[FUZZ bit]` PBIT, CBIT, IBIT, and live-server (`FUZZ-LIVE-*`) self-test components off-thread. |
| `/fuzz reload` | *(none)* | `leaffuzz.admin` (`op`) | Validates and hot-reloads `config.yml`, `messages.yml`, and `personas.jsonl` and refreshes the `plugins/*.jar` / `mods/*.jar` ownership index off-thread. |

---

## Stage Selector (`stage=...`)

| `stage=` Value | Behavior |
|---|---|
| `all` *(default)* | Executes the full 5-stage automated QC pass (Command Surface Audit, Persona Bot & Swarm Fuzzing, Main-Thread Stall/Hazard & Exception Attribution, Post-GC Class Retention Screen, and First/Second-Order Claim Delivery Audit) and writes `reports/<target>-qc-report.md` (`.yml` / `.json`). |
| `commands` | Runs Stage 1 only: audits live Brigadier & Bukkit command trees (augmented with white-box bytecode subcommand hints) for `default` vs `op` exposure and prints ready-to-paste LuckPerms mitigations. |
| `fuzz` | Runs the full QC pass focused on Stage 2 synthetic player boundary & lifecycle fuzzing. |
| `faults` | Inspects Stage 3 attributed exception (`exc:`), slow-tick stall (`stall:`), and synchronous main-thread hazard (`hazard:`) signatures filtered by `target=`. |
| `leaks` | Runs Stage 4 Bonferroni-corrected OLS class retention screening across captured post-GC checkpoints for `target=`. |
| `claims` | Runs Stage 5 zero-classloading bytecode & config causal graph audit (`BytecodeCausalGraphScanner` + optional `LlmCausalChainAuditor`), reporting Order-1 and Order-2 `Claims: <X> -> Does Not Deliver: <Y>` findings. |
| `snapshot` | Captures an immediate off-thread post-GC `GC.class_histogram` checkpoint (`manual-<n>`) for manual retention comparison. |

---

## Standalone External Swarm CLI (`java -jar LeafFuzz.jar`)

The same `LeafFuzz-<version>.jar` artifact can be executed directly from a terminal to drive an external multi-player TCP protocol swarm and ramp-to-instability capacity test:

```bash
# Ramp concurrent offline-mode TCP players until the server becomes unstable (up to 100 players)
java -jar LeafFuzz.jar swarm --host 127.0.0.1 --port 25565 --players auto --duration-sec 30 --report swarm-report.md

# Fixed 100-player concurrent swarm without ramp stop
java -jar LeafFuzz.jar swarm --host 127.0.0.1 --port 25565 --players 100 --no-ramp --duration-sec 60 --max-rtt-ms 55.0

# Extract the bundled Mineflayer bench-swarm.js script to disk
java -jar LeafFuzz.jar extract-mineflayer --out ./bench-swarm.js
```

| CLI Flag | Default | Description |
|---|---|---|
| `--host <host>` / `-H` | `127.0.0.1` | Target Minecraft server hostname or IP address. |
| `--port <port>` / `-p` | `25565` | Target Minecraft server TCP port (`1..65535`). |
| `--players <auto\|ramp\|1..500>` / `-n` | `100` (`auto`) | Target concurrent offline-mode TCP bot sockets dispersed across an Archimedean spiral. |
| `--ramp` / `--no-ramp` | `--ramp` | Progressively ramps population (`10 -> 25 -> 50 -> 75 -> 100+`) and records the exact instability threshold (`maxStablePlayers`). |
| `--duration-sec <sec>` | `15` | Hold/step duration in seconds (`1..3600`). |
| `--timeout-ms <ms>` | `3000` | Socket connection and handshake timeout in milliseconds (`200..30000`). |
| `--protocol <auto\|id>` | `auto` (`-1`) | Minecraft protocol version number, or `auto` to detect via Server List Ping (`SLP`). |
| `--max-rtt-ms <ms>` | `55.0` | Maximum `p95` ping/keep-alive RTT in milliseconds (`>= 10.0`) before declaring tick/network instability. |
| `--report <path>` | *(none)* | Writes a self-contained Markdown swarm readiness report to `<path>`. |
| `extract-mineflayer [--out <path>]` | `./bench-swarm.js` | Extracts the bundled `/META-INF/leaffuzz/swarm/bench-swarm.js` Mineflayer harness from the JAR. |

---

## Permission Nodes

| Permission Node | Default | Behavior |
|---|---|---|
| `leaffuzz.admin` | `op` (Permission Level 4 on Fabric/NeoForge) | Grants access to all `/fuzz`, `/leaffuzz`, and `/qc` quality-control, fuzzing, retention-screening, and diagnostic commands. |
