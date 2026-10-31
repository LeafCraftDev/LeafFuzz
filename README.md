# LeafFuzz

**One-command in-JVM quality control, persona-driven bot fuzzing, main-thread stall attribution, post-GC memory leak screening, and bytecode claim-delivery auditing for Paper, Spigot, Folia, Fabric, and NeoForge.**

---

## Quick Start: 3-Step Server & Plugin QC

1. **Download:** Drop `LeafFuzz-<version>.jar` into `plugins/` (Paper, Spigot, Folia) or `mods/` (Fabric, NeoForge) and start the server.
2. **Run Command:** Run `/fuzz check target=<PluginOrModName>` (or `/fuzz check target=TargetA,TargetB` / `/fuzz check players=auto`).
3. **Check Results:** Click `[Open Book Scorecard]` in chat (or run `/fuzz report`), read the instant 5-stage `PASS`/`WARN`/`FAIL` summary, and open `reports/<target>-qc-report.md` (plus `reports/<target>-qc-data.yml` and `.json`) for copy-pasteable `ddmin` reproducers, LuckPerms/`commands.yml` mitigations, post-GC leak slopes, and `Claims X -> Does Not Deliver Y` wiring findings.

---

## How the 5-Stage Automated QC Pass Works

| Stage | What It Verifies | Engine |
|---|---|---|
| **1. Command & Least-Privilege Audit** | Scans live Brigadier & Bukkit command trees across `default` vs `op` tiers (augmented with white-box bytecode subcommand & inline permission hints) and flags state-mutating subcommands (`reload`, `delete`, `give`, `admin`, `config`) accidentally left open to unprivileged players. | `CommandSurfaceAuditor`, `BrigadierDispatcherInspector`, `PaperCommandTreeInspector`, `BytecodeCausalGraphScanner` |
| **2. Persona Bot Boundary, GUI Menu & Swarm Fuzz Pass** | Spawns in-JVM synthetic bots (`NmsEmbeddedPlayerSession` + `PersonaPolicyBotActor`) backed by 256-byte `Int8[16x16]` `sleuth_persona_v1` policy genomes, steps autonomous player micro-skills, ramps concurrent player rosters across an Archimedean spiral (`players=auto` or `1..500`), clicks salient GUI menu slots (auditing `hazard:gui-item-leak` icon extraction), dispatches commands across numeric boundary ladders (`[min, -1, 0, 1, 16, 64, 256, 1024, max]`), and drives follow-up behaviors (`quit_lt1s`, `quit_delay`, `move`, `chunk_border_thrash`, `window_click`, `repeat`, `concurrent`), shrinking any failure via Zeller's `ddmin` + binary numeric bisection. | `SleuthServerFuzzer`, `PersonaPolicyBotActor`, `LeafFuzzPaperEpisodeRunner`, `NmsEmbeddedPlayerSession`, `NodeBandit`, `NumericBoundaryLadder`, `FuzzActionShrinker` |
| **3. Main-Thread Stall, Sync-Hazard & Exception Guard** | Taps JUL root loggers and samples slow ticks (`> 100 ms` outside GC pause windows), sub-100ms main-thread synchronous hazards (`hazard:sync-chunk:`, `hazard:sync-io:`, `hazard:blocking-wait:`), and grey-box thread coverage (`cov:`), attributing the deepest plugin/mod stack frame to its exact `.jar` (`exc:<Exception>:<Frame>`, `stall:<Frame>`). | `LogAndStallSignatureOracle`, `JarClassOwnershipIndex` |
| **4. Post-GC Class Retention Screen** | Captures post-GC class histograms (`GC.class_histogram`) off-thread across an idle control checkpoint (`qc-idle-control`) and tick-paced episode batches, fitting Bonferroni-corrected OLS slopes (`alpha = 0.05 / K`) against player departures and command executions to name the exact leaking Java class and `.jar`. | `ClassRetentionScreener`, `LeakProbe` |
| **5. Claim & Causal Delivery Audit** | Scans target `.jar` bytecode and YAML resources without loading classes to verify first-order (0-hop command/event/config registration, including `REGISTERED_CONFIG_GATED` vs `UNREGISTERED`) and second-order ($k$-hop causal chains to terminal effect sinks, $k \le 4$) delivery (`Claims: <X> -> Does Not Deliver: <Y>`), corroborated with live Stage 2 telemetry and optional AST-grounded `Jminor` LLM explanations. | `BytecodeCausalGraphScanner`, `LlmCausalChainAuditor` |

---

## Commands (`/fuzz`, `/leaffuzz`, `/qc`)

- `/fuzz check [target=<plugin|mod|TargetA,TargetB|all>] [episodes=<n>] [players=<auto|ramp|1..500>] [stage=<all|commands|fuzz|faults|leaks|claims|snapshot>]` — Run the 5-stage automated QC pass (ramping concurrent players dispersed across an Archimedean spiral until instability when `players=auto` or up to `players=100`) and write `reports/<target>-qc-report.md`, `reports/<target>-qc-data.yml`, and `reports/<target>-qc-data.json`.
- `/fuzz report` — Open the interactive in-game written-book scorecard (`LeafFuzzMenuBuilder`, audited by `BookContrastValidator`).
- `/fuzz reset [scope=<all|faults|leaks|campaign>]` — Clear recorded fault signatures, post-GC leak checkpoints, or campaign state.
- `/fuzz test` — Run `[FUZZ bit]` PBIT/CBIT/IBIT self-tests (`6` core checks + `3` live-server `FUZZ-LIVE-*` canaries).
- `/fuzz reload` — Validate and hot-reload `config.yml`, `messages.yml`, and optional `personas.jsonl`.
- `java -jar LeafFuzz.jar swarm --host 127.0.0.1 --port 25565 --players auto` — Standalone CLI mode driving an external TCP protocol bot swarm and ramp-to-instability capacity check (`java -jar LeafFuzz.jar extract-mineflayer` extracts the bundled `bench-swarm.js` script).

---

## Documentation

- [**Storefront Overview (`FRONT_PAGE.md`)**](resource/LeafFuzz/docs/publishing/FRONT_PAGE.md)
- [**Commands & Permissions Reference (`COMMANDS.md`)**](resource/LeafFuzz/docs/admin/COMMANDS.md)
- [**Configuration Reference (`CONFIGURATION.md`)**](resource/LeafFuzz/docs/admin/CONFIGURATION.md)
- [**BIT Diagnostic Codes (`BIT_CODES.md`)**](resource/LeafFuzz/docs/dev/BIT_CODES.md)
- [**Architecture Decision Records (`docs/adr/README.md`)**](resource/LeafFuzz/docs/adr/README.md)
- [**Changelog (`CHANGELOG.md`)**](resource/LeafFuzz/CHANGELOG.md)
