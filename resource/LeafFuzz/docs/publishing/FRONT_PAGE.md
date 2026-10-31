<!--
Single source for every LeafFuzz storefront page (BuiltByBit, Modrinth, Hangar, SpigotMC).
Follows docs/dev/RULES.md Rule D-006 (first-person plain voice, 3-Zone hierarchy,
ASCII punctuation only, concrete benchmark numbers and honest caveats).
  Title: "LeafFuzz"  tagline: "In-game plugin and mod quality checker, command fuzzer, and memory-leak screener for Paper, Folia, Fabric & NeoForge"
-->

<div align="center">

# {{name}}: In-Game Plugin & Mod QC, Command Fuzzer & Memory-Leak Screener

[![Build](https://github.com/LeafCraftDev/LeafFuzz/actions/workflows/gradle.yml/badge.svg)](https://github.com/LeafCraftDev/LeafFuzz/actions/workflows/gradle.yml)
[![Java](https://img.shields.io/badge/Java-17%2B-blue)](https://adoptium.net/)
[![Platforms](https://img.shields.io/badge/Platforms-Paper%20%7C%20Folia%20%7C%20Spigot%20%7C%20Fabric%20%7C%20NeoForge-orange)](#install)

</div>

## What it is

**{{name}} is an in-game plugin and mod quality checker, command fuzzer, and memory-leak screener.** Drop the jar into `plugins/` or `mods/`, run `/fuzz check target=<PluginOrMod>` (or `target=PluginA,PluginB`), and in one pass it checks five things: which commands are exposed to regular players vs ops, what happens when synthetic test players send edge-case arguments, click GUI menu items, or disconnect mid-countdown, whether the target throws exceptions or stalls the server, whether player sessions stay in memory after garbage collection, and whether advertised commands and config keys are actually wired in bytecode.

I built it from the behavior fuzzer in `LeafRTP` - the same tool that caught and verified the pre-3.3.0 disconnected-player retention bug in `LeafRTP` - so server admins and developers can vet any new plugin, mod, or update in three steps without setting up external bot harnesses or heap profilers.

One jar for Paper and Spigot (1.20+), Folia (1.21+), Fabric (1.21+), and NeoForge (1.21+), up to 26.3. It can also be run from a terminal (`java -jar {{jar}} swarm ...`) as a standalone external load tester.

### The short version

**Audits one plugin, a list of plugins, or a staging server in one command (`/fuzz check target=<Name>`) - producing an in-game book scorecard (`/fuzz report`) and a Markdown report with 1-line reproducers and ready-to-paste permission fixes.**

- [**Easy**](#install): 3-step workflow - drop `{{jar}}` into `plugins/` or `mods/`, run `/fuzz check target=<PluginOrMod>`, and read the in-game book scorecard (`/fuzz report`) or `reports/<target>-qc-report.md`.
- [**Safe**](#how-it-works): built-in command denylist (`stop`, `restart`, `op`, `deop`, `ban`, `kick`, `reload`, `whitelist`, `save-all`), target-scoped isolation, and zero synchronous chunk loads.
- [**Thorough**](#features): spawns synthetic in-game test players across `default` and `op` tiers (and up to 500 concurrent players via `players=auto`) to exercise player-only commands, GUI menus, movement, and mid-countdown disconnects.
- [**Leak proof**](#performance): compares background post-GC memory snapshots against an idle control window to catch retained player sessions while ignoring normal bounded caches.
- [**One jar**](#install): runs the same `/fuzz` command tree and 5-stage checker on Paper, Spigot, Folia, Fabric, and NeoForge.

<details>
<summary><b>More highlights</b></summary>

- **Dual fixes:** every finding outputs both a minimized 1-to-2 command reproducer for the developer and an immediate `commands.yml` or LuckPerms workaround for the server owner.
- **Claim & config wiring audit (`stage=claims`):** scans `.jar` bytecode and YAML files without loading classes to flag dead config keys, unregistered event listeners, and hollow commands (`Claims X -> Does Not Deliver Y`).
- **Boundary-exact multi-target isolation:** test one plugin (`target=RTP`), compare two plugins side-by-side (`target=RTP,LeafSleep`), or audit a disposable test server (`target=all`) without substring cross-talk.
- **Custom player personas (`personas.jsonl`):** ships with 8 survival and stress behavior profiles out of the box and loads custom exported player profiles when placed in the plugin/mod folder.
- **Built-in self-test (`[FUZZ bit]`):** `/fuzz test` verifies archive ownership indexing, command denylisting, reproducer shrinking, leak detection math, claim-delivery scanning, and live server canaries in under 15 ms.

</details>

## Common setups

These work out of the box on a staging server or local test instance:

- **Pre-install vetting for a new plugin or mod:** Drop the new jar alongside `{{jar}}` and run `/fuzz check target=<NewPlugin> episodes=24` before putting it on your live production server.
- **Permission-leak audit on an existing stack (`/fuzz check stage=commands`):** Run `/fuzz check target=all stage=commands` to list every state-changing command (`reload`, `clear`, `debug`, `give`, `delete`) accidentally left open to non-op players, with ready-to-paste LuckPerms revoke commands.
- **Release & pull-request regression gate:** Run `/fuzz check target=RTP episodes=24` over RCON or console and attach `reports/<target>-qc-report.md` (`json` / `yml` also generated) to the release or pull request.

---

## Install

**Requirements:** Paper or Spigot 1.20+, Folia 1.21+, Fabric 1.21+, or NeoForge 1.21+, up to 26.3. Java 17+ (Java 21+ on 1.20.5+, Java 25 on 26.x).

1. Drop `{{jar}}` into `plugins/` (Paper, Spigot, Folia) or `mods/` (Fabric, NeoForge) and start the server.
2. Run `/fuzz check target=<PluginOrModName>` (for example `/fuzz check target=RTP episodes=24` or `/fuzz check target=RTP,LeafSleep episodes=24`).
3. Click `[Open Book Scorecard]` in chat (or run `/fuzz report`) and open `plugins/LeafFuzz/reports/<target>-qc-report.md` (or `config/leaffuzz/reports/<target>-qc-report.md`).

---

## Features

- **Stage 1 - Command & permission surface audit:** walks the live command tree for both `default` (permission level 0) and `op` (permission level 4) players, seeds hidden subcommands and inline permission checks directly from `.class` bytecode, folds `namespace:command` aliases into canonical commands, enforces the built-in command denylist, and flags unguarded admin subcommands.
- **Stage 2 - Synthetic player, GUI menu & concurrent swarm fuzzer:** spawns in-game synthetic players (single-player or ramping up to 500 concurrent players with `players=auto`) that run player-only commands with boundary numbers (`-1`, `0`, `Integer.MAX_VALUE`), click salient GUI menu items (verifying cancelled menu clicks never leak icons into player inventories), and perform realistic follow-up actions (disconnecting within 1 second of a command, moving across blocks or chunks, or sending rapid command bursts) before shrinking any failure down to the shortest command sequence that reproduces it.
- **Stage 3 - Exception, sync-hazard & slow-tick attribution:** watches the server log and tick loop for uncaught exceptions (`exc:`), slow ticks (`> 100 ms` outside garbage-collection pauses, `stall:`), and synchronous main-thread hazards (`hazard:sync-chunk:`, `hazard:gui-item-leak:`), attributing each stack trace to the exact `.jar` that owns the offending class.
- **Stage 4 - Post-GC memory-leak screener:** takes background post-GC class histograms across an idle baseline and paced episode batches, flagging classes that keep growing with each departed player session while ignoring fixed-capacity caches.
- **Stage 5 - Claim & causal delivery audit:** scans target `.jar` bytecode and YAML configuration files without loading classes to flag dead config keys, unregistered event listeners, and hollow commands (`Claims X -> Does Not Deliver Y`), cross-checking them against live Stage 2 command runs.
- **In-game Book scorecard & Markdown/YAML/JSON export:** opens a multi-page written book (`/fuzz report`) checked for high-contrast readability on both parchment pages and dark hover tooltips, and writes `reports/<target>-qc-report.md` alongside status-leading `reports/<target>-qc-data.yml` and `reports/<target>-qc-data.json` moderation summaries.

---

## Performance

All JAR class-ownership indexing and heap histogram snapshots run on background worker threads with zero main-thread chunk loads, while synthetic player command dispatches and disconnect follow-ups are paced across server ticks so async plugin callbacks and warmup timers settle cleanly between checkpoints.

**Live `Paper 26.2-56` (`bamboo`) Verification & `LeafRTP` Regression Summary:**

| QC Stage / Verification Scenario | Measured Detection / Isolation Result | False Positive Rate (`FPR`) | Evidence / Verification Command |
|---|---|---|---|
| **Disconnected-Player Session Leak Detection & Fix (`LeafRTP` pre-`3.3.0` -> `3.3.0+`)** | **Caught `+3..+4` retained sessions/episode** (`3/3` replay) on pre-`3.3.0` mid-warmup quit (`latestTeleportData` & countdown boss bar); verified **`PASS` (`0` retained sessions)** across `24`- to `86`-episode post-fix runs | **`0.000%`** false leak flags on bounded region caches (`ResolvedRegion`) and post-`3.3.0` `LeafRTP` | `/fuzz check target=RTP episodes=24` |
| **Boundary-Exact Multi-Target Isolation (`AlphaTeleport` vs `BetterAlphaTeleport`)** | **`100.0%` Target Attribution** across Stage 1..5 when filtering overlapping plugin names (`AlphaTeleport` vs `BetterAlphaTeleport` vs `AlphaTeleport,GammaClaim`) | **`0.000%`** substring cross-matching across adjacent plugin JARs | Multi-target isolation suite & `/fuzz check target=A,B` |
| **`ddmin` Sequence & Numeric Boundary Bisection** | Shrinks noisy multi-command traces (e.g. 70-action bot episodes) to **1 minimal command + quit** and bisects numeric failure thresholds (`radius >= 256`) in **`O(log2 Range)`** steps | **`0`** unverified reproducers (every shrunk trace is re-verified against the oracle before reporting) | `/fuzz test` (`FUZZ-CBIT-001`) |
| **In-JVM `Int8[16x16]` Persona Policy Bot & Claim Scanner** | Exercises player-only commands (`sender instanceof Player`), GUI menu clicks, and Order-1/Order-2 bytecode claim delivery across `default` & `op` tiers | **`0` synchronous main-thread chunk loads** across static source and runtime checks | Platform integration suite & `/fuzz check` |
| **Built-In Self-Test Suite (`/fuzz test`, `[FUZZ bit]`)** | **`6 / 6 PASS` offline** (`FUZZ-PBIT-001..002`, `FUZZ-CBIT-001..003`, `FUZZ-IBIT-001`) and **`9 / 9 PASS` live** (`FUZZ-LIVE-001..003`) | **`< 15 ms`** total execution time off-thread; **`0`** book contrast violations | Live `Paper 26.2-56` `/fuzz test` |

**What fuzzing found and verified in `LeafRTP` (full logs in [`LEAK_FUZZING.md`](https://github.com/DailyStruggle/RTP/blob/V3/helpers/StressTestRTP/LEAK_FUZZING.md)):**

- **Player session cleanup on mid-warmup quit (fixed in `LeafRTP 3.3.0`):** Every platform player wrapper (`Bukkit`, `Paper`, `Folia`, `Fabric`, `NeoForge`) now holds the live player through a `WeakReference` plus a pure-data snapshot (`toPureData()`), and countdown boss bars clear on quit (`PersonalBossBars`). Earlier fuzzing flagged `latestTeleportData` cooldown caches, `FoliaRTPPlayer`, and active countdown boss bars retaining `+3` to `+4` player sessions per episode whenever a bot ran `/rtp` and disconnected within 1 second; post-fix runs verified `0` retained sessions across 86 episodes (including `/rtp reload`).
- **Bounded cache vs. per-departure leak separation (verified in `LeafRTP 3.3.0`):** Fixed-capacity region pre-filter caches (`RegionFileResolver$ResolvedRegion` and chunk section palettes) are separated from true memory leaks by regressing post-GC growth per repetition and per ended player session against an idle baseline. When `ResolvedRegion` climbed to the 48-bot ladder in `LeafRTP`, growth flattened below the linear leak prediction (`146` vs `506.35` predicted), confirming bounded cache warm-up rather than a leak.
- **Arrival chunk-ticket hold across initial ticks (fixed in `LeafRTP 3.3.0`):** Arrival chunk tickets remain held through the arriving player's first ticks so landing never triggers a synchronous main-thread chunk load or slow-tick stall.

---

## How it works

All archive ownership indexing, synthetic persona evaluation, bytecode claim scanning, and post-GC retention regressions run automatically in the background from a single `/fuzz check` command without external bot accounts or JVM attach agents:

- **Off-thread archive ownership map:** Scans `plugins/*.jar` and `mods/*.jar` zip headers off-thread to map every unique `.class` entry to its owning archive while excluding shaded libraries present in multiple jars (`com.google.gson.*`, `org.slf4j.*`) so shared dependencies are never falsely blamed.
- **In-JVM behavioral bot & concurrent player ramp:** Each episode spawns a synthetic player (or a concurrent roster up to 500 players when `players=auto` or `players=<n>` is passed) with a unique per-episode `UUID` and evaluates a 256-byte `Int8[16x16]` policy matrix over 16 state features and 16 gameplay micro-skills. After dispatching the target command through the platform command map or Brigadier dispatcher, the bot clicks salient GUI menu slots, executes its assigned follow-up behavior (disconnecting immediately, moving across blocks/chunks, closing an inventory window, or repeating commands), and fires target-scoped lifecycle events.
- **UCB1 bandit exploration & `ddmin` shrinking:** Prioritizes under-explored `(command, followUp)` combinations using Upper Confidence Bound (`UCB1`) rewards weighted by new stack frames, slow ticks, and memory deltas. When an episode triggers a fault, the shrinker reduces the action list via Zeller's `ddmin` algorithm and bisects numeric arguments to report the exact threshold where the command breaks.
- **Idle-controlled Bonferroni OLS leak regression:** Before running fuzz batches, `/fuzz check` captures `qc-baseline` and `qc-idle-control` post-GC histograms to measure background server noise, then paces weighted episode batches across server ticks (`qc-batch-1..3`). A class is flagged only if its post-GC instance count grows monotonically with player departures or commands (`slope >= +0.20 inst/event`, `R^2 >= 0.85`, and Bonferroni-corrected `p < 0.01 / K`).
- **Zero-classloading bytecode & config claim audit:** Parses `.class` constant pools, method bodies, and `BootstrapMethods` off-thread (`BytecodeCausalGraphScanner`) to extract hidden subcommands and verify first-order (0-hop command, listener, and config-key registration) and second-order (multi-hop causal chains to effect sinks) delivery (`Claims X -> Does Not Deliver Y`), corroborated by Stage 2 runtime telemetry.

---

## Testing and quality gates

Every release is checked automatically before packaging, and includes built-in checks you can run on your server:

- **Built-in self-test suite (`/fuzz test`):** runs 6 core diagnostic checks (`FUZZ-PBIT-001..002`, `FUZZ-CBIT-001..003`, `FUZZ-IBIT-001`) plus 3 live server canaries (`FUZZ-LIVE-001..003`) verifying JAR class attribution, command denylist safety, reproducer shrinking, leak regression math, claim-delivery scanning, and book menu readability in under 15 ms.
- **Cross-platform 5-stage QC & multi-target isolation:** automated test suites verify Brigadier and Bukkit command auditing, single-target and comma-separated multi-target isolation (`AlphaTeleport` vs `BetterAlphaTeleport`), and Markdown/YAML/JSON/Book scorecard output.
- **Synthetic player lifecycle & main-thread safety:** verifies in-JVM player command dispatch, GUI menu icon-leak checks, disconnect/move/inventory follow-up events, and static source checks forbidding synchronous main-thread chunk loads.
- **Reproducer shrinking & leak regression accuracy:** verifies delta-debugging sequence minimization, binary numeric boundary search, and idle-controlled post-GC memory leak detection across Paper, Folia, Fabric, and NeoForge packaging.

---

## Why I made it

While building and stress-testing `LeafRTP` across Paper, Folia, Fabric, and NeoForge, I found that the hardest bugs to catch weren't syntax errors or simple happy-path command calls - they were lifecycle races that only happened when a player ran `/rtp` and disconnected half a second later during the warmup countdown, or when a subcommand received an unexpected negative or extreme number. Running external Mineflayer bot swarms and Eclipse MAT heap dumps caught those bugs in `LeafRTP`, but setting up an external harness takes hours.

I built `{{name}}` to bring that exact workflow inside the server JVM in a single jar:
- **Zero-setup 3-step workflow:** Drop the jar in, run `/fuzz check target=<Name>`, and read the book or Markdown scorecard.
- **Target-agnostic by design:** Never hardcodes rules for any specific plugin; every command tree, permission check, stack frame, and heap class is discovered dynamically from the live server and `plugins/*.jar` or `mods/*.jar`.
- **Actionable for both audiences:** Gives the server owner an immediate `commands.yml` or LuckPerms workaround to protect their live server today, and gives the developer a 1-line minimal reproducer and exact leaking class name to fix the root cause.

---

## Commands, configuration, and FAQ

Operational commands, permissions, configuration keys, common operator questions, and support channels:

<details>
<summary><b>Commands, permissions, configuration files</b></summary>

**Operational commands** (aliases: `/leaffuzz`, `/qc`; uses `CommandsAPI` `name=value` syntax):

| Command | Description | Permission |
| --- | --- | --- |
| `/fuzz` / `/fuzz report` | Open the interactive in-game Book scorecard (or run `/fuzz check` when `target=`, `episodes=`, `players=`, or `stage=` is passed) | `leaffuzz.admin` |
| `/fuzz check [target=<Name\|A,B\|all>] [episodes=<n>] [players=<auto\|1..500>] [stage=<all\|commands\|fuzz\|faults\|leaks\|claims\|snapshot>]` | Run the 5-stage automated QC pass and write `reports/<target>-qc-report.md` (`.yml` / `.json`) | `leaffuzz.admin` |
| `/fuzz reset [scope=<all\|faults\|leaks\|campaign>]` | Clear recorded exception/stall/hazard signatures, leak histogram checkpoints, or campaign state | `leaffuzz.admin` |
| `/fuzz test` | Run `[FUZZ bit]` PBIT/CBIT/IBIT and live-server self-tests off-thread (`< 15 ms`) | `leaffuzz.admin` |
| `/fuzz reload` | Validate and reload `config.yml`, `messages.yml`, and `personas.jsonl` and refresh JAR ownership | `leaffuzz.admin` |

**Permissions** (`plugin.yml` / `paper-plugin.yml` / Brigadier):

| Permission | Default | Grants |
| --- | --- | --- |
| `leaffuzz.admin` | `op` (level 4) | Access to all `/fuzz`, `/leaffuzz`, and `/qc` commands |

**Configuration (`plugins/LeafFuzz/config.yml` or `config/leaffuzz/config.yml`):**

| Key | Default | Purpose |
| --- | --- | --- |
| `check.defaultEpisodes` | `250` | Default UCB1 episode count when `episodes=<n>` is omitted from `/fuzz check` (`1..100000`) |
| `check.defaultPlayers` | `1` | Default concurrent player roster (`1..500`, or `"auto"` / `"ramp"` to ramp until unstable) |
| `check.slowTickThresholdMs` | `100.0` | Main-thread tick duration threshold (ms) for slow-tick stall capture (`stall:`) |
| `check.requireDisposableForAll` | `true` | Safety guard requiring confirmation before whole-server sweeps (`target=all`) |
| `check.extraDenylist` | `[]` | Extra command prefixes excluded from fuzzing alongside `DEFAULT_DENYLIST` |
| `campaign.restartStrategy` | `"AUTO"` | Multi-boot campaign restart strategy (`AUTO`, `NONE`, `SPIGOT_RESTART`, `SUPERVISOR_STOP`) |
| `campaign.maxRestartRetries` | `3` | Maximum restart retries before isolating a crashing archive |
| `llmAudit.llmAuditEnabled` | `false` | Optional AST-grounded LLM fault explanations and advisory causal claim audit (`OFF` by default) |

</details>

<details>
<summary><b>FAQ</b></summary>

**Q: Can I test a single plugin or compare two plugins without fuzzing the entire server?**
A: Yes. Pass `target=<PluginName>` for a single plugin (for example `/fuzz check target=RTP episodes=24`) or a comma-separated list for multiple targets (`/fuzz check target=RTP,LeafSleep episodes=24`). `LeafFuzz` scopes Stage 1 command auditing, Stage 2 synthetic player episodes, Stage 3 fault attribution, Stage 4 post-GC leak screening, and Stage 5 bytecode claim auditing strictly to the selected target archives.

**Q: How does `LeafFuzz` test commands that reject console execution (`if (!(sender instanceof Player)) return`)?**
A: During Stage 2, `LeafFuzz` spawns in-JVM synthetic players across both `default` and `op` permission tiers, dispatching commands as a `Player` (or player-attributed Brigadier command source), clicking GUI menu items, and firing follow-up disconnect, move, and inventory-close events without needing external Mineflayer bots.

**Q: How do I pass parameters like `target`, `episodes`, `players`, or `stage`?**
A: `LeafFuzz` uses explicit `name=value` parameter syntax so parameter order never causes silent misparses (for example `/fuzz check target=RTP episodes=24 players=auto` or `/fuzz check target=RTP stage=claims`), and also accepts `/fuzz check <Target> [episodes]` as a positional shorthand.

**Q: Will `/fuzz check` accidentally run `/stop`, `/restart`, `/ban`, or `/op`?**
A: No. An immutable built-in denylist (`stop`, `restart`, `reload`, `op`, `deop`, `ban`, `ban-ip`, `pardon`, `kick`, `whitelist`, `save-all`, `save-off`, `timings`, `spark`) blocks dangerous administrative commands at both command-discovery time and right before execution, and you can add custom prefixes under `check.extraDenylist` in `config.yml`.

**Q: Does `LeafFuzz` make any outbound network connections or modify other plugin jars?**
A: Not during normal use. `/fuzz check` is 100% read-only on `plugins/*.jar` and `mods/*.jar` (scanning zip headers and bytecode off-thread) and makes zero outbound network connections by default (`llmAudit.llmAuditEnabled` is `false` unless you explicitly configure an API key or local Ollama endpoint). Archive quarantine (`.jar.sleuth-disabled`) only runs if you explicitly start an opt-in multi-boot campaign, and `/fuzz reset scope=campaign` restores all archives immediately.

</details>

<details>
<summary><b>Support</b></summary>

Support is me, in my spare time, so it's best effort.

- For command or config questions, check `COMMANDS.md`, `CONFIGURATION.md`, or open a thread in the `LeafCraft Plugin Support` Discord `#support` Forum (or GitHub Discussions).
- A bug report in GitHub Issues or the `#support` Forum needs: `/version`, `/fuzz test` output, the generated `reports/<target>-qc-report.md`, `config.yml`, and the server log uploaded to `mclo.gs`.
- Feature requests go in GitHub Discussions first.

</details>

---

## Links

- [**LeafFuzz README**](../../README.md): 3-step quick start, architecture overview, and multi-loader build commands
- [**Commands & Permissions**](../admin/COMMANDS.md): full subcommand and parameter reference
- [**Configuration Reference**](../admin/CONFIGURATION.md): `config.yml`, `messages.yml`, and `personas.jsonl` reference
- [**BIT Diagnostic Codes**](../dev/BIT_CODES.md): `FUZZ-PBIT-001` through `FUZZ-LIVE-003` reference
- [**Changelog**](../../CHANGELOG.md)
- [**LeafRTP**](https://github.com/DailyStruggle/RTP): zero-wait random teleportation (`/rtp` & `/wild`) with `.mca`/`.linear` region pre-filtering
- [**Source on GitHub**](https://github.com/LeafCraftDev/LeafFuzz): MIT source code, issues, and verification suites
