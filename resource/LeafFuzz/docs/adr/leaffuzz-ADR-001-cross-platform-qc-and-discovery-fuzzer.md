# leaffuzz-ADR-001: Cross-Platform In-JVM Quality Control, Command-Tree Fuzzing, Post-GC Leak Screening, and Bytecode Claim-Delivery Auditing

- **Status:** Accepted
- **Date:** 2026-10-30
- **Related ADRs:** [`ADR-049`](../../../../docs/adr/ADR-049-shared-platform-hooks.md), [`ADR-115`](../../../../docs/adr/ADR-115-package-dag-disentanglement-and-decision-preservation-hypergraph.md), [`ADR-125`](../../../../docs/adr/ADR-125-whole-server-discovery-fuzzing.md), [`ADR-126`](../../../../docs/adr/ADR-126-multi-product-monorepo-release-architecture.md), [`corpus-atlas-ADR-001`](../../../../corpus-atlas/docs/adr/corpus-atlas-ADR-001-scope-preserving-ast-synthesis-and-zero-open-cards.md), [`corpus-atlas-ADR-002`](../../../../corpus-atlas/docs/adr/corpus-atlas-ADR-002-method-scoped-ast-macro-comprehension-and-shorthand-ir.md), [`leafsleuth-ADR-006`](../../../LeafSleuth/docs/adr/leafsleuth-ADR-006-in-jvm-forensics-and-discovery-fuzzing.md)

## Context

Plugin and mod authors on Modrinth and BuiltByBit routinely test new releases by starting a local server, running a command once or twice, and checking the console for stack traces. In production, defects surface under boundary arguments (`-1`, `0`, `Integer.MAX_VALUE`), rapid disconnect races (`quit_lt1s`), unguarded `default`-tier subcommands, main-thread tick stalls (`> 100 ms`), synchronous main-thread chunk loads (`hazard:sync-chunk:`), per-departure object retention leaks that only appear across post-GC heap histograms, and unwired/hollow commands or dead YAML config keys (`Claims X -> Does Not Deliver Y`).

While `ADR-125` and `leafsleuth-ADR-006` introduced in-JVM command-surface auditing, UCB1 boundary fuzzing, `ddmin` shrinking, and `ClassRetentionScreener` inside `LeafSleuth`, bundling a QA fuzzer inside a production lag governor obscured both products and limited the fuzzer to Paper/Folia.

## Decision

1. **Standalone Multi-Loader Community Resource (`resource/LeafFuzz`):**
   - Package `LeafFuzz` as a standalone, MIT-licensed multi-loader JAR (`LeafFuzz-<version>.jar`) built from:
     - `:resource:LeafFuzz:leaffuzz-common` (pure Java 17 core consuming `:server-api`, `:commands-api`, `:yaml-api`, `:bit-api`, `:config-bit-api`, and `:helpers:stresstest-core`)
     - `:resource:LeafFuzz:leaffuzz-paper` (`PaperLeafFuzzPlugin` via `BukkitPluginServerAccessor`, `PaperCommandTreeInspector`, and `LeafFuzzPaperEpisodeRunner`)
     - `:resource:LeafFuzz:leaffuzz-fabric` (`FabricLeafFuzzMod` via `FabricModServerAccessor`, `BrigadierDispatcherInspector`, and `NmsEmbeddedPlayerSession`)
     - `:resource:LeafFuzz:leaffuzz-neoforge` (`NeoForgeLeafFuzzMod` via `NeoForgeModServerAccessor`, `BrigadierDispatcherInspector`, and `NmsEmbeddedPlayerSession`)
     - `:resource:LeafFuzz:leaffuzz-plugin` (shaded multi-loader assembly JAR with `Main-Class: net.leaf.fuzz.common.cli.LeafFuzzStandaloneCli`)
2. **Multi-Format Archive Ownership Indexing & Zero-Classloading Causal Graph Scanning (`JarClassOwnershipIndex`, `BytecodeCausalGraphScanner`):**
   - `JarClassOwnershipIndex#scanArchiveDirectories` indexes both `plugins/*.jar` (`paper-plugin.yml`, `plugin.yml`) and `mods/*.jar` (`fabric.mod.json`, `META-INF/neoforge.mods.toml`, `META-INF/mods.toml`, and nested `META-INF/jars/*` / `META-INF/jarjar/*` archives) off-thread, filtering out multi-JAR shaded class collisions.
   - `BytecodeCausalGraphScanner` (`:config-bit-api`) parses `.class` constant pools, method bodies, and `BootstrapMethods` without loading classes to extract white-box command schemas (`BytecodeCommandSchema` seeding Stage 1 & Stage 2) and evaluate Order-1 (0-hop command/event/config wiring, distinguishing `REGISTERED_UNCONDITIONAL`, `REGISTERED_CONFIG_GATED`, and `UNREGISTERED`) and Order-2 ($k$-hop causal chains to terminal effect sinks, $k \le 4$) claim delivery (`ClaimDeliveryFinding`).
   - `LlmCausalChainAuditor` (`:config-bit-api`) optionally enriches proven Stage 2/3/5 findings with `Jminor` AST-grounded explanations (`explainProvenFuzzFault`) and advisory semantic claim checks, verifying every cited `Class#method` against `CausalGraphReport#closedWorldSymbols()`.
3. **In-JVM Synthetic Persona Bot, Spiral Swarm Roster & One-Command 5-Stage QC Scorecard (`/fuzz check target=<target>`):**
   - `PersonaPolicyBotActor`, `LeafFuzzPaperEpisodeRunner`, and `NmsEmbeddedPlayerSession` evaluate the 256-byte `Int8[16x16]` `sleuth_persona_v1` policy genome (`selectPolicyActionInt` over 16 `POLICY_MICRO_SKILLS`), spawn live server-side `ServerPlayer` + Netty `EmbeddedChannel` sessions dispersed across golden-angle Archimedean spiral coordinates (`players=1..500` or `players=auto` ramp-to-instability), click salient GUI menu slots (auditing `hazard:gui-item-leak`), and drive lifecycle/spatial follow-ups (`quit_lt1s`, `quit_delay`, `move`, `chunk_border_thrash`, `window_click`, `repeat`, `concurrent`).
   - `/fuzz check [target=<target>] [episodes=<n>] [players=<auto|1..500>] [stage=<all|commands|fuzz|faults|leaks|claims|snapshot>]` runs Command & Least-Privilege Auditing (Stage 1), Persona Bot UCB1 Boundary, GUI Menu & Swarm Fuzzing with `ddmin` + binary numeric bisection (Stage 2), Main-Thread Stall, Sync-Hazard & Exception Attribution (Stage 3), Post-GC Bonferroni OLS Class Retention Screening (Stage 4), and First/Second-Order Causal Claim Delivery Auditing (Stage 5), outputting an in-game Book scorecard (`/fuzz report`) and status-leading reports in `<rootFolder>/reports/<target>-qc-report.md`, `<target>-qc-data.yml`, and `<target>-qc-data.json`.
   - `LeafFuzzStandaloneCli` and `LeafFuzzTcpSwarmClient` allow the same `LeafFuzz.jar` to run from a terminal (`java -jar LeafFuzz.jar swarm` / `extract-mineflayer`) as a zero-dependency external TCP swarm and capacity tester.

## Consequences

- **Positive:** Any Paper, Spigot, Folia, Fabric, or NeoForge developer or server administrator can drop `LeafFuzz.jar` into their test server and run `/fuzz check target=<PluginOrMod>` with zero external Python/Docker/RCON dependencies, or run `java -jar LeafFuzz.jar swarm` from a terminal.
- **Safety (`S-002`, `S-004`, `S-005`, `S-007`):** All archive `ZipFile` scans, bytecode causal graph scans, and `GC.class_histogram` invocations execute off the main tick thread via `ServerAccessor#scheduler()`; `NmsEmbeddedPlayerSession` releases all Netty `ReferenceCounted` buffers and removes `ServerPlayer` sessions on disconnect; destructive server commands (`CommandSurfaceAuditor.DEFAULT_DENYLIST`) are blocked from fuzz execution; all user-facing command failure strings are configurable in `messages.yml`.
