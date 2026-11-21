# LeafFuzz — Intended Usage

**LeafFuzz** is an autonomous quality-control fuzzer and invariant auditor for Minecraft server plugins and mods (`1.21.x` through `26.3`). It discovers command grammars, permission nodes, event listeners, and YAML configuration schemas directly from a target plugin JAR and executes bounded fuzzing episodes while monitoring main-thread/region-thread stalls (`S-005`), uncaught exceptions, memory leaks (`S-002`), and `[FUZZ bit]` fault codes.

---

## Primary Use Cases

1. **Automated Pre-Release Plugin QC (`/fuzz check <Plugin>`)**:
   - Run `/fuzz check <PluginName>` on a disposable Paper, Folia, or Spigot staging server (`1.21.x`–`26.3`) to automatically fuzz subcommands, boundary arguments, permission denials, and reload cycles.
   - Inspect the generated Markdown scorecard at `plugins/LeafFuzz/reports/<target>-qc-report.md` via `/fuzz report <target>`.
2. **Folia Thread-Ownership & Main-Thread I/O Auditing**:
   - Detects synchronous `getChunkAt` calls on the tick thread (`S-005`) and cross-region entity/block access violations (`F-001..F-003`) during synthetic player workloads.
3. **Standalone Multi-Bot `swarm` Stress Testing**:
   - Launch `LeafFuzz` in standalone `swarm` mode against a local containerized server to simulate concurrent player teleports, chunk loads, and command bursts.
