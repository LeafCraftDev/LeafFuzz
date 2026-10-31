# BIT Code Catalog (`[FUZZ bit]`)

Generated from the registered `LeafFuzzBitSuite` (`[FUZZ bit]`) catalog. IDs and keys are stable; retired codes are not reused.

Run `/fuzz test` (or `/qc test`) in-game or from the console to execute all 6 core PBIT, CBIT, and IBIT self-test components plus 3 live server canaries (`FUZZ-LIVE-001` through `FUZZ-LIVE-003`) when attached to a running server. A healthy installation reports `6/6 PASS` in headless/unit checks and `9/9 PASS` on a live server:

```text
[LeafFuzz] === [FUZZ bit] Self-Test Suite (9/9 PASS) ===
```

## Namespaces

| Prefix |
|---|
| `FUZZ` |

## `FUZZ`

| ID | Code | Severity | Tier | Subsystem | Remediation |
|---:|---|---|---|---|---|
| 1 | `FUZZ-PBIT-001` | ERROR | PBIT | ownership | Verify `JarClassOwnershipIndex` archive scanning permissions on `plugins/*.jar` or `mods/*.jar` and ensure shaded library classes are excluded from unique attribution. |
| 2 | `FUZZ-PBIT-002` | ERROR | PBIT | auditor | Verify `CommandSurfaceAuditor` `DEFAULT_DENYLIST` (`stop`, `restart`, `op`, `deop`, `ban`, `kick`, `reload`) and `LeastPrivilegeOracle` `default` vs `op` exposure checks. |
| 3 | `FUZZ-CBIT-001` | ERROR | CBIT | fuzzer | Verify `SleuthServerFuzzer` Zeller's `ddmin` + binary numeric boundary bisection and `PersonaPolicyBotActor` 256-byte `Int8[16x16]` policy genome evaluation. |
| 4 | `FUZZ-CBIT-002` | ERROR | CBIT | retention | Verify `ClassRetentionScreener` Bonferroni-corrected OLS post-GC class retention slope regression across player departures and command executions. |
| 5 | `FUZZ-CBIT-003` | ERROR | CBIT | claims | Verify `BytecodeCausalGraphScanner` Order-1/Order-2 claim delivery (`Claims X -> Does Not Deliver Y`), dead config key detection (`CLAIM_DEAD_CONFIG_KEY`), and config-gated listener registration modes (`REGISTERED_CONFIG_GATED` vs `UNREGISTERED`). |
| 6 | `FUZZ-IBIT-001` | ERROR | IBIT | scorecard | Verify `LogAndStallSignatureOracle` slow-tick stall (`stall:`), main-thread synchronous hazard (`hazard:sync-chunk:`), and grey-box coverage (`cov:`) attribution, `LeafFuzzMenuBuilder` `BookContrastValidator` WCAG 2.1 compliance, and `LeafFuzzScorecardReport` 5-stage Markdown/YAML/JSON export. |
| 7 | `FUZZ-LIVE-001` | ERROR | LIVE-GC | retention | Verify live JMX `DiagnosticCommandMBean#gcClassHistogram` (`GC.class_histogram`) heap canary allocation and post-GC reclamation (`LiveHeapCanary`). |
| 8 | `FUZZ-LIVE-002` | ERROR | LIVE-MSPT | oracle | Verify live main-thread MSPT sampling (`currentServerMspt()`) and `JarClassOwnershipIndex` archive discovery on the running server. |
| 9 | `FUZZ-LIVE-003` | ERROR | LIVE-BOT | fuzzer | Verify live `ServerPlayer` spawn, random-slot salient GUI menu click (`InventoryClickEvent`), and clean player disconnect without residual online sessions. |
