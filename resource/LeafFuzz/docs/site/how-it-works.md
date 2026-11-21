# LeafFuzz — How It Works

## 1. Static JAR & Schema Introspection

When `/fuzz check <target>` starts, `LeafFuzz` inspects the target plugin's loaded `PluginDescriptionFile` / `paper-plugin.yml`, Brigadier / `CommandMap` registrations, `@EventHandler` bytecode descriptors, and default YAML resources to build a typed input generator covering valid, boundary, and adversarial command/config inputs.

## 2. Bounded Episode Runner & Tick-Stall Watchdog

Each fuzzing episode executes under a deterministic PRNG seed (`seed=<n>`) and monitors:
- **Tick Duration (`slowTickThresholdMs`)**: Flags any command or event dispatch that pushes server MSPT above `slowTickThresholdMs` (default `50 ms`) or triggers synchronous chunk I/O (`S-005`).
- **Console & Exception Interceptor**: Captures `SEVERE`/`WARN` stack traces, unhandled `CommandException`s, and `[BIT]` fault codes, deduplicating them by root stack frame.
- **State & Memory Hygiene**: Compares active scheduler tasks, chunk tickets, and listener registrations before and after `/fuzz check` and plugin reload cycles.

## 3. Deterministic Markdown QC Report Generation

Upon completion, `LeafFuzz` writes a reproducible report to `plugins/LeafFuzz/reports/<target>-qc-report.md` containing the exact failing command/config seed, stack trace, MSPT delta, and `[FUZZ bit]` classification (`FUZZ-PBIT-*`, `FUZZ-CBIT-*`, `FUZZ-IBIT-*`).
