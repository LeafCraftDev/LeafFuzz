# LeafFuzz — What Not To Do

## 1. Never Run Destructive Fuzz Episodes on a Live Production World
`LeafFuzz` intentionally executes boundary commands, rapid reload cycles, and stress workloads to uncover crashes and state corruption. Always run `/fuzz check`, `/fuzz stress`, and `swarm` mode on a **disposable staging or devstack server** (`allow-live-production: false` in `config.yml`), never on a live player world.

## 2. Do Not Disable `abortOnCriticalBit` During Automated CI Runs
Keep `abortOnCriticalBit: true` and `slowTickThresholdMs` configured in `plugins/LeafFuzz/config.yml` so severe tick freezes or `OutOfMemoryError` precursors halt the episode cleanly and flush `reports/<target>-qc-report.md` to disk.

## 3. Do Not Point Standalone `swarm` Mode at External Public Servers
Standalone `swarm` mode is restricted to loopback/local staging targets (`127.0.0.1`, `localhost`, or explicitly authorized devstack containers).
