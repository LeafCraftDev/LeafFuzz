# Configuration Reference (`LeafFuzz`)

Configuration files are generated on first server startup under `plugins/LeafFuzz/` on `Paper`, `Spigot`, `Purpur`, and `Folia` (or `config/leaffuzz/` on `Fabric` and `NeoForge`).

---

## File Overview

| File | Purpose | Key Sections |
|---|---|---|
| `config.yml` | Default episode budget, concurrent player roster, slow-tick MSPT threshold, disposable-server guard, extra command denylist, multi-boot campaign settings, and optional AST-grounded LLM audit | `check`, `campaign`, `llmAudit` |
| `messages.yml` | All operator-facing chat/console prefix, permission, parameter, busy, and reload strings | `prefix`, `noPermission`, `badParameter`, `invalidCommand`, `busy`, `reloadSuccess`, `reloadFailed` |
| `personas.jsonl` *(optional)* | Custom `sleuth_persona_v1` JSONL behavioral profiles (`Int8[16x16]` policy genome + biometric cadence) loaded alongside the 8 built-in archetypes | One JSON object per line (`schema: "sleuth_persona_v1"`) |
| `reports/<target>-qc-report.md` | Self-contained 5-stage Markdown QC scorecard written automatically after every `/fuzz check` run | Stage 1..5 verdicts, LuckPerms / `commands.yml` fixes, `ddmin` reproducers, `exc:`/`stall:`/`hazard:` stacks, Bonferroni OLS retention slopes, and Order-1/Order-2 bytecode causal findings |
| `reports/<target>-qc-data.yml` & `.json` | Machine-readable quality and safety moderation evidence leading on line 1 with `status: <PASS\|WARN\|FAIL>` | `status`, `moderation_ready`, `stage_verdicts`, `quality_metrics`, `shrunk_reproducers`, `fault_signatures`, `retention_findings`, `causal_findings` |

---

## `config.yml` Settings

| Key | Type | Default | Description |
|---|---|---|---|
| `check.defaultEpisodes` | Integer | `250` | Default number of UCB1 synthetic persona bot episodes executed when `episodes=<n>` is omitted from `/fuzz check`. Valid range: `1..100000`. |
| `check.defaultPlayers` | Integer \| String | `1` | Default concurrent player survival roster size (`1..500`, or `"auto"` / `"ramp"` to progressively ramp concurrent players until instability) dispersed across an Archimedean spiral when `players=` is omitted from `/fuzz check`. |
| `check.slowTickThresholdMs` | Number | `100.0` | Main-thread tick duration threshold in milliseconds (`>= 10.0`) above which `LogAndStallSignatureOracle` captures a slow-tick stack trace (`stall:`) outside JVM GC pause windows. |
| `check.requireDisposableForAll` | Boolean | `true` | Safety guard for whole-server sweeps (`target=all`). |
| `check.extraDenylist` | List\<String\> | `[]` | Additional command prefixes excluded from Stage 2 fuzzing alongside the built-in `DEFAULT_DENYLIST` (`stop`, `restart`, `op`, `deop`, `ban`, `kick`, `reload`, `whitelist`, `save-all`). |
| `campaign.restartStrategy` | String | `"AUTO"` | Multi-boot campaign restart strategy (`"AUTO"`, `"NONE"`, `"SPIGOT_RESTART"`, `"SUPERVISOR_STOP"`). |
| `campaign.maxRestartRetries` | Integer | `3` | Maximum crash/restart retries (`1..20`) before `FuzzCampaignStateStore` halts or isolates a crashing archive. |
| `llmAudit.llmAuditEnabled` | Boolean | `false` | Enables optional AST-grounded root-cause explanations and advisory `Jminor` causal chain auditing via `LlmCausalChainAuditor`. Makes zero network calls when `false`. |
| `llmAudit.llmProvider` | String | `"OFF"` | LLM provider identifier (`"OFF"`, `"GEMINI"`, `"OPENAI_COMPATIBLE"`, `"ANTHROPIC"`, or `"OLLAMA"`). |
| `llmAudit.llmModel` | String | `"gemini-2.5-flash"` | Model identifier sent to the configured provider. |
| `llmAudit.llmEndpoint` | String | `""` | Custom HTTP endpoint URL, or empty to use the provider's default endpoint (`http://127.0.0.1:11434/v1/chat/completions` for `OLLAMA`). |
| `llmAudit.llmApiKeyEnv` | String | `"GEMINI_API_KEY"` | Environment variable name holding the provider API key (never stored in plaintext in `reports/`). |
| `llmAudit.explainFuzzFaults` | Boolean | `true` | When `llmAudit.llmAuditEnabled` is `true`, attaches closed-world verified `Class#method` root-cause explanations to proven Stage 2/3/5 findings without altering pass/fail verdicts. |
| `llmAudit.maxChainsPerTarget` | Integer | `6` | Maximum number of `Jminor` causal chains or findings sent to the LLM per target (`1..32`). |

---

## `messages.yml` Settings

| Key | Default | Description |
|---|---|---|
| `prefix` | `"&8[&2LeafFuzz&8] &r"` | Chat and console prefix prepended to `/fuzz` replies. |
| `noPermission` | `"&cYou do not have permission to run this LeafFuzz command."` | Sent when a caller lacks `leaffuzz.admin`. |
| `badParameter` | `"&cInvalid parameter '[param]': '[value]'."` | Sent when a `name=value` parameter fails validation. |
| `invalidCommand` | `"&cUnknown subcommand '[arg]'. Use /fuzz help."` | Sent when an unknown subcommand or bare positional token is supplied. |
| `busy` | `"&eA diagnostic snapshot or fuzz pass is already running; please wait."` | Sent when `/fuzz check` or `/fuzz leaks snapshot` is invoked while another pass is already active. |
| `reloadSuccess` | `"&aLeafFuzz configuration and messages reloaded."` | Sent after `/fuzz reload` validates and reloads `config.yml` and `messages.yml`. |
| `reloadFailed` | `"&cLeafFuzz reload failed: [errors]"` | Sent when `config.yml` fails validation during `/fuzz reload`. |
