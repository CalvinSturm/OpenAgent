# LocalAgent CLI Reference

This document is a comprehensive command and flag reference for `localagent`.

## Binary

```bash
localagent [OPTIONS] [COMMAND]
```

## Global Command Pattern

Global options are parsed before subcommands.

```bash
localagent --provider lmstudio --model <model> --prompt "hello" run
localagent --provider lmstudio --model <model> chat --tui
```

## Top-Level Commands

- `run`
- `exec`
- `version`
- `init`
- `template`
- `chat`
- `doctor`
- `mcp`
- `hooks`
- `policy`
- `approvals`
- `approve`
- `deny`
- `check`
- `profile`
- `replay`
- `session`
- `eval`
- `repo`
- `pack`
- `learn`
- `tui`
- `tasks`

## Global Options (All-Mode)

- `--provider <lmstudio|llamacpp|ollama|mock>`
- `--model <MODEL>`
- `--base-url <BASE_URL>`
- `--api-key <API_KEY>`
- `--prompt <PROMPT>`
- `--max-steps <N>` (default: `20`)
- `--workdir <PATH>` (default: `.`)
- `--state-dir <PATH>`
- `--mcp <NAME>` (repeatable)
- `--pack <PACK_ID>` (repeatable)
- `--mcp-config <PATH>`
- `--reliability-profile <local_small_strict|coding_balanced|web_cautious>`

### Tool/Execution Safety

- `--allow-shell`
- `--allow-write`
- `--enable-write-tools`
- `--max-tool-output-bytes <N>` (default: `200000`)
- `--max-read-bytes <N>` (default: `200000`)

### Execution Target

- `--exec-target <host|docker>` (default: `host`)
- `--docker-image <IMAGE>` (default: `ubuntu:24.04`)
- `--docker-workdir <PATH>` (default: `/work`)
- `--docker-network <none|bridge>` (default: `none`)
- `--docker-user <uid:gid>`

### Trust/Approvals

- `--trust <off|auto|on>` (default: `off`)
- `--approval-mode <interrupt|auto|fail>` (default: `interrupt`)
- `--auto-approve-scope <run|session>` (default: `run`)
- `--approval-key <v1|v2>` (default: `v1`)
- `--policy <PATH>`
- `--approvals <PATH>`
- `--audit <PATH>`

### Unsafe Controls

- `--unsafe`
- `--no-limits`
- `--unsafe-bypass-allow-flags`

### Session/Memory

- `--session <NAME>` (default: `default`)
- `--no-session`
- `--reset-session`
- `--max-session-messages <N>` (default: `40`)
- `--use-session-settings`
- `--use-repomap`
- `--repomap-max-bytes <N>` (default: `32768`)

### Compaction

- `--max-context-chars <N>` (default: `0`, disabled)
- `--compaction-mode <off|summary>` (default: `off`)
- `--compaction-keep-last <N>` (default: `20`)
- `--tool-result-persist <all|digest|none>` (default: `digest`)

### Hooks

- `--hooks <off|auto|on>` (default: `off`)
- `--hooks-config <PATH>`
- `--hooks-strict`
- `--hooks-timeout-ms <N>` (default: `2000`)
- `--hooks-max-stdout-bytes <N>` (default: `200000`)

### Tool Arg Validation

- `--tool-args-strict <on|off>` (default: `on`)

### Instruction Profiles

- `--instructions-config <PATH>`
- `--instruction-model-profile <NAME>`
- `--instruction-task-profile <NAME>`
- `--task-kind <NAME>`

### Taint/Repro

- `--taint <off|on>` (default: `off`)
- `--taint-mode <propagate|propagate-and-enforce>` (default: `propagate`)
- `--taint-digest-bytes <N>` (default: `4096`)
- `--repro <off|on>` (default: `off`)
- `--repro-out <PATH>`
- `--repro-env <off|safe|all>` (default: `safe`)

### Capabilities/Streaming/Events

- `--caps <auto|off|strict>` (default: `off`)
- `--stream`
- `--events <PATH>`

### Provider HTTP Resilience

- `--http-max-retries <N>` (default: `2`)
- `--http-timeout-ms <N>` (default: `0`)
- `--http-connect-timeout-ms <N>` (default: `2000`)
- `--http-stream-idle-timeout-ms <N>` (default: `0`)
- `--http-max-response-bytes <N>` (default: `10000000`)
- `--http-max-line-bytes <N>` (default: `200000`)

### TUI + Planner/Worker

- `--tui`
- `--tui-refresh-ms <N>` (default: `50`)
- `--tui-max-log-lines <N>` (default: `200`)
- `--mode <single|planner-worker>` (default: `single`)
- `--planner-model <MODEL>`
- `--worker-model <MODEL>`
- `--planner-max-steps <N>` (default: `2`)
- `--planner-output <json|text>` (default: `json`)
- `--enforce-plan-tools <off|soft|hard>` (default: `off`)
- `--mcp-pin-enforcement <off|warn|hard>` (default: `hard`)
- `--planner-strict <true|false>` (default: `true`)
- `--no-planner-strict`

## Command Reference

### `run`

```bash
localagent run
```

Runs one-shot execution using global flags (`--prompt` required for practical use).

### `exec`

Alias of `run`.

### `chat`

```bash
localagent chat [--tui] [--plain-tui] [--no-banner]
```

### `version`

```bash
localagent version [--json]
```

### `init`

```bash
localagent init [--state-dir <PATH>] [--workdir <PATH>] [--force] [--print]
```

Note: `localagent` auto-initializes `.localagent/` on first use in a project. `init` remains useful for explicit, up-front scaffolding.

### `template`

- `localagent template list`
- `localagent template show <NAME>`
- `localagent template write <NAME> --out <PATH> [--force]`

### `doctor`

```bash
localagent doctor --provider <lmstudio|llamacpp|ollama> [--base-url <URL>] [--api-key <KEY>]
localagent doctor --docker
```

Notes:
- `doctor --docker` checks that the Docker daemon is reachable and that the configured Docker image (from `--docker-image`, default runtime config, or profile-resolved run config) exists locally.
- Docker shell sandbox runs do not fall back to host shell execution if Docker fails.
- Windows: Docker Desktop must be running and the workdir drive must be shared/mountable. If Docker mount checks fail, inspect the resolved workdir path and Docker config summary in the error output/artifacts.

### `mcp`

- `localagent mcp list`
- `localagent mcp doctor <NAME>`

### `hooks`

- `localagent hooks list`
- `localagent hooks doctor`

### `policy`

- `localagent policy doctor [--policy <PATH>]`
- `localagent policy print-effective [--policy <PATH>] [--json]`
- `localagent policy test --cases <PATH> [--json] [--policy <PATH>]`

### `approvals`

- `localagent approvals list`
- `localagent approvals prune`
- `localagent approve <ID> [--ttl-hours <N>] [--max-uses <N>]`
- `localagent deny <ID>`

### `check`

- `localagent check run [--path <DIR_OR_FILE>] [--json-out <PATH>] [--junit-out <PATH>] [--max-checks <N>]`

Notes:
- Checks are discovered from `.localagent/checks/` by default (`*.md` with strict YAML frontmatter).
- `check run` is fail-closed/non-interactive by default (`approval_mode=fail`, sessions disabled).
- `write`/`shell` checks run in isolated scratch workdirs when enabled via allow flags.
- `allowed_tools` is enforced against tools actually used during the check run.
- Exit codes are deterministic:
  - `0` pass
  - `2` invalid checks / schema / loader config
  - `3` one or more check failures
  - `4` runner/runtime errors

Example:

```bash
localagent --provider mock --model mock check run --path .localagent/checks --json-out check-report.json --junit-out check-report.xml
```

### `profile`

- `localagent profile list`
- `localagent profile show <NAME>`

Notes:
- Reliability profiles are deterministic built-in presets for local-model budgets/caps and approval posture defaults.
- Profiles do not enable shell/write or write-tool exposure; those remain explicit flags.
- Use `--reliability-profile <NAME>` with `run` / `chat` / other run-mode flows, then override any profile-managed setting explicitly with CLI flags.

### `replay`

- `localagent replay <RUN_ID>`
- `localagent replay verify <RUN_ID> [--strict] [--json]`

### `session`

- `localagent session info`
- `localagent session show [--last <N>]`
- `localagent session drop [--from <IDX>] [--last <N>]`
- `localagent session reset`

Task memory:

- `localagent session memory add --title <TITLE> --content <CONTENT>`
- `localagent session memory list`
- `localagent session memory show <ID>`
- `localagent session memory update <ID> [--title <TITLE>] [--content <CONTENT>]`
- `localagent session memory delete <ID>`

### `eval`

```bash
localagent eval [OPTIONS]
```

Major eval-only options:

- `--models <CSV>`
- `--pack <coding|browser|all>`
- `--out <PATH>`
- `--junit <PATH>`
- `--summary-md <PATH>`
- `--cost-model <PATH>`
- `--runs-per-task <N>`

### `repo`

- `localagent repo map [--print-content] [--no-write] [--max-files <N>] [--max-scan-bytes <N>] [--max-out-bytes <N>]`

### `pack`

- `localagent pack list`
- `localagent pack show <PACK_ID>`

Notes:
- Packs are discovered from `.localagent/packs/<pack_id>/PACK.md`.
- Pack activation is operator-controlled and per-run via repeatable `--pack <PACK_ID>`.
- Activated packs inject bounded guidance blocks and are recorded in run artifacts/events.
- `--timeout-seconds <N>`
- `--min-pass-rate <0..1>`
- `--fail-on-any`
- `--max-avg-steps <N>`
- `--compare-baseline <NAME>`
- `--fail-on-regression`
- `--bundle <PATH>`

Eval groups:

- `localagent eval profile list`
- `localagent eval profile show <NAME> [--json] [--profile-path <PATH>]`
- `localagent eval profile doctor <NAME> [--profile-path <PATH>]`
- `localagent eval baseline create <NAME> --from <RESULTS_JSON>`
- `localagent eval baseline show <NAME>`
- `localagent eval baseline delete <NAME>`
- `localagent eval baseline list`
- `localagent eval report compare --a <RESULT_A> --b <RESULT_B> --out <MD_OUT> [--json <JSON_OUT>]`

### `learn`

- `localagent learn capture --category <workflow-hint|prompt-guidance|check-candidate> --summary <TEXT> [--run <RUN_ID>] [--task-summary <TEXT>] [--profile <TEXT>] [--guidance-text <TEXT>] [--check-text <TEXT>] [--tag <TAG>]... [--evidence <KIND:VALUE>]... [--evidence-note <TEXT>]... [--assist] [--write]`
- `localagent learn list`
- `localagent learn show <ID>`
- `localagent learn archive <ID>`
- `localagent learn promote <ID> --to <check|pack|agents> [--slug <SLUG>] [--pack-id <PACK_ID>] [--force] [--check-run] [--replay-verify] [--replay-verify-run-id <RUN_ID>] [--replay-verify-strict]`

Notes:
- `learn capture --assist` is preview-only unless `--write` is provided.
- `learn promote --to check` requires `--slug`.
- `learn promote --to pack` requires `--pack-id`.

### `tui`

- `localagent tui tail --events <PATH> [--refresh-ms <N>]`

### `tasks`

- `localagent tasks run --taskfile <PATH> [--resume] [--checkpoint <PATH>] [--fail-fast <true|false>] [--max-nodes <N>] [--propagate-summaries <off|on>]`
- `localagent tasks status --checkpoint <PATH>`
- `localagent tasks reset --checkpoint <PATH>`

## Common Full Commands

Fast local test run:

```bash
localagent --provider lmstudio --model <model> --caps off --trust off --hooks off --no-session --max-steps 8 --prompt "Say hi." run
```

Enable shell and write tools intentionally:

```bash
localagent --provider lmstudio --model <model> --allow-shell --enable-write-tools --allow-write --prompt "..." run
```

TUI chat:

```bash
localagent --provider lmstudio --model <model> chat --tui
```

Chat TUI slash commands:

- `/help`
- `/mode`
- `/mode safe`
- `/mode coding`
- `/mode web`
- `/mode custom`
- `/timeout`
- `/timeout <seconds|+N|-N|off>`
- `/dismiss`
- `/clear`
- `/exit`
- `/hide tools|approvals|logs`
- `/show tools|approvals|logs|all`

Mode naming note:

- `/mode coding` is the command token.
- Header label displays as `Code`.
- `/timeout` updates request and stream-idle timeout together (connect timeout is unchanged).
- `/timeout off` disables request and stream-idle timeout (connect timeout remains unchanged).

---

For provider install/setup walkthroughs, see `docs/LLM_SETUP.md`.
