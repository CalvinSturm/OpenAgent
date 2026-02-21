# LocalAgent
<img width="858" height="445" alt="Screenshot 2026-02-21 052058" src="https://github.com/user-attachments/assets/b2dbe95b-90bd-4bb3-821a-4bb019834c49" />

LocalAgent is a local-first agent runtime CLI for coding and automation with explicit safety controls.

It supports local model providers, tool calling, trust/approval workflows, replayable artifacts, eval harnesses, MCP tool sources, and a TUI chat experience.

## Why LocalAgent

- Local-provider focused (`lmstudio`, `llamacpp`, `ollama`)
- Safe defaults (shell/write disabled unless explicitly enabled)
- Deterministic artifacts and event logs for debugging/replay
- Trust controls (policy, approvals, audit)
- MCP stdio integration (including Playwright MCP)
- Built-in eval framework for repeatable model testing

## Installation

### Option 1: Build from source

```bash
cargo build --release
```

Binary:

- Windows: `target/release/localagent.exe`
- Linux/macOS: `target/release/localagent`

### Option 2: Install globally from source

```bash
cargo install --path . --force
```

### Option 3: GitHub releases

Download the correct `localagent-<OS>-<tag>` asset from Releases and place it on your `PATH`.

## First-Time Setup

Run in your project directory:

```bash
localagent init
```

This scaffolds default state/config under:

```text
<workdir>/.localagent/
```

Then verify provider connectivity:

```bash
localagent doctor --provider lmstudio
localagent doctor --provider ollama
```

## Command Pattern (Important)

Global flags come before subcommands.

```bash
localagent --provider lmstudio --model essentialai/rnj-1 --prompt "hello" run
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui
```

## Quickstart Examples

### One-shot run

```bash
localagent --provider ollama --model llama3.2 --prompt "Summarize src/main.rs" run
```

Alias:

```bash
localagent --provider ollama --model llama3.2 --prompt "Summarize src/main.rs" exec
```

### Interactive chat (TUI)

```bash
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui
```

### Auto-discovery mode

```bash
localagent
```

## Providers

Defaults:

- `lmstudio` -> `http://localhost:1234/v1`
- `llamacpp` -> `http://localhost:8080/v1`
- `ollama` -> `http://localhost:11434`

Set explicitly when needed:

```bash
localagent --provider lmstudio --base-url http://localhost:1234/v1 --model <model> --prompt "..." run
```

## Safety Model

Default posture is conservative:

- `--trust off`
- `--enable-write-tools false`
- `--allow-write false`
- `--allow-shell false`
- tool output limits enabled

Shell and write side effects require explicit enablement.

### Enable shell/write intentionally

```bash
localagent \
  --provider lmstudio \
  --model <model> \
  --allow-shell \
  --enable-write-tools \
  --allow-write \
  --prompt "..." run
```

## Trust + Approvals

Enable trust controls:

```bash
localagent --provider lmstudio --model <model> --trust on --prompt "..." run
```

Manage approvals:

```bash
localagent approvals list
localagent approve <id> [--ttl-hours 24] [--max-uses 10]
localagent deny <id>
```

Policy tools:

```bash
localagent policy doctor
localagent policy print-effective
localagent policy test --cases .localagent/policy_cases.yaml
```

## TUI Controls

In chat TUI:

- `Esc`: quit
- `Ctrl+1/2/3`: toggle tools/approvals/logs panes
- Mouse wheel: scroll transcript
- `Ctrl+J/K`: move approval selection
- `Ctrl+A`: approve selected request
- `Ctrl+X`: deny selected request
- `Ctrl+R`: refresh approvals
- `/`: open slash-command dropdown
- `?`: show keybind help dropdown

## Sessions and Memory

Session flags:

```bash
--session <name>
--no-session
--reset-session
--use-session-settings
```

Task memory commands:

```bash
localagent session memory add --title "Goal" --content "..."
localagent session memory list
localagent session memory show <id>
localagent session memory update <id> --content "..."
localagent session memory delete <id>
```

## Replay and Reproducibility

Replay a run:

```bash
localagent replay <run_id>
```

Verify environment/config consistency for a prior run:

```bash
localagent replay verify <run_id>
```

Capture reproducibility snapshot during run:

```bash
localagent --repro on --repro-env safe --prompt "..." run
```

## Eval

Run deterministic eval packs:

```bash
localagent eval --provider ollama --models "qwen3:8b" --pack coding
```

Common outputs include JSON results, optional JUnit, and Markdown summaries.

## MCP

List configured MCP servers:

```bash
localagent mcp list
```

Health-check a server:

```bash
localagent mcp doctor playwright
```

Use a server in run/chat:

```bash
localagent --mcp playwright --provider lmstudio --model <model> chat --tui
```

## Task Graph Execution

Run DAG taskfiles with checkpointing:

```bash
localagent tasks run --taskfile .localagent/tasks/example_taskfile.json --resume
```

Checkpoint/status commands:

```bash
localagent tasks status --checkpoint .localagent/tasks/checkpoint.json
localagent tasks reset --checkpoint .localagent/tasks/checkpoint.json
```

## Templates

```bash
localagent template list
localagent template show policy.yaml
localagent template write policy.yaml --out .localagent/policy.yaml --force
```

## Common Troubleshooting

`The term 'localagent' is not recognized`:

- Run with Cargo directly:

```bash
cargo run -- --help
```

- Or install globally:

```bash
cargo install --path . --force
```

`unexpected argument` errors:

- Ensure global flags come before subcommands.
- Example:

```bash
localagent --provider lmstudio --model <model> --prompt "hi" run
```

Provider connection failures:

```bash
localagent doctor --provider lmstudio
localagent doctor --provider ollama
```

## Docs

- Install: `docs/INSTALL.md`
- Templates: `docs/TEMPLATES.md`
- CLI reference: `docs/CLI_REFERENCE.md`
- Provider setup: `docs/LLM_SETUP.md`
- Contributing: `CONTRIBUTING.md`
- Release notes: `docs/RELEASE_NOTES_v0.1.0.md`
- Changelog: `CHANGELOG.md`
- Security policy: `SECURITY.md`
- Code of conduct: `CODE_OF_CONDUCT.md`

## License

MIT
