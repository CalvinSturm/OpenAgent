# LocalAgent

Local-first agent runtime for building custom MCP-powered capabilities with local models, safety controls, reproducible runs, and beginner-to-pro UX.

<img width="1100" height="587" alt="123" src="https://github.com/user-attachments/assets/2be9a0d3-8d49-4231-8c14-8547f2a87625" />

LocalAgent is a local-first CLI runtime for developers who want to build stronger agents by connecting local LLMs to custom MCP tools.

Use it to prototype and harden MCP-powered capabilities on your own machine with safe defaults, trust/approval workflows, replayable artifacts, evals, and an interactive TUI chat experience.

Designed for everyone from beginners to power users: easy to start, explicit to operate, and deep enough for advanced MCP workflows.

## Quick Start

Run `cargo install --path . --force` from the LocalAgent repository root.

Run `localagent` from the project/workspace directory you want to work in (LocalAgent initializes `.localagent/` in the current directory).

```bash
# 1) Build or install
cargo install --path . --force

# 2) Start LocalAgent setup (auto-detects providers and initializes .localagent/)
localagent

# 3) (Optional) Verify a specific local provider is reachable
localagent doctor --provider ollama

# 4) Run a one-shot task
localagent --provider ollama --model llama3.2 --prompt "Summarize src/main.rs" run

# 5) Start interactive chat (TUI)
localagent --provider ollama --model llama3.2 chat --tui
```

Add `--trust on` when you want policy + approvals, and enable shell/write tools explicitly only when needed.

For local providers (`LM Studio`, `Ollama`, `llama.cpp`), start the provider first and make sure a model is available before running `localagent`. If you open `localagent` first, press `R` in the startup screen to refresh provider detection after the provider is ready.

## Why LocalAgent

- Beginner-to-pro UX: easy onboarding with advanced controls when you need them
- Build and test custom MCP-powered agent capabilities with local models
- Local-provider focused (`lmstudio`, `llamacpp`, `ollama`)
- Safe defaults (shell/write disabled unless explicitly enabled)
- Deterministic artifacts and event logs for debugging/replay
- Trust controls (policy, approvals, audit)
- MCP stdio integration (including Playwright MCP)
- Built-in eval framework for repeatable model testing

## Who This Is For

- Beginner: You want a safe, guided way to run a local model agent and learn how tools/MCP work.
- Builder: You want to prototype and iterate on MCP-powered workflows for coding or automation on your own machine.
- Advanced MCP developer: You want explicit policy/approval controls, reproducible artifacts, and evals to harden and validate custom MCP capabilities.

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

### Updating an existing install (Windows users especially)

From the repo root, reinstall with:

```bash
cargo install --path . --force
```

If Windows reports a `failed to move ... localagent.exe` error, the previous `localagent.exe` is still running or locked.

- Close any `localagent` sessions (especially TUI windows)
- Close terminals using `localagent`
- Run the install command again

Verify the active binary/version:

```powershell
Get-Command localagent
localagent version
```

### Option 3: GitHub releases

Download the correct `localagent-<OS>-<tag>` asset from Releases and place it on your `PATH`.

## First-Time Setup

On first use in a project directory, `localagent` auto-initializes `.localagent/` if it does not exist.

### Provider Prerequisites

| Provider | Before running `localagent` | Default endpoint |
| --- | --- | --- |
| LM Studio | Start LM Studio and load a model (serve OpenAI-compatible API) | `http://localhost:1234/v1` |
| Ollama | Start Ollama and ensure a model is available locally | `http://localhost:11434` |
| llama.cpp | Start the server (`llama-server`) with a loaded model | `http://localhost:8080/v1` |

You can still run init explicitly when you want deterministic scaffolding up front:

```bash
localagent init
```

This scaffolds default state/config under (same layout as auto-init):

```text
<workdir>/.localagent/
```

Then verify provider connectivity:

```bash
localagent doctor --provider lmstudio
localagent doctor --provider ollama
localagent doctor --provider llamacpp
```

## Command Pattern (Important)

Global flags come before subcommands.

```bash
localagent --provider lmstudio --model essentialai/rnj-1 --prompt "hello" run
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui
```

## Quick Start Examples

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

Startup screen controls:

- `↑/↓`: move selection
- `Space`: select option / toggle custom option
- `Enter`: start chat when provider is connected
- `R`: refresh provider detection
- `D`: toggle provider details
- `Esc`: quit

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
- `/mode <safe|coding|web|custom>`: switch chat runtime mode
- `/timeout [seconds|+N|-N|off]`: show and adjust request/stream idle timeout for slow generations
- `/dismiss`: dismiss active timeout notification
- `?`: show keybind help dropdown

Mode naming note:

- Use `/mode coding` in commands.
- The header label for that mode is shown as `Code`.

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
localagent doctor --provider llamacpp
```

## Docs

Need deeper setup, profiles, or reference docs? Start here.

- [Install](docs/INSTALL.md)
- [Templates](docs/TEMPLATES.md)
- [CLI reference](docs/CLI_REFERENCE.md)
- [Provider setup](docs/LLM_SETUP.md)
- [Contributing](CONTRIBUTING.md)
- [Release notes](docs/release-notes/README.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT
