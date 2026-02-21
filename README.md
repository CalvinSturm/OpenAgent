# LocalAgent
<img width="858" height="445" alt="Screenshot 2026-02-21 052058" src="https://github.com/user-attachments/assets/b2dbe95b-90bd-4bb3-821a-4bb019834c49" />

LocalAgent is a local-runtime agent CLI with tool calling, trust controls, and replayable artifacts.

Primary command is `localagent`.

## Quickstart

```bash
cargo build
localagent init
localagent doctor --provider lmstudio
```

## Command Pattern (Important)

Global flags come before subcommands.

```bash
localagent --provider lmstudio --model essentialai/rnj-1 --prompt "hello" run
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui
```

## Common Commands

One-shot run:

```bash
localagent --provider ollama --model llama3.2 --prompt "Summarize src/main.rs" run
```

Alias:

```bash
localagent --provider ollama --model llama3.2 --prompt "Summarize src/main.rs" exec
```

Chat TUI:

```bash
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui
```

Copy-friendly TUI (no alternate screen):

```bash
localagent --provider lmstudio --model essentialai/rnj-1 chat --tui --plain-tui
```

Chat TUI controls:

- `Esc` quit
- `Ctrl+1/2/3` toggle tools/approvals/logs panes
- `PgUp/PgDn`, `Ctrl+U/Ctrl+D`, mouse wheel: transcript scroll
- `Ctrl+J/K` select approval, `Ctrl+A` approve, `Ctrl+X` deny, `Ctrl+R` refresh
- `/` opens slash command dropdown (Up/Down + Enter)
- `?` opens keybinds dropdown

Auto mode (no args): discovers a local provider and opens chat TUI.

```bash
localagent
```

## Providers

- `lmstudio` default: `http://localhost:1234/v1`
- `llamacpp` default: `http://localhost:8080/v1`
- `ollama` default: `http://localhost:11434`

## Safety Defaults

- `--trust off`
- `--enable-write-tools` off
- `--allow-write` off
- `--allow-shell` off
- output truncation limits on

## State + Templates

Default state dir: `<workdir>/.localagent`

```bash
localagent init
localagent init --print
localagent template list
localagent template show instructions.yaml
localagent template write policy.yaml --out .localagent/policy.yaml --force
```

## Instructions Profiles

`localagent init` now scaffolds `.localagent/instructions.yaml`.

Use task/model overlays:

```bash
localagent --provider lmstudio --model essentialai/rnj-1 --task-kind summarize --prompt "read README.md and summarize" run
localagent --provider lmstudio --model essentialai/rnj-1 --instruction-model-profile essentialai_rnj_tool_discipline --task-kind summarize --prompt "read README.md and summarize" run
```

## Trust + Approvals

```bash
localagent --provider lmstudio --model essentialai/rnj-1 --trust on --approval-mode auto --auto-approve-scope run --prompt "..." run
localagent approvals list
localagent approve <id> [--ttl-hours 24] [--max-uses 10]
localagent deny <id>
```

## Replay

```bash
localagent replay <run_id>
localagent replay verify <run_id>
```

## Help

```bash
localagent --help
localagent chat --help
localagent eval --help
```

## Docs

- Install: `docs/INSTALL.md`
- Templates: `docs/TEMPLATES.md`
- Release notes: `docs/RELEASE_NOTES_v0.1.0.md`
