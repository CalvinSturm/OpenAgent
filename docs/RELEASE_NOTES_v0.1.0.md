# LocalAgent v0.1.0 Release Notes

Date: 2026-02-21

## Highlights

- Local-runtime agent CLI for LM Studio, llama.cpp server, and Ollama.
- Deterministic tool-calling loop with structured events and run artifacts.
- Trust-lite controls: policy, approvals, audit, approval keying, and replayability.
- MCP stdio integration (including Playwright MCP) with namespaced tools.
- Chat TUI with slash dropdown, approvals actions, and pane toggles.
- Eval harness with local deterministic coding/browser fixtures and reports.
- Session persistence, task memory, replay, and verification workflows.

## Primary Command Name

- Primary binary/CLI command is now `localagent`.

## UX Notes

- Global flags come before subcommands.
- `run` and `exec` are supported one-shot aliases.
- Chat TUI:
  - `Esc` quits
  - `/` opens slash command dropdown (Up/Down + Enter)
  - `?` opens keybinds dropdown
  - tools/approvals/logs are hidden by default; toggle with `Ctrl+1/2/3`

## Safe Defaults

- `--trust off`
- `--allow-shell` off
- `--enable-write-tools` off
- `--allow-write` off
- output limits on by default

## Init + Templates

- `localagent init` scaffolds `.localagent/` state.
- Includes deterministic templates such as:
  - `policy.yaml`
  - `instructions.yaml`
  - `hooks.yaml`
  - `mcp_servers.json`
  - `eval_profile_local_ollama.yaml`

## Upgrade / Install

```bash
cargo install --path . --force
localagent --help
```
