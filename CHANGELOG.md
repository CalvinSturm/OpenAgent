# Changelog

## v0.1.0 - 2026-02-21

- Released LocalAgent v0.1.0 (local-runtime agent CLI).
- Set primary CLI command to `localagent`.
- Added `run` and `exec` command aliases for one-shot usage.
- Updated chat TUI UX:
  - pane toggles (`Ctrl+1/2/3`)
  - slash command dropdown (`/` + Up/Down + Enter)
  - keybinds dropdown (`?`)
  - `Esc` to quit
  - tools/approvals/logs hidden by default
- Added deterministic instruction profiles support:
  - `--instructions-config`
  - `--instruction-model-profile`
  - `--instruction-task-profile`
  - `--task-kind`
- Added scaffolded `instructions.yaml` via `localagent init`.
- Updated README and docs for current command patterns and behavior.
