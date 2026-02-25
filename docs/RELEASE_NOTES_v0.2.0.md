# LocalAgent v0.2.0 Release Notes

Date: 2026-02-25

## Highlights

- Runtime architecture refactor: major decomposition of `main.rs` into focused runtime modules.
- Startup UX improvement: automatic `.localagent/` initialization on first project use.
- Planner/chat/task execution paths hardened with preserved deterministic behavior and full regression coverage.
- Documentation alignment for current behavior, especially init flow and in-chat timeout controls.

## What Shipped

### Runtime Modularization

The runtime surface was split into dedicated modules to reduce coupling and improve maintainability:

- `agent_runtime`
- `chat_tui_runtime`
- `chat_repl_runtime`
- `tasks_graph_runtime`
- `startup_bootstrap`
- `startup_detect`
- `startup_init`
- `runtime_wiring`
- `runtime_paths`
- `runtime_events`
- `runtime_flags`
- `task_apply`
- `task_eval_profile`
- `ops_helpers`
- `session_ops`
- `approvals_ops`
- `instruction_runtime`
- `planner_runtime`

`main.rs` now primarily acts as command orchestration and entrypoint wiring.

### Startup / Init Behavior

- LocalAgent now auto-initializes `.localagent/` on first command use in a project when missing.
- `localagent init` remains available for explicit, deterministic scaffold generation.

### Chat and Timeout UX

- Slash-command timeout behavior is documented and aligned with runtime behavior:
  - `/timeout <seconds|+N|-N|off>`
  - `/timeout off` disables request/stream-idle timeout (connect timeout unchanged)

### Docs and Guidance Alignment

- Updated docs to reflect:
  - auto-init behavior
  - `.localagent/instructions.yaml` as the canonical profile path
  - current timeout command semantics

## Behavior Notes

- No intentional breaking CLI flag removals in this release.
- Runtime internals were substantially reorganized; integrations depending on internal module layout should update references accordingly.

## Verification Summary

- `cargo check` passes.
- `cargo test --workspace` passes.
- Regression harness remains green, including MCP/protocol guard tests.

## Upgrade

```bash
cargo install --path . --force
localagent version
```

## Recommended Post-Upgrade Checks

1. Run `localagent` in a fresh project dir to confirm auto-init behavior.
2. Validate provider connectivity via `localagent doctor --provider <provider>`.
3. Run one coding-task prompt in chat TUI and verify tool/approval/log panes behave as expected.
4. If using instruction profiles, verify path/config resolution under `.localagent/instructions.yaml`.
