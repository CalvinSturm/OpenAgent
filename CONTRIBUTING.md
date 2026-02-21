# Contributing to LocalAgent

Thanks for contributing.

## Development Setup

1. Install Rust stable.
2. Clone repo and enter root.
3. Build and validate:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

## Project Principles

- Keep default safety posture unchanged unless explicitly discussed.
- Prefer additive changes over breaking changes.
- Keep behavior deterministic and replayable.
- Do not weaken trust/approval/tool-gate invariants.

## Coding Guidelines

- Use concise, readable code and minimal diffs.
- Add tests for new behavior.
- Update docs when flags/commands/workflows change.
- Keep platform behavior cross-compatible (Windows/Linux/macOS) when possible.

## Pull Request Checklist

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes
- [ ] New/changed behavior covered by tests
- [ ] README/docs updated if user-facing changes were made

## Commit Guidance

- Use clear commit messages (e.g., `feat: ...`, `fix: ...`, `docs: ...`, `chore: ...`).
- Keep commits focused and reviewable.

## Reporting Issues

When filing issues, include:

- OS and version
- `localagent version --json` output
- Command used
- Expected vs actual behavior
- Relevant logs/artifacts (`.localagent/runs`, events JSONL) if available
