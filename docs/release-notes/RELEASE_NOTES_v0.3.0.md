# LocalAgent v0.3.0 Release Notes

Release date: 2026-02-27

## Highlights

- Shipped the full learn roadmap from capture through explicit promotion targets.
- Added assisted learning capture with provenance metadata and preview-first write gating.
- Delivered Chat TUI `/learn` support (Phase A + Phase B) with CLI-parity behavior.

## Included Changes

### Learning Store and Promotion

- Added `learn capture`, `learn list`, `learn show <id>`, and `learn archive <id>`.
- Added `learn promote <id> --to check --slug <slug>`.
- Added `learn promote <id> --to pack --pack-id <pack_id>`.
- Added `learn promote <id> --to agents`.
- Added deterministic promotion events (`openagent.learning_promoted.v1`) including target file hash metadata.

### Assisted Capture and Chaining

- Added assisted draft flow: `learn capture --assist` (preview-only by default) and `--write` to persist.
- Added provenance metadata fields for assisted captures.
- Added one-shot promote+validate chaining options:
  - `--check-run`
  - `--replay-verify`
  - `--replay-verify-run-id <RUN_ID>`
  - `--replay-verify-strict`

### Chat TUI

- Added `/learn help`, `/learn list`, `/learn show <id>`, `/learn archive <id>`.
- Added `/learn capture ...` and `/learn promote ...` passthrough with deterministic quoting/tokenization handling.
- Added busy-state rejection behavior for slash commands during active run/tool work.

### Reliability Fixes

- Fixed cancellation-channel lifetime handling so chat/TUI runs no longer terminate immediately as `cancelled` due to early sender drop.

## Compatibility Notes

- Changes are additive at the CLI/behavior layer for existing users.
- Learning artifacts/events added new fields and event kinds; consumers should continue to ignore unknown fields for forward compatibility.
