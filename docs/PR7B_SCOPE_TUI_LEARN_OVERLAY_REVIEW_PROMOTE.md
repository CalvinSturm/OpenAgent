# PR7B Scope: `feat: complete TUI learn overlay Review + Promote tabs` (Finalized)

## Goal

Complete the Learn Overlay UX for Review + Promote while preserving backend parity and safety invariants.

## In scope (PR7B)

### Review tab

- Show read-only review controls in overlay:
  - filter/status placeholders
  - selected learning ID input
- Preflight panel displays equivalent CLI for:
  - `learn list`
  - `learn show <id>`
- `Enter` behavior:
  - `PREVIEW`: run list/show preview command, no writes
  - `ARMED`: same as preview (review is read-only; no extra writes)

### Promote tab

- Promote form controls:
  - `id` (required)
  - target selector: `check | pack | agents`
  - `slug` required for `check`
  - `pack_id` required for `pack`
  - `force` toggle
  - chaining toggles:
    - `check_run`
    - `replay_verify`
    - `replay_verify_strict`
    - optional `replay_verify_run_id`
- Preflight panel shows equivalent CLI and planned writes by target.
- `Enter` behavior:
  - `PREVIEW`: no writes, preflight only
  - `ARMED`: execute promote through existing learn adapter.

## Hard rules

- Reuse existing slash adapter/backend logic; do not re-implement promote semantics in overlay.
- `PREVIEW` must never trigger filesystem writes.
- Busy state on submit must log:
  - `System busy. Operation deferred.`
  - `ERR_TUI_BUSY_TRY_AGAIN`
- Overlay actions must not append assistant transcript rows.

## Out of scope

- Full editable evidence/proposed-memory table UI.
- Batch promote.
- New learn schema/event changes.

## Acceptance tests

1. Review tab preview runs read-only list/show and does not write.
2. Promote tab `PREVIEW` shows target-specific planned writes and performs no write.
3. Promote tab `ARMED` executes:
   - check target (`--slug`)
   - pack target (`--pack-id`)
   - agents target
4. Missing required promote field blocks submit with deterministic inline log:
   - check without slug
   - pack without pack_id
5. Busy submit for Review/Promote logs busy text + `ERR_TUI_BUSY_TRY_AGAIN`.
6. Overlay submit paths do not append assistant transcript rows.
