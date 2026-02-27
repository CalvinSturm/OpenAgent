# PR7D Scope: `feat: guided capture workflow + eval-proof gated promotion` (Draft)

## Goal

Make `/learn` usable for beginner-to-intermediate users by replacing freeform capture with a guided
field-by-field workflow, and close the reliability gap by requiring evaluation proof before promotion
(unless explicitly waived with force).

This PR keeps explicit operator control while reducing authoring burden.

---

## In scope (PR7D)

### 1. Guided Capture: type -> submit -> next step

Capture tab becomes a deterministic step flow by category.

#### Category templates

- `workflow_hint`
  - `when` (required)
  - `do` (required)
  - `verify` (required)
- `prompt_guidance`
  - `goal` (required)
  - `instruction` (required)
  - `avoid` (required)
- `check_candidate`
  - `check` (required)
  - `pass_if` (required)
  - `fail_if` (required)

#### Interaction contract

- Single active field at a time.
- `Enter` submits current field and advances to next required field.
- On last required field:
  - generate deterministic preview draft,
  - show quality badges,
  - allow `Ctrl+W` + `Enter` to persist.
- Assist remains ON by default and drafts from structured fields.

### 2. Quality gate before write

Write is blocked until all required fields are complete and minimum quality gate passes:

- `specific` (no empty/vague placeholders)
- `actionable` (contains explicit operator action)
- `testable` (contains verification/pass-fail condition)

Deterministic error code:

- `LEARN_CAPTURE_QUALITY_GATE_FAILED`

### 3. Eval-proof requirement on promote

Promotion (`--to check|pack|agents`) requires proof from evals unless explicitly waived.

Accepted proof inputs:

- `--check-run <id>`
- `--replay-verify-run-id <id>`

New flag:

- `--no-eval-proof` (must be used with `--force`)

Deterministic error codes:

- `LEARN_PROMOTE_EVAL_PROOF_REQUIRED`
- `LEARN_PROMOTE_NO_EVAL_PROOF_REQUIRES_FORCE`

### 4. Evidence metadata on entry + event

Add optional promotion evidence block to learning entry (backward-compatible):

```json
"promotion_evidence": {
  "check_run_id": "optional string",
  "replay_verify_run_id": "optional string",
  "eval_result": "pass|fail|unknown",
  "evidence_hash_hex": "optional sha256"
}
```

`openagent.learning_promoted.v1` payload extends with:

- `eval_proof_present` (bool)
- `check_run_id` (optional)
- `replay_verify_run_id` (optional)
- `eval_result` (optional)
- `no_eval_proof_waived` (bool)

### 5. Overlay preflight clarity

Preflight panel must always show:

- `Eval proof: PASS | FAIL | MISSING | WAIVED`
- exact write intent
- next-step instruction line

### 6. Backward compatibility and safety

- Existing freeform capture entries remain readable.
- Existing promote flows still use current atomic ordering.
- No auto-promotion and no hidden writes.

---

## Out of scope (PR7D)

- Automatic eval execution orchestration.
- New check runner/replay engine behavior.
- Batch capture/promotion.
- Rich TUI table editor for evidence rows.

---

## Proposed error codes (authoritative for PR7D)

- `LEARN_CAPTURE_MISSING_REQUIRED_FIELD`
- `LEARN_CAPTURE_QUALITY_GATE_FAILED`
- `LEARN_PROMOTE_EVAL_PROOF_REQUIRED`
- `LEARN_PROMOTE_NO_EVAL_PROOF_REQUIRES_FORCE`

(Reuse existing deterministic promote/capture codes where applicable.)

---

## Invariants

- Promotion remains explicit operator action.
- `PREVIEW` mode performs zero writes.
- Assist can draft but cannot auto-write.
- Promotion without eval proof is blocked unless `--no-eval-proof --force` is set.
- Promotion atomicity ordering remains unchanged:
  - target write -> hash -> entry status -> promotion event.

---

## Acceptance criteria

1. Guided capture flow works end-to-end per category template.
2. `Enter` advances through required fields and generates deterministic preview draft.
3. Quality gate blocks weak/partial captures with deterministic code.
4. Promote without proof fails with `LEARN_PROMOTE_EVAL_PROOF_REQUIRED`.
5. `--no-eval-proof` without `--force` fails with `LEARN_PROMOTE_NO_EVAL_PROOF_REQUIRES_FORCE`.
6. `--no-eval-proof --force` promotion succeeds and is marked `WAIVED` in preflight/event.
7. Promotion event and entry metadata include eval-proof fields when provided.
8. Existing behavior for non-guided historical entries remains readable and non-breaking.

---

## Tests (minimum)

1. Guided capture field progression by category (`Enter` submit/advance).
2. Required field missing -> `LEARN_CAPTURE_MISSING_REQUIRED_FIELD`.
3. Quality gate fail -> `LEARN_CAPTURE_QUALITY_GATE_FAILED`.
4. Promote with neither `--check-run` nor `--replay-verify-run-id` -> `LEARN_PROMOTE_EVAL_PROOF_REQUIRED`.
5. Promote with `--no-eval-proof` and no `--force` -> `LEARN_PROMOTE_NO_EVAL_PROOF_REQUIRES_FORCE`.
6. Promote with proof includes evidence fields in entry + event.
7. Promote with waived proof sets `no_eval_proof_waived=true` and succeeds with `--force`.
8. `PREVIEW` path still performs zero writes.

---

## Suggested implementation order

1. Add guided capture form state machine (fields + Enter progression).
2. Add deterministic draft renderer from structured fields.
3. Add quality gate and error codes.
4. Add promote eval-proof arg validation and waiver semantics.
5. Persist evidence metadata + emit extended promotion event fields.
6. Update preflight display status (`PASS|FAIL|MISSING|WAIVED`).
7. Add tests and run full validation.
