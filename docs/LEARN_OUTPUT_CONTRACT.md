# /learn Output Contract

Version context: LocalAgent `v0.3.0` (2026-02-27)
Status: Draft (proposed authoritative contract)

## 1. Purpose

This document defines exactly what `/learn` produces, why it exists, and where it writes.

Hard rule: **capture stores candidate intent; promotion publishes active artifacts**.

## 2. Command-to-output mapping

### 2.1 `learn capture`

Purpose:

- Record candidate learning with provenance for later review.

Behavior impact:

- No immediate runtime behavior change.

Writes:

- `.localagent/learn/entries/<id>.json`
- `.localagent/learn/events.jsonl` (append: `openagent.learning_captured.v1`)

### 2.2 `learn list`, `learn show`, `learn help`

Purpose:

- Read-only inspection and operator awareness.

Writes:

- None.

### 2.3 `learn archive <id>`

Purpose:

- Remove candidate from active review queue while keeping audit record.

Writes:

- `.localagent/learn/entries/<id>.json` (status update)
- `.localagent/learn/events.jsonl` (archive/audit event if emitted by implementation)

### 2.4 `learn promote <id> --to check --slug <slug>`

Purpose:

- Publish a deterministic checks-as-code artifact.

Writes (success path):

- `.localagent/checks/<slug>.md`
- `.localagent/learn/entries/<id>.json` (status: `promoted`)
- `.localagent/learn/events.jsonl` (append: `openagent.learning_promoted.v1`)

### 2.5 `learn promote <id> --to pack --pack-id <pack_id>`

Purpose:

- Publish reusable guidance to pack-scoped managed artifact.

Writes (success path):

- `.localagent/packs/<pack_id>/PACK.md`
- `.localagent/learn/entries/<id>.json` (status: `promoted`)
- `.localagent/learn/events.jsonl` (append: `openagent.learning_promoted.v1`)

### 2.6 `learn promote <id> --to agents`

Purpose:

- Publish workspace-level persistent guidance.

Writes (success path):

- `AGENTS.md` (managed section insertion)
- `.localagent/learn/entries/<id>.json` (status: `promoted`)
- `.localagent/learn/events.jsonl` (append: `openagent.learning_promoted.v1`)

## 3. Active behavior boundary

What changes runtime behavior:

- promoted target artifacts only:
  - `.localagent/checks/*.md`
  - `.localagent/packs/*/PACK.md`
  - `AGENTS.md` managed guidance section

What does not:

- captured entries alone (`.localagent/learn/entries/*.json`)

## 4. Category-to-target intent guidance

- `workflow_hint`
  - Typical target: `agents` or `pack`
  - Meaning: reusable process pattern

- `prompt_guidance`
  - Typical target: `agents`
  - Meaning: instruction shaping operator/agent interaction

- `check_candidate`
  - Typical target: `check`
  - Meaning: deterministic validation/check rule

Note: category does not force target; operator chooses target explicitly.

## 5. Atomicity contract (promotion)

Required order on success:

1. write target file (`check/pack/AGENTS`)
2. compute target file hash
3. update entry status to `promoted`
4. append promotion event

Failure guarantee:

- if target write fails: no status update, no promotion event append.

## 6. Safety and gating contract

- sensitivity gate runs before workspace writes
- overwrite requires `--force` where applicable
- slug/pack_id/path validation is deterministic
- managed insertion is idempotent (`LEARN-<id>` block uniqueness)

## 7. TUI/overlay contract

- `PREVIEW`: computes and displays intended output; performs zero writes
- `ARMED`: executes same backend path as CLI
- overlay logs are informational; artifacts are source of truth

## 8. Canonical file ownership

- `.localagent/learn/**`: learning state and audit trail
- `.localagent/checks/**`: checks-as-code outputs
- `.localagent/packs/**`: pack-scoped guidance outputs
- `AGENTS.md`: workspace-level managed guidance outputs

## 9. Success criteria for UX/docs

A user should be able to answer, before pressing run:

1. What file will be written?
2. Why this target is the right one?
3. Whether this action changes runtime behavior now?
4. What audit trail entry will be appended?

## 10. Open follow-up (recommended)

- Add explicit eval-proof contract to promotion requirements (`proof present | waived`) and mirror in preflight/event payload.
