# /learn Workflow Reference

Version context: LocalAgent `v0.3.0` (2026-02-27)

## 1. Mental Model

`/learn` is a staged operator workflow for guidance/check curation:

- Capture: save a candidate learning entry.
- Review: inspect/list/archive candidates.
- Promote: explicitly publish one candidate into a target.

A learning entry is a candidate until promoted.

## 2. Command Surface (TUI + CLI parity)

TUI slash commands:

- `/learn help`
- `/learn list`
- `/learn show <id>`
- `/learn archive <id>`
- `/learn capture ...`
- `/learn promote ...`

Equivalent CLI:

- `localagent learn help`
- `localagent learn list`
- `localagent learn show <id>`
- `localagent learn archive <id>`
- `localagent learn capture ...`
- `localagent learn promote ...`

## 3. Primary User Flows

### 3.1 Capture candidate

Example:

```bash
localagent learn capture --category prompt-guidance --summary "Prefer deterministic fixtures"
```

Assist mode:

- `--assist` = preview only (no write)
- `--assist --write` = persist assisted draft

### 3.2 Review candidate

```bash
localagent learn list
localagent learn show <id>
```

### 3.3 Promote candidate

Check target:

```bash
localagent learn promote <id> --to check --slug <slug>
```

Pack target:

```bash
localagent learn promote <id> --to pack --pack-id <pack_id>
```

Agents target:

```bash
localagent learn promote <id> --to agents
```

Optional promote chaining/controls:

- `--force`
- `--check-run`
- `--replay-verify`
- `--replay-verify-run-id <run_id>`
- `--replay-verify-strict`

### 3.4 Archive candidate

```bash
localagent learn archive <id>
```

## 4. Candidate Data Structure

Persisted at:

- `.localagent/learn/entries/<id>.json`

Schema:

- `schema_version` = `openagent.learning_entry.v1`
- `id` (ULID)
- `created_at`
- `source` (`run_id`, `task_summary`, `profile`)
- `category` (`workflow_hint | prompt_guidance | check_candidate`)
- `summary`
- `evidence[]` (`kind`, `value`, optional `hash_hex`, optional `note`)
- `proposed_memory` (`guidance_text`, `check_text`, `tags[]`)
- `assist` (optional assisted-capture provenance block)
- `sensitivity_flags` (`contains_paths`, `contains_secrets_suspected`, `contains_user_data`)
- `status` (`captured | promoted | archived`)
- `truncations[]`
- `entry_hash_hex`

## 5. Files Touched by /learn

Core files:

- `.localagent/learn/entries/<id>.json`
- `.localagent/learn/events.jsonl`

Promotion targets:

- Check: `.localagent/checks/<slug>.md`
- Pack: `.localagent/packs/<pack_id>/PACK.md`
- Agents: `AGENTS.md` (workspace root)

## 6. Managed AGENTS.md Structure

Promote to agents inserts into a managed section:

```md
## LocalAgent Learned Guidance

### LEARN-<id>
learning_id: <id>
entry_hash_hex: <hash>
category: <category>
forced: <true|false>

<guidance_text or deterministic placeholder>
```

Rules:

- idempotent by `LEARN-<id>` (no duplicates)
- unmanaged content outside section preserved

## 7. Invariants UX Must Preserve

- promotion is explicit (never automatic)
- capture writes stay under `.localagent/learn/**`
- sensitivity gating applies before promotion writes
- managed insertion is deterministic/idempotent
- `/learn` output goes to TUI logs pane, not assistant transcript
- busy TUI rejects with `ERR_TUI_BUSY_TRY_AGAIN`

## 8. Deterministic Error Codes

Promote:

- `LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE`
- `LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE`
- `LEARN_PROMOTE_INVALID_SLUG`
- `LEARN_PROMOTE_INVALID_PACK_ID`

Assist:

- `LEARN_ASSIST_WRITE_REQUIRES_ASSIST`
- `LEARN_ASSIST_PROVIDER_REQUIRED`
- `LEARN_ASSIST_MODEL_REQUIRED`

TUI busy:

- `ERR_TUI_BUSY_TRY_AGAIN`

## 9. Status Lifecycle

- `captured` -> `promoted` on successful promote
- `captured|promoted` -> `archived` via archive

Atomicity:

- failed target write => no promote status update, no promoted event

## 10. Events and Auditability

Events appended to `.localagent/learn/events.jsonl`:

- `openagent.learning_captured.v1`
- `openagent.learning_promoted.v1`

Promotion event includes target metadata including target file hash.

## 11. UX Design Guidance

- model as three-step flow: capture -> review -> promote
- collect only required fields per action
- keep advanced flags in advanced disclosure
- show friendly text plus stable error code token
- preserve CLI/backend semantics, avoid TUI-only behavior divergence

## 12. Learn Overlay (TUI)

Typing `/learn` opens the Learn Overlay modal with three tabs:

- `[1] Capture`
- `[2] Review`
- `[3] Promote`

### Key controls

- `Esc`: close overlay
- `1/2/3`: switch tabs
- `Tab` / `Shift+Tab`: cycle focused input field
- `Enter`: preview/submit current tab action
- `w`: toggle write state (`PREVIEW` <-> `ARMED`)
- `a`: capture assist toggle
- Promote tab:
  - `t`: cycle target (`check|pack|agents`)
  - `f`: toggle `--force`
  - `k`: toggle `--check-run`
  - `r`: toggle `--replay-verify`
  - `s`: toggle `--replay-verify-strict`
  - `i`: focus promote ID input
  - `g`: focus slug input
  - `p`: focus pack_id input
  - `u`: focus replay verify run-id input

### Preflight/write semantics

- `PREVIEW`:
  - shows equivalent CLI + planned target metadata
  - performs no writes
- `ARMED`:
  - executes using existing `/learn ...` dispatch paths
  - preserves backend gating/validation semantics

### Busy behavior

When run/tool execution is active, submit attempts are rejected with:

- `System busy. Operation deferred.`
- `ERR_TUI_BUSY_TRY_AGAIN`
