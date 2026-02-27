# /learn Workflow Reference

Version context: LocalAgent `v0.3.0` (2026-02-27)
Status: Draft
Owner: LocalAgent maintainers  
Last reviewed: 2026-02-27

## 1. What `/learn` is for

`/learn` is a **staged memory workflow**. It does not auto-change agent behavior.

- `capture`: store a candidate learning entry.
- `review`: inspect/list/archive entries.
- `promote`: explicitly publish one entry into a real runtime target.

A captured entry is only a draft candidate until promoted.

## 2. Core mental model

Think of `/learn` as:

1. Capture a candidate.
2. Review/edit quality.
3. Promote into a deterministic artifact.

Reliability comes from the promotion target artifact, not from capture alone.

## 3. Candidate categories (plain-language)

- `workflow_hint`
  - Reusable process pattern for future work.
  - Example: "Before refactor, locate files with `rg`, then run targeted tests after edits."

- `prompt_guidance`
  - Guidance for agent interaction style or execution behavior.
  - Example: "If request is ambiguous, ask one clarifying question before editing."

- `check_candidate`
  - A candidate validation/check rule.
  - Example: "Generated check file must end with trailing newline."

Category only labels intent at capture time. Promotion decides where it becomes active.

## 4. Command surface (CLI and TUI slash parity)

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

Note:

- TUI typed slash commands (`/learn ...`) support the same argument surface as CLI.
- The TUI Learn Overlay UI intentionally exposes only core promote controls for beginner UX; advanced promote flags are available via typed slash/CLI.

## 5. Typical workflow (recommended)

### Step 1: Capture

```bash
localagent learn capture --category workflow-hint --summary "Before editing, identify exact files and run targeted tests"
```

Assisted capture:

- `--assist` = preview only (no write)
- `--assist --write` = persist assisted draft

### Step 2: Review

```bash
localagent learn list
localagent learn show <id>
```

### Step 3: Promote

Pick one target:

```bash
localagent learn promote <id> --to check --slug <slug>
localagent learn promote <id> --to pack --pack-id <pack_id>
localagent learn promote <id> --to agents
```

Optional promote controls:

- `--force`
- `--check-run`
- `--replay-verify`
- `--replay-verify-run-id <run_id>`
- `--replay-verify-strict`

### Step 4: Archive (optional)

```bash
localagent learn archive <id>
```

## 6. Promotion targets and what they do

- `--to check`
  - Writes `.localagent/checks/<slug>.md`
  - Produces deterministic checks-as-code artifact

- `--to pack`
  - Writes `.localagent/packs/<pack_id>/PACK.md`
  - Adds guidance to pack-managed content

- `--to agents`
  - Writes managed section in workspace-root `AGENTS.md`
  - Adds `LEARN-<id>` block idempotently

## 7. Files touched by `/learn`

Always possible:

- `.localagent/learn/entries/<id>.json`
- `.localagent/learn/events.jsonl`

Promotion targets:

- `.localagent/checks/<slug>.md`
- `.localagent/packs/<pack_id>/PACK.md`
- `AGENTS.md`

## 8. Entry structure (what a candidate contains)

Persisted at `.localagent/learn/entries/<id>.json`.

Key fields:

- `schema_version`
- `id`
- `created_at`
- `source` (run/task context)
- `category`
- `summary`
- `evidence[]`
- `proposed_memory` (`guidance_text`, `check_text`, `tags[]`)
- `assist` (optional provenance)
- `sensitivity_flags`
- `status` (`captured|promoted|archived`)
- `entry_hash_hex`

## 9. TUI Learn Overlay

Typing `/learn` opens modal overlay with tabs:

- Capture
- Review
- Promote

Current key controls:

- `Esc` or `q`: close overlay
- `Ctrl+1 / Ctrl+2 / Ctrl+3`: switch tabs
- `Tab` / `Shift+Tab`: move focus between fields
- `Enter`: preview/run depending on state
- `Ctrl+W`: toggle write state (`PREVIEW` <-> `ARMED`)
- Capture: `Ctrl+A` toggle assist
- Promote:
  - `Left/Right` target switch (`check|pack|agents`)
  - `Ctrl+F` force

Promote advanced flags:

- `--check-run`, `--replay-verify`, `--replay-verify-run-id`, and `--replay-verify-strict` remain available via typed `/learn promote ...` (or `localagent learn promote ...`), not overlay keybind toggles.

Write semantics:

- `PREVIEW`: no writes
- `ARMED`: executes through existing learn backend path

Busy semantics:

- If run/tool execution is active, learn submit is rejected with:
  - `System busy. Operation deferred.`
  - `ERR_TUI_BUSY_TRY_AGAIN`

## 10. Status lifecycle and atomicity

Lifecycle:

- `captured -> promoted` on successful promote
- `captured|promoted -> archived` via archive

Atomicity guarantee (promote):

- If target write fails: no status update, no promoted event emission

## 11. Managed AGENTS.md behavior

Promote to agents inserts deterministic managed blocks:

```md
## LocalAgent Learned Guidance

### LEARN-<id>
learning_id: <id>
entry_hash_hex: <hash>
category: <category>
forced: <true|false>

<guidance text>
```

Rules:

- idempotent by `LEARN-<id>` (no duplicate insertion)
- unmanaged content outside managed section preserved

## 12. Deterministic error codes (commonly seen)

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

## 13. Events and auditability

Events append to `.localagent/learn/events.jsonl`:

- `openagent.learning_captured.v1`
- `openagent.learning_promoted.v1`

Promoted events include target metadata (including target file hash) for traceability.

## 14. How to write effective candidates (quick rubric)

To improve promotion quality, use this format while capturing:

- Trigger: when this applies
- Action: what to do exactly
- Verification: how success/failure is checked

If missing one of these three, the candidate is usually too weak.

## 15. Troubleshooting

- "I captured something but behavior did not change"
  - Capture is draft-only. Run `learn promote ...` to publish.

- "Promote failed needing force"
  - Entry flagged sensitive or target exists. Re-run with `--force` after review.

- "Overlay does not run while model is active"
  - Expected. Busy state rejects writes with `ERR_TUI_BUSY_TRY_AGAIN`.

- "I’m unsure which category to use"
  - process pattern -> `workflow_hint`
  - agent interaction guidance -> `prompt_guidance`
  - validation rule -> `check_candidate`
