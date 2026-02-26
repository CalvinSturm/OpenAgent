# PR4 Scope: `feat: add learn promote --to pack and --to agents` (Draft)

## Goal

Implement the next learning promotion targets:

- `localagent learn promote <id> --to pack --pack-id <pack_id>`
- `localagent learn promote <id> --to agents`

while preserving:

- explicit operator control
- sensitivity gating before target writes
- deterministic insertion/formatting
- idempotent/reviewable behavior (safe re-run, no duplicate insertions)
- atomic promotion semantics (no partial promotion state)

PR4 should reuse PR3's promotion flow (load -> gate -> write -> hash -> status -> event) and only add target-specific managed-section insertion logic.

---

## In scope (PR4 only)

### 1. CLI: `learn promote ... --to pack|agents`

Implement `learn promote` support for:

- `--to pack`
- `--to agents`

#### Required args

Common:

- `<id>` (learning entry ID)
- `--to <pack|agents>`

Target-specific:

- `--to pack` requires `--pack-id <pack_id>`
- `--to agents` requires no extra target identifier

#### Optional args

- `--force`
  - used for:
    - sensitivity override
    - target file creation/overwrite policy only if needed by implementation

Keep `--force` semantics explicit and deterministic. Distinguish reasons with stable error codes when behavior differs.

Out of scope:

- `--to check` changes (already in PR3)
- archive command
- assisted capture
- validation auto-run/chaining (`check run`, etc.)

---

### 2. Sensitivity gating (reuse PR2 helper)

Before any target write:

- load learning entry
- call `require_force_for_sensitive_promotion(entry, force)`

#### Deterministic error code (existing)

- `LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE`

This gate applies to all promotion targets (including `.localagent/**` state targets and `AGENTS.md`) and must run before writing `AGENTS.md`, `PACK.md`, learning entry status updates, or promotion event append.

---

### 3. Target paths + path safety

#### `--to agents` target path

- `AGENTS.md` at the current workspace root (same root LocalAgent uses for `.localagent/`)
  - implementation must use the same root/workdir resolution LocalAgent uses for `.localagent/` state paths
  - do not derive a separate root from arbitrary CWD behavior

#### `--to pack` target path

- `.localagent/packs/<pack_id>/PACK.md`

#### Pack ID format (final for PR4)

PR4 uses hierarchical pack IDs to match existing LocalAgent pack conventions (for example `web/playwright`).

Validation rules:

- `pack_id` is one or more `/`-separated segments
- each segment must match: `^[a-z0-9][a-z0-9_-]{0,63}$`
- reject empty segments
- reject `.` and `..`
- reject absolute paths / drive prefixes / backslashes
- preserve the exact `pack_id` string in event payloads (case-sensitive by payload; validation should require lowercase segments)

#### Deterministic error code (recommended)

- `LEARN_PROMOTE_INVALID_PACK_ID`

#### Path safety requirements

- `pack_id` must not escape `.localagent/packs/`
- reject path traversal (`..`) and absolute paths
- normalize comparisons/path rendering to forward slashes for determinism

Successful promotion may touch only:

- target file (`AGENTS.md` or `.localagent/packs/<pack_id>/PACK.md`)
- `.localagent/learn/entries/<id>.json` (status update)
- `.localagent/learn/events.jsonl` (promotion event append)

---

### 4. Managed section insertion (deterministic)

PR4 uses managed sections for both targets to keep edits reviewable and idempotent.

#### `AGENTS.md` managed section marker (fixed string)

- `## LocalAgent Learned Guidance`

#### `PACK.md` managed section marker (fixed string)

- `## LocalAgent Learned Guidance`

Use the same marker string in both targets unless a strong target-specific reason appears during implementation.

#### Entry header format (fixed)

- `### LEARN-<id>`

Each promoted learning entry is inserted as a managed block under the managed section.

#### Managed block content (deterministic)

Use an exact stable block template in PR4 (metadata wording may differ, but choose one template and test it as golden output).

Recommended template:

```text
## LocalAgent Learned Guidance

### LEARN-<id>
learning_id: <id>
entry_hash_hex: <hash>
category: <category>
forced: <true|false>

<guidance_text_or_placeholder>
```

Spacing rules (fixed):

- exactly one blank line between managed section header and first entry
- exactly one blank line between metadata and body
- exactly one blank line between entries
- trailing newline present

Preferred deterministic content order within each block:

1. `### LEARN-<id>`
2. metadata lines (target-independent, fixed order)
3. learned text body (normalized newlines)

Recommended metadata fields (exact wording can be finalized in implementation, but keep stable):

- `learning_id`
- `entry_hash_hex`
- `promoted_from_category`
- `forced`

If the entry has `proposed_memory.guidance_text`, use it.
Else derive a deterministic placeholder from `summary`.

For `--to pack`, use `guidance_text` first (not `check_text`).
For `--to agents`, use `guidance_text` first.

---

### 5. Idempotent insertion + re-run behavior (critical)

PR4 must be safe to re-run for the same learning ID and target.

#### Idempotency rule (same target file)

If managed section already contains:

- `### LEARN-<id>`

then:

- do not insert a duplicate block
- do not rewrite unrelated content

#### Re-run behavior (same ID, same target)

Default behavior recommendation (PR4):

- treat as idempotent no-op for target content (no duplicate insertion)
- still deterministic outcome/reporting to operator

Status/event behavior for no-op re-run should be defined explicitly in implementation and tests.

Recommended PR4 behavior:

- if no target content change occurs:
  - leave learning status as-is (`promoted` if already promoted)
  - do not append a new `learning_promoted` event (avoid noisy duplicate events)
  - return success (exit code 0)
  - print deterministic noop output (for example: `already promoted (noop): LEARN-<id> already present in managed section`)

If you choose to emit an event for no-op re-run, make it explicit and include a `noop: true` field. Do not leave this ambiguous.

#### Existing unmanaged content

The insertion logic must preserve:

- all content before the managed section
- all content after the managed section
- exact unmanaged text except newline normalization policy (see formatting section)

---

### 6. File creation / overwrite semantics

#### `--to agents`

If `AGENTS.md` does not exist:

- create it with deterministic content containing the managed section and one `LEARN-<id>` block

If `AGENTS.md` exists:

- insert/update only within the managed section area
- preserve unrelated content outside the managed section

#### `--to pack`

If `.localagent/packs/<pack_id>/PACK.md` does not exist:

- create parent directories as needed
- create `PACK.md` with deterministic content containing the managed section and one `LEARN-<id>` block

If file exists:

- insert idempotently using managed section rules

PR4 does not need "overwrite whole file" semantics for managed insertion. Prefer structural insertion over full-file replacement.

---

### 7. Canonical formatting (deterministic)

Managed-section insertion and generated blocks must follow fixed formatting rules:

- `\n` line endings in generated output
- trailing newline present
- stable marker/header spelling and capitalization
- stable metadata line order
- stable blank-line spacing around managed section and blocks

Insertion helper(s) should be pure/deterministic where possible (string in -> string out + change metadata).

Recommended split:

- pure string transformer for managed-section insertion
- file I/O wrapper for path handling and atomic write sequencing

Atomic write mechanism recommendation:

- reuse existing atomic-write patterns/helpers in the codebase where possible
- otherwise use same-directory temp file + replace/rename semantics
- avoid partial target files on interruption/crash

---

### 8. File write + atomic promotion behavior

Atomicity rule matches PR3:

On failure to write target file:

- do not update learning entry status
- do not emit `learning_promoted`

Only after successful target file write:

1. compute target file hash
2. update entry status to `promoted`
3. emit promotion event

For idempotent no-op re-runs, behavior must be explicit (see Section 5).

---

### 9. Promotion event emission

Emit:

- `openagent.learning_promoted.v1`

for successful PR4 promotions (`target = "pack"` or `"agents"`).

Payload includes at least:

- `learning_id`
- `entry_hash_hex`
- `target = "pack"` or `"agents"`
- `target_path`
- `forced` (bool)
- `target_file_sha256_hex`

For `--to pack`, include:

- `pack_id`

For `--to agents`, `pack_id` is omitted.

If no-op re-runs emit events, include:

- `noop` (bool)

---

## Out of scope (do not implement in PR4)

- changes to PR3 check generation
- archive command
- assisted capture
- auto-validation chaining
- TUI `/learn` commands
- dedupe/similarity beyond `LEARN-<id>` idempotency in managed section
- broader `AGENTS.md` editing/synthesis beyond managed section insertion
- multi-learning batch promote (one `<id>` per invocation only)
- updating/replacing an existing `LEARN-<id>` block (treat as noop in PR4)

---

## Proposed functions / module boundaries (recommended)

### `src/cli_dispatch_learn.rs`

- parse/dispatch `learn promote ... --to pack|agents`
- enforce target-specific arg requirements
- handle deterministic CLI errors/output

### `src/learning.rs`

Add PR4 helpers (recommended names):

- `promote_learning_to_pack(...) -> anyhow::Result<PromoteToTargetResult>`
- `promote_learning_to_agents(...) -> anyhow::Result<PromoteToTargetResult>`
- `render_learning_to_guidance_block(...) -> String` (pure/deterministic)
- `insert_managed_learning_block(...) -> ManagedInsertResult` (pure/deterministic)
- `update_learning_status(...)` (reuse PR3)
- promotion event emitter (reuse/adapt PR3)

Keep file writes centralized (single write path per target) for easier atomicity testing.

---

## Invariants (must not change)

- Promotion is explicit (no auto-promotion)
- Sensitivity gate runs before target writes
- Managed-section insertion is deterministic and idempotent by `LEARN-<id>`
- No duplicate insertion on re-run for same target + same learning ID
- Successful promotion writes only expected target + learning entry + learning events file
- `learn capture/list/show` behavior remains unchanged
- PR3 check promotion behavior remains unchanged

---

## Acceptance Criteria

1. Promote to agents works

- `learn promote <id> --to agents` creates or updates `AGENTS.md`
- managed section is created if missing
- `### LEARN-<id>` block inserted deterministically

2. Promote to pack works

- `learn promote <id> --to pack --pack-id <pack_id>` creates or updates `.localagent/packs/<pack_id>/PACK.md`
- parent dirs created safely
- managed section + `LEARN-<id>` block inserted deterministically

3. Sensitivity gating enforced

- flagged entry + no `--force` -> `LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE`
- flagged entry + `--force` -> proceeds

4. Idempotent re-run behavior

- same `LEARN-<id>` already present in managed section -> no duplicate block
- behavior of status/event on no-op is explicit and test-covered

5. Formatting determinism

- stable marker/header strings
- `\n` newlines
- trailing newline present
- stable spacing and metadata ordering

6. Atomic promotion semantics

- failed target write => no status update, no promotion event
- successful target write => status updated to promoted, event emitted

7. Traceability

- `learning_promoted` event includes `target_file_sha256_hex`
- pack promotions include `pack_id`

8. Path safety

- pack target cannot escape `.localagent/packs/`
- only expected files are created/modified on success

9. Quality gate

- `cargo fmt --check`
- `cargo clippy -- -D warnings`
- `cargo test --quiet`

---

## PR4 Tests (minimum)

1. `--to agents` create/insert

- creates `AGENTS.md` when missing
- inserts managed marker and `### LEARN-<id>` block
- deterministic content for fixed fixture entry

2. `--to agents` idempotency

- re-run same learning ID does not duplicate block
- preserves unmanaged content before/after managed section
- unmanaged content preservation fixture: outside managed section remains byte-for-byte identical (except newline normalization if PR4 normalizes the whole file)

3. `--to pack` create/insert

- creates `.localagent/packs/<pack_id>/PACK.md` and parents
- inserts managed marker and `### LEARN-<id>` block

4. `--to pack` path safety

- rejects path traversal/absolute `pack_id`
- does not write outside `.localagent/packs/**`

5. `--to pack` idempotency

- re-run same learning ID does not duplicate block

6. Sensitivity gate

- flagged + no `--force` -> deterministic error code
- flagged + `--force` -> success

7. Atomicity

- simulate target write failure => learning entry status unchanged and no promoted event emitted

8. Promotion event payload

- includes `learning_id`, `target`, `target_path`, `target_file_sha256_hex`
- pack target includes `pack_id`

9. Path safety (success)

- only expected target file + learning entry + learning events file modified

---

## PR size guardrails

- Keep PR4 to `--to pack` and `--to agents` only
- Reuse PR3 promotion flow; avoid refactoring unrelated learning/capture code
- No auto-validation chaining
- No broad `AGENTS.md` rewriting outside managed section

---

## Suggested implementation order

1. Add CLI target support and target-specific arg validation (`pack_id` for `--to pack`)
2. Implement pure managed-section insertion helper with exact formatting + idempotency tests
3. Implement `--to agents` path (create/update `AGENTS.md`)
4. Implement `--to pack` path (safe path handling, create/update `PACK.md`)
5. Reuse PR3 status update + promotion event flow
6. Add atomicity/path-safety tests
7. Run validation and commit
