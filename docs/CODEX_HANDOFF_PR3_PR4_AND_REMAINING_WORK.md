# Codex Handoff: PR3 / PR4 Learning Feature + Remaining Roadmap

## Purpose

This handoff document is for starting a fresh Codex instance and continuing work without chat history.

Primary immediate focus:

1. PR3: `learn promote --to check`
2. PR4: `learn promote --to pack` and `learn promote --to agents`

Secondary focus:

- Remaining refactor roadmap items (after a long refactor sprint)

---

## Current Repo State (Important)

- Repo: `C:\Users\Calvin\Software Projects\LocalAgent`
- Branch: `main`
- Status at handoff:
  - local branch is **ahead of `origin/main` by 5 commits**
  - untracked file exists: `tmp_issue_11_body.md` (leave untouched)

### Latest local commits (not yet pushed at handoff)

- `c3afa2e` `build: add regex to lockfile for learning sensitivity helpers`
- `825c94a` `hardening: add learning sensitivity gating helpers`
- `8b6308f` `feat: add learning review commands`
- `f39e298` `feat: add learning store capture and hashing`
- `7771d5a` `feat: add learn cli commands and schema types`

---

## What Was Completed Before This Handoff (High-Level)

### Major feature/hardening work already landed (and mostly pushed)

- MCP hardening + progressive disclosure (`/tool docs`, truncation, docs drift pinning, schema fallback tightening)
- AGENTS.md project guidance + `/project guidance`
- repo map cache + optional injection
- checks-as-code (`localagent check run`)
- reliability profiles
- operator-activated packs
- operator queue semantics (`Interrupt` / `Next`)
- Docker shell hardening + `doctor --docker`

### Major refactor sprint completed (157 commits total during sprint)

- `agent.rs` helper extraction wave
- `agent_runtime.rs` orchestration decomposition wave
- `cli_dispatch.rs` split by command family
- `store` split into `types/io/hash/render`
- `eval` split into `types/report/metrics` + `run_eval()` slices
- `tui/state.rs` `UiState::apply_event()` split by event families
- `chat_tui_runtime.rs` decomposed toward orchestrator shape
- `providers/common.rs` introduced with safe/medium shared helpers
- duplication cleanup:
  - `write_json_atomic`
  - provider `to_u32_opt`
  - `sha256_hex`

### GitHub process improvements already set up

- Refactor umbrella issue: `#11`
- Learning feature umbrella issue: `#12`
- Refactor PR template + labels added on GitHub

---

## Learning Feature Roadmap Status (Issue #12)

### PR1 (Complete locally)
**Capture + review store**

Delivered by:
- `7771d5a`
- `f39e298`
- `8b6308f`

Commands:
- `localagent learn capture`
- `localagent learn list`
- `localagent learn show <id>`

Key behavior:
- writes learning entries to `.localagent/learn/entries/<ULID>.json`
- deterministic ULID IDs and list ordering
- canonical hash (`entry_hash_hex`)
- bounded/redacted `list/show` output

### PR2 (Complete locally)
**Sensitivity detection + gating helpers**

Delivered by:
- `825c94a`
- `c3afa2e` (lockfile update for regex)

Key behavior:
- deterministic regex-based sensitivity detection
- path detection flag (`contains_paths`, informational)
- deterministic redaction helper (`[REDACTED_SECRET]`, capped)
- promotion gating helper + stable code:
  - `LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE`

### PR3 (Next to implement)
**`learn promote --to check`**

Scope finalized (see below)

### PR4 (After PR3)
**`learn promote --to pack` and `learn promote --to agents`**

Scope drafted in this handoff (see below)

---

## Learning Feature Architecture / Current Code Pointers

### Files already in use (PR1 + PR2)

- `src/cli_args.rs`
  - contains `Learn` command and `capture/list/show` args
- `src/cli_dispatch_learn.rs`
  - capture/list/show command handlers
- `src/learning.rs`
  - learning store schema, hashing, capture/list/show, sensitivity helpers
- `src/checks/schema.rs`
  - canonical checks-as-code schema (must use for PR3 generation)

### Important schema fact for PR3

Current checks schema in `src/checks/schema.rs` (`CheckFrontmatter`) requires:
- `schema_version: u32`
- `name: String`
- `description: Option<String>`
- `required: bool` (defaults false)
- `allowed_tools: Option<Vec<String>>`
- `required_flags: Vec<String>`
- `pass_criteria: PassCriteria`
- `budget: Option<CheckBudget>`

PR3 generator must emit the **existing schema**, not a new one.

---

## PR3 Finalized Scope: `feat: add learn promote --to check`

### Goal
Implement:

- `localagent learn promote <id> --to check --slug <slug> [--force]`

First learning promotion target that writes LocalAgent state (`.localagent/**`), with:
- explicit operator action
- deterministic generation
- sensitivity gating before workspace writes
- atomic promotion semantics

### In Scope

#### 1. CLI support (`learn promote --to check`)
Add `learn promote` command with:
- required:
  - `<id>`
  - `--to check`
  - `--slug <slug>`
- optional:
  - `--force`

#### 2. Slug validation (explicit, deterministic)
Validate `--slug` up front.

Recommended rule:
- regex: `^[a-z0-9][a-z0-9_-]{0,63}$`
- reject `/`, `\\`, `..`, `:`, any path separators

Add stable error code:
- `LEARN_PROMOTE_INVALID_SLUG`

#### 3. Sensitivity gate (PR2 helper)
Before any workspace write:
- load entry
- call `require_force_for_sensitive_promotion(entry, force)`

If sensitive + no force:
- fail with `LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE`

#### 4. Overwrite gate (distinct code)
Target path:
- `.localagent/checks/<slug>.md`

If file exists and `--force` is not set:
- fail with:
  - `LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE`

#### 5. Deterministic check file generator (schema-valid)
Generate `.localagent/checks/<slug>.md` using **existing checks schema**.

Authoritative generated frontmatter keys:
- required:
  - `name`
  - `description`
  - `allowed_tools`
  - `pass_criteria`
- optional:
  - `required` (recommended emit default `false`)

Hard rule for PR3:
- always emit `allowed_tools: []`

Body generation:
- use `entry.proposed_memory.check_text` if present (bounded)
- else deterministic draft from `summary`

Prefer schema-valid deterministic draft over smart synthesis.

#### 6. Canonical markdown formatting (deterministic)
Lock:
- frontmatter key order (fixed)
- `\n` line endings
- trailing newline present
- stable placeholder/body structure

`render_learning_to_check_markdown(...)` should be pure (no FS, no clock).

#### 7. Atomic promotion semantics
Allowed writes only (successful promotion path):
- `.localagent/checks/<slug>.md`
- `.localagent/learn/entries/<id>.json` (status update)
- `.localagent/learn/events.jsonl` (promotion event append)

Atomicity order:
1. write check file
2. compute check file hash
3. update learning entry status -> `promoted`
4. emit `openagent.learning_promoted.v1`

If check file write fails:
- do NOT update entry status
- do NOT emit promoted event

#### 8. Promotion event emission
Emit:
- `openagent.learning_promoted.v1`

Payload includes at least:
- `learning_id`
- `entry_hash_hex`
- `target = "check"`
- `target_path`
- `slug`
- `forced`
- `target_file_sha256_hex`

### Out of Scope (PR3)
- `--to pack`
- `--to agents`
- archive command
- validation auto-run (`check run`)
- smart check synthesis

### PR3 Tests (minimum)
1. create check file under `.localagent/checks/<slug>.md`
2. deterministic content for fixed fixture
3. required frontmatter keys present + no unexpected generated keys
4. `allowed_tools: []`
5. canonical formatting (`\n`, key order, trailing newline)
6. sensitivity gate (`LEARN_PROMOTE_SENSITIVE_REQUIRES_FORCE`)
7. overwrite gate (`LEARN_PROMOTE_TARGET_EXISTS_REQUIRES_FORCE`)
8. atomicity: failed check write => no status update, no promoted event
9. status update to `promoted` on success
10. promotion event payload includes `target_file_sha256_hex`
11. path safety: only allowed paths modified

### Suggested commit breakdown for PR3 (small commits)
1. `feat: add learn promote cli args for check target`
2. `feat: add deterministic learning-to-check generator`
3. `feat: add learn promote to check write path`
4. `test: add learn promote to check coverage`

---

## PR4 Scope (Planned): `feat: add learn promote --to pack and --to agents`

This is the follow-up after PR3 and should reuse the same safety model.

### Goal
Implement:
- `localagent learn promote <id> --to pack ...`
- `localagent learn promote <id> --to agents`

with:
- explicit operator action
- sensitivity gating (PR2 helper)
- idempotent managed-section insertion
- deterministic formatting and traceability

### In Scope (PR4)

#### 1. `--to agents`
Target:
- `AGENTS.md`

Behavior:
- create file if missing
- use managed section marker (fixed string):
  - `## LocalAgent Learned Guidance`
- insert entries with fixed header:
  - `### LEARN-<id>`
- if `LEARN-<id>` already present in managed section: no duplicate insertion (idempotent)

#### 2. `--to pack`
Target:
- `.localagent/packs/<pack_id>/PACK.md`

Behavior:
- create directory/file if missing
- managed marker section + `### LEARN-<id>` entries
- idempotent by learning ID

#### 3. Sensitivity gate + overwrite semantics
- use PR2 gating helper before workspace writes
- `--force` semantics should stay explicit and deterministic
- keep separate error codes for different force reasons if needed

#### 4. Atomic promotion ordering
Same principle as PR3:
1. write target file
2. compute target file hash
3. update learning entry status
4. emit `learning_promoted`

#### 5. Promotion event payload
Include:
- `target = "agents"` or `"pack"`
- `target_path`
- `target_file_sha256_hex`

### Out of Scope (PR4)
- assisted capture
- auto-validation chaining
- TUI `/learn` commands
- dedupe/similarity suggestions

### PR4 Tests (minimum)
- create `AGENTS.md` if missing
- create pack `PACK.md` if missing
- managed marker insertion exact formatting
- idempotent re-run by `LEARN-<id>` header
- sensitivity gate behavior
- path safety (only expected paths + learning entry status)
- promotion event payload hash included

---

## Learning Feature Invariants (Do Not Regress)

### Write semantics
- `.localagent/**` writes are LocalAgent state writes and allowed as internal state writes
- Workspace writes are anything outside `.localagent/**` (includes `AGENTS.md`)
- Promotion writes must respect existing write safeguards

### Determinism
- Learning IDs are ULIDs
- `learn list` sorts by `id` lexicographically
- `entry_hash_hex` excludes `id`, `created_at`, `status`
- bounded/redacted CLI output (no unbounded dumps)

### Sensitivity / redaction
- redaction token exactly: `[REDACTED_SECRET]`
- deterministic left-to-right non-overlapping replacement
- capped replacements
- PR2 gate blocks promotion unless `--force` when `contains_secrets_suspected == true`

---

## Remaining Refactor Roadmap (Post-Sprint, Optional / Deferred)

### Completed already (major)
- Phases 0, 1, 1.5, 2, most of 3, 3.5 (key tests), 4 (major TUI/state), 5 key duplication cleanup, Phase 6 safe/medium provider helper sharing

### Remaining / deferred

#### Phase 3 (optional eval cleanup)
- additional `run_eval()` orchestration slimming slices (optional)

#### Phase 3.5 (optional targeted tests)
- selected `agent_runtime` / `cli_dispatch` / `agent_*` helper tests

#### Phase 4 (optional more TUI slicing)
- `chat_tui_runtime.rs` is now close to orchestrator shape; likely good enough

#### Phase 6 (providers)
- higher-risk streaming helper unification is deferred (recommended stop point reached)

#### Phase 7 (deferred structural churn)
- directory/module reorg:
  - `agent_*` -> `agent/`
  - `chat_*` -> `chat/`
  - `runtime_*` -> `runtime/`
  - `startup_*` -> `startup/`
- simplify `main.rs` / `lib.rs`

#### Phase 8 (later, user-facing risk)
- `RunArgs` grouping via `clap` flatten
- `localagent --help` diff verification

### Recommendation
Focus on feature delivery (learning PR3/PR4), treat further refactor work as opportunistic.

---

## Validation Commands (Always Run)

Use these after each PR / commit slice:

```powershell
cargo fmt --check
cargo clippy -- -D warnings
cargo test --quiet
```

---

## Notes for New Codex Instance

- Preserve small-PR discipline (same as refactor sprint)
- Keep PR3 and PR4 separate
- Do not touch `tmp_issue_11_body.md`
- Prefer deterministic tests over broad integration behavior tests where possible
- Reuse existing patterns in:
  - `src/cli_dispatch_*` modules for command routing
  - `src/checks/schema.rs` for checks schema correctness
  - `src/learning.rs` for hashing/redaction/sensitivity helpers
