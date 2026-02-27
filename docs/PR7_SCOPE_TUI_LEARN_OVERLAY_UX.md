# PR7 Scope: `feat: add TUI /learn overlay UX` (Finalized)

## Goal

Ship a beginner-friendly TUI overlay for `/learn` that guides capture/review/promote workflows
without changing existing learn backend semantics.

Primary entrypoint:

- typing `/learn` in chat TUI opens the Learn Overlay modal

while preserving:

- explicit operator control for all writes
- deterministic behavior/parity with existing `learn` command logic
- logs-only learn output (no assistant transcript writes)
- busy-state rejection semantics (`ERR_TUI_BUSY_TRY_AGAIN`)

---

## In scope (PR7)

### 1. Overlay entry and lifecycle

- `/learn` (exact command) opens Learn Overlay modal.
- `Esc` closes modal.
- Modal rendering is layered above the normal chat frame.

### 2. Overlay layout contract (v1)

Render follows the approved design:

- Header: `LEARN OVERLAY`
- Tabs: `[1] Capture  [2] Review  [3] Promote`
- Right badge: `Target: <Capture|Review|Promote>`
- Left panel: form inputs for active tab
- Right panel: `CLI REVIEW` preflight panel
- Bottom command hint row:
  - `Assist: ON/OFF (a) | Enter: Preview | w: Arm Write | Esc: Close | 1/2/3: Tabs`
- Bottom logs row scoped to learn overlay context

### 3. Capture tab (end-to-end in PR7)

Capture tab fields:

- category selector:
  - `workflow_hint`
  - `prompt_guidance`
  - `check_candidate`
- summary input (required)
- collapsed rows:
  - `Advanced Parameters`
  - `Proposed Memory`
  - `Evidence Rows`

For PR7, collapsed sections are UI placeholders only (non-interactive).

### 4. Preflight panel behavior

Preflight panel shows deterministic values for current tab state:

- Equivalent CLI command
- Write state badge (`PREVIEW` vs `ARMED`)
- `Will write: YES|NO`
- `Writes to` list
- target path
- sensitivity flags (capture defaults)

Hard rule:

- when write state is `PREVIEW`, `Writes to` must show `none`.
- when write state is `ARMED`, show planned write paths for the active action.

### 5. Input/key behavior (PR7)

Capture tab:

- `Up/Down`: cycle category
- text keys / `Backspace`: edit summary
- `a`: toggle assist on/off
- `w`: toggle write state `PREVIEW <-> ARMED`
- `1|2|3`: switch tabs
- `Enter`:
  - if busy: log deterministic busy message + token
    - `System busy. Operation deferred.`
    - `ERR_TUI_BUSY_TRY_AGAIN`
  - if not busy + `PREVIEW`: run preflight only (no writes)
  - if not busy + `ARMED`: execute capture via existing learn dispatch path

### 6. Dispatch/parity contract

PR7 must reuse existing learn backend paths (no duplicate business logic):

- `chat_tui_learn_adapter::parse_and_dispatch_learn_slash(...)`

Capture execute path is created from overlay state as an equivalent `/learn capture ...` line
and delegated through the same parser/dispatch used by typed slash commands.

### 7. Review/Promote tabs (PR7 scope)

- Render tab shells with `Target` + `CLI REVIEW` placeholders.
- No promote/review execution changes in PR7.
- Existing typed slash commands (`/learn list`, `/learn show`, `/learn promote ...`) remain supported.

---

## Out of scope (PR7)

- replacing existing typed `/learn ...` command support
- interactive editors for advanced/proposed/evidence sections
- multi-step promote wizard execution
- new backend learn schema/event logic
- changes to sensitivity gate semantics

---

## Acceptance criteria

1. `/learn` opens and `Esc` closes overlay.
2. Capture tab renders with required fields and approved key hints.
3. Preflight shows exact equivalent CLI and deterministic write-state behavior.
4. `PREVIEW` mode causes zero filesystem writes.
5. `ARMED` mode executes capture via existing learn dispatch path.
6. Busy-state submit logs deterministic busy text + `ERR_TUI_BUSY_TRY_AGAIN`.
7. Overlay actions do not append assistant transcript rows.
8. Existing typed `/learn ...` slash command behavior remains intact.

---

## Tests (minimum)

1. `/learn` opens overlay state.
2. `Esc` closes overlay without exiting chat.
3. Capture preflight `PREVIEW` shows `Will write: NO` and `Writes to: none`.
4. Capture `ARMED` submit executes and produces capture confirmation log.
5. Busy submit logs `ERR_TUI_BUSY_TRY_AGAIN`.
6. Overlay submit does not add assistant transcript rows.
7. Existing `/learn capture ...` typed slash path still passes.
