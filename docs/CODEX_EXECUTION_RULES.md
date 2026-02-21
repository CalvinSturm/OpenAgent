# OpenAgent Roadmap Specs

## Global invariants (apply to every milestone)

**Deliverables must preserve:**

* Default safety posture unchanged:

  * `--trust off`
  * `--enable-write-tools=false`
  * `--allow-write=false`
  * `--allow-shell=false`
* Gate decision happens before tool side effects.
* Deterministic tool ordering before every model request.
* Run artifacts written best-effort on all exits (including cancel).
* Config hash excludes secrets (api_key).
* New schema fields must be additive (backward compatible) unless explicitly version bumped.

**Required validation for every milestone:**

* `cargo fmt`
* `cargo clippy -- -D warnings`
* `cargo test`

---

## Milestone 0: Baseline foundation (completed)

### Deliverables

* Core agent loop, providers (openai-compat + ollama), built-in tools
* Safety gates, trust-lite (policy, approvals, audit)
* Run artifacts + replay + sessions
* MCP stdio + registry + Playwright MCP
* Streaming + event bus
* Capability detection + caching + strict mode
* Eval runner + CI-grade packs + local browser fixtures + reports
* Deterministic compaction (opt-in)

### Acceptance tests

* `cargo fmt && cargo clippy -- -D warnings && cargo test`
* `openagent --help` shows all major flags
* `openagent doctor --provider ollama` returns correct exit code for running or missing service
* `openagent replay <run_id>` prints header and transcript
* `openagent eval --help` and a successful manual eval run when provider is available

---

## Milestone 1: Hooks and plugins system (safe, opt-in)

### Deliverables

* Hooks config file under state dir, YAML schema v1
* Hook stages:

  * `pre_model` append-only messages (system or developer)
  * `tool_result` redact/transform tool output content only
* Hooks cannot modify tool name, tool args, tool_call_id, ok flag
* Hook failures:

  * non-strict mode warns and continues
  * strict mode aborts run
* CLI:

  * `--hooks <off|auto|on>`
  * `--hooks-config <path>`
  * `--hooks-strict`
  * `--hooks-timeout-ms`
  * `--hooks-max-stdout-bytes`
* Commands:

  * `openagent hooks list`
  * `openagent hooks doctor`
* Events:

  * HookStart, HookEnd, HookError
* Run artifact capture:

  * hooks config fields are fingerprinted
  * hook invocation report with digests, not unbounded I/O

### Acceptance tests

* Unit tests:

  * config parse + deterministic ordering
  * protocol validation and enforcement (append-only, max size)
  * strict vs non-strict failure behavior
  * tool_result hook modifies content seen by model (fake provider)
  * hook cannot change tool args or tool identity (rejected)
* Manual:

  * `openagent hooks doctor` returns 0 when hooks are valid

---

## Milestone 2: Policy v2 ergonomics

### Deliverables

* Policy schema v2 (or v1 additive extension if possible)
* Rule reason strings:

  * surfaced in deny and approval-required messages
  * included in audit events
* Include/import support:

  * policy.yaml can include other policy files
  * deterministic ordering and cycle detection
* Optional allowlist support:

  * MCP servers allowed list (by name)
  * MCP tools allowed list (glob)

### Acceptance tests

* Unit tests:

  * include resolution
  * cycle detection
  * reason propagation to decision outputs and audit
  * allowlist behavior
* Manual:

  * `openagent --trust on` with v2 policy produces correct deny/approval-required messages with reasons

---

## Milestone 3: Tool metadata and schema hardening

### Deliverables

* Tool metadata classification:

  * side_effects: none, filesystem_read, filesystem_write, shell_exec, network, browser
* Argument schema validation before execution:

  * type checks for expected fields
  * reject unknown fields when configured (optional strict mode)
* Standardize tool result envelopes across builtin and MCP:

  * include ok, truncated, and content fields consistently

### Acceptance tests

* Unit tests:

  * schema validation rejects invalid args
  * metadata classification exposed and stable
  * envelopes consistent
* Manual:

  * invalid tool args from model produce deterministic error tool message

---

## Milestone 4: TUI interactive mode on top of events

### Deliverables

* `openagent tui` or `openagent run --tui` mode
* Live rendering:

  * streaming assistant output
  * tool timeline and decisions
  * approvals UI (approve, deny)
* Reads event stream from EventBus directly or from `--events` file
* Does not change core run artifact schemas or default run behavior

### Acceptance tests

* Unit tests:

  * event rendering primitives (no snapshot brittleness required)
* Manual:

  * run with `--stream` and `--tui` shows live updates
  * approvals can be executed from UI and reflected in store

---

## Milestone 5: Provider resilience

### Deliverables

* Request retry and backoff for transient HTTP failures
* Harden SSE parsing:

  * robust chunk boundaries
  * graceful termination
  * handle malformed events with clear errors
* Per-provider timeouts and max payload guards
* Emit structured error events with enough context for replay/debug

### Acceptance tests

* Unit tests:

  * retry logic with stub transport
  * SSE parser handles partial frames
  * timeout triggers consistent exit_reason and artifacts
* Manual:

  * confirm non-stream run behavior unchanged

---

## Milestone 6: Session intelligence

### Deliverables

* Session compaction policies:

  * allow per-session compaction settings
  * avoid cross-task contamination defaults
* Task memory blocks:

  * explicit blocks for goals/constraints that persist safely
  * must be editable and visible in replay
* Session diff and rebase:

  * list messages
  * drop ranges
  * re-run from checkpoint (optional light version)

### Acceptance tests

* Unit tests:

  * session compaction deterministic
  * task memory persisted and replayed
* Manual:

  * `openagent session` subcommands operate correctly

---

## Milestone 7: Eval expansion, real repo-scale coding pack

### Deliverables

* Add at least 2 repo-style coding tasks:

  * multi-file change
  * tests must pass
  * lint or clippy optional
* Deterministic verification based on local fixtures
* Add per-task “skills required” metadata:

  * write tools required
  * shell required
  * MCP required

### Acceptance tests

* Unit tests:

  * task serialization and skip logic
  * deterministic assertions
* Manual:

  * `openagent eval` on a working provider yields stable reports

---

## Milestone 8: Eval expansion, stable browser pack

### Deliverables

* Add 2 more browser tasks on local fixture site:

  * multi-page navigation
  * DOM extraction via accessibility snapshot
* Add “prompt injection attempt” fixture page:

  * task ensures model does not execute unsafe tools due to page content
  * must pass under trust settings

### Acceptance tests

* Unit tests:

  * fixture pages served and stable
  * assertion engine supports required checks
* Manual:

  * browser eval works with Playwright MCP

---

## Milestone 9: CI integration and baselines

### Deliverables

* Eval profiles:

  * `openagent eval --profile <name>`
  * profile files stored under state dir or repo docs
* Baselines:

  * store last known good results per model
  * compare current run to baseline
* Regression gates:

  * threshold on pass rate
  * threshold on max median steps
  * fail-on-regression mode

### Acceptance tests

* Unit tests:

  * profile load + override merging
  * baseline diff logic
* Manual:

  * run eval twice and see regression behavior trigger correctly

---

## Milestone 10: Scoring and telemetry

### Deliverables

* Metrics:

  * wall time, steps, tool calls
  * tokens if provider can supply it (optional)
  * bytes written, files changed
* Comparison reports:

  * model-to-model diff for a task pack
* Output formats:

  * JSON stays source of truth
  * markdown summary improvements

### Acceptance tests

* Unit tests:

  * metrics aggregation stable
  * compare report correctness
* Manual:

  * generate summary for a multi-model run

---

## Milestone 11: Planner and worker mode (optional)

### Deliverables

* Optional run mode:

  * planner produces step plan and tool intentions
  * worker executes under same TrustGate
* Planner cannot execute tools directly
* Artifacts record planner outputs separately

### Acceptance tests

* Unit tests:

  * planner output parsing
  * tool execution only in worker phase
* Manual:

  * planner-worker run completes on a simple coding task

---

## Milestone 12: Task graph execution and checkpoints

### Deliverables

* `openagent run --taskfile <json>` executes multiple tasks
* Dependency graph support:

  * task B depends on A
* Checkpointing:

  * resume from last completed node
* Artifacts:

  * task graph stored in run artifact

### Acceptance tests

* Unit tests:

  * graph evaluation ordering
  * resume behavior
* Manual:

  * stop mid-run, resume continues correctly

---

## Milestone 13: Remote execution targets

### Deliverables

* Run tools in isolated targets:

  * docker container option
  * VM or remote host option (future)
* Must preserve trust and audit semantics
* Tool outputs tagged with execution target

### Acceptance tests

* Unit tests:

  * target config parsing
* Manual:

  * run a safe tool in container mode

---

## Milestone 14: Trust hardening, approval keys v2

### Deliverables

* Approval key includes:

  * tool schema hash
  * hook config hash
  * compaction settings hash (optional)
* Provenance digests everywhere:

  * original tool output digest
  * modified tool output digest (after hooks)
* Policy test runner:

  * `openagent policy test <cases>`

### Acceptance tests

* Unit tests:

  * key stability and invalidation on schema change
  * policy test runner correctness
* Manual:

  * approval created pre-change no longer authorizes post-change if hashes differ

---

## Milestone 15: Prompt injection defenses and taint tracking

### Deliverables

* Tag untrusted content sources:

  * browser page text
  * file reads
* Taint propagation:

  * if tainted content influences tool args, escalate decision
* Policy hooks:

  * rules based on taint level
* Replay and audit include taint flags

### Acceptance tests

* Unit tests:

  * taint propagation rules
  * escalation on tainted influence
* Manual:

  * injection fixture page cannot force unsafe actions

---

## Milestone 16: Reproducible execution mode

### Deliverables

* “Pinned run” mode:

  * pinned model, caps, hooks, policy, and tool schema hashes
* Verify replay:

  * verify digests and config hash match
  * report mismatch reasons

### Acceptance tests

* Unit tests:

  * pinned config serialization stable
  * verify detects mismatch reliably
* Manual:

  * replay verification passes for unchanged environment

---

## Milestone 17: Packaging and distribution

### Deliverables

* Release artifacts:

  * Linux, Windows
* Install docs and templates:

  * policy, hooks, eval profiles
* Optional auto-update mechanism (separate flag)

### Acceptance tests

* Manual:

  * clean install and first run flows
  * docs validated against current CLI help output

---

## Milestone 18: Library-first refactor and ecosystem

### Deliverables

* Split into:

  * `openagent-core` library crate
  * `openagent` CLI thin wrapper
* Stable public API for embedding
* Curated hook recipes and eval packs distribution format

### Acceptance tests

* Unit tests:

  * CLI uses core API only
  * core API usable by a tiny example crate
* Manual:

  * build and run examples, same behavior as CLI