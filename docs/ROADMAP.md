## OpenAgent complete roadmap (ordered)

### Phase 0 — Foundation (done)

* Core agent loop: tool-calling, max steps, deterministic tool ordering
* Providers: OpenAI-compat (LM Studio/llama.cpp), Ollama
* Built-in tools: list/read/shell/write/apply_patch + truncation
* Safety defaults + hard gates: allow flags, write-tool exposure
* Trust-lite: policy YAML, approvals, audit JSONL
* Run artifacts + replay + sessions
* Auto-approve + unsafe/no-limits modes (explicit)
* MCP stdio + registry + Playwright MCP integration
* Streaming + event bus
* Capability detection + caching + strict mode
* Eval runner + CI-grade packs + local browser fixtures + reports
* Deterministic compaction/context budgeting (opt-in)

### Phase 1 — Extensibility (next)

1. **Hooks / Plugin system (safe, opt-in)**

   * pre_model append-only hooks
   * tool_result redaction/transform hooks
   * hook events + artifact reports
   * strict vs non-strict behavior

2. **Policy v2 + Rule ergonomics**

   * explicit “reason” field per rule (surface in deny/approval required messages)
   * allowlists for MCP servers/tools
   * policy include/import support (split policies)

3. **Tool capability metadata + tool schemas hardening**

   * per-tool “side_effects” classification
   * argument schema validation before execution
   * stronger tool result typing (still JSON, but consistent envelopes)

### Phase 2 — Reliability and UX

4. **TUI/interactive mode on top of events**

   * live streaming + tool timeline + approvals UI
   * attach to a run via run_id (tail events file)

5. **Provider resilience**

   * retries/backoff for transient HTTP failures
   * better SSE robustness + reconnect strategy
   * per-provider timeouts, max payload guards

6. **Session intelligence**

   * session compaction policies per session
   * “task memory” blocks (goals, constraints) that persist safely
   * session diff/rebase tools

### Phase 3 — Evaluation and regression prevention

7. **Eval expansions**

   * repo-scale coding pack (multi-file, tests, lint)
   * browser pack with more deterministic flows
   * “agent reliability” pack (tool misuse, prompt injection attempts)

8. **CI integration**

   * `openagent eval --profile <name>` for pinned configs
   * baselines + regression thresholds per model
   * artifact bundling for failing runs

9. **Scoring and telemetry**

   * normalized metrics: wall time, steps, tool calls, tokens (when available)
   * “cost” estimation for API providers (optional)
   * run comparison reports (diff of artifacts)

### Phase 4 — Multi-agent + orchestration

10. **Planner/Worker architecture (optional mode)**

* split “planner” and “executor” loops
* shared tool gate + unified audit trail
* deterministic handoff messages

11. **Task graph execution**

* queue multiple tasks with dependencies
* resumable runs (checkpointing)

12. **Remote execution targets**

* run tools in isolated sandboxes/containers
* remote MCP servers with allowlists
* signed tool results (future)

### Phase 5 — Security hardening (toward “AGI-grade OpenClaw”)

13. **Trust hardening**

* stronger approval keys (include tool schema hash, hook config hash)
* provenance tracking: hook input/output digests everywhere
* policy test runner: `openagent policy test <cases>`

14. **Prompt injection defenses (browser + files)**

* content classification for untrusted text
* “taint tracking” tags through messages/tool outputs
* deny/require-approval escalation rules when tainted content influences actions

15. **Reproducible execution mode**

* deterministic tool environment snapshot
* pinned model + pinned caps + pinned hooks + pinned policy
* “replay with verification” (assert hashes match)

### Phase 6 — Productization

16. **Packaging and distribution**

* install script, release artifacts, auto-update (optional)
* docs + examples + templates (policy, hooks, eval profiles)

17. **SDK / library-first refactor (optional)**

* `openagent-core` crate for embedding
* CLI becomes thin wrapper

18. **Ecosystem**

* official hook recipes (redaction, prompt headers, safety banners)
* curated MCP server configs
* eval packs as shareable bundles