# /learn Research Brief

Version context: LocalAgent `v0.3.0` (2026-02-27)
Status: Draft research plan + alignment framework

## 1. Objective

Research and validate what makes human-authored learning guidance actually effective in agent systems,
then convert findings into concrete `/learn` UX and policy defaults.

Desired outcome:

- higher-quality candidates at capture time
- fewer low-value promotions
- better post-promotion reliability

## 2. Core questions

1. What candidate structure best predicts useful promoted guidance?
2. Which quality gates improve reliability without overburdening users?
3. How should eval-proof be represented and enforced before promotion?
4. Which defaults reduce user effort while preserving operator control?

## 3. Scope boundaries

In scope:

- guidance/check authoring quality
- human-in-the-loop promotion workflows
- eval-linked gating policy and provenance metadata
- practical TUI UX patterns for stepwise input

Out of scope:

- model architecture benchmarking
- unrelated prompt-optimization techniques with no operational workflow tie-in

## 4. Hypotheses to test

H1:

- Structured capture (trigger/action/verification) outperforms freeform summary for promotion quality.

H2:

- Preview-first with explicit write arming reduces accidental low-quality writes.

H3:

- Requiring eval proof (or explicit waived override) improves trust in promoted artifacts.

H4:

- Category-specific templates reduce confusion and increase first-pass usability.

## 5. Candidate evaluation rubric (proposed)

Every candidate should score on:

- Specific: clear trigger/context
- Actionable: explicit action text
- Testable: concrete verification/pass-fail
- Scoped: avoids overbroad universal claims
- Safe: avoids leaking sensitive data

Minimum promotion gate recommendation:

- pass `Specific + Actionable + Testable`

## 6. Proposed evidence model for promotion

Promotion should record one of:

- check-run reference (`check_run_id`)
- replay verification run (`replay_verify_run_id`)
- explicit waived path (`no_eval_proof_waived=true` with force)

Recommended policy:

- block promotion when proof missing
- allow waiver only with `--no-eval-proof --force`
- always mark waiver in event payload and entry metadata

## 7. Suggested source categories to review

- Human factors for checklist/decision support systems
- Prompting/policy authoring patterns for reliable LLM tool use
- Memory and retrieval governance in agentic systems
- CI/checklist quality control literature (deterministic pass/fail definition)

## 8. Deliverables

### D1. Evidence summary (5-10 sources)

For each source:

- citation
- claim relevant to `/learn`
- confidence level
- implication for product behavior

### D2. Policy recommendations

- final capture template per category
- final quality gate conditions
- final eval-proof gating rule
- waiver semantics and audit requirements

### D3. UX recommendations

- field-by-field overlay flow
- copywriting for next-step guidance
- error messaging style (`friendly text + deterministic code`)

### D4. Implementation mapping

- required CLI/TUI changes
- schema/event additions
- acceptance test additions

## 9. Initial recommendations (pre-research baseline)

1. Use category templates instead of freeform-only capture.
2. Keep assist ON by default, but never auto-write.
3. Require eval proof for promotion with explicit forced waiver.
4. Show exact output targets and behavior impact in preflight.
5. Keep writes atomic and auditable via event hashes.

## 10. Decision log template

Use this for each major policy decision:

- Decision:
- Alternatives considered:
- Chosen option and rationale:
- Risks:
- Mitigations:
- Validation test:

## 11. Suggested execution plan

1. Gather and summarize sources.
2. Finalize capture templates and gates.
3. Finalize eval-proof policy contract.
4. Update docs contracts (`LEARN_OUTPUT_CONTRACT.md`, workflow reference).
5. Implement in small PR slices with acceptance tests.
