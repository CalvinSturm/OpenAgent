## Summary

Behavior-preserving refactor only.

This PR extracts/reorganizes code to improve maintainability and reduce hotspot complexity. It does **not** intentionally change runtime behavior, event payloads, artifact schemas, or CLI semantics.

## Scope

- [ ] Helper extraction
- [ ] Module/file split
- [ ] Type move
- [ ] Duplication cleanup

## What Changed

- Moved/extracted:
  - `...`
- Updated references/imports:
  - `...`

## What Did NOT Change (intentional)

- [ ] Trust/policy/approval behavior
- [ ] Event payload keys/schemas
- [ ] Run artifact schemas
- [ ] Replay/repro behavior
- [ ] CLI flags/semantics

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo clippy -- -D warnings`
- [ ] `cargo test --quiet`

## Notes / Risks

- Low-risk structural change only
- Any differences should be formatting/import/module-path only

## Tracking

- Related issue: #11
