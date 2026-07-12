# Open follow-ups

Deliberately deferred work, tracked here so it survives across sessions rather
than living in memory. None of these is a defect; each is a known, documented
gap or a cleanup with its own reason to be a separate change.

## 1. Focused mutation selectors (harness)

Requested in review round 5. Give each mutation in `scripts/mutation_check.py` a
`tests=(...)` selector naming the smallest test(s) that prove its invariant, and
add `--focused` / `--full` modes:

- `--focused` (PR / routine CI): run only the selected tests per mutation. Fast.
- `--full` (nightly / manual): run the whole suite per mutation. Deep.

Safety semantics the harness MUST enforce so a mispaired selector cannot create
false confidence:

- The selected tests pass on the UNMUTATED copy (green-before).
- The mutation is applied exactly once (already checked: stale detection).
- The selected tests FAIL on the mutated copy (red-after).
- A collection error or timeout is reported as a HARNESS ERROR, not a kill.
- The original source is unchanged after the run.

Rationale for a separate commit: this changes the assurance mechanism itself, so
it must be independently reviewable.

## 2. Dual-form `ExecutionEngine` constructor cleanup

Deferred since round 4. The engine accepts both the new
`ExecutionEngine(broker, budget)` and the legacy
`ExecutionEngine(monitor, broker, budget)` (where the monitor must equal
`broker.monitor`). Migrate the ~21 call sites to the new form and remove the old
one. Its own commit, with its own red/green cycle, because it is a broad
mechanical edit across test files.

## 3. Approval workflow

Deferred since the start. `REQUIRE_APPROVAL` currently classifies and stops. The
full workflow (persist the pending action, authenticate an approval,
re-authorize, resume) is designed but not implemented. Documented honestly in the
README status table. Design it only when a review round requires it; approval
persistence depends on the monitor-ownership and trusted-code boundaries settled
in round 4.

## 4. Architecture diagram

A corrected single-process architecture diagram exists (matches `main` after
round 4: no OpenTelemetry/RAG boxes, in-memory audit labeled as such, ModelView
caveat, credential-copy invariant). Commit it under `docs/` and link it from the
README trust-model section, with a date note ("architecture as of review round N")
so it does not silently go stale. Prefer a version-controlled diagram (e.g.
Mermaid in the README) over a binary export for the in-repo copy.
