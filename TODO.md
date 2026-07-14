# Open follow-ups

Deliberately deferred work, tracked here so it survives across sessions rather
than living in memory. None of these is a defect; each is a known, documented
gap or a cleanup with its own reason to be a separate change.

## 1. Focused mutation selectors (harness) — DONE (commit 6dffc4e)

Delivered: `--focused` / `--full` modes; optional per-mutation `tests=(...)`
selectors; the four safety semantics (green-before, applied-once, red-after,
collection-error/timeout-as-harness-error); and self-tests for the harness in
`capcore/tests/test_mutation_harness.py`.

ONGOING CONVENTION (not a separate task, just a habit): selectors are declared on
23 of 85 mutations. A mutation without selectors falls back to the full suite in
focused mode (safe, just slower). When adding a NEW mutation, give it a selector
while the relevant test is fresh; back-filling the remaining 62 is low-value grunt
work and a wrong selector is worse than none, so let them accrue rather than
bulk-adding. (Round 9 added 17 selectors this way, from 3 to 23, at no extra cost.)

CAVEAT, learned in round 9: focused mode is for routine feedback, NOT for closing a
review round. Run the FULL suite per mutation before merging. Three times in round 9
a mutation still matched its anchor, still passed `check_stale`, and had quietly
stopped biting, because a later fix made its guard redundant or moved the code its
killing test exercised. The suite was green and `check_stale` was clean every time.
Only the full run caught it.

## 2. Dual-form `ExecutionEngine` constructor cleanup

Deferred since round 4. The engine accepts both the new
`ExecutionEngine(broker, budget)` and the legacy
`ExecutionEngine(monitor, broker, budget)` (where the monitor must equal
`broker.monitor`). Migrate the 21 legacy call sites (verified by grep at round 9;
all in test files) to the new form and remove the old one. Its own commit, with its
own red/green cycle, because it is a broad mechanical edit across test files.

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
