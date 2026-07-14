# Open follow-ups

Deliberately deferred work, tracked here so it survives across sessions rather
than living in memory. None of these is a defect; each is a known, documented
gap or a cleanup with its own reason to be a separate change.

Rough order: (2) is a one-line CI fix and should just be done. (3) is mechanical and
low-risk. (4) is the only real feature left, and is gated by (5). (5) is not a build
task at all right now: it is a question to answer before any of the above matters.

## 1. Focused mutation selectors (harness) — DONE (commit 6dffc4e)

Delivered: `--focused` / `--full` modes; optional per-mutation `tests=(...)`
selectors; the four safety semantics (green-before, applied-once, red-after,
collection-error/timeout-as-harness-error); and self-tests for the harness in
`capcore/tests/test_mutation_harness.py`.

ONGOING CONVENTION (not a separate task, just a habit): selectors are declared on
43 of 103 mutations. A mutation without selectors falls back to the full suite in
focused mode (safe, just slower). When adding a NEW mutation, give it a selector
while the relevant test is fresh; back-filling the remaining 62 is low-value grunt
work and a wrong selector is worse than none, so let them accrue rather than
bulk-adding. (Rounds 9-10 added 40 selectors this way, from 3 to 43, at no extra cost.)

CAVEAT, learned in round 9 and reinforced in round 10: focused mode is for routine
feedback, NOT for closing a review round. Run the FULL run locally before merging.
(CI already runs it on every push and PR to `main`, so nothing can land un-run; the
point of running it locally is to find survivors BEFORE the merge commit rather than
after.) Repeatedly, a mutation has still matched its anchor, still passed
`check_stale`, and quietly stopped biting, because a later fix made its guard redundant
or moved the code its killing test exercised. The suite was green and `check_stale` was
clean every time. Only the full run caught it.

THE DISARMING PATTERN, four instances across rounds 9-10, and it is systemic rather
than incidental. Every time: a NEW guard makes an OLDER one redundant, the security
property stays intact, the suite stays green, `check_stale` stays clean, and
falsifiability quietly disappears.
  - R9  the ToolPolicy seal made the broker's own grant_tool guard redundant
  - R10 splitting the budget gate per mode disarmed budget_not_enforced and
        budget_gate_disabled (each test exercised only one mode)
  - R10 the CredentialVault seal made the broker's issue_credential guard redundant
        (it survived only by luck: the two layers raise different exception types)
  - R10 checked_expiry made checked_now's finiteness guard redundant on every path
        EXCEPT ttl_seconds=None, where it turned out to be the only guard at all
The resolution is the same each time, and it is never "delete the redundant guard" or
"delete the mutation": make the LAYERING observable. Assert which layer refused (they
carry distinct messages), so each guard is separately killable.

A related failure mode, also worth naming: a TEST that passes for the wrong reason.
Round 9's `test_deeply_nested_json_returns_invalid` was green on 3.14 while the defect
was fully present, because its fixture would have been INVALID anyway. Round 10 drafted
a concurrency load test that passed against the unfixed code (it never hit the race
window) and deleted it. The discipline in both cases: a fixture must be one that would
PASS but for the property under test, and a test that cannot fail for the reason it
exists is not a weak test, it is false comfort.

## 2. Add Python 3.14 to the CI test matrix

CI runs 3.11 / 3.12 / 3.13 on Ubuntu and Windows. Local development is on 3.14.
That gap is backwards: the interpreter the code is actually exercised on daily is
the one CI does not check.

It is not hypothetical. Round 9's F2 was ONLY visible because of it, and only by
accident: CPython 3.11-3.13 raise RecursionError decoding 10000-deep JSON, and 3.14
simply PARSES it. A fix relying on `except RecursionError` would have been correct on
every interpreter CI tests and silently broken on the one in daily use, and it took a
hand-run of a test on the dev box to notice. The control had to become a pre-decode
nesting cap precisely because the exception is a property of the interpreter, not the
input.

Round 10 then added threading (MonotonicClock's lock, the vault lock, and their
ordering), which is exactly the kind of code that diverges across interpreters.

Change: add "3.14" to `matrix.python-version` in `.github/workflows/ci.yml`. One line.

Also worth fixing while there: the mutation-check job's comment claims the check is
"platform-independent". Round 9 disproved that. It runs on 3.12 only, so a mutation
that bites on some interpreters and not others would not be caught. Either correct
the comment or (cheaper than it sounds, since the job is already `needs: tests`)
consider whether it should matrix too.


## 3. Dual-form `ExecutionEngine` constructor cleanup

Deferred since round 4. The engine accepts both the new
`ExecutionEngine(broker, budget)` and the legacy
`ExecutionEngine(monitor, broker, budget)` (where the monitor must equal
`broker.monitor`). Migrate the 21 legacy call sites (verified by grep at round 9;
all in test files) to the new form and remove the old one. Its own commit, with its
own red/green cycle, because it is a broad mechanical edit across test files.

## 4. Approval workflow

Deferred since the start. `REQUIRE_APPROVAL` currently classifies and stops, so the
reference monitor has three verdicts and only two of them do anything. The full
workflow (persist the pending action, authenticate an approval, re-authorize, resume)
is designed but not implemented, and is documented honestly in the README status table.

BLOCKER RESTATED (the old note here was stale). This item used to say the design was
blocked on "the monitor-ownership and trusted-code boundaries settled in round 4".
Those are settled, and they are no longer the binding constraint. The real one is
item 5: whether the broker runs in the model's process.

Under the current single-process TCB, an "approval" that is an in-process Python call
is forgeable by anything that can steer the loop. So the design's three hard questions
  - where does pending state live?
  - how is an approval AUTHENTICATED?
  - how does resume re-authorize?
have completely different answers depending on whether the broker is in-process, a
sidecar, or a separate service. Designing against the in-process model now means
designing it twice.

Two coherent ways forward, and they are a real choice, not a sequencing detail:
  (a) Scope authentication OUT explicitly, deliver pause/persist/resume mechanics,
      and say plainly in the docs that approval authentication is not enforced. That
      completes the portfolio piece honestly.
  (b) Design it for an OUT-OF-PROCESS broker (item 5) and implement in-process first
      as a demonstration. Slower, but the design survives the move.
(b) is the only ordering that does not throw work away IF the product path is taken.


## 5. Out-of-process enforcement (the trust-model gap)

NOT a feature. This is the thing standing between capcore and a product, and it is not
tracked anywhere else, so it is tracked here.

The current honest claim is: single-process; all in-process Python is TCB; enforcement
holds against a hostile MODEL. Everything hardened in rounds 1-10 (the seal, the vault,
the clock domain, the budget gates, the credential confinement) is enforced by objects
sitting in the same address space as the thing they constrain. That is why finding
after finding was correctly rated "Low direct exploitability under the single-process
TCB": true, and also the admission that the enforcement is advisory against anything
except a hostile model. `broker._policy._sealed = False` is one line.

A regulated-sector buyer's threat model is not a hostile model. It is a compromised
process, a malicious insider, a bad dependency. Against those, the current architecture
enforces nothing, and saying so is the point of the honest status labelling.

So enforcement has to live somewhere the model's process cannot reach. That is a
DIFFERENT ARCHITECTURE, not a later milestone, and it gates item 4.

DO NOT BUILD THIS YET. It is expensive and it is downstream of a question nobody has
answered: does anyone want it? That question is answerable cheaply and without code,
by talking to five or six platform security people at companies actually deploying
agents and asking what stops their agent doing something catastrophic today. If the
answer is "we don't deploy agents with real credentials yet", there is no market yet.
If it is "we built something like this ourselves", there is a market and we are late.
If it is "we don't know, and it terrifies us", there is something here.

That is a two-week exercise with no code, and it dominates every other decision in this
file.

## 6. Architecture diagram

A corrected single-process architecture diagram exists (matches `main` after
round 4: no OpenTelemetry/RAG boxes, in-memory audit labeled as such, ModelView
caveat, credential-copy invariant). Commit it under `docs/` and link it from the
README trust-model section, with a date note ("architecture as of review round N")
so it does not silently go stale. Prefer a version-controlled diagram (e.g.
Mermaid in the README) over a binary export for the in-repo copy.
