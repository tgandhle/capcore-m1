# Open follow-ups

Deliberately deferred work, tracked here so it survives across sessions rather
than living in memory. None of these is a defect; each is a known, documented
gap or a cleanup with its own reason to be a separate change.

Rough order: (3) is mechanical and low-risk. (4) is the only real feature left, and is
gated by (5). (5) is not a build task at all right now: it is a question to answer
before any of the above matters.

## 1. Focused mutation selectors (harness) — DONE (commit 6dffc4e)

Delivered: `--focused` / `--full` modes; optional per-mutation `tests=(...)`
selectors; the four safety semantics (green-before, applied-once, red-after,
collection-error/timeout-as-harness-error); and self-tests for the harness in
`capcore/tests/test_mutation_harness.py`.

ONGOING CONVENTION (not a separate task, just a habit): selectors are declared on
45 of 104 mutations. A mutation without selectors falls back to the full suite in
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

## 2. Add Python 3.14 to the CI test matrix — DONE

Delivered: `matrix.python-version` is now `["3.11", "3.12", "3.13", "3.14"]`, so the
matrix is 8 cells (4 versions x Ubuntu/Windows). `requires-python = ">=3.11"` already
claimed 3.14 support; the claim is now tested rather than aspirational.

Also corrected the mutation-check job's comment, which claimed the check was
"platform-independent". Review 9 disproved that: a test can be green on one interpreter
and red on another for the same defect, so a mutation could be caught on some and
survive on others. Running it on 3.12 only is a COST decision (the matrix would multiply
several minutes by eight), and the residual risk is stated at the job. The mitigation is
upstream, in how mutations are written: prefer controls that are pure functions of their
input (a nesting cap) over ones that depend on interpreter behaviour (catching
RecursionError).

WHY IT MATTERED: Review 9's F2 was only visible because the dev interpreter (3.14) was
outside the matrix, and only by accident. CPython 3.11-3.13 raise RecursionError decoding
10000-deep JSON; 3.14 simply PARSES it. A fix relying on `except RecursionError` would
have passed every version CI tested and been silently broken on the one in daily use.


## 3. Dual-form `ExecutionEngine` constructor cleanup — DONE

Delivered: one call form, `ExecutionEngine(broker, budget, pre_execute_hook=None)`.
The legacy `ExecutionEngine(monitor, broker, budget)` is gone, along with the runtime
check that a passed monitor equalled `broker.monitor`. 20 call sites migrated (17
mechanical, 3 needing judgment).

THE POINT OF IT, which turned out to be more than tidying: split authority (an engine
authorizing through monitor A while the broker executes through monitor B, so revoking
through one is a silent no-op) is now UNCONSTRUCTIBLE rather than merely refused. There
is no monitor parameter, and `self.monitor = broker.monitor` is the only assignment.
The defect is designed out, not guarded against.

That deleted a security test and the `engine_accepts_divergent_monitor` mutation, which
is worth being explicit about because this project otherwise NEVER deletes a mutation
that stops biting (see the disarming pattern in item 1: four instances, and every time
the answer was to make the layering observable). The distinction:
  - DISARMED:     the bad state is still reachable, nothing tests the guard -> fix the test
  - DESIGNED OUT: the bad state is unreachable, there is no guard at all     -> delete
Deleting for the first reason hides a coverage loss. Deleting for the second is the
point. The invariant moved into the SIGNATURE and is asserted there.

Two guards turned out to have never been armed at all, and the cleanup surfaced them:
the engine's broker type check and its budget type check both had no mutation, and a
probe confirmed both were unfalsifiable. Now armed
(`engine_accepts_a_non_broker`, `engine_accepts_a_non_budget`).

Net: 335 -> 336 tests, 103 -> 104 mutations.

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
