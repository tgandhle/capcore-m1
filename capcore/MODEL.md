# M1 capability core - model and test regime

This is the trusted decision path for the capability-enforced agent runtime.
Given a **trusted** `RunContext` (identity) and an **untrusted** `Proposal`
(model-emitted request), the `ReferenceMonitor` returns `ALLOW`,
`REQUIRE_APPROVAL`, or `DENY`. Deny is the default.

## Semantics

- **Identity is trusted.** `tenant`, `principal`, `run` come from `RunContext`,
  supplied by the runtime. The `Proposal` carries only `resource` and `verb` and
  has no identity field. This closes the confused-deputy hole where a proposal
  could claim to act as another tenant.
- **Scope is segment-aware.** `scope_covers(scope, resource)` is a path-segment
  positional prefix, not a raw string prefix. `acme/data` covers `acme/data/x`
  but not `acme/database`.
- **Alternative grants combine by union.** A proposal is allowed if *any single*
  applicable capability both covers the resource and grants the verb. Independent
  grants are never intersected. (An earlier implementation intersected them; that
  was wrong and is now a mutation-tested regression.)
- **Attenuation is validated at issue time.** `derive_child` rejects any child
  that widens tenant, scope, actions, or drops an approval requirement the parent
  imposes on a shared action. The runtime never re-derives attenuation at
  authorize time.
- **Precedence.** The effective order is: mandatory explicit-deny, then a valid
  unconditional capability path (ALLOW), then REQUIRE_APPROVAL when every
  granting path is approval-gated, then default deny. A mandatory `DenyPolicy`
  overrides an otherwise-valid grant. Note this is union semantics, not a simple
  deny>approval>allow ranking: if any single applicable capability grants the
  verb without approval, the result is ALLOW; approval is required only when all
  granting capabilities gate it. (Mandatory tenant/platform approval policies,
  which would override an unconditional capability, are not yet implemented.)
- **Fail closed.** Malformed proposals, revoked/unknown capabilities, invalid or
  traversal resources, and any ambiguity resolve to deny. Malformed input on the
  authorize path never raises.

## Test regime: proof vs evidence

The suite distinguishes two strengths of claim, and uses the word "prove" only
for the first.

- **PROOF** - finite domain, exhaustively enumerated. Holds for *all* inputs in
  the domain.
  - `test_union_of_grants_proof`: over the full powerset of a 4-verb universe for
    two same-scope grants, union semantics hold for every combination.
  - `test_deny_beats_everything_proof`: explicit deny wins over every finite
    capability configuration (grant present/absent x approval-gated/not).
  - `test_prefix_confusion_proof`: enumerated confusable siblings are not covered.

- **EVIDENCE** - unbounded/large domain, property-tested over random structured
  inputs via Hypothesis. High confidence, not proof.
  - attenuation never widens; accepted children stay within parent
  - tenant isolation; identity ignores the proposal
  - revoked capabilities authorize nothing
  - malformed proposals deny and never throw
  - `scope_covers` equals a segment-prefix reference implementation
  - duplicate ids fail closed

M1 defines no unbounded numeric or temporal constraint types yet, so there is no
"boundary-tested" regime here; every claim is either enumerated (proof) or
property-tested over structured inputs (evidence). When numeric/temporal
constraints are added, their `meet` operation gets boundary tests and joins the
evidence tier.

## Mutation results

The suite's value is that it catches the bugs that were actually shipped or
found in review. Reintroducing each defect turns the suite red; the correct core
is green. Verified defects caught:

1. identity derived from the untrusted resource (confused deputy)
2. attenuation action-subset check removed
3. combine by intersection instead of union
4. raw string prefix instead of segment-aware scope
5. duplicate capability id silently overwrites
6. malformed proposal throws instead of denying
7. explicit platform deny ignored

Each maps to at least one failing test under mutation, and this is reproducible:
`python scripts/mutation_check.py` reintroduces each defect into a copy of the
core, runs the suite, and asserts every mutation is caught (exit non-zero if any
survives). A passing suite means the
core resists these specific attacks; it does not mean the core resists all
attacks. The attacker model is M1: hostile model output only (the model emits
arbitrary proposed actions; the runtime host, the human reviewer, and the audit
store are trusted). A passing suite means containment holds against that attacker,
not all attackers.

## Post-review fixes (found after the first M1 cut)

Six defects were found in later review and are now fixed and mutation-tested in
`test_security_regressions.py`:

8. **Denial reason leaked boundary detail to the model.** `Decision` now splits
   `public_reason` (generic, model-facing: "no applicable authority") from
   `audit_reason` and `trace` (detailed, audit-only). `decision.for_model()`
   returns a stripped copy; the runtime logs the full decision to audit and
   returns only the model view to the agent loop. Rationale: a specific deny
   reason ("resource belongs to tenant globex") lets an adversarial model map
   the capability boundary.
9. **Derivation from a revoked parent was allowed.** `derive_child` now rejects
   a revoked parent ("parent is revoked"). A revoked capability is dead as an
   authority source, including for creating new grants.
10. **`issue()` accepted child-shaped capabilities, bypassing attenuation.**
    A capability with a `parent` set could be issued directly via `issue()`,
    skipping `derive_child`'s attenuation validation and becoming live authority
    with arbitrary scope/actions. Fixed: `issue_root()` rejects any capability
    that names a parent (and `issue()` is now a deprecated alias for it). Root
    issuance and child derivation are distinct, and only derivation can produce
    a capability with a parent. Also validates non-empty id/tenant/actions and a
    valid resource at issue time.
11. **Resource comparison accepted path traversal and empty scopes.**
    `scope_covers("acme/data", "acme/data/../secret")` returned True, and an
    empty scope covered everything. Fixed: `validate_resource` rejects empty
    input, `.`/`..` segments, empty internal segments, backslashes,
    percent-encoding, and control characters. Resources and scopes are validated
    before comparison; a malformed proposal resource fails closed at the schema
    gate. Internal call sites use a non-raising wrapper (`_covers_safe`) so a
    stored bad scope denies rather than crashing the monitor.
12. **`*` was permitted in resource segments.** The regex allowed `*`, which the
    monitor treats as a literal; a future adapter reading it as a wildcard would
    disagree with the monitor, a bypass. Fixed: `*` is rejected until an explicit
    wildcard grammar with matching containment algebra exists.
13. **Malformed mandatory deny policy failed OPEN.** `platform_denies` compared
    the policy scope with the swallow-errors wrapper, so a policy with an empty
    or invalid scope silently matched nothing and the action it was meant to deny
    was ALLOWED, a fail-open in the strongest control in the system. Fixed:
    `DenyPolicy` validates verb, reason, and scope at construction (raising on
    malformed input), and `ReferenceMonitor.__init__` revalidates every policy,
    so a malformed policy fails monitor construction rather than silently
    disabling a mandatory deny.

Note on the mutation runner (`scripts/mutation_check.py`): it reintroduces the
full current set of documented defects (85 as of review round 9), each into a
fresh isolated temp copy, and asserts the suite catches every one. It disables
bytecode writing, isolates Hypothesis storage, and applies a per-mutation timeout
(a timeout is a harness error, not a caught mutation). `scripts/check_stale.py`
is a fast companion that verifies every mutation anchor still matches its source
exactly once, without running any tests; CI runs it as a pre-gate.

## Status and open decisions

Status: **M1 implemented within documented scope.** Implemented: tenant isolation, union-of-grants, segment
scope, issue-time attenuation, deny precedence, fail-closed, generic model-facing
denials, no-derivation-from-revoked-parent, and principal/run binding. Not yet
implemented, honestly marked:

- **Principal/run binding: IMPLEMENTED.** `Capability` has optional `principal`
  and `run` fields. Authorization matches them against the trusted `RunContext`:
  a capability that names a principal authorizes only when `ctx.principal` equals
  it, and likewise for `run`; `None` means unbound on that axis. Binding tightens
  down the derivation chain (`derive_child` may narrow `None` -> specific but
  never loosen specific -> `None` or change a bound value). The intended usage:
  a derivation-only root is tenant-wide (principal=run=None), and the live run
  capability derived for an execution binds all three. Design note: a capability
  with principal=run=None is still tenant-wide by construction, which is correct
  for roots; the guarantee is "a capability is bound to whatever it names," and
  runtime run-capabilities are expected to name a run. Property-tested that a
  capability bound to run A never authorizes run B, and the same for principal.
- **Revocation of existing descendants (cascade).** V1 semantics: revoking a
  capability prevents its direct use and future child derivation; existing
  descendants retain independent validity until explicitly revoked, expired, or
  invalidated by policy. Cascade revocation is deferred pending a concrete
  containment requirement. This is a deliberate `[DECISION]`, not an oversight.
- **Canonical resource type.** Resources are now validated (`validate_resource`
  rejects empty input, `.`/`..` traversal, empty internal segments, backslashes,
  percent-encoding, control characters, and `*` until a wildcard grammar exists)
  and compared as canonical segment tuples. The remaining limitation is narrower:
  resources are still stored and passed as strings rather than a dedicated
  immutable `ResourceScope` type, so validation happens at each comparison rather
  than once at construction. Promoting to a real type is the open item.
- **Runtime run-binding requirement.** Optional fields mean a tenant-wide runtime
  capability can be constructed. Making the live authorization path *require*
  that a runtime (non-derivation-only) capability names a run, so tenant-wide
  runtime authority is impossible, is a reasonable next tightening. Currently the
  binding is enforced-if-present, not required-on-runtime-caps.

## M2: the trusted execution loop (`capcore/runtime.py`)

M1 is the decision function; M2 is the loop that uses it. `ExecutionEngine` drives
a run through a trusted state machine (`RunRecord`, `RunState`), enforces a per-run
`Budget`, and hands authorized actions to the broker. It **owns no tool catalog and
holds no adapter**, so it cannot dispatch around the credential boundary.

The model is abstracted behind `ModelClient`, so the same engine runs against a
deterministic `ScriptedModel` (all tests, CI) or a real local LLM (`OllamaModel`).

### Trusted state is not model-reachable

Under CapCore's single-process trust model, every in-process component is TCB,
including the `ModelClient` implementation. What is untrusted is the DATA it
produces (proposals), which is authorized before it can act. The mechanism below
prevents ACCIDENTAL trusted-state mutation through the documented interface; it
does not isolate hostile same-interpreter code (see README "Trust model").

`ModelClient.next_proposal` receives an immutable, redacted `ModelView`, **not** the
live `RunRecord`.

This was a defect in the documented interface. The adapter used to receive the real
`RunRecord`, and a careless adapter could write `record.steps_taken = -100`. Both
the run-loop guard and the step-level budget check read that same field, so the
adapter could bypass its budget *and* produce a **nonterminating run**: a liveness
failure of the enforcement loop. `ModelView` closes that accidental path. It does
not isolate hostile in-process code (nothing in-process can); the independent loop
ceiling in `run()` is the structural bound against runaway iteration.

`ModelView` also drops `audit_reason`. That field carries the boundary-mapping
detail M1 already withholds from the model via the `public_reason`/`audit_reason`
split; passing the raw history to the model would have reopened that hole by
another route.

### Termination is structural

`run()` is bounded by `for _ in range(budget.max_iterations)`, a **local** counter never
derived from, and never written by, anything the model can reach. The trusted
`steps_taken` check remains authoritative for the budget verdict; the ceiling is an
independent second bound. Even if trusted counter state were corrupted by any means,
the loop cannot iterate more than `max_iterations` times. The action budget
(`max_actions`) is a SEPARATE control, enforced in step() when an action is
attempted, so a denied attempt does not consume liveness and a model is always
allowed to declare completion. Mutation-tested
(`budget_not_enforced`, `engine_loop_ceiling_removed`).

### Terminal state is honest

`RunRecord.stop_reason` says **why** a run ended, now including `ADAPTER_LIMIT_REACHED` (a ModelClient hit its own cap, which is an abort, not a task completion): `MODEL_FINISHED`,
`BUDGET_EXHAUSTED`, `CEILING_REACHED`, `MODEL_ERROR`, `PROVIDER_UNAVAILABLE`, or
`TOOL_FAILED`.

Previously a `ModelClient` returned `Optional[Proposal]`, and `None` meant **both**
"I am done" and "my provider is down". A run against a dead Ollama server therefore
reported `COMPLETED` with zero actions taken: silent total failure, reported as
success. `ModelResult` (PROPOSAL / FINISHED / ERROR) forces the adapter to say which,
and an adapter that raises, or returns an untyped value, is treated as a failure
rather than a completion. Mutation-tested (`provider_error_reported_as_completion`,
`model_exception_swallowed_as_completion`, `ollama_error_becomes_finished`).

### One capability store

`ExecutionEngine` derives its store from the monitor rather than taking a second one.
An earlier version accepted both, which permitted a divergent state where the monitor
authorized against store A while `engine.store` pointed at store B. Both
authorization checks read `monitor.store`, so revoking through `engine.store` was a
silent no-op and the action executed anyway. The store was a parallel reference with
no authority that looked like it had some.

### The revoke race

Double authorization has not been weakened; it **moved into the broker**, where the
re-check now happens at redemption, immediately before the credential is touched. A
capability revoked between propose and execute stops the action there, and the tool
never runs. Mutation-tested (`broker_skips_reauthorization_at_redemption`).

### Live LLM

The real-LLM path (`OllamaModel`, `scripts/demo_live.py`) is deliberately NOT in CI:
it needs a local Ollama server and produces nondeterministic output. Its parsing
logic (`parse_proposal`) is unit-tested with fixed strings; the live network call is
verified by running the demo locally. This keeps the security properties
deterministic and CI-safe while still wiring in a genuine model: the LLM's outputs
are untrusted and pass through the identical trusted pipeline as a scripted proposal.

## M3: the trusted execution broker (`capcore/broker.py`, `capcore/httptool.py`)

The broker does not hand out secrets. It **executes tools inside its own boundary**
and returns sanitized results. It is the only path from an authorized proposal to a
running adapter.

### Redemption, not inspection

An earlier version took a caller-supplied `Decision` and checked
`decision.verdict == ALLOW`. That is authorization by *inspection*, and inspection
cannot establish authenticity in Python: `Decision(Verdict.ALLOW, "authorized")` is
one constructor call away. Enriching the object does not help. A frozen dataclass
carrying a digest, a version, and an expiry is integrity-preserving after
construction but still not *authentic*, because an attacker who can call the
constructor sets whatever fields the checker wants to see.

So the broker **redeems**:

1. `register_authorized_execution(context, execution_proposal) -> action_id`.
   The broker authorizes **independently** through its own monitor (it accepts no
   caller `Decision` at all), resolves the tool from its own catalog, checks the
   tool policy, and stores a `PendingAuthorization` in its own state. It returns an
   opaque random id.
2. `redeem_and_execute(action_id) -> SanitizedToolResult`. The caller presents
   **only** the id. The action, the tool, the version, and the credential are all
   read from stored state.

The `action_id` is not the authority. It is a lookup key. The authority is the
broker-held record.

This closes four attacks structurally:

- **Forgery.** A fabricated authorization has no record; lookup fails. Mutation-
  tested (`broker_skips_reauthorization_at_redemption`).
- **Replay.** Redemption atomically claims PENDING -> EXECUTING. Single-use is a
  state machine, not a deletion, so a crash after the transition leaves the
  authorization non-redeemable rather than silently retryable. Mutation-tested
  (`broker_allows_replay_of_claimed_action`).
- **Staleness.** The live monitor re-authorizes immediately before the credential
  is touched, so a capability revoked after mint stops the action.
- **Substitution.** The caller supplies neither tool nor credential at redemption.
  Both are bound at mint, and the record pins registration id **and version**, so a
  tool swapped out after authorization is refused.

### Catalog existence is not authorization

`read_customer_record` and `read_payroll_database` may both serve `verb=read`. If
catalog lookup were the only check, an untrusted model naming its own executor
would choose which one runs. `ToolPolicy` is therefore **deny-by-default**: an
empty policy authorizes nothing, and a tool must be explicitly granted for a scope.
Mutation-tested (`broker_ignores_tool_policy`, `broker_ignores_tool_verb_match`).

### Secret containment, and the limit of it

`Secret` never renders its value in repr/str/format/logging. But that protects the
**wrapper**. Once `.reveal()` is called and the value is interpolated into an
`Authorization` header, the result is an ordinary Python string, and any exception
carrying it carries the credential. A transport raising
`RuntimeError(headers["Authorization"])` leaked `Bearer <token>` in an earlier
version, which is why the old claim ("secrets never appear in exceptions") was
false as written.

The mechanism now: `.reveal()` is called **only inside the broker's execution
boundary**, where every exception from the adapter is caught and **discarded**,
never inspected, formatted, re-raised, chained, or logged. The returned failure
code is a constant, not derived from the exception. The claim is exactly as strong
as that mechanism: *secrets are contained by the broker boundary.*

**The limit, stated rather than buried:** the broker cannot protect the credential
from a *malicious credentialed adapter in the same process*. The adapter receives
the secret in order to use it, and could log it, retain it, or send it elsewhere.
Every `CredentialedTool` is therefore inside the TCB. Real isolation means a
separate process behind restricted IPC, which is not done.

### Delivery boundary (`HttpTool`)

Destinations are validated at **construction**, so a tool that exists is a tool
whose destination is safe: https only (a cleartext scheme would put the
`Authorization` header on the wire), no embedded userinfo (which leaks into logs,
proxies, and parser-confusion attacks), an explicit host allowlist, an explicit
port policy, and URL normalization before comparison. Redirects are disabled: a 3xx
from the pinned host would otherwise re-send the header to an attacker-chosen
`Location`, which defeats destination pinning entirely. Mutation-tested
(`httptool_allows_any_scheme`, `httptool_allows_embedded_userinfo`).

Credential and tool-grant scopes are validated at issuance via the same
`validate_resource` M1 uses, so a malformed scope fails closed at configuration
time rather than mid-action with a secret already in play. Mutation-tested
(`credential_scope_not_validated_at_issue`, `tool_grant_scope_not_validated`).

### Re-authorization semantics (a deliberate choice)

Redemption asks the monitor: *is this action authorized right now, through any
valid capability path?* That is **current-authority** semantics. If the capability
that originally authorized the action is revoked but a different valid capability
would independently authorize the same action, redemption **succeeds**. It is not
original-capability-continuity; binding to the exact granting capability would
require the monitor to return granting capability ids, which it does not.

### Live demo

The real-secret/real-network path (`scripts/demo_live_m3.py`) is deliberately NOT
in CI. It reads a token from `CAPCORE_DEMO_TOKEN` (never committed) and makes a
real HTTPS call to httpbin.org/bearer, which echoes the token back so you can see
it arrived at the allowed endpoint and confirm the runtime, not the model, put it
there. This keeps a real credential out of the repo and out of CI logs while still
demonstrating real containment.

## Run

```
pip install -e ".[test]"
python -m pytest
python scripts/mutation_check.py      # all 68 mutations must be caught

# live demos (local, not part of CI):
pip install -e ".[live]"
#   M2 (needs Ollama): ollama pull llama3.2
python scripts/demo_live.py
#   M3 (real secret + real HTTPS):
#   PowerShell: $env:CAPCORE_DEMO_TOKEN = "demo-token-abc123"
python scripts/demo_live_m3.py
```
