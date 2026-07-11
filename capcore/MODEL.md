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

Note on the mutation runner: the 13 defects above, plus two mutations covering
the principal-binding and run-binding enforcement added with the identity-binding
feature, are all individually caught by the suite (15 mutations total). The runner
suite. The runner (`scripts/mutation_check.py`) uses a fresh isolated temp copy
per mutation, disables bytecode writing, isolates Hypothesis storage, and applies
a per-mutation timeout (a timeout counts as a harness error, not a caught
mutation). An earlier runner reused one temp dir and could stall; this one runs
to completion in about two minutes.

## Status and open decisions

Status: **Partial.** Implemented: tenant isolation, union-of-grants, segment
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

M1 is the decision function; M2 is the loop that uses it. `ExecutionEngine`
drives a run through a trusted state machine (`RunRecord`, `RunState`), enforces
a per-run `Budget`, and dispatches authorized actions to a `ToolRegistry`. The
model is abstracted behind `ModelClient`, so the same engine runs against a
deterministic `ScriptedModel` (all tests, CI) or a real local LLM (`OllamaModel`
in `capcore/adapters.py`). New security properties, all tested against a scripted
model so they are reproducible:

- **Trusted state.** Run state lives in `RunRecord`, not in anything the model
  controls.
- **Double authorization (revoke race).** Each action is authorized at propose
  time AND re-authorized immediately before execution. If a capability is revoked
  in between, the execute-time check denies and the action does not run on a
  stale authorization. Mutation-tested (`revoke_race_reexecute_skipped`).
- **Budget.** A run cannot exceed `max_steps`; an exhausted budget aborts the run
  and denies further actions, and denied attempts count against the budget so a
  hostile model cannot burn unlimited probes. Enforced at both the run-loop and
  step level (defense in depth). Mutation-tested (`budget_not_enforced`).
- **Tool boundary.** Only ALLOWed actions reach a tool; denied and
  approval-gated actions never touch one. A tool that raises fails the run
  cleanly (state FAILED) rather than crashing the engine.

The real-LLM path (`OllamaModel`, `scripts/demo_live.py`) is deliberately NOT in
CI: it needs a local Ollama server and produces nondeterministic output. Its
PARSING logic (`parse_proposal`) is unit-tested with fixed strings; the live
network call is verified by running the demo locally. This keeps the security
properties deterministic and CI-safe while still wiring in a genuine model: the
LLM's outputs are untrusted and pass through the identical trusted pipeline as a
scripted proposal.

## Run

```
pip install -e ".[test]"
python -m pytest
python scripts/mutation_check.py      # all 17 mutations must be caught

# live demo (local LLM), not part of CI:
#   install Ollama, then: ollama pull llama3.2
pip install -e ".[live]"
python scripts/demo_live.py
```
