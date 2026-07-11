# M1 capability core — model and test regime

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
- **Precedence is a total order: explicit-deny > require-approval > allow.** A
  mandatory `DenyPolicy` overrides an otherwise-valid grant.
- **Fail closed.** Malformed proposals, revoked/unknown capabilities, and any
  ambiguity resolve to deny. Malformed input never raises.

## Test regime: proof vs evidence

The suite distinguishes two strengths of claim, and uses the word "prove" only
for the first.

- **PROOF** — finite domain, exhaustively enumerated. Holds for *all* inputs in
  the domain.
  - `test_union_of_grants_proof`: over the full powerset of a 4-verb universe for
    two same-scope grants, union semantics hold for every combination.
  - `test_deny_beats_everything_proof`: explicit deny wins over every finite
    capability configuration (grant present/absent × approval-gated/not).
  - `test_prefix_confusion_proof`: enumerated confusable siblings are not covered.

- **EVIDENCE** — unbounded/large domain, property-tested over random structured
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

Each maps to at least one failing test under mutation. A passing suite means the
core resists these specific attacks; it does not mean the core resists all
attacks. The attacker model is BUILD.md §0.5 M1: hostile model output only.

## Post-review fixes (found after the first M1 cut)

Two defects were found in later review and are now fixed and mutation-tested in
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

## Status and open decisions

Status: **Partial.** Implemented: tenant isolation, union-of-grants, segment
scope, issue-time attenuation, deny precedence, fail-closed, generic model-facing
denials, no-derivation-from-revoked-parent. Not yet implemented, honestly marked:

- **Principal/run binding.** `RunContext` carries `principal` and `run`, but
  authorization enforces only `tenant`. The design binds capabilities to tenant,
  principal, AND run, so this is a design-to-code gap, not merely optional.
- **Revocation of existing descendants (cascade).** V1 semantics: revoking a
  capability prevents its direct use and future child derivation; existing
  descendants retain independent validity until explicitly revoked, expired, or
  invalidated by policy. Cascade revocation is deferred pending a concrete
  containment requirement. This is a deliberate `[DECISION]`, not an oversight.
- **Canonical resource type.** Resources are validated as non-empty strings and
  compared segment-wise, but there is no canonicalization pass rejecting `.`,
  `..`, encoded separators, or ambiguous wildcard forms. Real hardening, still
  open.

## Run

```
pip install hypothesis pytest
python -m pytest capcore/tests/ -v
```
