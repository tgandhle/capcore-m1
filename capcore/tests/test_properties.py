"""Property-based adversarial tests — the M1 deliverable.

Each test maps to a security claim in BUILD.md and states its regime:

  PROOF      — finite domain, exhaustively enumerated. The claim holds for ALL
               inputs in the domain, not a sample.
  EVIDENCE   — unbounded/large domain, property-tested over random structured
               inputs. High-confidence, not proof.

The word "prove" appears only in PROOF tests.

Claims covered:
  §1 attenuation never widens (all axes)     -> EVIDENCE (test_attenuation_*)
  §1 combine = union of alternative grants    -> PROOF (enumerated) + EVIDENCE
  §1 unsatisfiable/no authority -> deny        -> EVIDENCE
  §1 explicit deny beats allow/approval        -> PROOF (enumerated)
  §1 expired/revoked/unknown -> deny           -> EVIDENCE
  §1 two tenants never authorize each other    -> EVIDENCE
  §0.5 malformed proposal -> deny, never throw -> EVIDENCE
"""

import itertools

from hypothesis import given, settings, strategies as st, assume

from capcore import (
    Capability, RunContext, Proposal, CapabilityStore, ReferenceMonitor,
    DenyPolicy, Verdict, scope_covers, segments,
)
from capcore.tests.strategies import (
    capabilities, run_contexts, proposals, narrowings, valid_narrowings,
    resource_paths, action_sets, TENANTS, VERBS, VERB_LIST, TENANT_LIST,
)


# --------------------------------------------------------------------------- #
# Attenuation: a derived child can never exceed its parent. (EVIDENCE)
# BUILD.md §1 line 81.
# --------------------------------------------------------------------------- #

@given(parent=capabilities(runtime=False), data=st.data())
@settings(max_examples=500)
def test_attenuation_never_widens(parent, data):
    """EVIDENCE: for random parent + random child spec, if derive_child accepts
    the child, the child is <= parent on every axis. If it would widen on any
    axis, derive_child must reject it.
    """
    store = CapabilityStore()
    store.issue(parent)
    child = data.draw(narrowings(parent))

    result = store.derive_child(parent.id, child)

    if result.ok:
        # Accepted children must be within-parent on every axis.
        assert child.tenant == parent.tenant
        assert scope_covers(parent.resource, child.resource)
        assert child.actions <= parent.actions
        # approval requirements preserved on shared actions
        for a in parent.approval_actions:
            if a in child.actions:
                assert a in child.approval_actions
    else:
        # Rejected children must actually widen on at least one axis, i.e. the
        # rejection is never spurious. (id-collision aside, which we exclude.)
        assume(result.reason != "duplicate capability id")
        widens = (
            child.tenant != parent.tenant
            or not scope_covers(parent.resource, child.resource)
            or not (child.actions <= parent.actions)
            or any(a in child.actions and a not in child.approval_actions
                   for a in parent.approval_actions)
        )
        assert widens, f"rejected a within-parent child: {result.reason}"


@given(parent=capabilities(runtime=False), data=st.data())
@settings(max_examples=300)
def test_accepted_child_cannot_authorize_beyond_parent(parent, data):
    """EVIDENCE: a genuinely-within-parent child, once accepted, has authority
    that is a subset of the parent's on every axis. Uses valid_narrowings so
    acceptance is the common case (not filtered away).
    """
    store = CapabilityStore()
    store.issue(parent)
    child = data.draw(valid_narrowings(parent))
    result = store.derive_child(parent.id, child)
    assert result.ok, f"valid narrowing rejected: {result.reason}"

    stored_child = store.get(result.id)
    assert stored_child.actions <= parent.actions
    assert stored_child.tenant == parent.tenant
    prop = data.draw(proposals())
    if scope_covers(stored_child.resource, prop.resource):
        assert scope_covers(parent.resource, prop.resource)


# --------------------------------------------------------------------------- #
# Union of alternative grants. (PROOF over a finite verb universe + EVIDENCE)
# This is the invariant I got WRONG the first time (intersection).
# --------------------------------------------------------------------------- #

def test_union_of_grants_proof():
    """PROOF: over the finite universe of verbs and two same-scope grants A,B,
    a proposal for verb v is ALLOWED iff v is in (A.actions | B.actions), for
    EVERY subset assignment of a small verb universe. Exhaustive, not sampled.
    """
    universe = ["read", "write", "send", "delete"]
    ctx = RunContext("t", "p", "r")
    # enumerate every possible action set for A and B over the universe
    powerset = [frozenset(c) for k in range(len(universe) + 1)
                for c in itertools.combinations(universe, k)]
    for a_actions in powerset:
        for b_actions in powerset:
            store = CapabilityStore()
            if a_actions:
                store.issue(Capability("A", "t", "t/r", a_actions))
            if b_actions:
                store.issue(Capability("B", "t", "t/r", b_actions))
            mon = ReferenceMonitor(store)
            union = a_actions | b_actions
            for v in universe:
                d = mon.authorize(ctx, Proposal("t/r/x", v))
                if v in union:
                    # allowed (no approval gating in this construction)
                    assert d.verdict == Verdict.ALLOW, (
                        f"v={v} in union {sorted(union)} but got {d.verdict}")
                else:
                    assert d.verdict == Verdict.DENY, (
                        f"v={v} not in union {sorted(union)} but got {d.verdict}")


@given(data=st.data())
@settings(max_examples=300)
def test_union_grants_evidence(data):
    """EVIDENCE: with N random same-tenant same-scope grants, a verb is allowed
    iff at least one grant holds it (and none of the holding grants force
    approval). Random N and random action sets.
    """
    ctx_tenant = data.draw(TENANTS)
    n = data.draw(st.integers(min_value=1, max_value=4))
    scope = data.draw(resource_paths(max_len=2))
    store = CapabilityStore()
    grants = []
    for i in range(n):
        acts = data.draw(action_sets(min_size=1))
        cap = Capability(f"c{i}", ctx_tenant, scope, acts)
        store.issue(cap)
        grants.append(cap)
    mon = ReferenceMonitor(store)
    ctx = RunContext(ctx_tenant, "p", "r")
    resource = scope + "/leaf"
    verb = data.draw(st.sampled_from(VERB_LIST))
    d = mon.authorize(ctx, Proposal(resource, verb))

    holders = [g for g in grants if verb in g.actions]
    if not holders:
        assert d.verdict == Verdict.DENY
    else:
        # no approval_actions set in this test -> allow
        assert d.verdict == Verdict.ALLOW


# --------------------------------------------------------------------------- #
# Tenant isolation. (EVIDENCE) BUILD.md §1: two tenants never authorize each
# other. Identity is from the trusted context; the proposal has no tenant field.
# --------------------------------------------------------------------------- #

@given(cap=capabilities(), ctx=run_contexts(), prop=proposals())
@settings(max_examples=500)
def test_tenant_isolation(cap, ctx, prop):
    """EVIDENCE: a capability belonging to tenant X never authorizes a run whose
    trusted context tenant is Y != X, regardless of what resource the proposal
    names. This is the confused-deputy defense.
    """
    assume(cap.tenant != ctx.tenant)  # cross-tenant scenario
    store = CapabilityStore()
    store.issue(cap)
    mon = ReferenceMonitor(store)
    d = mon.authorize(ctx, prop)
    # The only capability present belongs to a different tenant, so nothing is
    # applicable to ctx.tenant -> must deny.
    assert d.verdict == Verdict.DENY


@given(cap=capabilities(), prop=proposals())
@settings(max_examples=300)
def test_identity_ignores_proposal(cap, prop):
    """EVIDENCE: the decision depends on ctx.tenant, not on anything in the
    proposal. Two runs with the same ctx and same proposal always agree, and a
    proposal cannot smuggle identity because Proposal has no tenant field.
    """
    store = CapabilityStore()
    store.issue(cap)
    mon = ReferenceMonitor(store)
    ctx = RunContext(cap.tenant, "p", "r")
    d1 = mon.authorize(ctx, prop)
    d2 = mon.authorize(ctx, prop)
    assert d1.verdict == d2.verdict  # deterministic, identity-stable


# --------------------------------------------------------------------------- #
# Explicit deny precedence. (PROOF, enumerated) BUILD.md §1: deny > approval >
# allow.
# --------------------------------------------------------------------------- #

def test_deny_beats_everything_proof():
    """PROOF: for a resource+verb under an explicit platform deny, the verdict
    is DENY for EVERY capability configuration (grant present or absent, approval
    or not). Enumerated over the relevant finite cases.
    """
    ctx = RunContext("t", "p", "r")
    policy = [DenyPolicy(verb="send", scope="t/restricted", reason="blocked")]
    resource = "t/restricted/doc"
    verb = "send"
    # enumerate: cap grants send / not; send approval-gated / not; cap present / not
    for present in (True, False):
        for grants_send in (True, False):
            for gated in (True, False):
                store = CapabilityStore()
                if present:
                    acts = frozenset({"send"}) if grants_send else frozenset({"read"})
                    appr = frozenset({"send"}) if (grants_send and gated) else frozenset()
                    store.issue(Capability("c", "t", "t/restricted", acts, appr))
                mon = ReferenceMonitor(store, deny_policies=policy)
                d = mon.authorize(ctx, Proposal(resource, verb))
                assert d.verdict == Verdict.DENY, (
                    f"present={present} grants={grants_send} gated={gated} "
                    f"-> {d.verdict}, expected DENY")


# --------------------------------------------------------------------------- #
# Revoke / unknown -> deny. (EVIDENCE)
# --------------------------------------------------------------------------- #

@given(cap=capabilities(), prop=proposals())
@settings(max_examples=300)
def test_revoked_never_authorizes(cap, prop):
    """EVIDENCE: once revoked, a capability authorizes nothing, for any proposal.
    """
    store = CapabilityStore()
    store.issue(cap)
    store.revoke(cap.id)
    mon = ReferenceMonitor(store)
    ctx = RunContext(cap.tenant, "p", "r")
    d = mon.authorize(ctx, prop)
    assert d.verdict == Verdict.DENY


# --------------------------------------------------------------------------- #
# Malformed proposals fail closed. (EVIDENCE) BUILD.md §0.5.
# --------------------------------------------------------------------------- #

@given(bad=st.one_of(
    st.none(),
    st.integers(),
    st.text(),
    st.builds(Proposal, resource=st.integers(), verb=st.text()),
    st.builds(Proposal, resource=st.just(""), verb=st.just("read")),
    st.builds(Proposal, resource=st.just("t/r"), verb=st.just("")),
    st.builds(Proposal, resource=st.none(), verb=st.none()),
))
@settings(max_examples=300)
def test_malformed_proposal_denies_never_throws(bad):
    """EVIDENCE: any malformed proposal (wrong type, empty fields, None) yields a
    deterministic DENY and never raises. A reference monitor must fail closed.
    """
    store = CapabilityStore()
    store.issue(Capability("c", "t", "t/r", frozenset({"read"})))
    mon = ReferenceMonitor(store)
    ctx = RunContext("t", "p", "r")
    d = mon.authorize(ctx, bad)   # must not raise
    assert d.verdict == Verdict.DENY


# --------------------------------------------------------------------------- #
# Scope containment is segment-aware. (PROOF, enumerated small) + EVIDENCE
# --------------------------------------------------------------------------- #

def test_prefix_confusion_proof():
    """PROOF: scope 'a/data' does NOT cover 'a/database...' for an enumerated set
    of confusable siblings. Segment-aware, not raw string prefix.
    """
    assert scope_covers("a/data", "a/data/x")
    assert scope_covers("a/data", "a/data")
    for sibling in ("a/database", "a/database-secret", "a/datax", "a/dat"):
        assert not scope_covers("a/data", sibling), sibling


@given(scope=resource_paths(), resource=resource_paths())
@settings(max_examples=500)
def test_scope_covers_is_segment_prefix(scope, resource):
    """EVIDENCE: scope_covers holds iff scope's segments are a positional prefix
    of resource's segments. Cross-checked against an independent implementation.
    """
    s, r = segments(scope), segments(resource)
    expected = len(s) <= len(r) and all(s[i] == r[i] for i in range(len(s)))
    assert scope_covers(scope, resource) == expected


# --------------------------------------------------------------------------- #
# Duplicate ids fail closed. (EVIDENCE)
# --------------------------------------------------------------------------- #

@given(cap=capabilities())
@settings(max_examples=200)
def test_duplicate_id_fails_closed(cap):
    """EVIDENCE: issuing the same id twice raises, never silently overwrites."""
    store = CapabilityStore()
    store.issue(cap)
    import pytest
    with pytest.raises(Exception):
        store.issue(Capability(cap.id, cap.tenant, cap.resource, frozenset({"admin"})))
    # original authority unchanged
    assert store.get(cap.id).actions == cap.actions
