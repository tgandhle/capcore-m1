"""Security regression tests for defects found in review after the first M1 cut.

Each test pins a specific fix so the defect cannot silently return. These are
the Python analogue of the mutation-tested invariants: they fail if the fix is
reverted.
"""

import pytest
from hypothesis import given, settings, strategies as st

from capcore import (
    Capability, RunContext, Proposal, CapabilityStore, ReferenceMonitor,
    DenyPolicy, Verdict,
)
from capcore.tests.strategies import capabilities, proposals, run_contexts


# --------------------------------------------------------------------------- #
# Defect: denial reason leaked boundary detail to the model.
# Fix: model-facing reason is generic; detail lives in audit_reason only.
# --------------------------------------------------------------------------- #

GENERIC_DENY = "no applicable authority"


def test_model_facing_deny_is_generic_cross_tenant():
    """The model must not learn that a resource belongs to another tenant."""
    store = CapabilityStore()
    store.issue(Capability("g", "globex", "globex/records", frozenset({"read"})))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "p", "r")            # acme run reaching for globex
    full = mon.authorize(ctx, Proposal("globex/records/secret", "read"))
    model_view = full.for_model()

    assert full.verdict == Verdict.DENY
    # audit retains the detail...
    assert "globex" in full.audit_reason or "tenant" in full.audit_reason
    # ...but the model-facing view does not.
    assert model_view.public_reason == GENERIC_DENY
    assert model_view.audit_reason == GENERIC_DENY
    assert model_view.trace == ()
    assert "globex" not in model_view.public_reason


def test_authorize_for_model_never_leaks(request):
    """Every deny path, via authorize_for_model, returns only the generic reason
    and no trace. Covers schema, platform-deny, no-authority, verb-missing.
    """
    store = CapabilityStore()
    store.issue(Capability("c", "acme", "acme/records", frozenset({"read"})))
    mon = ReferenceMonitor(store, deny_policies=[
        DenyPolicy("send", "acme/records/restricted", "restricted")])
    ctx = RunContext("acme", "p", "r")

    deny_cases = [
        None,                                              # schema
        Proposal("acme/records/restricted/x", "send"),     # platform deny
        Proposal("other/thing", "read"),                   # no authority
        Proposal("acme/records/x", "delete"),              # verb missing
    ]
    for prop in deny_cases:
        d = mon.authorize_for_model(ctx, prop)
        assert d.verdict == Verdict.DENY
        assert d.public_reason == GENERIC_DENY
        assert d.trace == ()
        # no case-specific words leak
        for leak in ("restricted", "tenant", "verb", "schema", "globex"):
            assert leak not in d.public_reason


@given(cap=capabilities(), ctx=run_contexts(), prop=proposals())
@settings(max_examples=300)
def test_model_view_has_no_trace_ever(cap, ctx, prop):
    """EVIDENCE: for any input, the model-facing decision carries no trace and a
    reason drawn only from the fixed generic set.
    """
    store = CapabilityStore()
    store.issue(cap)
    mon = ReferenceMonitor(store)
    d = mon.authorize(ctx, prop).for_model()
    assert d.trace == ()
    assert d.public_reason in {"authorized", "approval required", "no applicable authority"}
    assert d.audit_reason == d.public_reason  # detail stripped


# --------------------------------------------------------------------------- #
# Defect: a revoked parent could still derive new children.
# Fix: derivation from a revoked capability is rejected.
# --------------------------------------------------------------------------- #

def test_no_derivation_from_revoked_parent():
    store = CapabilityStore()
    store.issue(Capability("root", "acme", "acme/records",
                           frozenset({"read", "write"}), runtime=False))
    store.revoke("root")
    r = store.derive_child("root", Capability(
        "child", "acme", "acme/records/x", frozenset({"read"})))
    assert not r.ok
    assert r.reason == "parent is revoked"


def test_derivation_from_live_parent_still_works():
    """Guard against over-correction: a live parent still derives valid children."""
    store = CapabilityStore()
    store.issue(Capability("root", "acme", "acme/records",
                           frozenset({"read", "write"}), runtime=False))
    r = store.derive_child("root", Capability(
        "child", "acme", "acme/records/x", frozenset({"read"})))
    assert r.ok


@given(data=st.data())
@settings(max_examples=200)
def test_revoked_parent_derivation_always_denied(data):
    """EVIDENCE: no matter the (valid) child spec, a revoked parent derives
    nothing.
    """
    parent = data.draw(capabilities(runtime=False))
    store = CapabilityStore()
    store.issue(parent)
    store.revoke(parent.id)
    child = Capability(
        id="ch",
        tenant=parent.tenant,
        resource=parent.resource + "/leaf",
        actions=frozenset(list(parent.actions)[:1]) or frozenset({"read"}),
    )
    r = store.derive_child(parent.id, child)
    assert not r.ok
    assert r.reason == "parent is revoked"
