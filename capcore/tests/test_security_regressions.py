"""Security regression tests for defects found in review after the first M1 cut.

Each test pins a specific fix so the defect cannot silently return. These are
the Python analogue of the mutation-tested invariants: they fail if the fix is
reverted.
"""

import pytest
from hypothesis import given, settings, strategies as st

from capcore import (
    Capability, RunContext, Proposal, CapabilityStore, ReferenceMonitor,
    DenyPolicy, Verdict, StoreError, is_valid_resource, ResourceError,
    validate_resource, _covers_safe,
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


# --------------------------------------------------------------------------- #
# Defect: issue() accepted child-shaped capabilities, bypassing attenuation.
# Fix: issue_root rejects any capability with a parent set.
# --------------------------------------------------------------------------- #

def test_issue_root_rejects_child_shaped_capability():
    """A capability that names a parent must not be issuable as a root; doing so
    would skip derive_child's attenuation validation entirely.
    """
    store = CapabilityStore()
    orphan = Capability(id="orphan", tenant="acme", resource="acme/data",
                        actions=frozenset({"read"}), parent="missing-parent")
    with pytest.raises(StoreError):
        store.issue_root(orphan)
    with pytest.raises(StoreError):
        store.issue(orphan)  # deprecated alias must reject too
    # and it must not be live
    assert store.get("orphan") is None


def test_issue_root_rejects_empty_fields():
    """Empty id, tenant, resource, or action set fail closed at issue."""
    store = CapabilityStore()
    bad_caps = [
        Capability(id="", tenant="t", resource="t/r", actions=frozenset({"read"})),
        Capability(id="c", tenant="", resource="t/r", actions=frozenset({"read"})),
        Capability(id="c", tenant="t", resource="", actions=frozenset({"read"})),
        Capability(id="c", tenant="t", resource="t/r", actions=frozenset()),
    ]
    for cap in bad_caps:
        with pytest.raises(StoreError):
            store.issue_root(cap)


# --------------------------------------------------------------------------- #
# Defect: resource comparison accepted traversal and empty scopes.
# Fix: validate_resource rejects them; scope_covers on invalid input fails.
# --------------------------------------------------------------------------- #

def test_resource_traversal_rejected():
    """Path traversal must not authorize outside scope."""
    from capcore import validate_resource, ResourceError
    for bad in ("acme/data/../secret", "..", "a/../b", "a/./b",
                "a//b", "", "a\\b", "a/%2e%2e/b", "a/b%2Fc"):
        assert not is_valid_resource(bad), bad
    # a valid scope never "covers" a traversal resource: proposal fails closed
    store = CapabilityStore()
    store.issue(Capability("c", "acme", "acme/data", frozenset({"read"})))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "p", "r")
    d = mon.authorize(ctx, Proposal("acme/data/../secret", "read"))
    assert d.verdict == Verdict.DENY


def test_asterisk_rejected_until_wildcard_grammar():
    """'*' is not a permitted resource character: the monitor treats it as a
    literal, and allowing it invites a wildcard-interpretation bypass in a
    future adapter. Reject until an explicit wildcard grammar exists.
    """
    assert not is_valid_resource("acme/*")
    assert not is_valid_resource("acme/*/secret")
    assert not is_valid_resource("*")
    store = CapabilityStore()
    with pytest.raises(StoreError):
        store.issue(Capability("c", "t", "t/*", frozenset({"read"})))


def test_empty_scope_does_not_cover_everything():
    """An empty scope must be rejected, not treated as a wildcard."""
    assert not is_valid_resource("")
    store = CapabilityStore()
    # attempting to issue a cap with empty scope fails closed
    with pytest.raises(StoreError):
        store.issue(Capability("c", "t", "", frozenset({"read"})))


@given(scope=st.text(min_size=0, max_size=12), resource=st.text(min_size=0, max_size=12))
@settings(max_examples=300)
def test_scope_covers_never_raises_uncaught_via_safe_path(scope, resource):
    """EVIDENCE: the internal fail-closed wrapper never raises, for arbitrary
    text input including traversal and junk.
    """
    from capcore import _covers_safe
    _covers_safe(scope, resource)  # must not raise
