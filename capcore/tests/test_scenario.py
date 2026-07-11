"""Scenario test: the exact six cases the web demo runs, asserted here so the
demo and the Python core are the same semantics, not two drifting copies.
"""

from capcore import (
    Capability, RunContext, Proposal, CapabilityStore, ReferenceMonitor,
    DenyPolicy, Verdict,
)


def build():
    store = CapabilityStore()
    # derivation-only root
    store.issue(Capability("cap-acme-root", "acme", "acme/records",
                           frozenset({"read", "write", "send"}),
                           approval_actions=frozenset({"send"}), runtime=False))
    # validated child
    r = store.derive_child("cap-acme-root", Capability(
        "cap-acme-run", "acme", "acme/records/customers",
        frozenset({"read", "send"}), approval_actions=frozenset({"send"})))
    assert r.ok, r.reason
    # separate tenant
    store.issue(Capability("cap-globex", "globex", "globex/records",
                           frozenset({"read", "write"})))
    policies = [DenyPolicy("send", "acme/records/restricted",
                           "platform policy: restricted records may not be sent")]
    return ReferenceMonitor(store, deny_policies=policies), store


ACME = RunContext("acme", "agent-7", "run-42")


def test_scenario_matches_demo():
    mon, _ = build()
    cases = [
        (Proposal("acme/records/customers/c-1001", "read"),  Verdict.ALLOW),
        (Proposal("acme/records/customers/c-1001", "send"),  Verdict.REQUIRE_APPROVAL),
        (Proposal("globex/records/secret", "read"),          Verdict.DENY),   # cross-tenant
        (Proposal("acme/records/customers/c-1001", "write"), Verdict.DENY),   # over-attenuation
        (Proposal("acme/records/database-secret", "read"),   Verdict.DENY),   # prefix confusion
        (Proposal("acme/records/restricted/c-9", "send"),    Verdict.DENY),   # explicit deny
    ]
    for prop, expected in cases:
        d = mon.authorize(ACME, prop)
        assert d.verdict == expected, f"{prop} -> {d.verdict}, expected {expected}: {d.audit_reason}"


def test_revoke_then_repropose_denies():
    mon, store = build()
    ok = mon.authorize(ACME, Proposal("acme/records/customers/c-1002", "read"))
    assert ok.verdict == Verdict.ALLOW
    store.revoke("cap-acme-run")
    after = mon.authorize(ACME, Proposal("acme/records/customers/c-1002", "read"))
    assert after.verdict == Verdict.DENY  # no fallback to derivation-only root


def test_malformed_scenario():
    mon, _ = build()
    assert mon.authorize(ACME, None).verdict == Verdict.DENY
    assert mon.authorize(ACME, Proposal(resource=123, verb="read")).verdict == Verdict.DENY
