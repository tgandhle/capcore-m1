"""M3 credential broker tests.

The central security property: a known mock secret is released ONLY to an
authorized, bound, in-scope action, and NEVER appears in repr/str/logs/audit or
any model-facing output. All deterministic; no real secret, no network.
"""

import time
import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext, Verdict,
)
from capcore.broker import (
    Secret, Credential, CredentialBroker, CredentialError, ReleaseAudit,
)

MOCK_SECRET = "SEKRET-TOKEN-12345"


def build():
    store = CapabilityStore()
    store.issue(Capability("cap-run", "acme", "acme/records",
                           frozenset({"read", "send"}),
                           approval_actions=frozenset({"send"}),
                           principal="p1", run="r1"))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "p1", "r1")
    return store, mon, ctx


def a_credential(**over):
    kw = dict(id="cred-1", capability_id="cap-run", verb="read",
              scope="acme/records", secret=Secret(MOCK_SECRET))
    kw.update(over)
    return Credential(**kw)


# --------------------------------------------------------------------------- #
# Secret never prints itself.
# --------------------------------------------------------------------------- #

def test_secret_never_reveals_in_repr_str_format():
    s = Secret(MOCK_SECRET)
    assert MOCK_SECRET not in repr(s)
    assert MOCK_SECRET not in str(s)
    assert MOCK_SECRET not in f"{s}"
    assert MOCK_SECRET not in "{}".format(s)
    assert MOCK_SECRET not in f"{s!r}"
    # the ONLY way to get the value:
    assert s.reveal() == MOCK_SECRET


def test_secret_rejects_empty():
    with pytest.raises(ValueError):
        Secret("")


def test_secret_not_in_exception_message():
    s = Secret(MOCK_SECRET)
    try:
        raise RuntimeError(f"failure involving {s}")
    except RuntimeError as e:
        assert MOCK_SECRET not in str(e)


# --------------------------------------------------------------------------- #
# Release only for authorized + bound + scoped action.
# --------------------------------------------------------------------------- #

def test_release_on_authorized_action():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential())
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)
    assert decision.verdict == Verdict.ALLOW
    secret = broker.release("cred-1", "cap-run", prop, decision)
    assert secret is not None and secret.reveal() == MOCK_SECRET


def test_no_release_when_denied():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential(verb="write", scope="acme/records"))
    prop = Proposal("acme/records/x", "write")  # write not granted -> deny
    decision = mon.authorize(ctx, prop)
    assert decision.verdict == Verdict.DENY
    assert broker.release("cred-1", "cap-run", prop, decision) is None


def test_no_release_wrong_capability_binding():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential(capability_id="some-other-cap"))
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)
    # authorized, but the credential is bound to a different capability
    assert broker.release("cred-1", "cap-run", prop, decision) is None


def test_no_release_verb_mismatch():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential(verb="send"))  # credential is for send
    prop = Proposal("acme/records/x", "read")  # action is read
    decision = mon.authorize(ctx, prop)
    assert broker.release("cred-1", "cap-run", prop, decision) is None


def test_no_release_out_of_credential_scope():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential(scope="acme/records/customers"))
    prop = Proposal("acme/records/other", "read")  # in cap scope, not cred scope
    decision = mon.authorize(ctx, prop)
    assert broker.release("cred-1", "cap-run", prop, decision) is None


# --------------------------------------------------------------------------- #
# Single-use.
# --------------------------------------------------------------------------- #

def test_single_use_consumed_after_one_release():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential(single_use=True))
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)
    first = broker.release("cred-1", "cap-run", prop, decision)
    assert first is not None
    second = broker.release("cred-1", "cap-run", prop, decision)
    assert second is None  # consumed


# --------------------------------------------------------------------------- #
# TTL expiry.
# --------------------------------------------------------------------------- #

def test_ttl_expiry_denies_after_deadline():
    store, mon, ctx = build()
    broker = CredentialBroker()
    cred = a_credential(ttl_seconds=10.0)
    broker.issue(cred)
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)
    t0 = cred._issued_at
    # before deadline: released
    assert broker.release("cred-1", "cap-run", prop, decision, now=t0 + 5) is not None
    # after deadline: refused
    assert broker.release("cred-1", "cap-run", prop, decision, now=t0 + 11) is None


def test_invalid_ttl_rejected():
    with pytest.raises(CredentialError):
        a_credential(ttl_seconds=0)
    with pytest.raises(CredentialError):
        a_credential(ttl_seconds=-5)


# --------------------------------------------------------------------------- #
# Audit never contains the secret.
# --------------------------------------------------------------------------- #

def test_audit_never_contains_secret():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential(single_use=True))
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)
    broker.release("cred-1", "cap-run", prop, decision)          # granted
    broker.release("cred-1", "cap-run", prop, decision)          # refused (consumed)
    # every audit record, granted or refused, must be secret-free
    for rec in broker.audit:
        blob = f"{rec} {rec.reason}"
        assert MOCK_SECRET not in blob
    assert any(r.granted for r in broker.audit)
    assert any(not r.granted for r in broker.audit)


# --------------------------------------------------------------------------- #
# Containment: the secret reaches the authorized tool and NOTHING model-facing.
# --------------------------------------------------------------------------- #

def test_secret_reaches_only_authorized_tool_not_model_facing():
    store, mon, ctx = build()
    broker = CredentialBroker()
    broker.issue(a_credential())
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)

    # model-facing view of the decision must never contain the secret
    model_view = decision.for_model()
    assert MOCK_SECRET not in model_view.public_reason
    assert MOCK_SECRET not in str(model_view.trace)

    # the secret is released to the tool boundary
    secret = broker.release("cred-1", "cap-run", prop, decision)
    delivered = []
    def tool(p, sec): delivered.append(sec.reveal()); return "ok"
    tool(prop, secret)

    # the raw secret reached the tool exactly once...
    assert delivered == [MOCK_SECRET]
    # ...and appears nowhere in the broker audit or the model view
    assert all(MOCK_SECRET not in r.reason for r in broker.audit)
    assert MOCK_SECRET not in model_view.public_reason


def test_duplicate_credential_id_rejected():
    broker = CredentialBroker()
    broker.issue(a_credential())
    with pytest.raises(CredentialError):
        broker.issue(a_credential())  # same id
