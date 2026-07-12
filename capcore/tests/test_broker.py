"""M3 credential broker tests (redemption surface).

Central property: a known mock secret is delivered ONLY to an authorized, bound,
in-scope, currently-authorized action via broker-controlled execution, and NEVER
appears in repr/str/logs/audit/result or any model-facing output. The broker
redeems a server-side authorization by opaque id; it never inspects a
caller-supplied authorization object. Deterministic; no real secret, no network.
"""

import time

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext, Verdict,
)
from capcore.broker import (
    Secret, Credential, TrustedExecutionBroker, CredentialError,
    AuthorizationError, AuthorizationState, ReleaseAudit, SanitizedToolResult,
    ToolKind, ToolRegistration, ExecutionProposal,
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


class Recorder:
    """A credentialed adapter that records the revealed secret. Stands in for a
    real tool so tests can assert exactly where the secret went."""
    def __init__(self):
        self.delivered = []

    def execute_with_credential(self, proposal, secret):
        self.delivered.append(secret.reveal())
        return "tool-ok"


def ep(resource, verb="read", tool="tool-1"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


def wired(monitor, recorder=None, cred=None, tool_version="1", verb="read"):
    """A broker with one credential and one credentialed tool bound to it."""
    broker = TrustedExecutionBroker(monitor)
    broker.issue_credential(cred or a_credential())
    broker.register_tool(ToolRegistration(
        registration_id="tool-1", verb=verb, kind=ToolKind.CREDENTIALED,
        adapter=recorder or Recorder(), version=tool_version,
        credential_id="cred-1",
    ))
    broker.grant_tool("tool-1", "acme/records")
    return broker


def mint(broker, mon, ctx, prop, tool="tool-1"):
    """prop is an M1 Proposal; wrap it for the execution layer."""
    return broker.register_authorized_execution(
        ctx, ExecutionProposal(action=prop, tool_registration_id=tool))


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
# Execute only for authorized + bound + scoped + currently-authorized action.
# --------------------------------------------------------------------------- #

def test_execute_on_authorized_action_delivers_secret_to_tool():
    store, mon, ctx = build()
    rec = Recorder()
    broker = wired(mon, rec)
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))

    result = broker.redeem_and_execute(action_id)

    assert result.ok is True
    assert rec.delivered == [MOCK_SECRET]     # secret reached the tool, once
    assert result.body == "tool-ok"
    assert MOCK_SECRET not in (result.body or "")  # summary is not the token


def test_cannot_register_a_denied_action():
    """The broker authorizes independently; a denied action never mints."""
    store, mon, ctx = build()
    broker = wired(mon)
    prop = Proposal("acme/records/x", "write")  # write not granted -> deny
    assert mon.authorize(ctx, prop).verdict == Verdict.DENY
    with pytest.raises(AuthorizationError):
        mint(broker, mon, ctx, prop)


def test_no_delivery_verb_mismatch():
    """The CREDENTIAL is bound to `send` while the action is `read`. The tool and
    the capability both permit read, so this isolates the credential's own binding
    check, which is independent of capability scope."""
    store, mon, ctx = build()
    rec = Recorder()
    broker = wired(mon, rec, cred=a_credential(verb="send"))  # cred for send
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))

    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert rec.delivered == []


def test_no_delivery_out_of_credential_scope():
    store, mon, ctx = build()
    rec = Recorder()
    broker = wired(mon, rec, cred=a_credential(scope="acme/records/customers"))
    # in capability scope, outside credential scope
    action_id = mint(broker, mon, ctx, Proposal("acme/records/other", "read"))

    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert rec.delivered == []


# --------------------------------------------------------------------------- #
# Single-use: an authorization is redeemable exactly once (state machine).
# --------------------------------------------------------------------------- #

def test_authorization_is_single_use():
    store, mon, ctx = build()
    rec = Recorder()
    broker = wired(mon, rec, cred=a_credential(single_use=True))
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))

    first = broker.redeem_and_execute(action_id)
    second = broker.redeem_and_execute(action_id)

    assert first.ok is True
    assert second.ok is False
    assert rec.delivered == [MOCK_SECRET]     # delivered exactly once
    assert broker.authorization_state(action_id) is AuthorizationState.COMPLETED


# --------------------------------------------------------------------------- #
# TTL.
# --------------------------------------------------------------------------- #

def test_action_ttl_expiry_denies_after_deadline():
    store, mon, ctx = build()
    rec = Recorder()
    broker = TrustedExecutionBroker(mon, action_ttl_seconds=10.0)
    broker.issue_credential(a_credential())
    broker.register_tool(ToolRegistration(
        registration_id="tool-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=rec, version="1", credential_id="cred-1",
    ))
    broker.grant_tool("tool-1", "acme/records")
    prop = Proposal("acme/records/x", "read")
    decision = mon.authorize(ctx, prop)
    # The ACTION ttl is self-consistent (expires_at is derived from this same
    # `now`), so an absolute origin is safe here. Anchoring anyway, so that no
    # test in this file mixes clock origins and a future credential TTL added to
    # this fixture cannot silently reintroduce the monotonic-origin bug.
    t0 = time.monotonic()
    action_id = broker.register_authorized_execution(
        ctx, ExecutionProposal(action=prop, tool_registration_id="tool-1"), now=t0)

    result = broker.redeem_and_execute(action_id, now=t0 + 11.0)

    assert result.ok is False
    assert rec.delivered == []


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
    rec = Recorder()
    broker = wired(mon, rec, cred=a_credential(single_use=True))
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))
    broker.redeem_and_execute(action_id)        # granted
    broker.redeem_and_execute(action_id)        # refused (already redeemed)

    for r in broker.audit:
        assert MOCK_SECRET not in f"{r} {r.reason}"
    assert any(r.granted for r in broker.audit)
    assert any(not r.granted for r in broker.audit)


# --------------------------------------------------------------------------- #
# Containment: the secret reaches the authorized tool and nothing model-facing.
# --------------------------------------------------------------------------- #

def test_secret_reaches_only_authorized_tool_not_model_facing():
    store, mon, ctx = build()
    rec = Recorder()
    broker = wired(mon, rec)
    prop = Proposal("acme/records/x", "read")

    decision = mon.authorize(ctx, prop)
    model_view = decision.for_model()
    assert MOCK_SECRET not in model_view.public_reason
    assert MOCK_SECRET not in str(model_view.trace)

    action_id = mint(broker, mon, ctx, prop)
    result = broker.redeem_and_execute(action_id)

    assert rec.delivered == [MOCK_SECRET]       # reached the tool, once
    assert all(MOCK_SECRET not in r.reason for r in broker.audit)
    assert MOCK_SECRET not in (result.body or "")


def test_duplicate_credential_id_rejected():
    store, mon, ctx = build()
    broker = TrustedExecutionBroker(mon)
    broker.issue_credential(a_credential())
    with pytest.raises(CredentialError):
        broker.issue_credential(a_credential())


def test_consumed_credential_refuses_a_fresh_authorization():
    """Credential-level single-use is independent of action-level single-use.

    Action single-use is enforced by the PENDING->EXECUTING claim. Credential
    single-use is enforced by cred.is_available(). These are different guards,
    and a bypass of the credential guard must be caught on its own. Here the
    credential is single-use and gets consumed by a first action; a SECOND,
    freshly-minted authorization against the SAME credential must then be refused
    because the credential itself is spent, even though the new action_id is
    perfectly valid and has never been redeemed.
    """
    store, mon, ctx = build()
    rec = Recorder()
    broker = wired(mon, rec, cred=a_credential(single_use=True))

    first_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))
    second_id = mint(broker, mon, ctx, Proposal("acme/records/y", "read"))

    first = broker.redeem_and_execute(first_id)
    second = broker.redeem_and_execute(second_id)

    assert first.ok is True
    assert second.ok is False, "credential was consumed; second action must fail"
    assert rec.delivered == [MOCK_SECRET], "secret delivered exactly once"


def test_expired_credential_refuses_execution():
    """An expired credential refuses regardless of a valid, current action.

    NOTE ON CLOCKS. Credential._issued_at defaults to time.monotonic(), whose
    origin is arbitrary and machine-dependent (seconds since boot, roughly). An
    injected `now` must therefore be anchored to the credential's OWN issue time,
    not to an absolute number, or the test's outcome depends on how long the host
    has been up. An earlier version of this test hard-coded now=1000.0 and passed
    or failed depending on the machine. Anchor to _issued_at.
    """
    store, mon, ctx = build()
    rec = Recorder()
    broker = TrustedExecutionBroker(mon, action_ttl_seconds=10_000.0)
    cred = a_credential(ttl_seconds=10.0)
    broker.issue_credential(cred)
    broker.register_tool(ToolRegistration(
        registration_id="tool-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=rec, version="1", credential_id="cred-1",
    ))
    broker.grant_tool("tool-1", "acme/records")
    t0 = cred._issued_at          # anchor everything to the credential's clock

    prop = Proposal("acme/records/x", "read")
    action_id = broker.register_authorized_execution(
        ctx, ExecutionProposal(action=prop, tool_registration_id="tool-1"), now=t0)

    # well inside the action TTL (10_000s), well past the CREDENTIAL TTL (10s)
    result = broker.redeem_and_execute(action_id, now=t0 + 50.0)

    assert result.ok is False
    assert rec.delivered == [], "expired credential must not deliver the secret"


def test_credential_within_ttl_still_delivers():
    """Control for the above: inside the credential TTL, the secret is delivered.

    Without this control, test_expired_credential_refuses_execution could pass for
    the wrong reason (e.g. some unrelated check refusing every redemption).
    """
    store, mon, ctx = build()
    rec = Recorder()
    broker = TrustedExecutionBroker(mon, action_ttl_seconds=10_000.0)
    cred = a_credential(ttl_seconds=100.0)
    broker.issue_credential(cred)
    broker.register_tool(ToolRegistration(
        registration_id="tool-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=rec, version="1", credential_id="cred-1",
    ))
    broker.grant_tool("tool-1", "acme/records")
    t0 = cred._issued_at

    prop = Proposal("acme/records/x", "read")
    action_id = broker.register_authorized_execution(
        ctx, ExecutionProposal(action=prop, tool_registration_id="tool-1"), now=t0)

    result = broker.redeem_and_execute(action_id, now=t0 + 5.0)   # inside TTL

    assert result.ok is True
    assert rec.delivered == [MOCK_SECRET]


def test_redeem_and_execute_never_returns_a_secret():
    store, mon, ctx = build()
    broker = wired(mon)
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))
    result = broker.redeem_and_execute(action_id)
    assert isinstance(result, SanitizedToolResult)
    assert not isinstance(result.body, Secret)


# --------------------------------------------------------------------------- #
# Fail closed at CONSTRUCTION, not at use.
#
# A malformed scope used to be accepted and only blow up later, inside redeem, as
# a ResourceError from scope_covers. That is the wrong place and the wrong time:
# the failure surfaces during a live action, with a secret already in play. These
# scopes must be impossible to hold.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_scope", [
    "../bad",            # traversal
    "acme/../secret",    # traversal, mid-path
    "acme//records",     # empty segment
    "acme/records/..",   # traversal, trailing
    "*",                 # wildcard (no wildcard grammar)
    "acme\\records",     # backslash separator
    "acme/%2Frecords",   # encoded separator smuggling
])
def test_credential_scope_is_validated_at_issuance(bad_scope):
    with pytest.raises(CredentialError):
        a_credential(scope=bad_scope)


@pytest.mark.parametrize("bad_scope", [
    "../bad", "acme/../secret", "acme//records", "*", "acme\\records",
])
def test_tool_grant_scope_is_validated_at_construction(bad_scope):
    """A grant is an authorization rule. A malformed one that silently vanished at
    check time would be an allow-by-omission, the same fail-open direction that
    made a malformed DenyPolicy dangerous in M1."""
    from capcore.broker import ToolGrant
    with pytest.raises(ValueError):
        ToolGrant("some-tool", bad_scope)


def test_valid_scopes_are_still_accepted():
    """Control: the validator must not reject legitimate scopes."""
    from capcore.broker import ToolGrant
    assert a_credential(scope="acme/records").scope == "acme/records"
    assert ToolGrant("t", "acme/records/customers").scope == "acme/records/customers"
