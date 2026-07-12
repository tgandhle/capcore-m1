"""M2<->M3 integration: the first end-to-end chain.

Before this commit there was no path from the execution engine to a credentialed
tool. The engine had its own verb-keyed ToolRegistry; the broker had its own
registration-keyed catalog; nothing connected them, and the "live demo" assembled
the pieces by hand. These tests exercise the real chain:

    model proposes (action + executor, both untrusted)
      -> engine authorizes the ACTION (control flow / audit)
      -> broker authorizes INDEPENDENTLY at mint (it takes no caller Decision)
      -> broker checks the tool's verb matches the action
      -> broker checks ToolPolicy authorizes THIS executor for THIS action
      -> broker re-authorizes at redemption, immediately before the credential
      -> broker injects the credential and runs the adapter inside its boundary
      -> engine receives a SanitizedToolResult, never a Secret

The invariant that makes this safe: the engine owns no catalog and holds no
adapter, so it cannot dispatch around the broker.
"""

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext, Verdict,
)
from capcore.broker import (
    AuthorizationError, AuthorizationState, CatalogError, Credential,
    CredentialVault, ExecutionProposal, SanitizedToolResult, Secret, ToolCatalog,
    ToolKind, ToolPolicy, ToolRegistration, TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, RunRecord, RunState, ScriptedModel, StepOutcome,
)

SECRET = "SEKRET-TOKEN-12345"


def build_store():
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", "acme/records", frozenset({"read"}),
                           principal="p1", run="r1"))
    return store


def ctx():
    return RunContext("acme", "p1", "r1")


class PlainRecorder:
    def __init__(self):
        self.ran = []

    def __call__(self, action):
        self.ran.append(action.resource)
        return "plain-ok"


class CredRecorder:
    def __init__(self):
        self.delivered = []

    def execute_with_credential(self, action, secret):
        self.delivered.append(secret.reveal())
        return "cred-ok"


def build_broker(monitor, plain=None, cred=None, grant_plain=True,
                 grant_cred=True, cred_scope="acme/records"):
    """A broker with one plain tool and one credentialed tool, both optionally
    policy-granted. Registration alone does NOT authorize; grants do."""
    broker = TrustedExecutionBroker(monitor)
    broker.issue_credential(Credential(
        "cred-1", "cap-1", "read", cred_scope, Secret(SECRET), single_use=False))
    broker.register_tool(ToolRegistration(
        registration_id="plain-read", verb="read", kind=ToolKind.PLAIN,
        adapter=plain or PlainRecorder(), version="1"))
    broker.register_tool(ToolRegistration(
        registration_id="cred-read", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=cred or CredRecorder(), version="1", credential_id="cred-1"))
    if grant_plain:
        broker.grant_tool("plain-read", "acme/records")
    if grant_cred:
        broker.grant_tool("cred-read", "acme/records")
    return broker


def ep(resource="acme/records/x", verb="read", tool="plain-read"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


# --------------------------------------------------------------------------- #
# The engine owns no catalog. It cannot dispatch around the broker.
# --------------------------------------------------------------------------- #

def test_engine_has_no_tool_registry():
    """The engine must hold no adapter and no catalog of its own.

    Two registries that must be kept in sync is the monitor-store / engine-store
    defect in a new costume. There is exactly one catalog, and the broker owns it.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    engine = ExecutionEngine(monitor, build_broker(monitor), Budget(3))

    assert not hasattr(engine, "tools")
    assert not hasattr(engine, "_tools")
    assert not hasattr(engine, "registry")


def test_engine_requires_a_broker():
    """Without a broker the engine can execute nothing. Fail closed at construction."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    with pytest.raises(TypeError):
        ExecutionEngine(monitor, object(), Budget(3))


# --------------------------------------------------------------------------- #
# ExecutionProposal: an incomplete executable proposal is unrepresentable.
# --------------------------------------------------------------------------- #

def test_execution_proposal_requires_registration_id():
    """No empty-string sentinel. A proposal without an executor cannot be built."""
    with pytest.raises(AuthorizationError):
        ExecutionProposal(action=Proposal("acme/records/x", "read"),
                          tool_registration_id="")
    with pytest.raises(AuthorizationError):
        ExecutionProposal(action=Proposal("acme/records/x", "read"),
                          tool_registration_id=None)


def test_execution_proposal_requires_a_real_action():
    with pytest.raises(AuthorizationError):
        ExecutionProposal(action="acme/records/x", tool_registration_id="plain-read")


# --------------------------------------------------------------------------- #
# The chain, end to end.
# --------------------------------------------------------------------------- #

def test_plain_tool_executes_through_the_broker_catalog():
    store = build_store()
    monitor = ReferenceMonitor(store)
    plain = PlainRecorder()
    broker = build_broker(monitor, plain=plain)
    engine = ExecutionEngine(monitor, broker, Budget(3))

    record = engine.run(ctx(), ScriptedModel([ep(tool="plain-read")]))

    assert plain.ran == ["acme/records/x"]
    assert record.history[0].outcome is StepOutcome.EXECUTED
    assert record.history[0].tool_result == "plain-ok"


def test_credentialed_tool_executes_without_returning_the_secret():
    """The secret reaches the adapter and nothing else. The engine never sees it."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    cred = CredRecorder()
    broker = build_broker(monitor, cred=cred)
    engine = ExecutionEngine(monitor, broker, Budget(3))

    record = engine.run(ctx(), ScriptedModel([ep(tool="cred-read")]))

    assert cred.delivered == [SECRET]            # adapter got it, exactly once
    step = record.history[0]
    assert step.outcome is StepOutcome.EXECUTED
    assert step.tool_result == "cred-ok"
    assert SECRET not in (step.tool_result or "")  # engine's view is sanitized
    assert not isinstance(step.tool_result, Secret)
    # and nowhere in trusted run state
    assert SECRET not in str(record.history)
    # and nowhere in the audit
    for a in broker.audit:
        assert SECRET not in a.reason


# --------------------------------------------------------------------------- #
# Catalog existence is NOT authorization.
# --------------------------------------------------------------------------- #

def test_unknown_registration_is_denied():
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = build_broker(monitor)

    with pytest.raises(AuthorizationError):
        broker.register_authorized_execution(ctx(), ep(tool="does-not-exist"))


def test_registration_verb_must_match_the_proposed_action():
    """A tool registered for `send` cannot serve a `read`, even if both exist."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = TrustedExecutionBroker(monitor)
    broker.register_tool(ToolRegistration(
        registration_id="send-only", verb="send", kind=ToolKind.PLAIN,
        adapter=PlainRecorder(), version="1"))
    broker.grant_tool("send-only", "acme/records")

    with pytest.raises(AuthorizationError):
        broker.register_authorized_execution(
            ctx(), ep(verb="read", tool="send-only"))


def test_exact_registration_must_be_policy_authorized():
    """THE MIS-ROUTING DEFENCE.

    Two tools both serve verb=read: one benign, one sensitive. The action is
    authorized by the monitor and the tool exists in the catalog. If catalog
    lookup were the only check, an untrusted model could name the sensitive
    executor and get it. The ToolPolicy is what stops that, and it is
    deny-by-default: the sensitive tool is registered but NOT granted.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    sensitive = PlainRecorder()

    broker = TrustedExecutionBroker(monitor)
    broker.register_tool(ToolRegistration(
        registration_id="read-customer-record", verb="read", kind=ToolKind.PLAIN,
        adapter=PlainRecorder(), version="1"))
    broker.register_tool(ToolRegistration(
        registration_id="read-payroll-database", verb="read", kind=ToolKind.PLAIN,
        adapter=sensitive, version="1"))
    # ONLY the benign executor is granted. Both are registered; both serve `read`.
    broker.grant_tool("read-customer-record", "acme/records")

    engine = ExecutionEngine(monitor, broker, Budget(3))

    # The model names the executor it wants. That is not authorization.
    record = engine.run(ctx(), ScriptedModel([
        ep(tool="read-payroll-database")
    ]))

    assert sensitive.ran == [], "an ungranted executor must never run"
    assert record.history[0].outcome is StepOutcome.REVOKED_RACE


def test_registering_a_tool_does_not_authorize_it():
    """Deny by default: an empty policy authorizes no tool at all."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = TrustedExecutionBroker(monitor)
    broker.register_tool(ToolRegistration(
        registration_id="plain-read", verb="read", kind=ToolKind.PLAIN,
        adapter=PlainRecorder(), version="1"))
    # deliberately NO grant_tool call

    with pytest.raises(AuthorizationError):
        broker.register_authorized_execution(ctx(), ep(tool="plain-read"))


def test_grant_scope_is_enforced():
    """A grant is scoped. A tool granted under one scope cannot serve another."""
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", "acme", frozenset({"read"}),
                           principal="p1", run="r1"))
    monitor = ReferenceMonitor(store)
    tool = PlainRecorder()
    broker = TrustedExecutionBroker(monitor)
    broker.register_tool(ToolRegistration(
        registration_id="plain-read", verb="read", kind=ToolKind.PLAIN,
        adapter=tool, version="1"))
    broker.grant_tool("plain-read", "acme/records")     # granted only here

    # inside the grant: fine
    aid = broker.register_authorized_execution(ctx(), ep("acme/records/x"))
    assert broker.redeem_and_execute(aid).ok is True

    # outside the grant, though the capability allows the action
    with pytest.raises(AuthorizationError):
        broker.register_authorized_execution(ctx(), ep("acme/payroll/x"))
    assert tool.ran == ["acme/records/x"]


def test_cannot_grant_an_unregistered_tool():
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = TrustedExecutionBroker(monitor)
    with pytest.raises(CatalogError):
        broker.grant_tool("never-registered", "acme/records")


# --------------------------------------------------------------------------- #
# Binding: the action is pinned to a registration id AND version.
# --------------------------------------------------------------------------- #

def test_registration_cannot_be_substituted_at_redemption():
    """Swap the adapter under the same id after mint. The old grant must not
    transfer to the new implementation."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    original = CredRecorder()
    broker = build_broker(monitor, cred=original)

    action_id = broker.register_authorized_execution(ctx(), ep(tool="cred-read"))

    impostor = CredRecorder()
    broker.catalog.replace_for_test(ToolRegistration(
        registration_id="cred-read", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=impostor, version="2", credential_id="cred-1"))

    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "authorization_refused"
    assert impostor.delivered == [], "the swapped-in adapter must not receive the secret"
    assert original.delivered == []


def test_redeem_takes_only_an_action_id():
    """The caller cannot supply a tool or credential at redemption: there is no
    parameter through which to do so."""
    import inspect
    sig = inspect.signature(TrustedExecutionBroker.redeem_and_execute)
    params = set(sig.parameters) - {"self"}
    assert params <= {"action_id", "now"}, (
        f"redeem_and_execute exposes {params}; a caller must not be able to pass "
        f"a tool or credential at redemption"
    )


def test_register_takes_no_caller_decision():
    """The broker authorizes independently. It does not accept a verdict."""
    import inspect
    sig = inspect.signature(TrustedExecutionBroker.register_authorized_execution)
    assert "decision" not in sig.parameters, (
        "the broker must not accept a caller-supplied Decision: a forged ALLOW is "
        "one constructor call away"
    )


# --------------------------------------------------------------------------- #
# Replay, revocation, expiry through the integrated chain.
# --------------------------------------------------------------------------- #

def test_replayed_action_id_is_denied():
    store = build_store()
    monitor = ReferenceMonitor(store)
    cred = CredRecorder()
    broker = build_broker(monitor, cred=cred)
    action_id = broker.register_authorized_execution(ctx(), ep(tool="cred-read"))

    first = broker.redeem_and_execute(action_id)
    second = broker.redeem_and_execute(action_id)

    assert first.ok is True
    assert second.ok is False
    assert cred.delivered == [SECRET]     # exactly once
    assert broker.authorization_state(action_id) is AuthorizationState.COMPLETED


def test_revoked_action_is_denied_at_redemption():
    """The revoke race, now enforced inside the broker immediately before the
    credential is touched."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    cred = CredRecorder()
    broker = build_broker(monitor, cred=cred)
    action_id = broker.register_authorized_execution(ctx(), ep(tool="cred-read"))

    store.revoke("cap-1")

    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "authorization_refused"
    assert cred.delivered == [], "a revoked action must never reach the adapter"


def test_revoke_race_through_the_engine():
    """End to end: revoke fires between propose-time authorization and dispatch.
    The tool must not run."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    cred = CredRecorder()
    broker = build_broker(monitor, cred=cred)

    def revoke_hook(engine, proposal, record):
        engine.store.revoke("cap-1")

    engine = ExecutionEngine(monitor, broker, Budget(3), pre_execute_hook=revoke_hook)
    record = engine.run(ctx(), ScriptedModel([ep(tool="cred-read")]))

    assert cred.delivered == []
    assert record.history[0].outcome is StepOutcome.REVOKED_RACE


def test_expired_action_is_denied():
    import time
    store = build_store()
    monitor = ReferenceMonitor(store)
    cred = CredRecorder()
    broker = TrustedExecutionBroker(monitor, action_ttl_seconds=10.0)
    broker.issue_credential(Credential(
        "cred-1", "cap-1", "read", "acme/records", Secret(SECRET)))
    broker.register_tool(ToolRegistration(
        registration_id="cred-read", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=cred, version="1", credential_id="cred-1"))
    broker.grant_tool("cred-read", "acme/records")

    t0 = time.monotonic()
    action_id = broker.register_authorized_execution(ctx(), ep(tool="cred-read"), now=t0)

    result = broker.redeem_and_execute(action_id, now=t0 + 11.0)

    assert result.ok is False
    assert cred.delivered == []


# --------------------------------------------------------------------------- #
# Containment through the integrated chain.
# --------------------------------------------------------------------------- #

class HostileAdapter:
    """A credentialed adapter whose transport raises WITH the auth header."""
    def execute_with_credential(self, action, secret):
        raise RuntimeError(f"Bearer {secret.reveal()}")


def test_adapter_exception_is_sanitized_end_to_end():
    """A hostile adapter cannot leak the secret past the boundary, and the engine
    sees a generic tool failure, not an exception carrying a credential."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = build_broker(monitor, cred=HostileAdapter())
    engine = ExecutionEngine(monitor, broker, Budget(3))

    record = engine.run(ctx(), ScriptedModel([ep(tool="cred-read")]))

    step = record.history[0]
    assert step.outcome is StepOutcome.TOOL_ERROR
    assert SECRET not in (step.audit_reason or "")
    assert SECRET not in (step.tool_result or "")
    assert SECRET not in str(record.history)
    for a in broker.audit:
        assert SECRET not in a.reason
