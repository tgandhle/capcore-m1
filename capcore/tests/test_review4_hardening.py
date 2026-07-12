"""Adversarial reproductions from the fourth review round.

Red baseline: each test asserts the CORRECT behaviour and fails against the code
as merged; the fixes turn them green. Committed before the fixes.

The round-4 CRITICAL finding (a hostile in-process ModelClient reaching trusted
state via stack inspection) is NOT here: it is not a code defect, it is a
trust-model documentation defect, already corrected on main in
"docs: correct the single-process trust boundary". No unit test can make hostile
same-interpreter Python safe; the resolution is the honest boundary (all
in-process code is TCB; only DATA crossing in is untrusted).

Seven code defects, in fix order:

  1. Engine and broker can hold different monitors (split authority, resurrected).
  2. An issued credential can be mutated by the caller (aliasing).
  3. A malformed ModelResult crashes run() instead of failing closed.
  4. A str subclass bypasses tool-result containment.
  5. Action budget and loop ceiling are one counter (conflated).
  6. Broker refusals are all mislabeled REVOKED_RACE.
  7. An action_id collision silently overwrites a pending authorization.
"""

import threading

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.broker import (
    Credential, ExecutionProposal, Secret, ToolKind, ToolRegistration,
    TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, ModelOutcome, ModelResult, RunRecord, RunState,
    ScriptedModel, StepOutcome, StopReason,
)


def build(tenant_scope="acme/api"):
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", tenant_scope, frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


def wired_broker(monitor, adapter=None, scope="acme/api", kind=ToolKind.PLAIN,
                 cred_id=None):
    b = TrustedExecutionBroker(monitor)
    if kind is ToolKind.CREDENTIALED:
        b.issue_credential(Credential(cred_id or "c1", "read", scope, Secret("SEK")))
        b.register_tool(ToolRegistration("t", "read", kind,
                                         adapter, "1", cred_id or "c1"))
    else:
        b.register_tool(ToolRegistration("t", "read", kind,
                                         adapter or (lambda a: "ok"), "1"))
    b.grant_tool("t", scope)
    return b


# --------------------------------------------------------------------------- #
# 1. The engine must not authorize through a different monitor than the broker.
#
# The engine derives control-flow authorization from its own monitor and the
# broker re-authorizes through the broker's monitor. If those are different
# monitors over different stores, revoking through one does not affect the other,
# and the split-authority defect (thought eliminated) is back at the engine/broker
# seam.
# --------------------------------------------------------------------------- #

def test_engine_rejects_a_broker_with_a_different_monitor():
    store_a = CapabilityStore()
    store_a.issue(Capability("cap-1", "acme", "acme/api", frozenset({"read"}),
                             principal="p", run="r"))
    store_b = CapabilityStore()
    store_b.issue(Capability("cap-1", "acme", "acme/api", frozenset({"read"}),
                             principal="p", run="r"))
    monitor_a = ReferenceMonitor(store_a)
    broker_b = wired_broker(ReferenceMonitor(store_b))

    # Old call form with a monitor that differs from the broker's must be refused
    # at construction, not silently accepted with a divergent authority.
    with pytest.raises(ValueError):
        ExecutionEngine(monitor_a, broker_b, Budget(2))


def test_engine_derives_authority_from_broker_monitor():
    """New call form: ExecutionEngine(broker, budget). The engine's monitor and
    store are exactly the broker's."""
    store, mon, ctx = build()
    broker = wired_broker(mon)
    engine = ExecutionEngine(broker, Budget(2))

    assert engine.monitor is broker.monitor
    assert engine.store is broker.monitor.store


# --------------------------------------------------------------------------- #
# 2. A credential must not be mutable by the caller after issuance.
#
# The vault stores the caller's object, so the caller can widen scope, reset
# single-use, un-expire, or swap the secret AFTER issuing.
# --------------------------------------------------------------------------- #

def test_issued_credential_scope_cannot_be_widened_by_caller():
    store, mon, ctx = build("acme/data")
    delivered = []

    class Rec:
        def execute_with_credential(self, a, s):
            delivered.append(s.reveal())
            return "ok"

    b = TrustedExecutionBroker(mon)
    cred = Credential("c1", "read", "acme/data/public", Secret("SEK"))
    b.issue_credential(cred)
    cred.scope = "acme/data/secret"          # widen AFTER issue
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     Rec(), "1", "c1"))
    b.grant_tool("t", "acme/data")

    action_id = b.register_authorized_execution(ctx, ep("acme/data/secret/x"))
    result = b.redeem_and_execute(action_id)

    assert delivered == [], (
        "caller widened credential scope after issuance and the secret was "
        "delivered for the widened resource"
    )


def test_issued_credential_single_use_cannot_be_reset_by_caller():
    store, mon, ctx = build("acme/data")
    delivered = []

    class Rec:
        def execute_with_credential(self, a, s):
            delivered.append(s.reveal())
            return "ok"

    b = TrustedExecutionBroker(mon)
    cred = Credential("c1", "read", "acme/data", Secret("SEK"), single_use=True)
    b.issue_credential(cred)
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     Rec(), "1", "c1"))
    b.grant_tool("t", "acme/data")

    a1 = b.register_authorized_execution(ctx, ep("acme/data/x"))
    b.redeem_and_execute(a1)                  # consumes it

    cred._consumed = False                    # caller resets
    a2 = b.register_authorized_execution(ctx, ep("acme/data/y"))
    b.redeem_and_execute(a2)

    assert len(delivered) == 1, (
        "caller reset single-use state on the issued object and the credential "
        "was delivered twice"
    )


def test_issued_credential_secret_value_cannot_be_swapped_by_caller():
    """Even the Secret's value must not remain caller-mutable after issuance."""
    store, mon, ctx = build("acme/data")
    delivered = []

    class Rec:
        def execute_with_credential(self, a, s):
            delivered.append(s.reveal())
            return "ok"

    b = TrustedExecutionBroker(mon)
    secret = Secret("ORIGINAL")
    cred = Credential("c1", "read", "acme/data", secret)
    b.issue_credential(cred)
    # attempt to swap the wrapped value through the retained reference
    try:
        object.__setattr__(secret, "_value", "SWAPPED")
    except Exception:
        pass
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     Rec(), "1", "c1"))
    b.grant_tool("t", "acme/data")

    action_id = b.register_authorized_execution(ctx, ep("acme/data/x"))
    b.redeem_and_execute(action_id)

    assert delivered == ["ORIGINAL"], (
        f"caller swapped the secret value after issuance; delivered {delivered}"
    )


# --------------------------------------------------------------------------- #
# 3. A malformed ModelResult must fail closed, not crash run().
# --------------------------------------------------------------------------- #

def test_malformed_proposal_result_fails_closed():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired_broker(mon), Budget(3))

    class Malformed:
        def next_proposal(self, view):
            # PROPOSAL outcome but the payload is not an ExecutionProposal
            return ModelResult(ModelOutcome.PROPOSAL, "not-an-execution-proposal")

    # Must NOT raise out of run(); must terminate in a failed state.
    record = engine.run(ctx, Malformed())

    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.MODEL_ERROR


def test_boundary_catches_a_malformed_result_that_bypassed_the_constructor():
    """run() must validate the proposal type ITSELF, not rely on
    ModelResult.__post_init__.

    A hostile adapter can build a ModelResult without triggering validation
    (object.__new__ + object.__setattr__). The engine does not control adapter
    code, so the boundary check in run() is the real guarantee; __post_init__ is
    a convenience. Without the boundary check this run crashes with
    AttributeError instead of failing closed.
    """
    store, mon, ctx = build()
    engine = ExecutionEngine(wired_broker(mon), Budget(3))

    class Sneaky:
        def next_proposal(self, view):
            mr = object.__new__(ModelResult)
            object.__setattr__(mr, "outcome", ModelOutcome.PROPOSAL)
            object.__setattr__(mr, "proposal", "not-a-proposal")
            return mr

    record = engine.run(ctx, Sneaky())

    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.MODEL_ERROR


def test_proposal_result_must_carry_an_execution_proposal():
    """ModelResult itself should reject an invalid outcome/payload combination."""
    with pytest.raises((TypeError, ValueError)):
        ModelResult(ModelOutcome.PROPOSAL, "not-a-proposal")


# --------------------------------------------------------------------------- #
# 4. A str subclass must not bypass tool-result containment.
#
# isinstance(out, str) accepts a subclass that overrides encode() to fake its
# size and carries mutable state into trusted history.
# --------------------------------------------------------------------------- #

def test_str_subclass_tool_result_is_rejected():
    from capcore.broker import _normalize_tool_result

    class EvilStr(str):
        def encode(self, *a, **k):
            return b""                        # fake zero length, beat the cap
        meta = {"mutable": True}

    ok, body = _normalize_tool_result(EvilStr("x" * 70000))

    assert ok is False, "a str subclass bypassed result containment"
    assert body is None


def test_exact_str_tool_result_is_accepted():
    """Control: a genuine built-in str within the cap still passes."""
    from capcore.broker import _normalize_tool_result
    ok, body = _normalize_tool_result("a normal result")
    assert ok is True
    assert body == "a normal result"
    assert type(body) is str


# --------------------------------------------------------------------------- #
# 5. Action budget and loop ceiling must be separate controls.
#
# max_steps is BOTH the loop ceiling and the action budget, so
# count_denied_attempts=False cannot work: a denied attempt still consumes a loop
# iteration, and a single valid action can never be followed by a completion.
# --------------------------------------------------------------------------- #

def test_denied_attempt_does_not_consume_the_action_budget():
    store, mon, ctx = build()
    calls = []
    b = wired_broker(mon, adapter=lambda a: calls.append(1) or "ok")
    # one action allowed; denied attempts must not count
    engine = ExecutionEngine(mon, b, Budget(max_actions=1, max_iterations=5,
                                            count_denied_attempts=False))

    class Model:
        def __init__(self):
            self.i = 0

        def next_proposal(self, view):
            self.i += 1
            if self.i == 1:
                return ModelResult.propose(ep("acme/other/x", "write"))  # denied
            if self.i == 2:
                return ModelResult.propose(ep("acme/api/x", "read"))     # valid
            return ModelResult.finished()

    record = engine.run(ctx, Model())

    assert calls == ["acme/api/x"] or calls == [1], (
        "the denied attempt consumed the single-action budget, so the valid "
        "action never executed"
    )


def test_single_action_budget_allows_completion():
    """A budget of one action that executes should let the model then finish,
    not be force-aborted by the loop ceiling."""
    store, mon, ctx = build()
    b = wired_broker(mon)
    engine = ExecutionEngine(mon, b, Budget(max_actions=1, max_iterations=5))

    class Model:
        def __init__(self):
            self.i = 0

        def next_proposal(self, view):
            self.i += 1
            if self.i == 1:
                return ModelResult.propose(ep())
            return ModelResult.finished()

    record = engine.run(ctx, Model())

    assert record.state is RunState.COMPLETED
    assert record.stop_reason is StopReason.MODEL_FINISHED


# --------------------------------------------------------------------------- #
# 6. Broker refusals must not all be reported as REVOKED_RACE.
#
# The engine maps every "authorization_refused" to REVOKED_RACE, so an expired
# credential (a real, distinct condition the broker records correctly) is
# mislabeled in trusted history. Contradicts "terminal state is honest".
# --------------------------------------------------------------------------- #

def test_expired_credential_is_not_reported_as_revocation_race():
    from capcore.broker import FakeClock
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", "acme/api", frozenset({"read"}),
                           principal="p", run="r"))
    mon = ReferenceMonitor(store)
    clock = FakeClock(1000.0)
    b = TrustedExecutionBroker(mon, action_ttl_seconds=10_000.0, clock=clock)
    b.issue_credential(Credential("c1", "read", "acme/api", Secret("SEK"),
                                  ttl_seconds=10.0))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     lambda a: "ok", "1", "c1"))
    # a credentialed adapter needs the credential method; use a real object
    class Rec:
        def execute_with_credential(self, a, s):
            return "ok"
    b._catalog._replace_unsafe(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                                Rec(), "1", "c1"))
    b.grant_tool("t", "acme/api")

    engine = ExecutionEngine(mon, b, Budget(max_actions=3, max_iterations=3),
                             pre_execute_hook=lambda e, p, r: clock.advance(50.0))
    record = engine.run(RunContext("acme", "p", "r"),
                        ScriptedModel([ep()]))

    outcome = record.history[0].outcome
    assert outcome is not StepOutcome.REVOKED_RACE, (
        f"an expired credential was reported as {outcome.value}; REVOKED_RACE must "
        f"be reserved for a live capability re-authorization failure"
    )


# --------------------------------------------------------------------------- #
# 7. An action_id collision must fail closed, not overwrite.
# --------------------------------------------------------------------------- #

def test_action_id_collision_does_not_overwrite_a_pending_record():
    import capcore.broker as bk
    store, mon, ctx = build("acme/data")
    b = wired_broker(mon, scope="acme/data")

    orig = bk.secrets.token_urlsafe
    bk.secrets.token_urlsafe = lambda n: "COLLIDE"
    try:
        a1 = b.register_authorized_execution(ctx, ep("acme/data/x"))
        # a colliding id must not silently replace the first record. Either a
        # fresh id is minted (a1 != a2), or the second registration is refused.
        try:
            a2 = b.register_authorized_execution(ctx, ep("acme/data/y"))
        except Exception:
            return  # refused: acceptable fail-closed
        assert a1 != a2, "a colliding action_id silently overwrote the first record"
    finally:
        bk.secrets.token_urlsafe = orig
