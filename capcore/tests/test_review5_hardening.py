"""Adversarial reproductions from the fifth review round.

Red baseline: each test asserts the CORRECT behaviour and fails against the code
as merged; the fixes turn them green. Committed before the fixes.

Five findings, framed on two axes (engineering severity / demonstrated
exploitability under the documented single-process trust model):

  F5 size limits    High / High   the ONLY one reachable from untrusted remote
                                  model output (plain oversized JSON strings).
                                  Fixed FIRST.
  F1 exact types    High / Low    authorization and execution can see different
                                  semantic values via a str subclass; building
                                  the subclass needs in-process (TCB) code.
  F2 outcome algebra High / Low   an outcome outside the explicit algebra falls
                                  through and executes; bypassing the ctor needs
                                  TCB code.
  F3 budget count   Medium        a broker-denied action (no executor) still
                                  consumes the execution budget.
  F4 refusal reason Medium        an expired pending authorization is still
                                  reported REVOKED_RACE.

The str-subclass and unknown-outcome cases are boundary-consistency and
fail-closed-completeness defects: the runtime documents proposal DATA as
untrusted and already enforces exact built-ins at the tool-result boundary, so
the same invariant must hold at the action boundary. They are not claims that a
remote model can construct a Python subclass.
"""

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
    valid_proposal,
)
from capcore.broker import (
    BrokerRefusal, ExecutionProposal, ToolKind, ToolRegistration,
    TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, ModelOutcome, ModelResult, RunState, ScriptedModel,
    StepOutcome, StopReason,
)


def build(scope="acme/api"):
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", scope, frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


def wired(monitor):
    b = TrustedExecutionBroker(monitor)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    return b


# --------------------------------------------------------------------------- #
# F5 (do first). Untrusted proposal / model-response fields must be bounded.
#
# The ONLY finding reachable from the real adversary: a remote provider can
# return an oversized ordinary JSON string with no Python subclassing. It
# amplifies across validation, hashing, audit, trusted history, and every
# subsequent ModelView and prompt.
# --------------------------------------------------------------------------- #

def test_proposal_resource_length_is_bounded():
    # Many small segments: no single segment is oversized, but the TOTAL exceeds
    # the resource limit. This isolates the resource-total bound from the
    # per-segment bound.
    huge = "acme/" + "/".join("x" * 8 for _ in range(1000))   # ~9 KB, segs of 8
    assert valid_proposal(Proposal(huge, "read")) is False, (
        "a resource exceeding the total size limit validated as well-formed; "
        "untrusted remote output is not size-bounded"
    )


def test_proposal_single_giant_segment_is_bounded():
    """A single oversized segment is also rejected (per-segment bound)."""
    huge = "acme/api/" + "x" * 1_000_000
    assert valid_proposal(Proposal(huge, "read")) is False


def test_proposal_resource_segment_length_is_bounded():
    # One segment over the 255-byte segment limit, but the TOTAL resource stays
    # under the 4 KiB total limit, so this isolates the per-segment bound from the
    # resource-total bound. (256-byte segment + short prefix = ~265 bytes total.)
    seg = "acme/api/" + "x" * 256
    assert valid_proposal(Proposal(seg, "read")) is False


def test_proposal_verb_length_is_bounded():
    assert valid_proposal(Proposal("acme/api/x", "r" * 1000)) is False


def test_tool_registration_id_length_is_bounded():
    with pytest.raises(Exception):
        ExecutionProposal(action=Proposal("acme/api/x", "read"),
                          tool_registration_id="t" * 100_000)


# --------------------------------------------------------------------------- #
# F1. Exact canonical types at the untrusted action boundary.
#
# A str subclass can override split()/__str__()/encode(), so authorization
# validates one semantic value while the adapter receives another. Same class of
# defect already fixed at the tool-result boundary; enforce it here too.
# --------------------------------------------------------------------------- #

def test_resource_str_subclass_is_rejected():
    class EvilRes(str):
        def split(self, *a, **k):
            return ["acme", "api", "public", "x"]   # lie to the validator

    evil = EvilRes("acme/api/public/../secret")
    assert valid_proposal(Proposal(evil, "read")) is False, (
        "a str subclass that overrides split() passed proposal validation; "
        "authorization and execution could see different resources"
    )


def test_validate_resource_directly_rejects_str_subclass():
    """validate_resource is called directly by scope_covers, not only via
    valid_proposal, so its OWN exact-type check must reject a subclass. Without
    this, a subclass reaching scope comparison could split() differently than it
    validated.
    """
    from capcore import validate_resource, ResourceError

    class EvilRes(str):
        def split(self, *a, **k):
            return ["acme", "api", "x"]

    with pytest.raises(ResourceError):
        validate_resource(EvilRes("acme/api/../secret"))


def test_verb_str_subclass_is_rejected():
    class EvilVerb(str):
        def __str__(self):
            return "delete"

    assert valid_proposal(Proposal("acme/api/x", EvilVerb("read"))) is False


def test_execution_proposal_requires_exact_types():
    """A str subclass as the tool id, or a Proposal subclass as the action, is
    rejected: the security check depends on exact built-in behaviour."""
    class EvilId(str):
        def __str__(self):
            return "other-tool"

    with pytest.raises(Exception):
        ExecutionProposal(action=Proposal("acme/api/x", "read"),
                          tool_registration_id=EvilId("t"))


# --------------------------------------------------------------------------- #
# F2. An outcome outside the explicit algebra must fail closed, not execute.
# --------------------------------------------------------------------------- #

def test_unknown_model_outcome_fails_closed():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon), Budget(3))
    calls = []
    # rebuild broker with a call-recording tool so we can see if it ran
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: calls.append(1) or "ok", "1"))
    b.grant_tool("t", "acme/api")
    engine = ExecutionEngine(b, Budget(3))

    class Bogus:
        def next_proposal(self, view):
            # An outcome value outside the algebra, payload otherwise valid.
            mr = object.__new__(ModelResult)
            object.__setattr__(mr, "outcome", "bogus-not-an-enum")
            object.__setattr__(mr, "proposal", ep())
            return mr

    record = engine.run(ctx, Bogus())

    assert calls == [], "an unknown model outcome executed a tool"
    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.MODEL_ERROR


# --------------------------------------------------------------------------- #
# F3. A broker-denied action (no executor) must not consume the execution budget.
# --------------------------------------------------------------------------- #

def test_broker_denial_does_not_consume_execution_budget():
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    calls = []
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: calls.append(1) or "ok", "1"))
    b.grant_tool("t", "acme/api")
    engine = ExecutionEngine(b, Budget(max_actions=1, max_iterations=5,
                                       count_denied_attempts=False))

    class Model:
        def __init__(self):
            self.i = 0

        def next_proposal(self, view):
            self.i += 1
            if self.i == 1:
                # valid M1 action, but a nonexistent executor: broker refuses,
                # nothing runs. This must NOT spend the single-action budget.
                return ModelResult.propose(ep(tool="nonexistent-tool"))
            if self.i == 2:
                return ModelResult.propose(ep(tool="t"))   # valid: should run
            return ModelResult.finished()

    record = engine.run(ctx, Model())

    assert calls == ["acme/api/x"] or len(calls) == 1, (
        "the broker-denied action consumed the single-action budget, so the "
        "valid action never executed"
    )


# --------------------------------------------------------------------------- #
# F4. An expired pending authorization must not be reported as a revoke race.
# --------------------------------------------------------------------------- #

def test_pending_authorization_expiry_is_not_revoked_race():
    from capcore.broker import FakeClock
    store, mon, ctx = build()
    clock = FakeClock(1000.0)
    b = TrustedExecutionBroker(mon, action_ttl_seconds=10.0, clock=clock)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")

    action_id = b.register_authorized_execution(ctx, ep())
    clock.advance(50.0)    # the PENDING authorization expires before redemption

    result = b.redeem_and_execute(action_id)

    assert result.ok is False
    # The broker must report a SPECIFIC reason for an expired pending auth, not
    # the generic CLAIM_REFUSED that the engine maps to REVOKED_RACE. REVOKED_RACE
    # is reserved for a live capability re-authorization failure.
    assert result.audit_code != BrokerRefusal.CLAIM_REFUSED, (
        "an expired pending authorization reported the generic claim-refused "
        "code, which the engine maps to REVOKED_RACE"
    )
    assert result.audit_code != BrokerRefusal.REAUTHORIZATION_FAILED, (
        "an expired pending authorization must not be a re-authorization failure"
    )


def test_expired_pending_auth_maps_to_a_non_revoke_race_outcome():
    """The engine's mapping of an expired pending authorization must not be
    REVOKED_RACE.

    Tested at the mapping level: exercising the expiry end-to-end through the
    engine is not reliably possible (time cannot be injected between the engine's
    internal mint and redeem). This calls the mapping function directly with each
    non-reauth refusal code and asserts none maps to REVOKED_RACE.
    """
    from capcore.runtime import _map_refusal, StepOutcome
    from capcore.broker import BrokerRefusal

    # Only a genuine re-authorization failure is a revoke race.
    assert _map_refusal(BrokerRefusal.REAUTHORIZATION_FAILED)[0] is StepOutcome.REVOKED_RACE

    # Every pending-authorization refusal must NOT be a revoke race.
    for code in (BrokerRefusal.ACTION_EXPIRED,
                 BrokerRefusal.UNKNOWN_ACTION_ID,
                 BrokerRefusal.ACTION_ALREADY_REDEEMED,
                 BrokerRefusal.CLAIM_REFUSED):
        outcome, _ = _map_refusal(code)
        assert outcome is not StepOutcome.REVOKED_RACE, (
            f"{code} mapped to REVOKED_RACE; it is not a revoke race"
        )
        assert outcome is StepOutcome.AUTHORIZATION_REFUSED

    # An unknown code fails closed to the neutral refusal, never REVOKED_RACE.
    assert _map_refusal("some-future-code")[0] is StepOutcome.AUTHORIZATION_REFUSED
