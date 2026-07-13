"""Adversarial reproductions from the sixth review round.

Red baseline: each asserts the CORRECT behaviour and fails against the code as
merged; the fixes turn them green. Committed before the fixes.

Reachability (stated plainly, since it drives priority):

  REACHABLE FROM ORDINARY UNTRUSTED PROVIDER DATA (the real adversary):
    F2  malformed unicode (lone surrogate) crashes fail-closed validation
    F1  an oversized/invalid proposal is retained in trusted history
    F6  raw provider responses are unbounded before parsing

  REQUIRE IN-PROCESS TCB BEHAVIOUR OR MALFORMED TRUSTED CONFIG:
    F3  catalog snapshot race (needs a replacement DURING a split read)
    F4  mint refusals classified by exception string (audit-integrity)
    F5  non-finite TTLs accepted (malformed trusted configuration)

Fix order: F2, F1, F6 first (they violate published M1/M2 guarantees and are
remotely reachable), then F3, F4, F5.
"""

import math

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
    valid_proposal,
)
from capcore.broker import (
    BrokerRefusal, Credential, ExecutionProposal, Secret, ToolKind,
    ToolRegistration, TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, ModelResult, RunState, ScriptedModel, StepOutcome,
    StopReason,
)

SURROGATE = "\ud800"   # a lone surrogate: a valid str, but not utf-8 encodable


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
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    return b


# --------------------------------------------------------------------------- #
# F2 (do first). Malformed unicode must FAIL CLOSED (deny), never raise.
#
# M1's contract is two outcomes: valid or invalid. A lone surrogate is a valid
# `str` (JSON decoders accept "\ud800") but cannot be utf-8 encoded, so the
# byte-length checks raise UnicodeEncodeError instead of denying. Every untrusted
# text boundary that calls .encode("utf-8") must be fail-closed.
# --------------------------------------------------------------------------- #

def test_lone_surrogate_resource_fails_closed():
    # Must return False, not raise.
    assert valid_proposal(Proposal("acme/api/" + SURROGATE, "read")) is False


def test_lone_surrogate_verb_fails_closed():
    assert valid_proposal(Proposal("acme/api/x", SURROGATE)) is False


def test_lone_surrogate_tool_id_fails_closed():
    # ExecutionProposal must reject (deterministically), not crash.
    with pytest.raises(Exception) as exc:
        ExecutionProposal(action=Proposal("acme/api/x", "read"),
                          tool_registration_id=SURROGATE)
    # It must be an AuthorizationError (a clean deny), NOT a UnicodeEncodeError.
    assert not isinstance(exc.value, UnicodeError)


def test_surrogate_in_monitor_authorize_does_not_raise():
    """The reference monitor must deny a surrogate proposal, not raise."""
    store, mon, ctx = build()
    decision = mon.authorize(ctx, Proposal("acme/api/" + SURROGATE, "read"))
    from capcore import Verdict
    assert decision.verdict is Verdict.DENY


def test_surrogate_in_tool_result_fails_closed():
    """A tool returning a surrogate string must be rejected, not crash the
    boundary."""
    from capcore.broker import _normalize_tool_result
    ok, body = _normalize_tool_result("result" + SURROGATE)
    assert ok is False
    assert body is None


def test_surrogate_in_action_digest_does_not_crash_redemption():
    """The action digest hashes verb+resource with .encode('utf-8'). A surrogate
    that reached mint must not crash redemption. (Belt: it should be denied long
    before, but the digest path must be fail-closed on its own.)"""
    from capcore.broker import action_digest
    # action_digest must not raise on a surrogate; it returns a value or the
    # caller path denies. Here we assert it does not raise UnicodeEncodeError.
    try:
        action_digest(Proposal("acme/api/" + SURROGATE, "read"))
    except UnicodeError:
        pytest.fail("action_digest raised UnicodeError on a surrogate resource")
    except Exception:
        pass  # any other deterministic failure is acceptable; a crash-by-encode is not


# --------------------------------------------------------------------------- #
# F1. An invalid (e.g. oversized) proposal must NOT enter trusted history.
#
# The size check denies authorization, but step() still stores the original
# oversized action in StepResult.history, which flows into ModelView. It must
# fail closed at the runtime boundary BEFORE StepResult is built, as
# MODEL_ERROR (a malformed model output), not DENIED (which implies a valid
# action was policy-denied), and must retain no raw field.
# --------------------------------------------------------------------------- #

def test_oversized_invalid_proposal_is_not_retained_in_history():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon), Budget(3))
    huge = "acme/api/" + "x" * 1_000_000   # oversized -> invalid proposal

    class M:
        def __init__(self):
            self.i = 0

        def next_proposal(self, view):
            self.i += 1
            if self.i == 1:
                return ModelResult.propose(ep(resource=huge))
            return ModelResult.finished()

    record = engine.run(ctx, M())

    # No history entry may retain the megabyte string.
    for step in record.history:
        assert len(step.proposal.resource) < 10_000, (
            f"an invalid oversized proposal ({len(step.proposal.resource)} chars) "
            f"was retained in trusted history"
        )


def test_oversized_invalid_proposal_fails_closed_as_model_error():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon), Budget(3))
    huge = "acme/api/" + "x" * 1_000_000

    record = engine.run(ctx, ScriptedModel([ep(resource=huge)]))

    # A malformed proposal is a model error, not a policy denial.
    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.MODEL_ERROR


# --------------------------------------------------------------------------- #
# F6. Raw provider responses must be bounded before parsing.
# --------------------------------------------------------------------------- #

def test_raw_model_response_size_is_bounded():
    from capcore.adapters import parse_proposal
    big = "x" * 5_000_000 + '{"verb":"read","resource":"acme/api/x","tool":"t"}'
    # An oversized raw response must be rejected before parsing yields a proposal.
    assert parse_proposal(big) is None


def test_generated_text_field_has_its_own_limit():
    """Even within a bounded HTTP body, the generated-text field is bounded."""
    from capcore import MAX_GENERATED_MODEL_TEXT_BYTES
    assert isinstance(MAX_GENERATED_MODEL_TEXT_BYTES, int)
    assert MAX_GENERATED_MODEL_TEXT_BYTES > 0


def test_http_transport_bounds_body_by_bytes_read():
    """The live transport bounds by bytes ACTUALLY READ, not Content-Length.

    Covered with a fake streaming response (no live Ollama needed): a response
    that lies about Content-Length but streams more bytes must be rejected on the
    bytes actually read.
    """
    from capcore.httptool import bounded_read, ProviderResponseTooLarge

    class FakeStream:
        """Streams `chunks` regardless of the (lying) content_length header."""
        def __init__(self, chunks):
            self._chunks = chunks

        def iter_content(self, chunk_size):
            yield from self._chunks

    limit = 1024
    # streams 4 KiB despite whatever a header might claim
    big = FakeStream([b"x" * 512] * 8)
    with pytest.raises(ProviderResponseTooLarge):
        bounded_read(big, limit)

    small = FakeStream([b"x" * 100, b"y" * 100])
    assert bounded_read(small, limit) == b"x" * 100 + b"y" * 100


# --------------------------------------------------------------------------- #
# F3. Tool binding must read the catalog atomically (snapshot), and the catalog
# must be explicitly sealable.
# --------------------------------------------------------------------------- #

def test_catalog_exposes_atomic_snapshot():
    """resolve()+generation() as two calls is a split read. A single snapshot()
    returns registration and generation from one locked state."""
    from capcore.broker import ToolCatalog
    cat = ToolCatalog()
    cat.register(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    snap = cat.snapshot("t")
    assert snap is not None
    assert snap.registration.registration_id == "t"
    assert isinstance(snap.generation, int)


def test_catalog_can_be_sealed_and_rejects_mutation():
    from capcore.broker import ToolCatalog, CatalogError
    cat = ToolCatalog()
    cat.register(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    cat.seal()
    with pytest.raises(CatalogError):
        cat.register(ToolRegistration("u", "read", ToolKind.PLAIN, lambda a: "ok", "1"))


def test_execution_requires_a_sealed_catalog():
    """A broker whose catalog is not sealed must refuse to mint: configuration
    state is made visible, not silently defaulted."""
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    # deliberately NOT sealed
    from capcore.broker import AuthorizationError
    with pytest.raises(AuthorizationError):
        b.register_authorized_execution(ctx, ep())


# --------------------------------------------------------------------------- #
# F4. Mint refusals must be typed, not classified by exception string.
# --------------------------------------------------------------------------- #

def test_action_id_exhaustion_is_not_revoked_race():
    import capcore.broker as bk
    store, mon, ctx = build("acme/data")
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/data")
    if hasattr(b, "seal_catalog"):
        b.seal_catalog()

    orig = bk.secrets.token_urlsafe
    bk.secrets.token_urlsafe = lambda n: "COLLIDE"   # force id exhaustion
    try:
        # The first mint succeeds and occupies "COLLIDE"; the second collides on
        # every retry and must exhaust the id space.
        b.register_authorized_execution(ctx, ep("acme/data/x"))
        with pytest.raises(Exception) as exc:
            b.register_authorized_execution(ctx, ep("acme/data/y"))
    finally:
        bk.secrets.token_urlsafe = orig

    # The failure must carry a typed code that is NOT a revoke race.
    from capcore.broker import MintRefused, MintRefusal
    assert isinstance(exc.value, MintRefused)
    assert exc.value.code is MintRefusal.ACTION_ID_EXHAUSTED


def test_engine_does_not_string_parse_mint_refusals():
    """The engine's step() must not classify mint failures by substring."""
    import inspect
    from capcore.runtime import ExecutionEngine
    src = inspect.getsource(ExecutionEngine.step)
    assert "in reason" not in src, (
        "engine still classifies mint refusals by parsing exception text"
    )


def test_unknown_tool_maps_to_tool_not_found_not_revoke_race():
    """An unknown tool at mint is TOOL_NOT_FOUND, never REVOKED_RACE. This
    exercises the engine's typed mint-refusal mapping end to end."""
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    engine = ExecutionEngine(b, Budget(3))

    # The model names a tool that does not exist.
    record = engine.run(ctx, ScriptedModel([ep(tool="does-not-exist")]))

    outcome = record.history[0].outcome
    assert outcome is StepOutcome.TOOL_NOT_FOUND, (
        f"unknown tool mapped to {outcome.value}; must be TOOL_NOT_FOUND, not a "
        f"revoke race"
    )


# --------------------------------------------------------------------------- #
# F5. Security TTLs must reject non-finite and non-exact-numeric values.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"),
                                 True, False, 0, -1])
def test_credential_ttl_rejects_bad_values(bad):
    with pytest.raises((ValueError, Exception)):
        Credential("c1", "read", "acme/api", Secret("X"), ttl_seconds=bad)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, 0, -5])
def test_action_ttl_rejects_bad_values(bad):
    store, mon, ctx = build()
    with pytest.raises((ValueError, Exception)):
        TrustedExecutionBroker(mon, action_ttl_seconds=bad)


def test_finite_positive_ttl_is_accepted():
    """Control: a normal finite TTL still works."""
    c = Credential("c1", "read", "acme/api", Secret("X"), ttl_seconds=30.0)
    assert c.ttl_seconds == 30.0
    assert Credential("c2", "read", "acme/api", Secret("X")).ttl_seconds is None
