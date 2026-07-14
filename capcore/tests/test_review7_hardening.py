"""Adversarial reproductions from the seventh review round.

Review 7 was a focused follow-up: every finding is an INCOMPLETENESS in a Round 6
fix. Each defect was fixed at one entry point (run(), parse_proposal()) and left a
second path to the same trusted operation.

  F1  run() validates the action, but step() (the public, history-writing
      boundary) does not. A direct step() call retains a raw oversized action.
  F2  parse_proposal() enforces the size/utf-8 gate, but _signals_done() is a
      SECOND parser that re-parses raw text with neither gate.
  F3A _call() decodes with errors="replace", silently repairing malformed bytes
      (contradicting the Round 6 "malformed unicode fails closed" decision).
  F3B the live provider response is never closed.

Red baseline: each asserts the CORRECT behaviour and fails against the code as
merged; the fixes turn them green.
"""

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.broker import (
    ExecutionProposal, ToolKind, ToolRegistration, TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, RunRecord, RunState, StepOutcome, StopReason,
)

SURROGATE = "\ud800"


def build():
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", "acme/api", frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def wired(mon):
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    return b


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


# --------------------------------------------------------------------------- #
# F1. step() is the history-writing boundary and must validate the action
# itself, before the budget check, not rely on run() having done so.
# --------------------------------------------------------------------------- #

def test_step_rejects_oversized_action_before_history():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon), Budget(3))
    record = RunRecord(ctx=ctx, state=RunState.RUNNING)
    huge = "acme/api/" + "x" * 1_000_000

    result = engine.step(record, ep(resource=huge))

    # No raw oversized action may be stored in trusted history.
    for step in record.history:
        assert len(step.proposal.resource) < 10_000, (
            f"step() retained a raw oversized action ({len(step.proposal.resource)} "
            f"chars) in trusted history"
        )
    assert result.outcome is StepOutcome.MALFORMED_PROPOSAL


def test_step_redacts_malformed_action_when_budget_is_exhausted():
    """step() checks budget before authorization, so a malformed action must be
    validated BEFORE the budget check, or it lands in a BUDGET_EXHAUSTED result."""
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon), Budget(1))
    record = RunRecord(ctx=ctx, state=RunState.RUNNING)
    record.steps_taken = 1   # budget already spent
    huge = "acme/api/" + "x" * 1_000_000

    result = engine.step(record, ep(resource=huge))

    for step in record.history:
        assert len(step.proposal.resource) < 10_000, (
            "a malformed action was stored via the budget-exhausted path"
        )


def test_step_rejects_non_execution_proposal():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon), Budget(3))
    record = RunRecord(ctx=ctx, state=RunState.RUNNING)

    result = engine.step(record, "not-an-execution-proposal")

    assert result.outcome is StepOutcome.MALFORMED_PROPOSAL


# --------------------------------------------------------------------------- #
# F2. Model output has ONE parse path. The completion signal must pass the same
# size and utf-8 gate as a proposal.
# --------------------------------------------------------------------------- #

def test_oversized_done_response_is_not_finished():
    from capcore.adapters import OllamaModel
    from capcore.runtime import ModelOutcome

    class Model(OllamaModel):
        def _call(self, prompt):
            return "x" * 300_000 + '{"done": true}'   # over the 256 KiB limit

    class _V:
        run_id = "r"; remaining_steps = 5; history = ()

    result = Model().next_proposal(_V())
    assert result.outcome is not ModelOutcome.FINISHED, (
        "an oversized completion was accepted as FINISHED, bypassing the "
        "generated-text limit"
    )


def test_surrogate_done_response_is_not_finished():
    from capcore.adapters import OllamaModel
    from capcore.runtime import ModelOutcome

    class Model(OllamaModel):
        def _call(self, prompt):
            return SURROGATE + '{"done": true}'   # malformed utf-8

    class _V:
        run_id = "r"; remaining_steps = 5; history = ()

    result = Model().next_proposal(_V())
    assert result.outcome is not ModelOutcome.FINISHED, (
        "a malformed-unicode completion was accepted as FINISHED, bypassing the "
        "utf-8 gate"
    )


def test_valid_done_response_is_finished():
    """Control: a clean, in-bounds completion is still FINISHED."""
    from capcore.adapters import OllamaModel
    from capcore.runtime import ModelOutcome

    class Model(OllamaModel):
        def _call(self, prompt):
            return '{"done": true}'

    class _V:
        run_id = "r"; remaining_steps = 5; history = ()

    assert Model().next_proposal(_V()).outcome is ModelOutcome.FINISHED


# --------------------------------------------------------------------------- #
# F3A. The live transport must decode strictly (no silent repair) and validate
# the response shape.
# --------------------------------------------------------------------------- #

def test_call_decodes_strictly_not_with_replace():
    """errors='replace' silently repairs malformed bytes, contradicting the
    fail-closed unicode decision. Check the actual decode CALL, not comments.

    The decode itself now lives in decode_provider_envelope, which Review 9
    extracted from _call so the envelope's untrusted-input gates (utf-8, JSON
    nesting cap, shape) are testable without a live provider. The INVARIANT is
    unchanged, so this test follows the code rather than pinning it in place:
    inspect both, and require the strict decode to exist in one of them and a
    repairing decode in NEITHER.
    """
    import inspect
    import re
    from capcore.adapters import OllamaModel, decode_provider_envelope
    src = (inspect.getsource(OllamaModel._call)
           + inspect.getsource(decode_provider_envelope))
    # find every .decode(...) call and assert none passes errors="replace"
    for call in re.findall(r"\.decode\([^)]*\)", src):
        assert "replace" not in call, (
            f"the provider path decodes with a repairing errors mode: {call}"
        )
    # and it must strict-decode somewhere
    assert '.decode("utf-8")' in src or ".decode('utf-8')" in src


def test_provider_response_field_must_be_exact_string():
    """The provider protocol errors if the response field is not an exact str."""
    from capcore.httptool import ProviderProtocolError
    assert issubclass(ProviderProtocolError, Exception)


def test_non_string_response_field_fails_closed():
    """A provider whose `response` field is not a string (e.g. a number or object)
    must raise ProviderProtocolError, not be coerced or silently accepted."""
    from capcore.httptool import ProviderProtocolError
    # response field is a JSON number, not a string
    body = b'{"response": 12345}'
    out, resp, err = _ollama_with_fake(None, [body])
    assert isinstance(err, ProviderProtocolError)
    assert resp.closed is True


# --------------------------------------------------------------------------- #
# F3B. The live provider response must be closed on every exit path.
# --------------------------------------------------------------------------- #

def test_call_uses_a_context_manager_for_the_response():
    import inspect
    from capcore.adapters import OllamaModel
    src = inspect.getsource(OllamaModel._call)
    assert "with requests" in src, (
        "the provider response is not used as a context manager and may leak the "
        "connection"
    )


# --------------------------------------------------------------------------- #
# F3, behavioural: strict decode fails closed, and the response is closed on
# every exit path. Tested with a fake requests.post (no live provider).
# --------------------------------------------------------------------------- #

class _FakeResponse:
    """A stand-in for a streaming requests response that records close/exit."""
    def __init__(self, chunks, status_ok=True):
        self._chunks = chunks
        self._status_ok = status_ok
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def raise_for_status(self):
        if not self._status_ok:
            raise RuntimeError("HTTP error")

    def iter_content(self, chunk_size):
        yield from self._chunks


def _ollama_with_fake(monkeypatch_post, chunks, status_ok=True):
    """Run OllamaModel._call against a fake requests.post; return (result, resp)."""
    import capcore.adapters as ad
    resp = _FakeResponse(chunks, status_ok=status_ok)

    class _FakeRequests:
        @staticmethod
        def post(*a, **k):
            return resp

    import sys
    real = sys.modules.get("requests")
    sys.modules["requests"] = _FakeRequests
    try:
        model = ad.OllamaModel()
        try:
            out = model._call("prompt")
            return out, resp, None
        except Exception as e:
            return None, resp, e
    finally:
        if real is not None:
            sys.modules["requests"] = real
        else:
            del sys.modules["requests"]


def test_invalid_utf8_provider_body_fails_closed():
    from capcore.httptool import ProviderProtocolError
    out, resp, err = _ollama_with_fake(None, [b"\xff\xfe not utf8"])
    assert isinstance(err, ProviderProtocolError)


def test_provider_response_is_closed_after_success():
    good = b'{"response": "{\\"done\\": true}"}'
    out, resp, err = _ollama_with_fake(None, [good])
    assert err is None
    assert resp.closed is True


def test_provider_response_is_closed_after_size_rejection():
    from capcore import MAX_PROVIDER_HTTP_BODY_BYTES
    big = [b"x" * (MAX_PROVIDER_HTTP_BODY_BYTES + 1000)]
    out, resp, err = _ollama_with_fake(None, big)
    assert err is not None                 # ProviderResponseTooLarge
    assert resp.closed is True


def test_provider_response_is_closed_after_http_error():
    out, resp, err = _ollama_with_fake(None, [b"{}"], status_ok=False)
    assert err is not None
    assert resp.closed is True
