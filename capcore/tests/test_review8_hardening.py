"""Adversarial reproductions from the eighth review round.

Five findings. Only F1 is reachable from an untrusted REMOTE service (a hostile
allowed endpoint); the rest need model-triggerable input (F3) or in-process TCB
behaviour / malformed trusted config (F2, F4, F5).

  F1  the live credentialed HTTP transport buffers an unbounded response body
      (resp.text, no stream, no close) even though the body is discarded. HIGH,
      remote-reachable, availability. FIX FIRST.
  F2  parse_model_output promises typed outcomes but still RAISES on some
      malformed provider input (oversized/surrogate tool id, non-str input).
  F3  step() checks the action budget BEFORE M1 authorization, so an out-of-scope
      proposal reports BUDGET_EXHAUSTED instead of DENIED once the budget is spent.
  F4  seal_catalog() freezes the catalog but NOT the tool policy; a grant added
      after sealing still mints. "Sealed" must mean sealed.
  F5  the broker rewrites an injected vault's clock, so credentials pre-issued
      under the vault's original clock keep stale issued_at and outlive their TTL.
"""

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.broker import (
    CatalogError, Credential, ExecutionProposal, Secret, ToolKind,
    ToolRegistration, TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, RunRecord, RunState, ScriptedModel, StepOutcome,
)


def build(scope="acme/api"):
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", scope, frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


def wired(mon):
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    return b


# --------------------------------------------------------------------------- #
# F1 (do first). The live credentialed HTTP transport must stream, must not
# access the body, and must close the response.
# --------------------------------------------------------------------------- #

def test_real_transport_streams_and_never_buffers_body():
    import inspect
    from capcore.httptool import real_requests_transport
    src = inspect.getsource(real_requests_transport)
    # strip the docstring so mentions of .text/.content in prose don't false-match
    import ast
    tree = ast.parse(src)
    fn = tree.body[0]
    if (fn.body and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)):
        fn.body = fn.body[1:]   # drop docstring node
    code = ast.unparse(fn)

    assert "stream=True" in code, "real_requests_transport does not stream"
    assert ".text" not in code, "real_requests_transport accesses resp.text (buffers body)"
    assert ".content" not in code, "real_requests_transport accesses resp.content"
    assert "with requests" in code, "response is not closed via a context manager"
    assert "allow_redirects=False" in code, "redirects must stay disabled"


def test_real_transport_returns_only_status():
    """The tool ignores the body, so the transport must not return one."""
    import inspect
    from capcore.httptool import real_requests_transport
    src = inspect.getsource(real_requests_transport)
    # the return dict must not carry a body field
    assert '"body"' not in src and "'body'" not in src, (
        "transport still returns a body field the tool discards"
    )


# --------------------------------------------------------------------------- #
# F2. parse_model_output must be TOTAL: never raise, always a typed outcome.
# --------------------------------------------------------------------------- #

def test_parse_model_output_never_raises_on_oversized_tool_id():
    from capcore.adapters import parse_model_output, ParsedOutputKind
    huge = '{"verb":"read","resource":"acme/api/x","tool":"' + "t" * 100_000 + '"}'
    parsed = parse_model_output(huge)   # must NOT raise
    assert parsed.kind is ParsedOutputKind.INVALID


def test_parse_model_output_never_raises_on_non_string():
    from capcore.adapters import parse_model_output, ParsedOutputKind
    parsed = parse_model_output(12345)   # must NOT raise (non-str input)
    assert parsed.kind is ParsedOutputKind.INVALID


def test_parse_model_output_never_raises_on_none():
    from capcore.adapters import parse_model_output, ParsedOutputKind
    parsed = parse_model_output(None)
    assert parsed.kind is ParsedOutputKind.INVALID


# --------------------------------------------------------------------------- #
# F3. M1 classification must survive budget exhaustion: an out-of-scope proposal
# is DENIED, not BUDGET_EXHAUSTED, even when the action budget is spent.
# --------------------------------------------------------------------------- #

def test_denied_proposal_reported_as_denied_not_budget_exhausted():
    store, mon, ctx = build()
    engine = ExecutionEngine(wired(mon),
                             Budget(max_actions=1, max_iterations=3,
                                    count_denied_attempts=False))
    record = RunRecord(ctx=ctx, state=RunState.RUNNING)
    record.steps_taken = 1   # budget already spent

    # an action OUTSIDE capability scope (globex, not acme) must be DENIED
    result = engine.step(record, ep(resource="globex/secret"))

    assert result.outcome is StepOutcome.DENIED, (
        f"an out-of-scope proposal reported {result.outcome.value} instead of "
        f"DENIED once the budget was spent"
    )


# --------------------------------------------------------------------------- #
# F4. Sealing must freeze the tool policy too, not only the catalog.
# --------------------------------------------------------------------------- #

def test_grant_after_seal_is_rejected():
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    # seal via whichever API exists (seal_configuration preferred, seal_catalog alias)
    (getattr(b, "seal_configuration", None) or b.seal_catalog)()
    with pytest.raises(CatalogError):
        b.grant_tool("t", "acme/api")


def test_credential_issue_after_seal_is_rejected():
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    (getattr(b, "seal_configuration", None) or b.seal_catalog)()
    with pytest.raises(CatalogError):
        b.issue_credential(Credential("cred-late", "read", "acme/api", Secret("X")))


# --------------------------------------------------------------------------- #
# F5. The broker must not rewrite an injected vault's clock; a credential
# pre-issued under a different clock must not outlive its TTL.
# --------------------------------------------------------------------------- #

def test_injected_vault_must_share_the_broker_clock():
    from capcore.broker import CredentialVault, FakeClock
    vault_clock = FakeClock(1000.0)
    vault = CredentialVault(vault_clock)
    store, mon, ctx = build()
    broker_clock = FakeClock(0.0)
    # Injecting a vault whose clock differs from the broker's must be refused,
    # not silently rewritten.
    with pytest.raises((ValueError, Exception)):
        TrustedExecutionBroker(mon, vault=vault, clock=broker_clock)


def test_vault_sharing_broker_clock_is_accepted():
    """Control: a vault constructed with the broker's own clock is fine."""
    from capcore.broker import CredentialVault, FakeClock
    store, mon, ctx = build()
    clock = FakeClock(0.0)
    vault = CredentialVault(clock)
    # same clock object -> accepted
    b = TrustedExecutionBroker(mon, vault=vault, clock=clock)
    assert b is not None
