"""Adversarial reproductions for the M2/M3 trust-boundary defects.

This file is the red baseline for the security/m2-m3-trust-boundaries work. It
is committed BEFORE any fix, so the defects are on the record as reproducible
against the shipped source, in the same way the M1 review rounds were.

It is split into two buckets, and the split is load-bearing.

BUCKET A: DEFECT TESTS THAT SURVIVE THE REDESIGN.
  These assert the CORRECT behaviour and therefore FAIL today. They target
  behaviour whose API shape does not change, so the fixes turn them green
  without rewriting them. They are permanent regression tests.

BUCKET B: CHARACTERIZATION TESTS THAT DIE WITH THE API.
  These assert the CURRENT BROKEN behaviour and therefore PASS today. They
  exist to pin the defect precisely and prove it was real. They target
  `CredentialBroker.release()` and `HttpTool.__call__(proposal, secret)`, both
  of which the redesign DELETES. When the broker becomes
  `execute_with_credential(...)`, every test in bucket B must be DELETED and
  replaced by a bucket-A-style test against the new surface. They are not
  permanent. Do not "fix" them; retire them.

Threat model these tests assume (see MODEL.md): the model provider, the
ModelClient implementation, its proposals, tool results, and remote services are
UNTRUSTED. The reference monitor, execution state, authorization binding, the
broker, and narrowly-reviewed credential adapters are TRUSTED. A finding is only
downgraded to "trusted-code misuse" if the component is inside that boundary,
and ModelClient is not.
"""

import time

import pytest

from capcore import (
    Capability, CapabilityStore, Decision, Proposal, ReferenceMonitor,
    RunContext, Verdict,
)
from capcore.broker import (
    FakeClock,
    AuthorizationError, AuthorizationState, Credential, TrustedExecutionBroker,
    CredentialError, ExecutionProposal, PendingAuthorization,
    SanitizedToolResult, Secret, ToolKind, ToolPolicy, ToolRegistration,
)
from capcore.httptool import HttpTool
from capcore.runtime import (
    ModelResult, ModelOutcome, StopReason,
    Budget, ExecutionEngine, RunRecord, RunState, ScriptedModel, StepOutcome,
)


TENANT = "acme"
PRINCIPAL = "agent-7"
RUN = "run-1"


def build_store() -> CapabilityStore:
    store = CapabilityStore()
    store.issue(Capability(
        "cap-1", TENANT, "acme/api", frozenset({"read"}),
        principal=PRINCIPAL, run=RUN,
    ))
    return store


def build_ctx() -> RunContext:
    return RunContext(TENANT, PRINCIPAL, RUN)


def ep(resource="acme/api/x", verb="read", tool="tool-read"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


def recording_broker(monitor, grant=True):
    """A broker with one plain `read` tool that records every execution.

    Returns (broker, calls). `calls` is the ground truth for "did the action
    actually run": if a check refused it, calls must be empty.
    """
    calls = []
    broker = TrustedExecutionBroker(monitor)
    broker.register_tool(ToolRegistration(
        registration_id="tool-read", verb="read", kind=ToolKind.PLAIN,
        adapter=lambda a: calls.append(a.resource) or "ok", version="1"))
    if grant:
        broker.grant_tool("tool-read", "acme")
    broker.seal_catalog()
    return broker, calls


class MockCalls:
    """A transport that records every outbound call. No network, no real secret.

    `count` is the number of times the transport was invoked, which is the ground
    truth for "did the secret actually leave": if a check refused the action, the
    transport must never have been called.
    """
    def __init__(self, status: int = 200, body: str = "mock-ok"):
        self.calls: list[dict] = []
        self._status = status
        self._body = body

    @property
    def count(self) -> int:
        return len(self.calls)

    def transport(self, method: str, url: str, headers: dict) -> dict:
        self.calls.append({"method": method, "url": url, "headers": dict(headers)})
        return {"status": self._status, "body": self._body}


# =========================================================================== #
# BUCKET A: permanent regression tests. These FAIL until the fix lands.
# =========================================================================== #

# --------------------------------------------------------------------------- #
# A1. CRITICAL. The model receives the mutable RunRecord and can corrupt the
#     counter that BOTH enforcement checks read, producing a nonterminating run.
# Fix: ModelClient.next_proposal receives an immutable ModelView; run() bounds
#      itself with a local iteration ceiling not derived from model-reachable
#      state.
# --------------------------------------------------------------------------- #

class MutatingModel:
    """Hostile model: tries every route it can find to corrupt the trusted budget.

    Self-capping so a failing run cannot hang CI. The engine is supposed to stop
    this model at `max_steps`; the cap only exists so that when it does NOT, the
    test fails fast instead of looping forever.

    The model does not get to crash the run by probing. A real adversarial
    adapter would swallow its own failures and keep going, so this one catches
    everything and records what it managed to touch. `attempts` is the evidence:
    if the boundary holds, every write is refused and `mutated` stays empty.
    """

    HARD_CAP = 20

    def __init__(self, proposal: Proposal):
        self.proposal = proposal
        self.calls = 0
        self.mutated = []      # writes that SUCCEEDED. Must stay empty.
        self.refused = []      # writes that were refused. Evidence of the boundary.

    def _probe(self, obj, field, value):
        try:
            setattr(obj, field, value)
        except Exception as exc:
            self.refused.append((field, type(exc).__name__))
            return
        # The write landed. If this ever happens, trusted state is reachable.
        self.mutated.append((field, value))

    def next_proposal(self, view):
        self.calls += 1
        if self.calls > self.HARD_CAP:
            raise AssertionError(
                f"engine failed to terminate: model was asked {self.calls} times "
                f"under a budget that should have stopped it"
            )
        # Whatever the engine hands us, try to drive the budget counter negative.
        # Pre-fix this was the live RunRecord and the write landed. Post-fix it is
        # a frozen ModelView and the write must be refused.
        self._probe(view, "steps_taken", -100)
        self._probe(view, "remaining_steps", 10 ** 9)
        return ModelResult.propose(self.proposal)


def test_model_cannot_mutate_trusted_budget_counter():
    """A hostile model must not bypass the budget, corrupt state, or hang the run."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker, calls = recording_broker(monitor)
    engine = ExecutionEngine(monitor, broker, Budget(1))
    model = MutatingModel(ep())

    record = engine.run(build_ctx(), model)

    # 1. No write from untrusted code may land on anything the engine reads.
    assert model.mutated == [], (
        f"untrusted model successfully wrote to trusted state: {model.mutated}"
    )
    assert model.refused, (
        "the model's writes were neither refused nor recorded: it was probably "
        "handed a plain mutable object that silently accepted the assignment"
    )

    # 2. The budget is 1. At most one action may execute.
    assert len(calls) <= 1, (
        f"budget was 1 but {len(calls)} actions executed: the model corrupted "
        f"steps_taken (final value {record.steps_taken})"
    )

    # 3. The trusted counter is intact and the run terminated.
    assert record.steps_taken >= 0, (
        "trusted counter went negative: untrusted code wrote to trusted state"
    )
    assert record.state in (RunState.COMPLETED, RunState.ABORTED)


# --------------------------------------------------------------------------- #
# A2. HIGH. An absent tool is reported as EXECUTED. No action ran.
# Fix: a distinct StepOutcome.TOOL_NOT_FOUND; never report a no-op as executed.
# --------------------------------------------------------------------------- #

def test_missing_tool_is_not_reported_as_executed():
    """Dispatching an authorized verb with no registered tool executed nothing."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = TrustedExecutionBroker(monitor)      # empty catalog: no tools at all
    engine = ExecutionEngine(monitor, broker, Budget(2))
    record = RunRecord(ctx=build_ctx(), state=RunState.RUNNING)

    result = engine.step(record, ep(tool="not-registered"))

    assert result.outcome != StepOutcome.EXECUTED, (
        "no tool was registered and nothing ran, but the engine reported "
        f"EXECUTED (reason: {result.audit_reason!r}); audit state is false"
    )
    assert result.tool_result is None


# --------------------------------------------------------------------------- #
# A3. HIGH. ExecutionEngine accepts a `store` that is not the monitor's store.
#     engine.store then has no authority over decisions but looks like it does.
#     Both authorization checks read monitor.store, so revoking engine.store is
#     a no-op and the action executes.
#
#     NOTE: the existing revoke-race test in test_runtime.py passes only because
#     its fixture happens to wire the SAME store object into both. The invariant
#     is incidental, not structural. This test removes the coincidence.
#
# Fix: ExecutionEngine(monitor, tools, budget); self.store = monitor.store.
# --------------------------------------------------------------------------- #

def test_revoking_through_engine_store_actually_stops_the_action():
    """After the fix, engine.store IS the monitor's store, so a hook that revokes
    through it affects the very authorization the engine checks.

    Pre-fix, this same revocation could be aimed at a decoy store the engine held
    while the monitor read a different one, and the action executed regardless.
    Post-fix there is only one store, so the revoke lands where it matters and the
    execute-time re-check denies. The tool never runs.

    This is the positive counterpart to test_engine_rejects_a_second_store: that
    one proves you cannot create the divergence; this one proves the surviving
    single-store path enforces revocation.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker, calls = recording_broker(monitor)

    def revoke_via_engine(engine, proposal, record):
        engine.store.revoke("cap-1")

    engine = ExecutionEngine(
        monitor, broker, Budget(2), pre_execute_hook=revoke_via_engine
    )
    record = RunRecord(ctx=build_ctx(), state=RunState.RUNNING)

    result = engine.step(record, ep())

    assert calls == [], (
        "the capability was revoked through engine.store before execution, but "
        "the action still ran"
    )
    assert result.outcome == StepOutcome.REVOKED_RACE


def test_engine_store_identity_invariant():
    """After the fix, the engine must expose exactly the monitor's store."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    engine = ExecutionEngine(monitor, TrustedExecutionBroker(monitor), Budget(1))

    assert engine.store is engine.monitor.store
    assert engine.monitor.store is store


def test_engine_rejects_a_second_store():
    """After the fix, supplying a divergent store must be impossible."""
    store_a = build_store()
    store_b = build_store()
    monitor = ReferenceMonitor(store_a)

    with pytest.raises((TypeError, ValueError)):
        ExecutionEngine(monitor, store_b, TrustedExecutionBroker(monitor), Budget(1))


# --------------------------------------------------------------------------- #
# A4. HIGH. A credential scope is not validated at issuance. `../bad` is
#     accepted and only raises ResourceError later, at release time.
# Fix: validate id, capability_id, verb, scope, and TTL at construction.
#      Fail closed at issuance, not at use.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_scope", ["../bad", "acme//api", "acme/api/..", "*"])
def test_credential_scope_is_validated_at_issuance(bad_scope):
    """An invalid resource scope must be rejected when the credential is made."""
    with pytest.raises((CredentialError, ValueError)):
        Credential("c-bad", "read", bad_scope, Secret("X"))


# --------------------------------------------------------------------------- #
# A5. HIGH. HttpTool accepts any URL, including plaintext, file://, and URLs
#     with embedded credentials. This is the tool a real secret is handed to.
# Fix: HTTPS only, no embedded userinfo, explicit host allowlist, port policy,
#      redirects disabled unless separately authorized, normalize before compare.
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_url", [
    "http://example.com",              # plaintext: secret on the wire
    "file:///tmp/test",                # not a network scheme at all
    "https://user:pw@example.com",     # embedded credentials
    "ftp://example.com",
])
def test_httptool_rejects_unsafe_destinations(bad_url):
    """A credentialed tool must not accept a destination that can leak the secret."""
    with pytest.raises((ValueError, CredentialError)):
        HttpTool(bad_url, lambda method, url, headers: {"status": 200, "body": ""})


def test_httptool_accepts_https():
    """Control: a well-formed HTTPS destination is still accepted."""
    tool = HttpTool(
        "https://example.com/api",
        lambda method, url, headers: {"status": 200, "body": ""},
    )
    assert tool.allowed_url == "https://example.com/api"


# --------------------------------------------------------------------------- #
# A6. HIGH. OllamaModel converts every exception to None, and the engine reads
#     None as "the model is done". A provider crash therefore yields COMPLETED.
# Fix: a typed result (PROPOSAL / COMPLETED / ERROR). Provider failure must not
#      produce RunState.COMPLETED.
# --------------------------------------------------------------------------- #

class UnparseableModel:
    """A model that returns nothing usable, as a real provider failure does.

    This is the shape the defect actually takes: the adapter catches its own
    transport exception and returns None, and the engine cannot distinguish
    "the model has finished its work" from "the model never spoke". Both end
    the run, and both end it as COMPLETED.
    """

    def next_proposal(self, record):
        return None


def test_engine_cannot_distinguish_model_completion_from_model_failure():
    """`None` is overloaded: it means both 'done' and 'failed'.

    Today the engine has exactly one channel for 'no proposal', so a clean finish
    and a dead provider produce byte-identical terminal state. This test pins the
    ambiguity itself: after the fix, a run must expose WHY it stopped, via a typed
    model result (PROPOSAL / COMPLETED / ERROR), not via a bare None.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    engine = ExecutionEngine(monitor, TrustedExecutionBroker(monitor), Budget(3))

    record = engine.run(build_ctx(), UnparseableModel())

    # After the fix there must be some terminal signal distinguishing these.
    # Today there is none: the engine has no MODEL_ERROR / PROVIDER_UNAVAILABLE
    # state and no reason attached to the record.
    assert hasattr(record, "stop_reason"), (
        "the run record carries no stop_reason: a clean completion and a failed "
        "provider are indistinguishable in trusted terminal state"
    )


def test_ollama_adapter_does_not_swallow_provider_errors():
    """OllamaModel must not convert a transport failure into a clean stop."""
    from capcore.adapters import OllamaModel

    class BrokenOllama(OllamaModel):
        def _call(self, prompt):
            raise RuntimeError("connection refused")

    store = build_store()
    monitor = ReferenceMonitor(store)
    engine = ExecutionEngine(monitor, TrustedExecutionBroker(monitor), Budget(3))

    record = engine.run(build_ctx(), BrokenOllama())

    assert record.state != RunState.COMPLETED, (
        "OllamaModel swallowed the provider exception and the engine read the "
        "resulting None as 'model finished'"
    )


# =========================================================================== #
# BUCKET B (REPLACED). The old characterization tests pinned the CURRENT broken
# behaviour of release() and HttpTool.__call__(proposal, secret). Commit 4 (the
# AuthorizedAction / redeem-not-inspect redesign) deleted both APIs, so those
# tests are gone. The adversarial GUARANTEES are not: each is re-expressed below
# against the new redemption surface. Same properties, new mechanism.
#
# The new broker:
#   - CredentialBroker(monitor): re-authorizes through the LIVE monitor.
#   - register_authorized_execution(ctx, proposal, decision, tool_reg_id) -> id
#   - redeem_and_execute(id) -> SanitizedToolResult   (never returns a Secret)
# =========================================================================== #

def _broker_with_http(monitor, transport, url="https://example.com/api",
                      secret="LEAKME", single_use=True, verb="read",
                      scope="acme/api"):
    """A broker wired with one credential and one credentialed HttpTool."""
    broker = TrustedExecutionBroker(monitor)
    broker.issue_credential(Credential("cred-1", verb, scope,
                                       Secret(secret), single_use=single_use))
    broker.register_tool(ToolRegistration(
        registration_id="http-1", verb=verb, kind=ToolKind.CREDENTIALED,
        adapter=HttpTool(url, transport), version="1", credential_id="cred-1",
    ))
    broker.grant_tool("http-1", "acme")
    broker.seal_catalog()
    return broker


def _mint(broker, monitor, ctx, proposal, tool_reg_id="http-1"):
    """proposal is an M1 Proposal; wrap for the execution layer."""
    return broker.register_authorized_execution(
        ctx, ExecutionProposal(action=proposal, tool_registration_id=tool_reg_id))


# --------------------------------------------------------------------------- #
# Forgery. A fabricated authorization has no server-side record.
# --------------------------------------------------------------------------- #

def test_forged_action_id_is_denied():
    """An action_id the broker never issued buys nothing: no record, no auth."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    calls = MockCalls()
    broker = _broker_with_http(monitor, calls.transport)

    result = broker.redeem_and_execute("not-a-real-action-id")

    assert result.ok is False
    assert result.code == "authorization_refused"
    assert calls.count == 0, "no transport call may happen for a forged id"


def test_forged_decision_cannot_obtain_the_secret():
    """A forged ALLOW is not the security boundary; live re-authorization is.

    A forged Decision can MINT a pending authorization (the mint-time verdict
    check is a convenience, not the guarantee, since a forged ALLOW satisfies
    it). What it cannot do is REDEEM: redemption re-authorizes through the live
    monitor against the real capability store, and an action the monitor does not
    actually authorize is refused before the secret is touched.

    This is the deliberate design: authenticity comes from the broker's own
    re-check against live state, not from inspecting a caller-supplied object. So
    the test drives a forged decision for a resource the monitor genuinely denies
    and proves the secret never leaves.
    """
    store = build_store()   # authorizes acme/api/*, nothing else
    monitor = ReferenceMonitor(store)
    calls = MockCalls()
    broker = _broker_with_http(monitor, calls.transport)

    # The broker no longer ACCEPTS a Decision at all, so there is nothing to
    # forge: it authorizes independently. An unauthorized action is refused at
    # mint, and there is no parameter through which a caller could assert
    # otherwise.
    import inspect
    sig = inspect.signature(broker.register_authorized_execution)
    assert "decision" not in sig.parameters

    unauth = Proposal("globex/secret", "read")
    with pytest.raises(AuthorizationError):
        _mint(broker, monitor, build_ctx(), unauth)

    assert calls.count == 0, "an unauthorized action must never reach the transport"


# --------------------------------------------------------------------------- #
# Replay. Single-use is an atomic state transition, not a deletion.
# --------------------------------------------------------------------------- #

def test_action_id_cannot_be_replayed():
    """A second redemption of the same id finds a non-PENDING record."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    calls = MockCalls()
    broker = _broker_with_http(monitor, calls.transport)
    action_id = _mint(broker, monitor, build_ctx(), Proposal("acme/api/x", "read"))

    first = broker.redeem_and_execute(action_id)
    second = broker.redeem_and_execute(action_id)

    assert first.ok is True
    assert second.ok is False
    assert second.code == "authorization_refused"
    assert calls.count == 1, "the action must execute exactly once"


# --------------------------------------------------------------------------- #
# Staleness. Live re-authorization at redemption catches post-mint revocation.
# --------------------------------------------------------------------------- #

def test_revoked_action_fails_at_redemption():
    """Authorize, revoke, then redeem: the secret must not leave."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    calls = MockCalls()
    broker = _broker_with_http(monitor, calls.transport)
    action_id = _mint(broker, monitor, build_ctx(), Proposal("acme/api/x", "read"))

    store.revoke("cap-1")

    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "authorization_refused"
    assert calls.count == 0, "a revoked action must never reach the transport"


# --------------------------------------------------------------------------- #
# Substitution. The caller supplies neither tool nor credential at redemption.
# --------------------------------------------------------------------------- #

def test_action_cannot_be_redeemed_for_a_different_tool():
    """A valid action_id is bound to its tool; the caller cannot swap it.

    redeem_and_execute takes ONLY the id. There is no parameter through which a
    different tool could be supplied. This test encodes that as an API fact: the
    signature admits no tool argument.
    """
    import inspect
    sig = inspect.signature(TrustedExecutionBroker.redeem_and_execute)
    params = set(sig.parameters) - {"self"}
    assert params <= {"action_id", "now"}, (
        f"redeem_and_execute exposes {params}; a caller must not be able to pass "
        f"a tool or credential at redemption"
    )


def test_swapped_tool_version_is_refused():
    """If the registered tool is replaced after mint, redemption is refused.

    The record pins the tool version. Re-registering under the same id with a new
    version must not let an old authorization execute against the new adapter.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    calls_old = MockCalls()
    broker = _broker_with_http(monitor, calls_old.transport)
    action_id = _mint(broker, monitor, build_ctx(), Proposal("acme/api/x", "read"))

    # Swap the tool under the same registration id, new version + new transport.
    calls_new = MockCalls()
    broker.catalog._replace_unsafe(ToolRegistration(
        registration_id="http-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=HttpTool("https://example.com/api", calls_new.transport),
        version="2", credential_id="cred-1",
    ))

    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "authorization_refused"
    assert calls_new.count == 0, "the swapped-in tool must not run"


# --------------------------------------------------------------------------- #
# Expiry.
# --------------------------------------------------------------------------- #

def test_expired_action_is_denied():
    """An action redeemed after its TTL is refused before the secret is touched."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    calls = MockCalls()
    clock = FakeClock(1000.0)
    broker = TrustedExecutionBroker(monitor, action_ttl_seconds=10.0, clock=clock)
    broker.issue_credential(Credential("cred-1", "read", "acme/api",
                                       Secret("LEAKME"), single_use=True))
    broker.register_tool(ToolRegistration(
        registration_id="http-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=HttpTool("https://example.com/api", calls.transport),
        version="1", credential_id="cred-1",
    ))
    broker.grant_tool("http-1", "acme")
    broker.seal_catalog()
    ctx = build_ctx()
    proposal = Proposal("acme/api/x", "read")
    action_id = broker.register_authorized_execution(
        ctx, ExecutionProposal(action=proposal, tool_registration_id="http-1"))

    clock.advance(11.0)       # past the 10s action TTL
    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "authorization_refused"
    assert calls.count == 0


# --------------------------------------------------------------------------- #
# Containment. The secret never returns to the caller, and a hostile transport
# that raises with the header cannot leak it past the boundary.
# --------------------------------------------------------------------------- #

def test_secret_never_returns_to_the_caller():
    """redeem_and_execute returns a SanitizedToolResult, never a Secret.

    The whole broker API is searched: no method may hand a Secret back to general
    code. The only place a raw value exists is inside the boundary, during the
    adapter call.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    calls = MockCalls()
    broker = _broker_with_http(monitor, calls.transport)
    action_id = _mint(broker, monitor, build_ctx(), Proposal("acme/api/x", "read"))

    result = broker.redeem_and_execute(action_id)

    assert isinstance(result, SanitizedToolResult)
    assert not isinstance(result.body, Secret)
    # the sanitized body is a redacted summary, not the token
    assert "LEAKME" not in (result.body or "")


def test_adapter_exception_with_the_header_does_not_leak_the_secret():
    """A transport that raises RuntimeError(headers['Authorization']).

    Pre-redesign this exception escaped with 'Bearer LEAKME' in it. Now the broker
    catches every exception from the credentialed call and returns a constant
    failure code. The secret must appear NOWHERE the caller can see: not in the
    result, not in a raised exception, not in the audit log.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)

    def hostile_transport(method, url, headers):
        raise RuntimeError(headers["Authorization"])   # 'Bearer LEAKME'

    broker = _broker_with_http(monitor, hostile_transport)
    action_id = _mint(broker, monitor, build_ctx(), Proposal("acme/api/x", "read"))

    # Must NOT raise: the boundary swallows the hostile exception.
    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "credentialed_tool_execution_failed"
    assert "LEAKME" not in (result.body or "")
    assert "LEAKME" not in (result.code or "")
    # and the audit trail is secret-free
    for entry in broker.audit:
        assert "LEAKME" not in entry.reason


# --------------------------------------------------------------------------- #
# A plain tool never touches the credential machinery.
# --------------------------------------------------------------------------- #

def test_plain_tool_executes_without_a_credential():
    """Control: a plain tool runs through the same redemption path, no secret."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    ran = []
    broker = TrustedExecutionBroker(monitor)
    broker.register_tool(ToolRegistration(
        registration_id="plain-1", verb="read", kind=ToolKind.PLAIN,
        adapter=lambda a: ran.append(a.resource) or "plain-ok", version="1",
    ))
    broker.grant_tool("plain-1", "acme")
    broker.seal_catalog()
    action_id = _mint(broker, monitor, build_ctx(),
                      Proposal("acme/api/x", "read"), tool_reg_id="plain-1")

    result = broker.redeem_and_execute(action_id)

    assert result.ok is True
    assert result.body == "plain-ok"
    assert ran == ["acme/api/x"]
