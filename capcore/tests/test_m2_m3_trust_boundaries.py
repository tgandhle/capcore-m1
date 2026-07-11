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

import pytest

from capcore import (
    Capability, CapabilityStore, Decision, Proposal, ReferenceMonitor,
    RunContext, Verdict,
)
from capcore.broker import Credential, CredentialBroker, CredentialError, Secret
from capcore.httptool import HttpTool
from capcore.runtime import (
    Budget, ExecutionEngine, RunRecord, RunState, ScriptedModel, StepOutcome,
    ToolRegistry,
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


def recording_registry():
    """A registry whose `read` tool records every execution."""
    calls = []
    registry = ToolRegistry()
    registry.register("read", lambda p: calls.append(p.resource) or "ok")
    return registry, calls


def build_broker(secret: str = "LEAKME") -> CredentialBroker:
    broker = CredentialBroker()
    broker.issue(Credential("c1", "cap-1", "read", "acme/api", Secret(secret)))
    return broker


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
        return self.proposal


def test_model_cannot_mutate_trusted_budget_counter():
    """A hostile model must not bypass the budget, corrupt state, or hang the run."""
    store = build_store()
    registry, calls = recording_registry()
    engine = ExecutionEngine(ReferenceMonitor(store), store, registry, Budget(1))
    model = MutatingModel(Proposal("acme/api/x", "read"))

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
    engine = ExecutionEngine(
        ReferenceMonitor(store), store, ToolRegistry(), Budget(2)
    )
    record = RunRecord(ctx=build_ctx(), state=RunState.RUNNING)

    result = engine.step(record, Proposal("acme/api/x", "read"))

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

def test_engine_store_must_be_the_monitors_store():
    """The engine must not hold a capability store the monitor does not read."""
    store_a = build_store()   # the monitor's store (authoritative)
    store_b = build_store()   # a decoy the engine is handed
    monitor = ReferenceMonitor(store_a)
    registry, calls = recording_registry()

    def revoke_via_engine(engine, proposal):
        # A caller reasonably believes this affects authorization. It does not.
        engine.store.revoke("cap-1")

    engine = ExecutionEngine(
        monitor, store_b, registry, Budget(2), pre_execute_hook=revoke_via_engine
    )
    record = RunRecord(ctx=build_ctx(), state=RunState.RUNNING)

    engine.step(record, Proposal("acme/api/x", "read"))

    assert calls == [], (
        "the capability was revoked through engine.store before execution, but "
        "the action still ran: engine.store is not the authoritative store"
    )


def test_engine_store_identity_invariant():
    """After the fix, the engine must expose exactly the monitor's store."""
    store = build_store()
    monitor = ReferenceMonitor(store)
    engine = ExecutionEngine(monitor, store, ToolRegistry(), Budget(1))

    assert engine.store is engine.monitor.store
    assert engine.monitor.store is store


def test_engine_rejects_a_second_store():
    """After the fix, supplying a divergent store must be impossible."""
    store_a = build_store()
    store_b = build_store()
    monitor = ReferenceMonitor(store_a)

    with pytest.raises((TypeError, ValueError)):
        ExecutionEngine(monitor, store_b, ToolRegistry(), Budget(1))


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
        Credential("c-bad", "cap-1", "read", bad_scope, Secret("X"))


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
    engine = ExecutionEngine(
        ReferenceMonitor(store), store, ToolRegistry(), Budget(3)
    )

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
    engine = ExecutionEngine(
        ReferenceMonitor(store), store, ToolRegistry(), Budget(3)
    )

    record = engine.run(build_ctx(), BrokenOllama())

    assert record.state != RunState.COMPLETED, (
        "OllamaModel swallowed the provider exception and the engine read the "
        "resulting None as 'model finished'"
    )


# =========================================================================== #
# BUCKET B: CHARACTERIZATION TESTS. These PASS today. They pin the CURRENT
# BROKEN behaviour of an API that the redesign DELETES.
#
# DO NOT FIX THESE. When `CredentialBroker.release()` is replaced by
# `execute_with_credential(...)` and `HttpTool.__call__(proposal, secret)` is
# replaced by the CredentialedTool protocol, DELETE this entire section and
# write bucket-A-style tests against the new surface.
#
# Each is named with a DEFECT_ prefix so the retirement is a grep.
# =========================================================================== #

def test_DEFECT_broker_releases_on_a_forged_decision():
    """CRITICAL. Any caller can mint an ALLOW; the broker never asks the monitor.

    The broker's only check on authorization is `decision.verdict == ALLOW`.
    `Decision` is a public dataclass. No reference monitor is consulted anywhere
    in release(), so a forged Decision is sufficient to obtain a real secret.

    Retire when: release() is replaced by an AuthorizedAction the broker REDEEMS
    against its own state (a lookup, not a field inspection) rather than a
    caller-supplied object it inspects and trusts.
    """
    broker = build_broker()
    forged = Decision(Verdict.ALLOW, "authorized")

    secret = broker.release(
        "c1", "cap-1", Proposal("acme/api/admin/secret", "read"), forged
    )

    assert secret is not None
    assert secret.reveal() == "LEAKME"


def test_DEFECT_broker_accepts_a_decision_replayed_onto_another_proposal():
    """CRITICAL. The decision is not bound to the proposal it was issued for.

    An ALLOW obtained for one resource can be paired with a completely different
    proposal at the broker, because release() takes `proposal` and `decision` as
    independent arguments and never checks that the decision was ISSUED FOR that
    proposal.

    Retire when: authorization carries a proposal digest and the broker
    revalidates it against the action being executed.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = build_broker()
    ctx = build_ctx()

    benign = Proposal("acme/api/public/x", "read")
    target = Proposal("acme/api/admin/secret", "read")

    decision_for_benign = monitor.authorize(ctx, benign)
    assert decision_for_benign.verdict == Verdict.ALLOW

    # The decision was issued for `benign`, and is now presented alongside
    # `target`. The broker cannot tell the difference.
    secret = broker.release("c1", "cap-1", target, decision_for_benign)

    assert secret is not None
    assert secret.reveal() == "LEAKME"


def test_DEFECT_broker_honours_a_decision_that_is_stale_after_revocation():
    """CRITICAL. Revocation does not reach the broker; authorization has no clock.

    The action is authorized, the capability is then revoked, and the OLD
    decision object still buys the secret. The broker never rechecks current
    authority, so revocation is bypassable by anyone holding a prior decision.

    Retire when: the broker revalidates current authority (capability version /
    revocation epoch) immediately before credential injection.
    """
    store = build_store()
    monitor = ReferenceMonitor(store)
    broker = build_broker()
    ctx = build_ctx()
    proposal = Proposal("acme/api/x", "read")

    decision = monitor.authorize(ctx, proposal)
    assert decision.verdict == Verdict.ALLOW

    store.revoke("cap-1")
    assert monitor.authorize(ctx, proposal).verdict == Verdict.DENY

    # The monitor now denies. The broker does not ask it.
    secret = broker.release("c1", "cap-1", proposal, decision)

    assert secret is not None
    assert secret.reveal() == "LEAKME"


def test_DEFECT_secret_leaks_through_a_transport_exception():
    """HIGH. Secret.__repr__ protects the WRAPPER, not the injected header.

    Once `secret.reveal()` is interpolated into an Authorization header, it is an
    ordinary Python string. Any exception raised by the transport that includes
    request context carries the credential in its message, and from there into
    logs, tracebacks, and error reporting.

    This is the concrete counterexample to "secrets never appear in exceptions".

    Retire when: the credential boundary lives inside the broker, transport
    exceptions are caught there, and only sanitized, typed errors cross out.
    """
    def hostile_transport(method, url, headers):
        raise RuntimeError(headers["Authorization"])

    tool = HttpTool("https://example.com/api", hostile_transport)

    with pytest.raises(RuntimeError) as exc_info:
        tool(Proposal("acme/api/x", "read"), Secret("LEAKME"))

    assert "LEAKME" in str(exc_info.value)


def test_DEFECT_released_secret_escapes_the_broker_boundary():
    """HIGH. release() hands the caller a Secret it can no longer control.

    "Single-use" constrains only FUTURE releases. The Secret already handed out
    can be revealed arbitrarily many times, its `_value` read directly, and
    passed anywhere. The broker is a secret getter, not a credential boundary.

    Retire when: the broker injects the credential and executes a trusted adapter
    itself, and never returns the secret to general application code.
    """
    broker = CredentialBroker()
    broker.issue(Credential(
        "c1", "cap-1", "read", "acme/api", Secret("LEAKME"), single_use=True
    ))
    forged = Decision(Verdict.ALLOW, "authorized")

    secret = broker.release("c1", "cap-1", Proposal("acme/api/x", "read"), forged)
    assert secret is not None

    # single_use is spent at the broker...
    assert broker.release(
        "c1", "cap-1", Proposal("acme/api/x", "read"), forged
    ) is None

    # ...but the caller's copy is unconstrained.
    assert secret.reveal() == "LEAKME"
    assert secret.reveal() == "LEAKME"
    assert object.__getattribute__(secret, "_value") == "LEAKME"
