"""M2 runtime tests: the trusted execution loop's security properties.

All tests use a deterministic ScriptedModel so the properties are reproducible
in CI. The revoke race is made deterministic via the engine's pre_execute_hook,
which fires a revocation at the exact point between propose-time and
execute-time authorization.
"""

import pytest
from hypothesis import given, settings, strategies as st

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext, Verdict,
)
from capcore.broker import (
    ExecutionProposal, ToolKind, ToolRegistration, TrustedExecutionBroker,
)
from capcore.runtime import (
    ModelResult, ModelOutcome, StopReason,
    RunState, StepOutcome, StepResult, RunRecord, Budget,
    ScriptedModel, ExecutionEngine,
)


class ToolRegistry:
    """Test shim.

    The engine no longer owns a tool registry: the broker's ToolCatalog is the
    sole catalog (see runtime.py). This shim keeps the verb-keyed shape these
    tests were written against and translates it into broker registrations, so
    the M2 loop's security properties stay tested without rewriting every body.

    Registering here also GRANTS the tool, since these tests predate ToolPolicy
    and are about the engine loop, not about tool routing. Routing and
    deny-by-default policy are covered in test_integration_m2_m3.py.
    """
    def __init__(self):
        self._tools = {}

    def register(self, verb, tool):
        self._tools[verb] = tool

    def install(self, broker):
        for verb, tool in self._tools.items():
            broker.register_tool(ToolRegistration(
                registration_id=f"tool-{verb}", verb=verb, kind=ToolKind.PLAIN,
                adapter=tool, version="1"))
            broker.grant_tool(f"tool-{verb}", "acme")


def ep(resource, verb):
    """Wrap an M1 action in an ExecutionProposal naming its verb's tool."""
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=f"tool-{verb}")


def build(budget_steps=10, pre_execute_hook=None, tools=None):
    store = CapabilityStore()
    store.issue(Capability("cap-run", "acme", "acme/records",
                           frozenset({"read", "send"}),
                           approval_actions=frozenset({"send"}),
                           principal="p1", run="r1"))
    mon = ReferenceMonitor(store)
    broker = TrustedExecutionBroker(mon)
    registry = tools or ToolRegistry()
    registry.install(broker)
    broker.seal_catalog()
    engine = ExecutionEngine(broker, Budget(budget_steps),
                             pre_execute_hook=pre_execute_hook)
    ctx = RunContext("acme", "p1", "r1")
    return engine, store, ctx, registry


# --------------------------------------------------------------------------- #
# Tool boundary: only ALLOWed actions reach a tool.
# --------------------------------------------------------------------------- #

def test_only_allowed_actions_reach_tools():
    calls = []
    def read_tool(p): calls.append(p.resource); return "ok:" + p.resource
    reg = ToolRegistry(); reg.register("read", read_tool)
    engine, store, ctx, _ = build(tools=reg)

    # read = allowed, send = approval-gated (must NOT reach a tool), write = denied
    model = ScriptedModel([
        ep("acme/records/x", "read"),   # allow -> tool called
        ep("acme/records/x", "send"),   # approval -> no tool
        ep("acme/records/x", "write"),  # deny -> no tool
        ep("globex/secret", "read"),    # cross-tenant deny -> no tool
    ])
    record = engine.run(ctx, model)

    outcomes = [s.outcome for s in record.history]
    assert outcomes == [StepOutcome.EXECUTED, StepOutcome.APPROVAL,
                        StepOutcome.DENIED, StepOutcome.DENIED]
    # the tool was called exactly once, only for the allowed read
    assert calls == ["acme/records/x"]


def test_approval_action_never_executes():
    calls = []
    def send_tool(p): calls.append(p.resource); return "sent"
    reg = ToolRegistry(); reg.register("send", send_tool)
    engine, store, ctx, _ = build(tools=reg)
    model = ScriptedModel([ep("acme/records/x", "send")])
    record = engine.run(ctx, model)
    assert record.history[0].outcome == StepOutcome.APPROVAL
    assert calls == []  # approval-gated action never touched the tool


# --------------------------------------------------------------------------- #
# Budget: a run cannot exceed its action budget.
# --------------------------------------------------------------------------- #

def test_budget_caps_executed_actions():
    calls = []
    def read_tool(p): calls.append(1); return "ok"
    reg = ToolRegistry(); reg.register("read", read_tool)
    engine, store, ctx, _ = build(budget_steps=2, tools=reg)
    # model wants to do 5 reads; budget is 2
    model = ScriptedModel([ep("acme/records/x", "read")] * 5)
    record = engine.run(ctx, model)
    assert record.state == RunState.ABORTED
    assert len(calls) == 2  # only 2 executed
    assert record.steps_taken == 2


def test_budget_counts_denied_attempts():
    """A hostile model cannot burn unlimited attempts probing the boundary:
    denied attempts count against the budget too.
    """
    engine, store, ctx, _ = build(budget_steps=3)
    # 5 denied attempts (write is not granted); budget 3
    model = ScriptedModel([ep("acme/records/x", "write")] * 5)
    record = engine.run(ctx, model)
    assert record.state == RunState.ABORTED
    assert record.steps_taken == 3
    # exactly 3 denials recorded, then aborted
    denials = [s for s in record.history if s.outcome == StepOutcome.DENIED]
    assert len(denials) == 3


def test_budget_zero_allows_nothing():
    engine, store, ctx, _ = build(budget_steps=0)
    model = ScriptedModel([ep("acme/records/x", "read")])
    record = engine.run(ctx, model)
    assert record.state == RunState.ABORTED
    assert record.steps_taken == 0


def test_step_level_budget_guard():
    """The budget is enforced at the STEP level, not only in the run loop. A
    caller invoking step() directly past the budget must get BUDGET_EXHAUSTED and
    no execution, so the guard protects direct callers too (defense in depth).
    """
    calls = []
    reg = ToolRegistry(); reg.register("read", lambda p: calls.append(1))
    engine, store, ctx, _ = build(budget_steps=1, tools=reg)
    record = RunRecord(ctx=ctx, state=RunState.RUNNING)
    # first direct step executes (budget 1)
    r1 = engine.step(record, ep("acme/records/x", "read"))
    assert r1.outcome == StepOutcome.EXECUTED
    # second direct step is over budget -> BUDGET_EXHAUSTED, tool not called again
    r2 = engine.step(record, ep("acme/records/x", "read"))
    assert r2.outcome == StepOutcome.BUDGET_EXHAUSTED
    assert len(calls) == 1


def test_invalid_budget_rejected():
    with pytest.raises(ValueError):
        Budget(-1)


# --------------------------------------------------------------------------- #
# Revoke race: authorized at propose, revoked before execute -> not executed.
# --------------------------------------------------------------------------- #

def test_revoke_between_propose_and_execute_stops_action():
    calls = []
    def read_tool(p): calls.append(p.resource); return "ok"
    reg = ToolRegistry(); reg.register("read", read_tool)

    # the hook fires AFTER propose-time allow, BEFORE execute-time re-check,
    # and revokes the capability. The re-check must then deny, and the tool
    # must NOT be called.
    def revoke_hook(engine, proposal, record):
        engine.store.revoke("cap-run")

    engine, store, ctx, _ = build(tools=reg, pre_execute_hook=revoke_hook)
    model = ScriptedModel([ep("acme/records/x", "read")])
    record = engine.run(ctx, model)

    assert record.history[0].outcome == StepOutcome.REVOKED_RACE
    assert calls == []  # the tool never ran despite the initial allow


def test_no_revoke_executes_normally():
    """Control: without the revoke, the same action executes."""
    calls = []
    def read_tool(p): calls.append(p.resource); return "ok"
    reg = ToolRegistry(); reg.register("read", read_tool)
    engine, store, ctx, _ = build(tools=reg)  # no hook
    model = ScriptedModel([ep("acme/records/x", "read")])
    record = engine.run(ctx, model)
    assert record.history[0].outcome == StepOutcome.EXECUTED
    assert calls == ["acme/records/x"]


# --------------------------------------------------------------------------- #
# Tool failure is contained.
# --------------------------------------------------------------------------- #

def test_tool_error_fails_run_without_crashing():
    def bad_tool(p): raise RuntimeError("boom")
    reg = ToolRegistry(); reg.register("read", bad_tool)
    engine, store, ctx, _ = build(tools=reg)
    model = ScriptedModel([ep("acme/records/x", "read")])
    record = engine.run(ctx, model)  # must not raise
    assert record.state == RunState.FAILED
    assert record.history[0].outcome == StepOutcome.TOOL_ERROR


# --------------------------------------------------------------------------- #
# State machine reaches a terminal state.
# --------------------------------------------------------------------------- #

def test_run_reaches_terminal_state():
    reg = ToolRegistry(); reg.register("read", lambda p: "ok")
    engine, store, ctx, _ = build(tools=reg)
    model = ScriptedModel([ep("acme/records/x", "read")])
    record = engine.run(ctx, model)
    assert record.state in {RunState.COMPLETED, RunState.ABORTED, RunState.FAILED}
    assert record.state == RunState.COMPLETED


@given(n=st.integers(min_value=0, max_value=8), budget=st.integers(min_value=0, max_value=8))
@settings(max_examples=100)
def test_executed_never_exceeds_budget(n, budget):
    """EVIDENCE: across random request counts and budgets, executed steps never
    exceed the budget.
    """
    reg = ToolRegistry(); reg.register("read", lambda p: "ok")
    engine, store, ctx, _ = build(budget_steps=budget, tools=reg)
    model = ScriptedModel([ep("acme/records/x", "read")] * n)
    record = engine.run(ctx, model)
    assert record.steps_taken <= budget


# --------------------------------------------------------------------------- #
# Liveness: the loop ceiling bounds a run INDEPENDENTLY of the trusted counter.
# --------------------------------------------------------------------------- #

def test_loop_ceiling_terminates_even_if_the_counter_is_corrupted():
    """run()'s `for _ in range(max_steps)` ceiling must be INDEPENDENTLY load-bearing.

    ModelView already stops an untrusted model from writing steps_taken. This test
    covers the layer BENEATH that: if trusted counter state were corrupted by any
    means (a bug, a refactor that re-exposes the record, a plugin), the run must
    still terminate, because run()'s bound is a LOCAL counter never derived from,
    and never written by, the record.

    The pre_execute_hook here is trusted code standing in for such a corruption: it
    drives the live record's steps_taken to -1000 on every step, so the budget
    check inside step() can never trip. If run() bounded itself by reading
    steps_taken (as it once did), this model would loop forever. Only the ceiling
    stops it.

    A mutation replacing the ceiling with `while True` is caught by this test and
    by nothing else in the suite.
    """
    calls = []
    reg = ToolRegistry()
    reg.register("read", lambda a: calls.append(a.resource) or "ok")

    def corrupt_the_counter(engine, proposal, record):
        record.steps_taken = -1000     # the counter now bounds nothing

    engine, store, ctx, _ = build(budget_steps=3, tools=reg,
                                  pre_execute_hook=corrupt_the_counter)

    class Endless:
        def __init__(self):
            self.calls = 0

        def next_proposal(self, view):
            self.calls += 1
            if self.calls > 100:
                raise AssertionError(
                    "engine failed to terminate: run() is not bounded by its own "
                    "loop ceiling once steps_taken is corrupted"
                )
            return ModelResult.propose(ep("acme/records/x", "read"))

    model = Endless()
    record = engine.run(ctx, model)   # must terminate

    assert record.steps_taken < 0, "fixture did not actually corrupt the counter"
    assert model.calls <= 3, (
        f"budget was 3 but the model was asked {model.calls} times: the loop "
        f"ceiling did not bound the run"
    )
    assert len(calls) <= 3


def test_run_terminates_against_a_model_that_never_stops():
    """End-to-end liveness: run() must return against an endless model."""
    calls = []
    reg = ToolRegistry()
    reg.register("read", lambda a: calls.append(a.resource) or "ok")
    engine, store, ctx, _ = build(budget_steps=3, tools=reg)

    class Endless:
        def __init__(self):
            self.calls = 0

        def next_proposal(self, view):
            self.calls += 1
            if self.calls > 100:
                raise AssertionError("engine failed to terminate")
            return ModelResult.propose(ep("acme/records/x", "read"))

    model = Endless()
    record = engine.run(ctx, model)

    assert model.calls <= 3
    assert len(calls) <= 3
    assert record.state in (RunState.COMPLETED, RunState.ABORTED)


# --------------------------------------------------------------------------- #
# Terminal state must be HONEST. A run that failed does not report success.
#
# The engine used to have one channel for "no proposal": the model returning None.
# A clean finish and a dead provider produced byte-identical terminal state, so a
# run against a broken Ollama server reported COMPLETED with zero actions taken.
# Silent total failure, reported as success.
# --------------------------------------------------------------------------- #

from capcore.runtime import ModelOutcome, ModelResult, StopReason


def test_model_finishing_is_a_real_completion():
    engine, store, ctx, _ = build(budget_steps=3)

    class Finishes:
        def next_proposal(self, view):
            return ModelResult.finished()

    record = engine.run(ctx, Finishes())

    assert record.state is RunState.COMPLETED
    assert record.stop_reason is StopReason.MODEL_FINISHED


def test_provider_failure_is_not_a_completion():
    engine, store, ctx, _ = build(budget_steps=3)

    class ProviderDown:
        def next_proposal(self, view):
            return ModelResult.error()

    record = engine.run(ctx, ProviderDown())

    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.PROVIDER_UNAVAILABLE
    assert record.state is not RunState.COMPLETED


def test_model_adapter_that_raises_is_not_a_completion():
    engine, store, ctx, _ = build(budget_steps=3)

    class Raises:
        def next_proposal(self, view):
            raise RuntimeError("adapter blew up")

    record = engine.run(ctx, Raises())

    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.MODEL_ERROR


def test_untyped_model_return_is_treated_as_failure():
    """An adapter that returns a bare value cannot be trusted to mean 'finished'.

    Fail closed: an unknown outcome is a failure, not a success. Otherwise a
    partially-migrated adapter silently reports completion.
    """
    engine, store, ctx, _ = build(budget_steps=3)

    class Untyped:
        def next_proposal(self, view):
            return None          # the OLD protocol

    record = engine.run(ctx, Untyped())

    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.MODEL_ERROR


def test_budget_exhaustion_is_distinguishable_from_completion():
    calls = []
    reg = ToolRegistry()
    reg.register("read", lambda a: calls.append(a.resource) or "ok")
    engine, store, ctx, _ = build(budget_steps=2, tools=reg)

    class Endless:
        def next_proposal(self, view):
            return ModelResult.propose(ep("acme/records/x", "read"))

    record = engine.run(ctx, Endless())

    assert record.state is RunState.ABORTED
    assert record.stop_reason in (StopReason.BUDGET_EXHAUSTED,
                                  StopReason.CEILING_REACHED)
    assert record.state is not RunState.COMPLETED


def test_tool_failure_is_distinguishable_from_completion():
    reg = ToolRegistry()

    def boom(action):
        raise RuntimeError("tool exploded")

    reg.register("read", boom)
    engine, store, ctx, _ = build(budget_steps=3, tools=reg)

    record = engine.run(ctx, ScriptedModel([ep("acme/records/x", "read")]))

    assert record.state is RunState.FAILED
    assert record.stop_reason is StopReason.TOOL_FAILED


def test_every_terminated_run_has_a_stop_reason():
    """No run may end without saying why. A None stop_reason on a terminated run
    means some path forgot, and that path is exactly where a failure could be
    silently reported as success."""
    scenarios = []

    class Finishes:
        def next_proposal(self, view):
            return ModelResult.finished()

    class Errors:
        def next_proposal(self, view):
            return ModelResult.error()

    class Raises:
        def next_proposal(self, view):
            raise RuntimeError("boom")

    for model_cls in (Finishes, Errors, Raises):
        engine, store, ctx, _ = build(budget_steps=2)
        scenarios.append(engine.run(ctx, model_cls()))

    reg = ToolRegistry()
    reg.register("read", lambda a: "ok")
    engine, store, ctx, _ = build(budget_steps=1, tools=reg)

    class Endless:
        def next_proposal(self, view):
            return ModelResult.propose(ep("acme/records/x", "read"))

    scenarios.append(engine.run(ctx, Endless()))

    for record in scenarios:
        assert record.state is not RunState.RUNNING
        assert record.stop_reason is not None, (
            f"a run terminated in {record.state} with no stop_reason: a failure "
            f"could be indistinguishable from success"
        )


def test_adapter_limit_is_not_a_completion():
    """A ModelClient hitting its own cap aborts; it does not report COMPLETED.

    Hitting an adapter ceiling means the adapter stopped asking, not that the
    model finished the task. Reporting COMPLETED would be the same false-success
    defect as swallowing a provider error.
    """
    engine, store, ctx, _ = build(budget_steps=10)

    class Capped:
        def next_proposal(self, view):
            return ModelResult.limit_reached()

    record = engine.run(ctx, Capped())

    assert record.state is RunState.ABORTED
    assert record.stop_reason is StopReason.ADAPTER_LIMIT_REACHED
    assert record.state is not RunState.COMPLETED
