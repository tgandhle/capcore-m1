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
from capcore.runtime import (
    RunState, StepOutcome, StepResult, RunRecord, Budget, Tool, ToolRegistry,
    ScriptedModel, ExecutionEngine,
)


def build(budget_steps=10, pre_execute_hook=None, tools=None):
    store = CapabilityStore()
    store.issue(Capability("cap-run", "acme", "acme/records",
                           frozenset({"read", "send"}),
                           approval_actions=frozenset({"send"}),
                           principal="p1", run="r1"))
    mon = ReferenceMonitor(store)
    registry = tools or ToolRegistry()
    engine = ExecutionEngine(mon, store, registry, Budget(budget_steps),
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
        Proposal("acme/records/x", "read"),   # allow -> tool called
        Proposal("acme/records/x", "send"),   # approval -> no tool
        Proposal("acme/records/x", "write"),  # deny -> no tool
        Proposal("globex/secret", "read"),    # cross-tenant deny -> no tool
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
    model = ScriptedModel([Proposal("acme/records/x", "send")])
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
    model = ScriptedModel([Proposal("acme/records/x", "read")] * 5)
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
    model = ScriptedModel([Proposal("acme/records/x", "write")] * 5)
    record = engine.run(ctx, model)
    assert record.state == RunState.ABORTED
    assert record.steps_taken == 3
    # exactly 3 denials recorded, then aborted
    denials = [s for s in record.history if s.outcome == StepOutcome.DENIED]
    assert len(denials) == 3


def test_budget_zero_allows_nothing():
    engine, store, ctx, _ = build(budget_steps=0)
    model = ScriptedModel([Proposal("acme/records/x", "read")])
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
    r1 = engine.step(record, Proposal("acme/records/x", "read"))
    assert r1.outcome == StepOutcome.EXECUTED
    # second direct step is over budget -> BUDGET_EXHAUSTED, tool not called again
    r2 = engine.step(record, Proposal("acme/records/x", "read"))
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
    def revoke_hook(engine, proposal):
        engine.store.revoke("cap-run")

    engine, store, ctx, _ = build(tools=reg, pre_execute_hook=revoke_hook)
    model = ScriptedModel([Proposal("acme/records/x", "read")])
    record = engine.run(ctx, model)

    assert record.history[0].outcome == StepOutcome.REVOKED_RACE
    assert calls == []  # the tool never ran despite the initial allow


def test_no_revoke_executes_normally():
    """Control: without the revoke, the same action executes."""
    calls = []
    def read_tool(p): calls.append(p.resource); return "ok"
    reg = ToolRegistry(); reg.register("read", read_tool)
    engine, store, ctx, _ = build(tools=reg)  # no hook
    model = ScriptedModel([Proposal("acme/records/x", "read")])
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
    model = ScriptedModel([Proposal("acme/records/x", "read")])
    record = engine.run(ctx, model)  # must not raise
    assert record.state == RunState.FAILED
    assert record.history[0].outcome == StepOutcome.TOOL_ERROR


# --------------------------------------------------------------------------- #
# State machine reaches a terminal state.
# --------------------------------------------------------------------------- #

def test_run_reaches_terminal_state():
    reg = ToolRegistry(); reg.register("read", lambda p: "ok")
    engine, store, ctx, _ = build(tools=reg)
    model = ScriptedModel([Proposal("acme/records/x", "read")])
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
    model = ScriptedModel([Proposal("acme/records/x", "read")] * n)
    record = engine.run(ctx, model)
    assert record.steps_taken <= budget
