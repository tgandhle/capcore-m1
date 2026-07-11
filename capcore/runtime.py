"""M2 runtime: the trusted execution loop around the M1 reference monitor.

M1 is a decision function (given identity + proposal -> allow/approval/deny).
M2 is the loop that USES it: it drives a run through a trusted state machine,
enforces per-run budgets, and executes authorized actions against a tool
boundary. The model (scripted or a real local LLM) proposes actions; the engine
authorizes each via M1 and only ever hands ALLOWed actions to a tool.

Security properties this module adds, all tested against a scripted model:
  - Trusted state: run state lives here, not in anything the model controls.
  - Double authorization (revoke race): an action is authorized at propose time
    AND re-checked immediately before execution. A capability revoked in between
    stops the action, it does not execute on a stale authorization.
  - Budget: a run cannot exceed its action budget; an exhausted budget denies
    even otherwise-valid actions, fail-closed.
  - Tool boundary: only ALLOWed actions reach a tool; denied/approval actions
    never touch one.

The model is abstracted behind ModelClient so the same engine runs against a
deterministic ScriptedModel (tests, CI) or a real local model (OllamaModel, in
adapters.py). The engine code is identical either way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Protocol

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
    Verdict, Decision,
)


# --------------------------------------------------------------------------- #
# Run state machine (trusted).
# --------------------------------------------------------------------------- #

class RunState(Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"          # budget exhausted or explicit stop
    FAILED = "failed"            # a tool raised


class StepOutcome(Enum):
    EXECUTED = "executed"        # authorized and ran
    DENIED = "denied"            # monitor denied
    APPROVAL = "approval"        # monitor requires human approval (not executed)
    REVOKED_RACE = "revoked_race"  # authorized at propose, revoked before execute
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOOL_ERROR = "tool_error"    # tool raised during execution


@dataclass(frozen=True)
class StepResult:
    outcome: StepOutcome
    proposal: Proposal
    # audit-only detail; never surfaced to the model
    audit_reason: str = ""
    tool_result: Optional[str] = None


@dataclass
class RunRecord:
    """Trusted per-run state. The model never receives this object.

    This is the authoritative record: run state, the budget counter both
    enforcement checks read, and the full history INCLUDING audit_reason. None of
    it is model-reachable. Model adapters get a ModelView built by
    `to_model_view()` below: an immutable, redacted copy.

    Handing this object to a ModelClient was a critical defect. An untrusted
    adapter could write `record.steps_taken = -100`, and because both the
    `run()` loop guard and the `step()` budget check read that same field, the
    model could bypass its budget AND produce a nonterminating run. See
    tests/test_m2_m3_trust_boundaries.py::test_model_cannot_mutate_trusted_budget_counter.
    """
    ctx: RunContext
    state: RunState = RunState.CREATED
    steps_taken: int = 0
    history: list[StepResult] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Model-facing view (untrusted boundary).
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ModelStepView:
    """One past step, as the MODEL is allowed to see it.

    Deliberately excludes `audit_reason`. That field is trusted-only diagnostic
    detail (which tenant owns a resource, whether a capability exists) and is the
    same information M1 already withholds from the model via Decision's
    public_reason/audit_reason split. Leaking it here through the history would
    reopen that hole by another route: an adversarial model could map the
    authorization boundary by reading why its prior attempts failed.

    `tool_result` IS included: the model needs the output of its own authorized
    actions to make progress. Tool results are themselves untrusted data.
    """
    verb: str
    resource: str
    outcome: StepOutcome
    tool_result: Optional[str] = None


@dataclass(frozen=True)
class ModelView:
    """Immutable, redacted snapshot handed to a ModelClient.

    A hostile adapter can mutate this all it likes: it is a frozen copy, and the
    engine never reads it back. Trusted state stays in RunRecord, which the model
    never sees.

    Note `remaining_steps` is derived, not the raw counter. The model is told how
    much budget it has left; it is not given the field the engine enforces on.
    """
    run_id: str
    remaining_steps: int
    history: tuple[ModelStepView, ...] = ()


def to_model_view(record: RunRecord, budget: "Budget") -> ModelView:
    """Build the untrusted model's view of a trusted run record.

    The ONLY channel from trusted run state to a model adapter. Copies, freezes,
    and redacts. `remaining_steps` is clamped at zero so a model can never see a
    negative budget even if trusted state is somehow inconsistent.
    """
    return ModelView(
        run_id=record.ctx.run,
        remaining_steps=max(0, budget.max_steps - record.steps_taken),
        history=tuple(
            ModelStepView(
                verb=s.proposal.verb,
                resource=s.proposal.resource,
                outcome=s.outcome,
                tool_result=s.tool_result,
            )
            for s in record.history
        ),
    )


# --------------------------------------------------------------------------- #
# Budget.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Budget:
    """Per-run hard limit. max_steps counts EXECUTED actions (and, by default,
    also counts denied attempts so a model cannot burn infinite attempts).
    """
    max_steps: int
    count_denied_attempts: bool = True

    def __post_init__(self):
        if not isinstance(self.max_steps, int) or self.max_steps < 0:
            raise ValueError("budget max_steps must be a non-negative int")


# --------------------------------------------------------------------------- #
# Tool boundary.
# --------------------------------------------------------------------------- #

class Tool(Protocol):
    """A tool executes an authorized action. In M2 tools are mock/local; no real
    network. A tool is only ever called for an ALLOWed action.
    """
    def __call__(self, proposal: Proposal) -> str: ...


class ToolRegistry:
    """Maps a verb to a tool. Only authorized actions are dispatched here."""
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, verb: str, tool: Tool) -> None:
        self._tools[verb] = tool

    def get(self, verb: str) -> Optional[Tool]:
        return self._tools.get(verb)


# --------------------------------------------------------------------------- #
# Model client (proposes actions). Abstracted so the engine is model-agnostic.
# --------------------------------------------------------------------------- #

class ModelClient(Protocol):
    """Produces the next Proposal given the run so far, or None to stop.

    The engine treats every proposal as UNTRUSTED. The model may be a script, a
    mock, or a real local LLM; the engine does not care.

    A ModelClient receives a ModelView, NOT a RunRecord. This is a trust
    boundary, not a convenience: a ModelClient implementation is untrusted code
    (it wraps an untrusted provider), so it must not be able to reach trusted
    execution state. See RunRecord's docstring for what happened when it could.
    """
    def next_proposal(self, view: ModelView) -> Optional[Proposal]: ...


class ScriptedModel:
    """Deterministic model that emits a fixed list of proposals in order, then
    stops. Used by all tests and CI so the engine's security properties are
    reproducible.
    """
    def __init__(self, proposals: list[Proposal]):
        self._proposals = list(proposals)
        self._i = 0

    def next_proposal(self, view: ModelView) -> Optional[Proposal]:
        if self._i >= len(self._proposals):
            return None
        p = self._proposals[self._i]
        self._i += 1
        return p


# --------------------------------------------------------------------------- #
# Execution engine (the loop).
# --------------------------------------------------------------------------- #

# A hook the tests use to inject an event (e.g. a revocation) BETWEEN the
# propose-time authorization and the execute-time re-check, to exercise the
# revoke race deterministically. In production this is None.
PreExecuteHook = Optional[Callable[["ExecutionEngine", Proposal], None]]


class ExecutionEngine:
    def __init__(
        self,
        monitor: ReferenceMonitor,
        tools: ToolRegistry,
        budget: Budget,
        pre_execute_hook: PreExecuteHook = None,
    ):
        """The engine authorizes exclusively through `monitor`, and its capability
        store is, by construction, the monitor's store.

        The engine used to take a separate `store` argument. That permitted a
        divergent state where `monitor` authorized against store A while
        `engine.store` (used by hooks and any revocation path) pointed at store B.
        Both authorization checks read `monitor.store`, so revoking `engine.store`
        was a silent no-op and the action executed anyway. The store was a
        parallel reference with no authority that looked like it had some.

        There is now no way to supply a second store. `self.store` is exactly the
        monitor's store, so anything that revokes through `engine.store` revokes
        the store the monitor actually reads. See
        tests/test_m2_m3_trust_boundaries.py::test_engine_store_must_be_the_monitors_store.
        """
        self.monitor = monitor
        self.store = monitor.store   # the ONLY capability store; not a copy, not a second ref
        self.tools = tools
        self.budget = budget
        self._pre_execute_hook = pre_execute_hook

        # Validate at construction so misuse fails closed HERE, not deep in a run.
        # Removing the old `store` parameter means an old-style call
        # ExecutionEngine(monitor, store, tools, budget) would otherwise bind
        # `store` into `tools` and `tools` into `budget` and construct silently,
        # surfacing only as a confusing AttributeError mid-run. Reject that now.
        if not isinstance(monitor, ReferenceMonitor):
            raise TypeError("monitor must be a ReferenceMonitor")
        if not isinstance(tools, ToolRegistry):
            raise TypeError(
                "tools must be a ToolRegistry; the engine no longer takes a "
                "separate store argument (it derives store from monitor)"
            )
        if not isinstance(budget, Budget):
            raise TypeError("budget must be a Budget")
        if pre_execute_hook is not None and not callable(pre_execute_hook):
            raise TypeError("pre_execute_hook must be callable or None")

    def _authorize(self, ctx: RunContext, proposal: Proposal) -> Decision:
        return self.monitor.authorize(ctx, proposal)

    def step(self, record: RunRecord, proposal: Proposal) -> StepResult:
        """Run one proposal through the trusted pipeline.

        Order matters and is security-relevant:
          1. Budget check (fail closed if exhausted).
          2. Authorize at PROPOSE time.
          3. [hook: a revocation may fire here in tests]
          4. Re-authorize at EXECUTE time (double authorization). If the second
             decision is not ALLOW, the action does NOT execute, even though it
             was allowed a moment ago. This closes the revoke-during-execution
             race: authorization is checked against current state at the instant
             of execution, not against a stale earlier decision.
          5. Dispatch to the tool only on a confirmed ALLOW.
        """
        # 1. Budget.
        if record.steps_taken >= self.budget.max_steps:
            record.state = RunState.ABORTED
            res = StepResult(StepOutcome.BUDGET_EXHAUSTED, proposal,
                             audit_reason="run budget exhausted")
            record.history.append(res)
            return res

        # 2. Authorize at propose time.
        first = self._authorize(record.ctx, proposal)
        # Count the attempt against the budget (denied attempts count too, so a
        # hostile model cannot burn unlimited attempts probing the boundary).
        if self.budget.count_denied_attempts or first.verdict == Verdict.ALLOW:
            record.steps_taken += 1

        if first.verdict == Verdict.DENY:
            res = StepResult(StepOutcome.DENIED, proposal,
                             audit_reason=first.audit_reason)
            record.history.append(res)
            return res
        if first.verdict == Verdict.REQUIRE_APPROVAL:
            res = StepResult(StepOutcome.APPROVAL, proposal,
                             audit_reason=first.audit_reason)
            record.history.append(res)
            return res

        # 3. Test hook: a revocation may fire here, between the two checks.
        if self._pre_execute_hook is not None:
            self._pre_execute_hook(self, proposal)

        # 4. Re-authorize at execute time (double authorization / revoke race).
        second = self._authorize(record.ctx, proposal)
        if second.verdict != Verdict.ALLOW:
            res = StepResult(StepOutcome.REVOKED_RACE, proposal,
                             audit_reason="authorization lost between propose and "
                                          "execute (revoke race); action not executed")
            record.history.append(res)
            return res

        # 5. Dispatch to the tool (only reached on a confirmed ALLOW).
        tool = self.tools.get(proposal.verb)
        if tool is None:
            # No tool for an authorized verb: treat as executed no-op with note.
            res = StepResult(StepOutcome.EXECUTED, proposal,
                             audit_reason="authorized; no tool registered",
                             tool_result=None)
            record.history.append(res)
            return res
        try:
            out = tool(proposal)
        except Exception as e:  # a tool failure must not crash the run
            record.state = RunState.FAILED
            res = StepResult(StepOutcome.TOOL_ERROR, proposal,
                             audit_reason=f"tool raised: {type(e).__name__}: {e}")
            record.history.append(res)
            return res
        res = StepResult(StepOutcome.EXECUTED, proposal, tool_result=out)
        record.history.append(res)
        return res

    def run(self, ctx: RunContext, model: ModelClient) -> RunRecord:
        """Drive a full run: pull proposals from the model until it stops or the
        budget is exhausted, stepping each through the trusted pipeline.

        TERMINATION IS STRUCTURAL. The loop is bounded by `range(max_steps)`, a
        local counter that is never derived from, and never written by, anything
        the model can reach. The old loop guard read `record.steps_taken`, which
        was the same field the model could write, so a model that drove it
        negative made the loop unbounded. Now, even if trusted state were somehow
        corrupted, this loop cannot iterate more than `max_steps` times.

        `record.steps_taken` is still enforced in step() and still authoritative
        for the budget verdict. It is no longer the only thing standing between a
        hostile model and an infinite run.
        """
        record = RunRecord(ctx=ctx, state=RunState.RUNNING)

        for _ in range(self.budget.max_steps):
            # The budget is still checked against trusted state; the loop ceiling
            # above is an INDEPENDENT second bound, not a replacement for it.
            if record.steps_taken >= self.budget.max_steps:
                record.state = RunState.ABORTED
                break

            # The model sees a frozen, redacted copy. Never the record itself.
            proposal = model.next_proposal(to_model_view(record, self.budget))
            if proposal is None:
                break

            result = self.step(record, proposal)
            if result.outcome == StepOutcome.BUDGET_EXHAUSTED:
                record.state = RunState.ABORTED
                break
            if result.outcome == StepOutcome.TOOL_ERROR:
                # already marked FAILED; stop the run
                break
        else:
            # The loop ran to its full ceiling without the model stopping: the
            # model had more to say than its budget allowed. That is an abort,
            # not a completion.
            if record.state == RunState.RUNNING:
                record.state = RunState.ABORTED

        if record.state == RunState.RUNNING:
            record.state = RunState.COMPLETED
        return record
