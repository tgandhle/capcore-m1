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
from capcore.broker import (
    AuthorizationError, ExecutionProposal, SanitizedToolResult,
    TrustedExecutionBroker,
)


# --------------------------------------------------------------------------- #
# Run state machine (trusted).
# --------------------------------------------------------------------------- #

class RunState(Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"      # the model said it was done
    ABORTED = "aborted"          # budget exhausted or ceiling reached
    FAILED = "failed"            # a tool raised, or the model provider died


class StopReason(Enum):
    """WHY a run ended. Distinct from RunState, which says only THAT it ended.

    The engine used to have exactly one channel for "no proposal": the model
    returning None. A clean finish and a dead provider produced byte-identical
    terminal state, so a run that crashed on its first call to a broken Ollama
    server reported COMPLETED. Success and failure were indistinguishable in
    trusted state, which is a correctness defect and an audit defect: nothing
    downstream could tell whether the work was actually done.
    """
    MODEL_FINISHED = "model_finished"            # the model chose to stop
    BUDGET_EXHAUSTED = "budget_exhausted"        # ran out of authorized actions
    CEILING_REACHED = "ceiling_reached"          # loop bound hit (see run())
    MODEL_ERROR = "model_error"                  # the adapter raised
    PROVIDER_UNAVAILABLE = "provider_unavailable"  # the model provider failed
    TOOL_FAILED = "tool_failed"                  # a tool raised during execution


class StepOutcome(Enum):
    EXECUTED = "executed"        # authorized and ran
    DENIED = "denied"            # monitor denied
    APPROVAL = "approval"        # monitor requires human approval (not executed)
    REVOKED_RACE = "revoked_race"  # authorized at propose, revoked before execute
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOOL_ERROR = "tool_error"    # tool raised during execution
    TOOL_NOT_FOUND = "tool_not_found"    # no such registration: NOTHING RAN
    TOOL_NOT_AUTHORIZED = "tool_not_authorized"  # registered but not policy-granted


@dataclass(frozen=True)
class StepResult:
    outcome: StepOutcome
    proposal: Proposal
    # audit-only detail; never surfaced to the model
    audit_reason: str = ""
    # The SANITIZED result from the broker. Never a Secret, never a raw exception.
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
    # WHY the run ended. None while running. Set exactly once, at termination.
    stop_reason: Optional[StopReason] = None


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

# NOTE: the engine has NO tool registry.
#
# There was a `ToolRegistry` here, keyed by verb. It is gone, and its absence is
# a security property, not a simplification:
#
#   1. TWO REGISTRIES CAN DISAGREE. An engine-side verb->tool map plus a
#      broker-side registration->adapter map is two trusted structures that must
#      be kept in sync. That is precisely the monitor-store / engine-store defect
#      in a new costume, and it is not repeated. There is exactly ONE catalog and
#      the broker owns it.
#
#   2. VERB IS NOT AN EXECUTOR. Routing by verb collapses the action class into
#      the concrete tool: one `read` implementation, forever. But
#      `read_customer_record` and `read_payroll_database` are both `read`. The
#      executor is named by the model (untrusted) and authorized by the broker's
#      ToolPolicy, which is deny-by-default.
#
# The engine therefore cannot dispatch around the broker. It has no adapter to
# call. Tests assert `not hasattr(engine, "tools")`.


# --------------------------------------------------------------------------- #
# Model client (proposes actions). Abstracted so the engine is model-agnostic.
# --------------------------------------------------------------------------- #

class ModelOutcome(Enum):
    PROPOSAL = "proposal"        # the model proposed an action
    FINISHED = "finished"        # the model chose to stop. Real completion.
    ERROR = "error"              # the provider or adapter failed. NOT completion.


@dataclass(frozen=True)
class ModelResult:
    """What a ModelClient returns.

    A bare `Optional[Proposal]` was the defect: None meant BOTH "I am done" and
    "my provider is down", and the engine could not tell them apart, so a crashed
    run reported COMPLETED. The type now forces the adapter to say which.

    Adapters that cannot distinguish the two (a raw HTTP client that swallows its
    own exceptions, say) must not paper over it by returning FINISHED. Return
    ERROR: an unknown outcome is a failure, not a success.
    """
    outcome: ModelOutcome
    proposal: Optional["ExecutionProposal"] = None

    @staticmethod
    def propose(p: "ExecutionProposal") -> "ModelResult":
        return ModelResult(ModelOutcome.PROPOSAL, p)

    @staticmethod
    def finished() -> "ModelResult":
        return ModelResult(ModelOutcome.FINISHED)

    @staticmethod
    def error() -> "ModelResult":
        return ModelResult(ModelOutcome.ERROR)


class ModelClient(Protocol):
    """Produces the next ExecutionProposal, or None to stop.

    The engine treats every proposal as UNTRUSTED, including the executor the
    model names. An ExecutionProposal carries BOTH the security action (verb +
    resource, which the monitor authorizes) AND the concrete tool the model wants
    to run it (which the broker's deny-by-default ToolPolicy authorizes
    separately). Naming a tool does not entitle the model to it.

    A ModelClient receives a ModelView, NOT a RunRecord. This is a trust boundary,
    not a convenience: a ModelClient implementation is untrusted code (it wraps an
    untrusted provider), so it must not be able to reach trusted execution state.
    See RunRecord's docstring for what happened when it could.
    """
    def next_proposal(self, view: ModelView) -> ModelResult: ...


class ScriptedModel:
    """Deterministic model that emits a fixed list of proposals in order, then
    finishes. Used by all tests and CI so the engine's security properties are
    reproducible.
    """
    def __init__(self, proposals: list[ExecutionProposal]):
        self._proposals = list(proposals)
        self._i = 0

    def next_proposal(self, view: ModelView) -> ModelResult:
        if self._i >= len(self._proposals):
            return ModelResult.finished()
        p = self._proposals[self._i]
        self._i += 1
        return ModelResult.propose(p)


# --------------------------------------------------------------------------- #
# Execution engine (the loop).
# --------------------------------------------------------------------------- #

# A hook the tests use to inject an event (e.g. a revocation) BETWEEN the
# propose-time authorization and the execute-time re-check, to exercise the
# revoke race deterministically. In production this is None.
# The hook receives the LIVE RunRecord as well as the engine and proposal. Tests
# use it to fire a revocation between propose-time authorization and dispatch, and
# to corrupt trusted counter state in order to prove that run()'s loop ceiling
# bounds the run INDEPENDENTLY of that counter. Production passes None.
PreExecuteHook = Optional[
    Callable[["ExecutionEngine", ExecutionProposal, "RunRecord"], None]
]


class ExecutionEngine:
    def __init__(
        self,
        monitor: ReferenceMonitor,
        broker: TrustedExecutionBroker,
        budget: Budget,
        pre_execute_hook: PreExecuteHook = None,
    ):
        """The engine authorizes through `monitor` and EXECUTES through `broker`.

        It owns no tool catalog and holds no adapter. There is no path from here
        to a running tool that does not go through the broker, which is the point:
        the credential boundary cannot be bypassed by a caller who happens to have
        an engine.

        `self.store` is exactly `monitor.store`, never a second reference. An
        earlier version took a separate `store` argument, which permitted a
        divergent state where the monitor authorized against store A while
        `engine.store` (used by hooks and revocation paths) pointed at store B.
        Both authorization checks read `monitor.store`, so revoking `engine.store`
        was a silent no-op and the action executed anyway.
        """
        self.monitor = monitor
        self.store = monitor.store   # the ONLY capability store
        self.broker = broker
        self.budget = budget
        self._pre_execute_hook = pre_execute_hook

        # Fail closed at construction, not deep in a run.
        if not isinstance(monitor, ReferenceMonitor):
            raise TypeError("monitor must be a ReferenceMonitor")
        if not isinstance(broker, TrustedExecutionBroker):
            raise TypeError(
                "broker must be a TrustedExecutionBroker; the engine no longer "
                "owns a tool registry and cannot execute anything without one"
            )
        if not isinstance(budget, Budget):
            raise TypeError("budget must be a Budget")
        if pre_execute_hook is not None and not callable(pre_execute_hook):
            raise TypeError("pre_execute_hook must be callable or None")

    def _authorize(self, ctx: RunContext, action: Proposal) -> Decision:
        return self.monitor.authorize(ctx, action)

    def step(self, record: RunRecord, proposal: ExecutionProposal) -> StepResult:
        """Run one ExecutionProposal through the trusted pipeline.

        Order is security-relevant:
          1. Budget (fail closed if exhausted).
          2. Authorize the ACTION at propose time. This drives control flow and
             audit. It is NOT what the broker trusts.
          3. [hook: a revocation may fire here in tests]
          4. Hand off to the broker, which authorizes INDEPENDENTLY at mint and
             AGAIN at redemption. The engine's decision is never passed along as
             proof of anything: the broker does not accept caller-supplied
             verdicts.

        The double-authorization that used to live here (propose-time then
        execute-time re-check) has not been weakened; it has MOVED INTO the
        broker, where the re-check happens immediately before the credential is
        touched. A capability revoked between propose and execute stops the
        action at redemption, and the tool never runs.
        """
        action = proposal.action

        # 1. Budget.
        if record.steps_taken >= self.budget.max_steps:
            record.state = RunState.ABORTED
            res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,
                             audit_reason="run budget exhausted")
            record.history.append(res)
            return res

        # 2. Propose-time authorization (control flow + audit).
        first = self._authorize(record.ctx, action)
        if self.budget.count_denied_attempts or first.verdict == Verdict.ALLOW:
            record.steps_taken += 1

        if first.verdict == Verdict.DENY:
            res = StepResult(StepOutcome.DENIED, action,
                             audit_reason=first.audit_reason)
            record.history.append(res)
            return res
        if first.verdict == Verdict.REQUIRE_APPROVAL:
            res = StepResult(StepOutcome.APPROVAL, action,
                             audit_reason=first.audit_reason)
            record.history.append(res)
            return res

        # 3. Test hook: a revocation may fire here, between propose and execute.
        if self._pre_execute_hook is not None:
            self._pre_execute_hook(self, proposal, record)

        # 4. Mint. The broker re-authorizes on its own; it does not take `first`.
        #    A tool the model named but is not policy-authorized dies here.
        try:
            action_id = self.broker.register_authorized_execution(record.ctx, proposal)
        except AuthorizationError as e:
            # The broker refused. WHY it refused matters for audit, and lumping
            # every refusal under REVOKED_RACE was false reporting: a model naming
            # a tool that does not exist is not a revocation race.
            reason = str(e)
            if "unknown tool registration" in reason:
                outcome = StepOutcome.TOOL_NOT_FOUND
            elif "not authorized" in reason and "tool" in reason:
                outcome = StepOutcome.TOOL_NOT_AUTHORIZED
            elif "verb does not match" in reason:
                outcome = StepOutcome.TOOL_NOT_AUTHORIZED
            else:
                # authorization for the ACTION was lost between propose and mint
                outcome = StepOutcome.REVOKED_RACE
            res = StepResult(outcome, action,
                             audit_reason=f"broker refused authorization: {reason}")
            record.history.append(res)
            return res

        # 5. Redeem. The broker re-authorizes AGAIN, resolves the tool and
        #    credential from its own state, executes inside its boundary, and
        #    returns a sanitized result. No Secret crosses back.
        result: SanitizedToolResult = self.broker.redeem_and_execute(action_id)

        if result.ok:
            res = StepResult(StepOutcome.EXECUTED, action, tool_result=result.body)
            record.history.append(res)
            return res

        if result.code == "authorization_refused":
            res = StepResult(StepOutcome.REVOKED_RACE, action,
                             audit_reason="authorization lost before execution")
            record.history.append(res)
            return res

        record.state = RunState.FAILED
        record.stop_reason = StopReason.TOOL_FAILED
        res = StepResult(StepOutcome.TOOL_ERROR, action,
                         audit_reason=f"tool failed: {result.code}")
        record.history.append(res)
        return res

    def run(self, ctx: RunContext, model: ModelClient) -> RunRecord:
        """Drive a full run. Every termination path sets a stop_reason.

        TERMINATION IS STRUCTURAL. The loop is bounded by `range(max_steps)`, a
        local counter never derived from, and never written by, anything the model
        can reach. The old loop guard read `record.steps_taken`, the same field an
        untrusted model could write, so a model that drove it negative made the
        loop unbounded. Even if trusted counter state were corrupted, this loop
        cannot iterate more than max_steps times.

        TERMINAL STATE IS HONEST. A run that ends because the model provider died
        does not report COMPLETED. `stop_reason` says which of MODEL_FINISHED,
        BUDGET_EXHAUSTED, CEILING_REACHED, MODEL_ERROR, PROVIDER_UNAVAILABLE, or
        TOOL_FAILED ended it. Nothing downstream has to guess whether the work was
        actually done.
        """
        record = RunRecord(ctx=ctx, state=RunState.RUNNING)

        for _ in range(self.budget.max_steps):
            # Budget is still checked against trusted state; the ceiling above is
            # an INDEPENDENT second bound, not a replacement for it.
            if record.steps_taken >= self.budget.max_steps:
                record.state = RunState.ABORTED
                record.stop_reason = StopReason.BUDGET_EXHAUSTED
                return record

            # The model sees a frozen, redacted copy. Never the record itself.
            try:
                result = model.next_proposal(to_model_view(record, self.budget))
            except Exception:
                # A ModelClient that raises is a failed provider, not a finished
                # one. Fail closed: no more actions, and say so.
                record.state = RunState.FAILED
                record.stop_reason = StopReason.MODEL_ERROR
                return record

            if not isinstance(result, ModelResult):
                # An adapter that does not speak the typed protocol cannot be
                # trusted to mean "finished" by returning None. Treat as failure.
                record.state = RunState.FAILED
                record.stop_reason = StopReason.MODEL_ERROR
                return record

            if result.outcome is ModelOutcome.ERROR:
                record.state = RunState.FAILED
                record.stop_reason = StopReason.PROVIDER_UNAVAILABLE
                return record

            if result.outcome is ModelOutcome.FINISHED:
                record.state = RunState.COMPLETED
                record.stop_reason = StopReason.MODEL_FINISHED
                return record

            if result.proposal is None:
                # PROPOSAL with nothing to propose is a malformed adapter.
                record.state = RunState.FAILED
                record.stop_reason = StopReason.MODEL_ERROR
                return record

            step_result = self.step(record, result.proposal)

            if step_result.outcome == StepOutcome.BUDGET_EXHAUSTED:
                record.state = RunState.ABORTED
                record.stop_reason = StopReason.BUDGET_EXHAUSTED
                return record
            if step_result.outcome == StepOutcome.TOOL_ERROR:
                # step() already marked FAILED and set TOOL_FAILED
                return record

        # The loop ran to its full ceiling without the model finishing: it had more
        # to say than its budget allowed. That is an abort, not a completion.
        record.state = RunState.ABORTED
        record.stop_reason = StopReason.CEILING_REACHED
        return record
