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
    AuthorizationError, ExecutionProposal, MintRefusal, MintRefused,
    SanitizedToolResult, TrustedExecutionBroker,
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
    ADAPTER_LIMIT_REACHED = "adapter_limit_reached"  # a ModelClient hit its own
    #                        cap (e.g. OllamaModel.max_proposals). NOT a task
    #                        completion: the adapter stopped asking, the model did
    #                        not say it was done.


class StepOutcome(Enum):
    EXECUTED = "executed"        # authorized and ran
    DENIED = "denied"            # monitor denied
    APPROVAL = "approval"        # monitor requires human approval (not executed)
    REVOKED_RACE = "revoked_race"  # authorized at propose, revoked before execute
    BUDGET_EXHAUSTED = "budget_exhausted"
    TOOL_ERROR = "tool_error"    # tool raised during execution
    TOOL_NOT_FOUND = "tool_not_found"    # no such registration: NOTHING RAN
    TOOL_NOT_AUTHORIZED = "tool_not_authorized"  # registered but not policy-granted
    CREDENTIAL_REFUSED = "credential_refused"    # credential expired/consumed/
    #                     scope/verb mismatch: distinct from a revoke race
    INTEGRITY_REFUSED = "integrity_refused"      # digest/tool-generation mismatch
    AUTHORIZATION_REFUSED = "authorization_refused"  # unredeemable pending auth
    #                     (unknown id, expired, already redeemed): NOT a revoke race
    MALFORMED_PROPOSAL = "malformed_proposal"    # the model produced an invalid
    #                     action (bad types, oversized, invalid resource): a model
    #                     error, NOT a policy denial. Raw fields are NOT retained.


def _redacted_action(action) -> "Proposal":
    """A safe, bounded stand-in for a malformed action, for trusted history.

    NEVER retain the raw untrusted fields of an invalid proposal: they may be
    megabytes, malformed unicode, or otherwise hostile, and they would flow into
    ModelView and subsequent prompts. This returns a small fixed Proposal so
    history records THAT a malformed action occurred without storing WHAT it was.
    The detail belongs in a bounded audit_reason string, not in the retained
    action.
    """
    from capcore import Proposal
    return Proposal("<redacted>", "<redacted>")


def _map_mint_refusal(code: "MintRefusal") -> "StepOutcome":
    """Map a typed MintRefusal code to a StepOutcome. Never REVOKED_RACE.

    A mint refusal means the broker declined to authorize an execution: the tool
    is unknown/unauthorized, the verb mismatched, the action was malformed, the
    catalog was unsealed, or the id space was exhausted. None of these is a revoke
    race (an authorization that was valid earlier and lost at live re-auth); each
    is its own honest outcome.
    """
    return {
        MintRefusal.UNKNOWN_TOOL: StepOutcome.TOOL_NOT_FOUND,
        MintRefusal.TOOL_NOT_AUTHORIZED: StepOutcome.TOOL_NOT_AUTHORIZED,
        MintRefusal.TOOL_VERB_MISMATCH: StepOutcome.TOOL_NOT_AUTHORIZED,
        # The action was authorized at propose-time but the broker's INDEPENDENT
        # re-authorization at mint denied it: authority was valid at an earlier
        # trusted check and lost before execution. That is exactly the revoke
        # race REVOKED_RACE names.
        MintRefusal.ACTION_NOT_AUTHORIZED: StepOutcome.REVOKED_RACE,
        MintRefusal.MALFORMED_ACTION: StepOutcome.MALFORMED_PROPOSAL,
        MintRefusal.NOT_AN_EXECUTION_PROPOSAL: StepOutcome.MALFORMED_PROPOSAL,
        MintRefusal.ACTION_NOT_UTF8: StepOutcome.MALFORMED_PROPOSAL,
        # An exhausted id space or an unsealed catalog is an internal/config error,
        # not a policy or revoke outcome. Neutral authorization refusal.
        MintRefusal.ACTION_ID_EXHAUSTED: StepOutcome.AUTHORIZATION_REFUSED,
        MintRefusal.CATALOG_NOT_SEALED: StepOutcome.AUTHORIZATION_REFUSED,
    }.get(code, StepOutcome.AUTHORIZATION_REFUSED)


def _map_refusal(audit_code: str) -> tuple["StepOutcome", str]:
    """Map a broker refusal audit_code to an honest StepOutcome.

    Extracted from step() so it is directly testable: exercising the expired /
    unknown / already-redeemed pending-authorization cases end-to-end through the
    engine is not reliably possible (time cannot be injected between the engine's
    internal mint and redeem), so the mapping is unit-tested here instead.

    REVOKED_RACE is reserved for exactly one code: REAUTHORIZATION_FAILED, a live
    capability re-authorization failure. Every other refusal maps to a distinct,
    non-revoke-race outcome. Unknown codes fail closed to a neutral refusal.
    """
    from capcore.broker import BrokerRefusal
    if audit_code == BrokerRefusal.REAUTHORIZATION_FAILED:
        return StepOutcome.REVOKED_RACE, "authorization lost before execution"
    if audit_code in (BrokerRefusal.CREDENTIAL_EXPIRED,
                      BrokerRefusal.CREDENTIAL_CONSUMED,
                      BrokerRefusal.CREDENTIAL_SCOPE_MISMATCH,
                      BrokerRefusal.CREDENTIAL_VERB_MISMATCH,
                      BrokerRefusal.NO_CREDENTIAL):
        return StepOutcome.CREDENTIAL_REFUSED, f"credential refused: {audit_code}"
    if audit_code in (BrokerRefusal.ACTION_DIGEST_MISMATCH,
                      BrokerRefusal.TOOL_CHANGED):
        return StepOutcome.INTEGRITY_REFUSED, f"integrity refused: {audit_code}"
    # Unredeemable pending authorization (expired / unknown / already redeemed),
    # and any unrecognized code: a neutral refusal, never REVOKED_RACE.
    return StepOutcome.AUTHORIZATION_REFUSED, f"authorization refused: {audit_code}"


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

    Handing this object to a ModelClient through the documented API was a defect:
    an adapter could write `record.steps_taken = -100`, and because both the
    `run()` loop guard and the `step()` budget check read that same field, a
    careless (not necessarily hostile) adapter could bypass its budget and produce
    a nonterminating run. `to_model_view()` closes that ACCIDENTAL path.

    It does NOT isolate hostile in-process code. A malicious ModelClient can reach
    this object anyway, via stack inspection or the object graph; under CapCore's
    single-process trust model every in-process component, ModelClient included, is
    TCB (see README "Trust model"). The independent loop ceiling in run() is the
    structural defense against runaway iteration; ModelView is the defense against
    accidental mutation through the interface. See
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
        remaining_steps=max(0, budget.max_actions - record.steps_taken),
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
    """Two SEPARATE per-run limits. They must never share one counter.

    - `max_iterations` is the unconditional LIVENESS ceiling: the loop in run()
      cannot ask the model more than this many times, no matter what. It bounds
      runaway iteration structurally, independent of any model-reachable state.

    - `max_actions` is the AUTHORIZATION/EXECUTION budget: how many actions the
      run may execute (and, if `count_denied_attempts`, how many attempts it may
      make). This is a policy limit on work, not a liveness bound.

    Conflating them (the old single `max_steps`) meant `count_denied_attempts=False`
    could not work: a denied attempt still consumed the shared counter, and a
    single valid action could never be followed by a model-declared completion.

    Backward compatibility: `Budget(n)` or `Budget(max_steps=n)` sets BOTH limits
    to n, preserving the previous single-counter behaviour. New code should pass
    `max_actions` and `max_iterations` explicitly.
    """
    max_actions: int = None
    max_iterations: int = None
    count_denied_attempts: bool = True
    max_steps: int = None            # deprecated alias; sets both when given

    def __post_init__(self):
        # Resolve the compat alias.
        if self.max_steps is not None:
            if self.max_actions is None:
                object.__setattr__(self, "max_actions", self.max_steps)
            if self.max_iterations is None:
                object.__setattr__(self, "max_iterations", self.max_steps)
        # A single positional (max_actions=n) with no iterations defaults the
        # ceiling to the same value, preserving old Budget(n) semantics.
        if self.max_actions is not None and self.max_iterations is None:
            object.__setattr__(self, "max_iterations", self.max_actions)
        if self.max_iterations is not None and self.max_actions is None:
            object.__setattr__(self, "max_actions", self.max_iterations)

        if not isinstance(self.max_actions, int) or self.max_actions < 0:
            raise ValueError("budget max_actions must be a non-negative int")
        if not isinstance(self.max_iterations, int) or self.max_iterations < 0:
            raise ValueError("budget max_iterations must be a non-negative int")
        # keep max_steps populated for any external reader
        object.__setattr__(self, "max_steps", self.max_actions)


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
    LIMIT_REACHED = "limit_reached"  # the ADAPTER hit its own cap. Not completion.


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

    def __post_init__(self):
        # Validate the outcome/payload algebra. A PROPOSAL must carry an actual
        # ExecutionProposal; any other outcome must carry no proposal. This is a
        # near-side guard; run() ALSO validates at the boundary, because it does
        # not control adapter behaviour and a hostile adapter can bypass a
        # constructor by any number of means.
        from capcore.broker import ExecutionProposal
        if self.outcome is ModelOutcome.PROPOSAL:
            if type(self.proposal) is not ExecutionProposal:
                raise TypeError(
                    "a PROPOSAL ModelResult must carry an ExecutionProposal, got "
                    f"{type(self.proposal).__name__}"
                )
        else:
            if self.proposal is not None:
                raise TypeError(
                    f"a {self.outcome.value} ModelResult must not carry a proposal"
                )

    @staticmethod
    def propose(p: "ExecutionProposal") -> "ModelResult":
        return ModelResult(ModelOutcome.PROPOSAL, p)

    @staticmethod
    def finished() -> "ModelResult":
        return ModelResult(ModelOutcome.FINISHED)

    @staticmethod
    def error() -> "ModelResult":
        return ModelResult(ModelOutcome.ERROR)

    @staticmethod
    def limit_reached() -> "ModelResult":
        return ModelResult(ModelOutcome.LIMIT_REACHED)


class ModelClient(Protocol):
    """Produces the next ExecutionProposal, or None to stop.

    The engine treats every proposal as UNTRUSTED, including the executor the
    model names. An ExecutionProposal carries BOTH the security action (verb +
    resource, which the monitor authorizes) AND the concrete tool the model wants
    to run it (which the broker's deny-by-default ToolPolicy authorizes
    separately). Naming a tool does not entitle the model to it.

    A ModelClient receives a ModelView, NOT a RunRecord. The DATA a ModelClient
    produces (its proposals) is untrusted and is authorized before it can act; the
    ModelClient CODE, running in-process, is trusted (see README "Trust model").
    ModelView keeps the documented interface from handing trusted state to the
    adapter by accident. It does not, and cannot, isolate hostile same-interpreter
    code. See RunRecord's docstring.
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
        monitor_or_broker=None,
        broker_=None,
        budget: Budget = None,
        pre_execute_hook: PreExecuteHook = None,
        *,
        monitor: ReferenceMonitor = None,
        broker: "TrustedExecutionBroker" = None,
    ):
        """The engine derives ALL authorization authority from the broker.

        There is a single source of truth for the monitor and the capability
        store: `broker.monitor`. The engine no longer accepts a separate monitor,
        so it is impossible to construct an engine that authorizes control flow
        through monitor A while the broker executes through monitor B. An earlier
        version accepted both and only type-checked them, which let engine and
        broker diverge onto different stores: revoking through one was a silent
        no-op and the action executed anyway (the split-authority defect, first
        seen as engine.store vs monitor.store, then again here as engine.monitor
        vs broker.monitor).

        Signature note: for backward compatibility with the previous
        `ExecutionEngine(monitor, broker, budget)` call form, a monitor passed in
        the first position is accepted and MUST equal `broker.monitor`, else
        construction fails. New code should call
        `ExecutionEngine(broker, budget)`.
        """
        # Untangle the two accepted call forms:
        #   new:  ExecutionEngine(broker, budget, pre_execute_hook=...)
        #   old:  ExecutionEngine(monitor, broker, budget, pre_execute_hook=...)
        passed_monitor = None
        if isinstance(monitor_or_broker, TrustedExecutionBroker):
            # NEW form: ExecutionEngine(broker, budget, ...)
            broker = monitor_or_broker
            if budget is None and isinstance(broker_, Budget):
                budget = broker_
        elif isinstance(monitor_or_broker, ReferenceMonitor):
            # OLD form: ExecutionEngine(monitor, broker, budget, ...)
            passed_monitor = monitor_or_broker
            if broker is None:
                broker = broker_
        if monitor is not None:
            passed_monitor = monitor

        if not isinstance(broker, TrustedExecutionBroker):
            raise TypeError(
                "ExecutionEngine requires a TrustedExecutionBroker; the engine "
                "derives its monitor and store from broker.monitor"
            )
        if not isinstance(budget, Budget):
            raise TypeError("budget must be a Budget")
        if pre_execute_hook is not None and not callable(pre_execute_hook):
            raise TypeError("pre_execute_hook must be callable or None")

        # If a monitor was passed (old call form), it MUST be the broker's.
        if passed_monitor is not None and passed_monitor is not broker.monitor:
            raise ValueError(
                "engine monitor differs from broker.monitor: split authority is "
                "not permitted. Construct with ExecutionEngine(broker, budget)."
            )

        self.broker = broker
        self.monitor = broker.monitor           # single source of truth
        self.store = broker.monitor.store
        self.budget = budget
        self._pre_execute_hook = pre_execute_hook

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
        # 0. VALIDATE FIRST. step() is the public, history-writing boundary, so
        #    it must enforce the malformed-input invariant BY CONSTRUCTION, not
        #    rely on run() having done so. This runs before the budget check,
        #    because a malformed action must never be stored, not even in a
        #    BUDGET_EXHAUSTED result, and never with its raw (possibly oversized
        #    or malformed-unicode) fields retained.
        from capcore import valid_proposal
        if type(proposal) is not ExecutionProposal:
            record.state = RunState.FAILED
            record.stop_reason = StopReason.MODEL_ERROR
            res = StepResult(StepOutcome.MALFORMED_PROPOSAL,
                             _redacted_action(None),
                             audit_reason="step called with a non-ExecutionProposal")
            record.history.append(res)
            return res

        action = proposal.action

        if not valid_proposal(action):
            record.state = RunState.FAILED
            record.stop_reason = StopReason.MODEL_ERROR
            res = StepResult(StepOutcome.MALFORMED_PROPOSAL,
                             _redacted_action(action),
                             audit_reason="model proposal was malformed or exceeded size limits")
            record.history.append(res)
            return res

        # 1. THE BUDGET GATE, WHOSE POSITION DEPENDS ON THE MODE.
        #
        # The two budget modes mean different things and therefore need different
        # orderings. Review 8 moved the gate after authorization to fix the
        # non-counting mode, and applied that ordering to BOTH, which silently
        # disabled the attempt budget in the counting mode.
        #
        #   count_denied_attempts=True   max_actions is an ATTEMPT budget: how many
        #                                proposals the model may put to the monitor
        #                                at all. So it must be checked BEFORE
        #                                authorization, or the run authorizes,
        #                                classifies, and counts an attempt it had no
        #                                budget for. (max_actions=1 with one attempt
        #                                spent still produced a DENIED and
        #                                steps_taken=2.)
        #
        #   count_denied_attempts=False  max_actions is an EXECUTION budget: only
        #                                actions that actually run consume it. An M1
        #                                denial must therefore keep its honest
        #                                classification (DENIED, not
        #                                BUDGET_EXHAUSTED) even once the budget is
        #                                spent, so the gate comes AFTER
        #                                authorization. This is the Review 8
        #                                invariant and it must not regress.
        #
        # The structural max_iterations ceiling (in run()) is what prevents an
        # unbounded loop; it always applied and still does. This is about policy
        # semantics: what max_actions is a budget FOR.
        if self.budget.count_denied_attempts:
            if record.steps_taken >= self.budget.max_actions:
                record.state = RunState.ABORTED
                res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,
                                 audit_reason="run budget exhausted")
                record.history.append(res)
                return res

        # 2. Propose-time authorization (control flow + audit). In the NON-counting
        #    mode this precedes the budget gate on purpose: M1's classification
        #    (DENY / REQUIRE_APPROVAL) must survive execution-budget exhaustion, so
        #    an out-of-scope proposal is DENIED, not BUDGET_EXHAUSTED, even when the
        #    budget is spent.
        first = self._authorize(record.ctx, action)

        # Budget accounting for DENIED / APPROVAL happens here ONLY when the run
        # counts denied attempts (and the gate above has already confirmed there
        # was budget for this attempt). With count_denied_attempts=False, an M1
        # denial or approval classification does not consume the ACTION budget; the
        # count for an authorized action is deferred until the broker actually
        # mints an authorization (execution attempted). See the mint site below.
        if self.budget.count_denied_attempts and first.verdict != Verdict.ALLOW:
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

        # 3. Budget gate for the NON-counting mode, AFTER M1 classification. Only an
        #    ALLOWed action that would actually execute is subject to the execution
        #    budget; a denial or approval has already returned above with its honest
        #    classification. In the counting mode this was already checked at step 1,
        #    so it is skipped here rather than double-gated.
        if not self.budget.count_denied_attempts:
            if record.steps_taken >= self.budget.max_actions:
                record.state = RunState.ABORTED
                res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,
                                 audit_reason="run budget exhausted")
                record.history.append(res)
                return res

        # 3. Test hook: a revocation may fire here, between propose and execute.
        if self._pre_execute_hook is not None:
            self._pre_execute_hook(self, proposal, record)

        # 4. Mint. The broker re-authorizes on its own; it does not take `first`.
        #    A tool the model named but is not policy-authorized dies here.
        try:
            action_id = self.broker.register_authorized_execution(record.ctx, proposal)
        except MintRefused as e:
            # The broker refused, with a TYPED code. Classify by code, never by
            # parsing the message. A refusal here means nothing executed; with
            # count_denied_attempts=False it does not consume the action budget.
            if self.budget.count_denied_attempts:
                record.steps_taken += 1
            outcome = _map_mint_refusal(e.code)
            res = StepResult(outcome, action,
                             audit_reason=f"broker refused mint: {e.code.value}")
            record.history.append(res)
            return res
        except AuthorizationError as e:
            # A non-typed authorization error (older path or a subclass without a
            # code). Fail closed to a neutral refusal, NOT a revoke race.
            if self.budget.count_denied_attempts:
                record.steps_taken += 1
            res = StepResult(StepOutcome.AUTHORIZATION_REFUSED, action,
                             audit_reason=f"broker refused authorization: {e}")
            record.history.append(res)
            return res

        # The broker minted an authorization: execution is now being attempted,
        # which may produce an external effect. Count it exactly once here, for
        # BOTH budget modes.
        record.steps_taken += 1

        # 5. Redeem. The broker re-authorizes AGAIN, resolves the tool and
        #    credential from its own state, executes inside its boundary, and
        #    returns a sanitized result. No Secret crosses back.
        result: SanitizedToolResult = self.broker.redeem_and_execute(action_id)

        if result.ok:
            res = StepResult(StepOutcome.EXECUTED, action, tool_result=result.body)
            record.history.append(res)
            return res

        if result.code == "authorization_refused":
            # Map the broker's SPECIFIC audit_code to an honest outcome. Only a
            # live capability re-authorization failure is a revoke race; a
            # credential that expired or was consumed, a scope/verb mismatch, or a
            # digest/tool-generation change are distinct conditions and must not be
            # mislabeled REVOKED_RACE. The model still saw only the generic code.
            outcome, why = _map_refusal(result.audit_code)
            res = StepResult(outcome, action, audit_reason=why)
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

        for _ in range(self.budget.max_iterations):
            # The loop is bounded by max_iterations (liveness). The ACTION budget
            # is enforced in step() when an action is actually attempted, NOT as a
            # pre-model gate here: gating before asking the model would abort a run
            # that has spent its actions but whose model still wants to declare
            # completion. A model must always be allowed to finish.

            # The model sees a frozen, redacted copy. Never the record itself.
            try:
                result = model.next_proposal(to_model_view(record, self.budget))
            except Exception:
                # A ModelClient that raises is a failed provider, not a finished
                # one. Fail closed: no more actions, and say so.
                record.state = RunState.FAILED
                record.stop_reason = StopReason.MODEL_ERROR
                return record

            if type(result) is not ModelResult:
                # An adapter that does not return an exact ModelResult cannot be
                # trusted to mean "finished". A subclass could override behaviour;
                # a None or look-alike is not the protocol. Fail closed.
                record.state = RunState.FAILED
                record.stop_reason = StopReason.MODEL_ERROR
                return record

            from capcore.broker import ExecutionProposal
            outcome = result.outcome

            if outcome is ModelOutcome.ERROR:
                record.state = RunState.FAILED
                record.stop_reason = StopReason.PROVIDER_UNAVAILABLE
                return record

            elif outcome is ModelOutcome.FINISHED:
                record.state = RunState.COMPLETED
                record.stop_reason = StopReason.MODEL_FINISHED
                return record

            elif outcome is ModelOutcome.LIMIT_REACHED:
                # The adapter stopped asking; the model did not say it was done.
                # That is an abort, not a completion: the task may be unfinished.
                record.state = RunState.ABORTED
                record.stop_reason = StopReason.ADAPTER_LIMIT_REACHED
                return record

            elif outcome is ModelOutcome.PROPOSAL:
                # A PROPOSAL must carry a real ExecutionProposal. run() checks this
                # at the boundary, not only in ModelResult.__post_init__, because
                # it does not control the adapter: a hostile or buggy adapter can
                # construct a ModelResult by paths that skip validation. A
                # malformed proposal fails closed here, never reaching step().
                if type(result.proposal) is not ExecutionProposal:
                    record.state = RunState.FAILED
                    record.stop_reason = StopReason.MODEL_ERROR
                    return record
                # The ACTION itself must be well-formed (valid types, in-bounds
                # sizes, valid resource) BEFORE it can enter step() and thus
                # trusted history / ModelView. An oversized or malformed action is
                # a MODEL_ERROR (the model produced a bad action), NOT a policy
                # DENY (which implies a valid action was evaluated). Crucially,
                # the raw action must not be retained anywhere: we record safe
                # metadata only and drop the field.
                from capcore import valid_proposal
                if not valid_proposal(result.proposal.action):
                    record.state = RunState.FAILED
                    record.stop_reason = StopReason.MODEL_ERROR
                    record.history.append(StepResult(
                        StepOutcome.MALFORMED_PROPOSAL,
                        _redacted_action(result.proposal.action),
                        audit_reason="model proposal was malformed or exceeded size limits",
                    ))
                    return record
                # fall through to dispatch below

            else:
                # ANY outcome outside the explicit algebra fails closed. This is
                # the whole point: unknown outcomes must not fall through and be
                # treated as a proposal. Covers a bypassed __post_init__, a future
                # enum member the loop does not handle, or a corrupted value.
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
