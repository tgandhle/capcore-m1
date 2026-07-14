"""Adversarial reproductions from the ninth review round.

A focused follow-up to Review 8: every finding here is a place where a Review 8
fix was narrower than the invariant it was documented as establishing.

  F1  HttpTool.execute_with_credential turns ANY status into a success string, so
      a 500/403/302 from the allowed endpoint is reported as StepOutcome.EXECUTED
      with a "http 500 from ..." tool result. HIGH: the classification is chosen
      by an untrusted REMOTE endpoint, and a failed external action is reported as
      a successful one. Fix first.
  F2  parse_model_output is documented as TOTAL (never raises, always a typed
      outcome) but catches only JSONDecodeError/ValueError. Deeply nested JSON
      breaks that contract. The control is a PRE-DECODE NESTING CAP, not a wider
      except clause: on 3.11-3.13 the decoder raises RecursionError, but on 3.14.6
      the same input PARSES (default recursion limit untouched), so RecursionError
      is a property of the interpreter, not of the input. See the F2 block below.
      The run still fails closed end to end (the engine catches the adapter
      exception), so this is a contract/portability defect, not a live hole.
  F3  the Review 8 reordering (authorize BEFORE the budget gate, so an M1 denial
      survives budget exhaustion) was applied to BOTH budget modes. With
      count_denied_attempts=True the attempt budget is therefore never enforced:
      max_actions=1 with steps_taken=1 still authorizes, classifies, and counts
      another attempt. The structural max_iterations ceiling still prevents an
      unbounded loop, so this is a policy-semantics defect, not a runaway.
  F4  seal_configuration() seals the catalog and the broker's own grant/issue
      methods, but ToolPolicy has no sealed state. A caller-supplied policy (the
      supported public constructor arg) is retained by reference, so
      policy.grant() still works after the seal and the new grant still mints.
      Low direct exploitability under the single-process TCB, but the README says
      sealing seals the whole configuration, and it does not.
  F5  the broker requires an injected vault to share its clock OBJECT, but never
      validates that clock's OUTPUT. A clock returning NaN produces NaN issued_at
      and expires_at; every expiry comparison (`now >= expires_at`,
      `now - issued_at >= ttl`) is False against NaN, so a finite TTL becomes a
      non-expiring control. Round 6 rejected non-finite TTL VALUES; a non-finite
      time SOURCE reintroduces the same condition.

Trust-model note. Only F1 is remotely reachable (a hostile or merely broken
allowed endpoint). F2 and F3 are model-triggerable. F4 and F5 require in-process
trusted configuration objects to be constructed wrongly, which is inside the TCB;
they are severity-medium as CONFIGURATION-SAFETY defects and as honesty defects
against documented invariants, not as exploit paths.
"""

import json
import math

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.adapters import OllamaModel, ParsedOutputKind, parse_model_output
from capcore.broker import (
    CatalogError, Credential, ExecutionProposal, FakeClock, Secret, ToolKind,
    ToolPolicy, ToolRegistration, TrustedExecutionBroker,
)
from capcore.httptool import HttpTool
from capcore.runtime import (
    Budget, ExecutionEngine, ModelOutcome, RunRecord, RunState, StepOutcome,
)


def build(scope="acme/api"):
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", scope, frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


def status_transport(status):
    """A transport pinned to one status. Stands in for a remote endpoint that
    answers, but not with success. Returns status only, matching the Review 8
    contract that the credentialed path never reads the body."""
    def _t(method, url, headers):
        return {"status": status}
    return _t


def http_broker(mon, transport):
    """A broker wired to ONE credentialed HttpTool, sealed and ready to mint."""
    tool = HttpTool("https://api.example.com/x", transport)
    b = TrustedExecutionBroker(mon)
    b.issue_credential(
        Credential("c", "read", "acme/api", Secret("tok"), ttl_seconds=60))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     tool, "1", credential_id="c"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()
    return b


# --------------------------------------------------------------------------- #
# F1 (do first). A non-success HTTP status is a FAILED action, not an executed
# one. The status is chosen by the remote endpoint, so this is the one finding an
# untrusted party controls directly.
# --------------------------------------------------------------------------- #

def test_http_500_is_not_reported_as_executed():
    """A 500 means the requested operation did not happen. Reporting EXECUTED
    lets an untrusted endpoint manufacture a successful terminal state."""
    _, mon, ctx = build()
    b = http_broker(mon, status_transport(500))
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is not StepOutcome.EXECUTED
    assert res.outcome is StepOutcome.TOOL_ERROR
    # And the fabricated success string must not reach the model as a result.
    assert res.tool_result is None or "500" not in str(res.tool_result)


def test_http_302_is_not_reported_as_executed():
    """Redirects are deliberately NOT followed (that is what protects the
    credential from being re-sent to an attacker-chosen Location). A 3xx
    therefore means the action did not occur, and must not read as EXECUTED.
    requests' raise_for_status() does not classify 3xx as an error, which is why
    this needs an explicit accepted-status range."""
    _, mon, ctx = build()
    b = http_broker(mon, status_transport(302))
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.TOOL_ERROR


def test_http_2xx_is_reported_as_executed():
    """The other half of the invariant: success must still be success. Guards
    against a fix that fails the whole HTTP path closed."""
    _, mon, ctx = build()
    b = http_broker(mon, status_transport(200))
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.EXECUTED
    assert "200" in res.tool_result


def test_explicit_accepted_statuses_admit_a_non_2xx_business_outcome():
    """Some tools legitimately treat a non-2xx as a real outcome. That must be an
    EXPLICIT construction-time decision, never the silent default."""
    _, mon, ctx = build()
    tool = HttpTool("https://api.example.com/x", status_transport(404),
                    accepted_statuses=frozenset({200, 404}))
    b = TrustedExecutionBroker(mon)
    b.issue_credential(
        Credential("c", "read", "acme/api", Secret("tok"), ttl_seconds=60))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     tool, "1", credential_id="c"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.EXECUTED


def test_non_integer_status_is_not_reported_as_executed():
    """A transport that returns a non-int status (a string, None, a bool) has not
    established that the action occurred.

    This test exists because WITHOUT it the explicit type check is unfalsifiable:
    a mutation removing it survives. `_is_success("200")` happens to fail anyway,
    but by two DIFFERENT accidents depending on the branch: on the default branch
    `200 <= "200" < 300` raises TypeError, and on the accepted_statuses branch
    `"200" in frozenset({200})` is quietly False. Same outcome, different
    mechanisms, neither of them chosen. The explicit check makes it ONE mechanism,
    deliberately, and this test is what proves the check is load-bearing.

    True is deliberately included: bool is an int subclass, so `200 <= True < 300`
    is False but `True in frozenset({1})` is True, and a transport returning
    `{"status": True}` must never be read as a status code.
    """
    for bad in ("200", None, True, 200.0):
        _, mon, ctx = build()
        b = http_broker(mon, status_transport(bad))
        eng = ExecutionEngine(b, Budget(3))
        rec = RunRecord(ctx=ctx)

        res = eng.step(rec, ep())

        assert res.outcome is StepOutcome.TOOL_ERROR, f"status={bad!r}"


def test_http_failure_does_not_leak_the_credential():
    """The failure path must stay generic. The broker discards adapter exceptions
    without inspecting them, so this asserts the invariant end to end: no secret
    in the outcome, the tool result, or the audit reason."""
    _, mon, ctx = build()
    b = http_broker(mon, status_transport(401))
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.TOOL_ERROR
    blob = f"{res.tool_result} {res.audit_reason} " + " ".join(
        f"{a.reason}" for a in b.audit)
    assert "tok" not in blob
    assert "Bearer" not in blob


# --------------------------------------------------------------------------- #
# F2. parse_model_output is documented as TOTAL: never raises, always a typed
# outcome. Deeply nested JSON breaks that contract.
#
# WHY THE CONTROL IS A DEPTH CAP AND NOT `except RecursionError`.
#
# The obvious fix is to widen the except clause. It is not sufficient, and the
# evidence is a cross-version divergence in this very suite:
#
#   CPython 3.11-3.13:  json.loads() at depth 10000 raises RecursionError
#   CPython 3.14.6:     json.loads() at depth 10000 PARSES, with the default
#                       recursion limit (1000) untouched
#
# So RecursionError is a property of the DECODER'S IMPLEMENTATION on a given
# interpreter, not a property of the INPUT. Two consequences, both fatal to the
# except-only fix:
#
#   1. A RecursionError test is green-by-accident on 3.14 (it returns INVALID for
#      an unrelated reason: no verb/resource/tool keys). It cannot go red there,
#      so it proves nothing, and a mutation guarding it could not be caught on
#      that interpreter. A guarantee that holds on three of four supported
#      Pythons is a coincidence, not a guarantee.
#   2. 3.14 did not remove the bound, it RAISED it. Some greater depth still
#      exhausts the C scanner's stack, and a native stack overflow is not a
#      catchable RecursionError. `except Exception` cannot save you from a
#      segfault, which is also why the provider-envelope decode needs the cap
#      even though next_proposal already wraps it broadly.
#
# The cap is a pure function of the input, so it behaves IDENTICALLY on every
# interpreter. RecursionError stays in the except tuple as defense in depth, not
# as the control.
#
# Depth convention (matches the scanner: increment on `[` and `{`):
#     {}            -> 1
#     {"a": []}     -> 2
#     {"a": [[]]}   -> 3
# MAX_JSON_NESTING is 16. The real schema is depth 1; 16 is margin.
# --------------------------------------------------------------------------- #

def nest(depth, opener="[", closer="]"):
    """Build JSON of EXACTLY `depth` nesting, per the convention above.

    Built to an exact depth rather than by counting brackets by eye: the
    off-by-one between `depth > limit` and `depth >= limit` is precisely what the
    boundary tests (and their mutation) exist to catch, so a fixture that is
    itself off by one would make the mutation uncatchable.
    """
    return opener * depth + closer * depth


def test_json_depth_at_the_limit_is_accepted():
    """Depth 16 is legal. The cap must not be off by one in the strict direction:
    that would be a silent compatibility break, not a security win."""
    from capcore.adapters import MAX_JSON_NESTING
    assert MAX_JSON_NESTING == 16
    text = '{"verb":"read","resource":"acme/api/x","tool":"t","meta":%s}' % nest(
        MAX_JSON_NESTING - 1)  # +1 for the enclosing object = exactly the limit
    out = parse_model_output(text)
    assert out.kind is ParsedOutputKind.PROPOSAL


def test_json_depth_one_past_the_limit_is_rejected():
    """Depth 17 is refused BEFORE json.loads runs, on every interpreter."""
    from capcore.adapters import MAX_JSON_NESTING
    text = '{"verb":"read","resource":"acme/api/x","tool":"t","meta":%s}' % nest(
        MAX_JSON_NESTING)  # +1 for the enclosing object = limit + 1
    out = parse_model_output(text)
    assert out.kind is ParsedOutputKind.INVALID


def test_deeply_nested_json_returns_invalid():
    """The original finding, with a payload that is otherwise VALID.

    The earlier version of this test used {"x": [[[...]]]}, which is INVALID on
    3.14 for a reason that has nothing to do with depth: no verb/resource/tool
    keys. It passed there while the defect was fully present. A test whose fixture
    would fail validation anyway proves nothing about the property under test.

    So the payload below carries a complete, legal proposal, and DEPTH is the only
    thing that can make it INVALID. Without the cap: 3.11-3.13 raise
    RecursionError, 3.14 returns PROPOSAL. Red on both, for the right reason."""
    from capcore.adapters import json_nesting_within_limit
    deep = ('{"verb":"read","resource":"acme/api/x","tool":"t","meta":%s}'
            % nest(10000))
    assert not json_nesting_within_limit(deep)
    out = parse_model_output(deep)
    assert out.kind is ParsedOutputKind.INVALID


def test_deep_object_nesting_is_rejected():
    """Objects, not just arrays."""
    out = parse_model_output('{"x":%s}' % nest(500, '{"a":', "}"))
    assert out.kind is ParsedOutputKind.INVALID


def test_mixed_object_and_array_nesting_is_rejected():
    """Alternating containers must accumulate depth, not reset it."""
    out = parse_model_output('{"x":%s%s}' % ('[{"a":' * 30, "}]" * 30))
    assert out.kind is ParsedOutputKind.INVALID


def test_ollama_nested_json_returns_model_error():
    """parse_model_output runs OUTSIDE next_proposal's transport try/except, so
    on 3.11-3.13 a RecursionError there escapes the adapter entirely rather than
    becoming a typed ModelResult.error(). On 3.14 the same text parses, and
    WITHOUT the cap this returns ModelOutcome.PROPOSE: the model successfully
    smuggles a 10000-deep payload through. The proposal below is otherwise legal,
    so depth is the only thing that can stop it."""
    from capcore.adapters import json_nesting_within_limit  # red until the cap exists
    m = OllamaModel.__new__(OllamaModel)
    m._asked = 0
    m.max_proposals = 5
    m._call = lambda prompt: (
        '{"verb":"read","resource":"acme/api/x","tool":"t","meta":%s}'
        % nest(10000))

    class _View:
        history = []

    res = m.next_proposal(_View())
    assert res.outcome is ModelOutcome.ERROR


# The scanner is string-aware. A naive bracket counter is WORSE than no scanner:
# it would reject legitimate output whose string VALUES contain brackets, which
# is ordinary in a resource path or an error message the model is quoting back.

def test_brackets_inside_strings_do_not_count():
    from capcore.adapters import json_nesting_within_limit
    assert json_nesting_within_limit('{"a":"' + "[" * 100 + '"}')


def test_braces_inside_strings_do_not_count():
    from capcore.adapters import json_nesting_within_limit
    assert json_nesting_within_limit('{"a":"' + "{" * 100 + '"}')


def test_escaped_quote_does_not_end_string_state():
    r"""An ESCAPED quote does not terminate the string, so brackets after it are
    still string CONTENT and must not count as structure.

    The JSON here is:   {"a": "\"[[[[...[[["}
    i.e. the value is a string whose first character is a literal quote, followed
    by 100 literal '[' characters. Depth is 1 (the object). A scanner that treats
    \" as a terminator leaves string state early, counts those 100 brackets as
    structure, and wrongly REJECTS a legitimate payload.

    Written as a raw string and cross-checked with json.loads. An earlier version
    of this fixture used a NON-raw '{"a":"\"', where \" collapses to a bare " and
    the string ends immediately: it tested the exact opposite of what its name
    says. The json.loads assertion is what makes that class of mistake impossible.
    If the fixture is not the JSON the docstring claims, it fails HERE rather than
    silently testing something else.
    """
    from capcore.adapters import json_nesting_within_limit
    text = r'{"a":"\"' + "[" * 100 + r'"}'
    assert json.loads(text) == {"a": '"' + "[" * 100}   # it IS the JSON I claim
    assert json_nesting_within_limit(text)


def test_escaped_backslash_before_quote_is_handled():
    r"""An escaped BACKSLASH does not escape the quote that follows it, so the
    string DOES terminate there and later brackets are structure again.

    The JSON here is:   {"a": "\\", "b": [[[...]]]}
    i.e. the value of "a" is a single literal backslash, the string then ENDS, and
    "b" carries 100 levels of real nesting. A scanner that swallows that quote as
    escaped stays in string state forever, stops counting real structure, and
    wrongly ACCEPTS an over-deep payload. That is the DANGEROUS direction of the
    bug, which is why this asserts rejection.
    """
    from capcore.adapters import json_nesting_within_limit
    text = r'{"a":"\\","b":' + nest(100) + "}"
    assert json.loads(text)["a"] == "\\"                 # it IS the JSON I claim
    assert not json_nesting_within_limit(text)


def test_a_json_string_containing_brackets_still_parses():
    """End to end: string-borne brackets must not make a legitimate proposal
    INVALID."""
    out = parse_model_output(
        '{"verb":"read","resource":"acme/api/[x]","tool":"t"}')
    assert out.kind is ParsedOutputKind.PROPOSAL


def test_provider_envelope_depth_is_capped_before_decode():
    """The envelope decode is a SECOND decoder on provider-controlled bytes.

    Asserts on the MESSAGE, not merely on the exception type, and that is
    load-bearing. Both the cap and the RecursionError backstop raise
    ProviderProtocolError, so a type-only assertion passes even with the cap
    REMOVED (on 3.11-3.13 the decoder raises RecursionError and the backstop
    converts it). A mutation deleting the cap survived exactly that way.

    The distinct message is what proves the cap fired BEFORE json.loads ran, which
    is the whole invariant: `except Exception` catches a RecursionError but not a
    native stack overflow, and on 3.14 there is no exception at all because the
    decoder simply parses it.
    """
    from capcore.adapters import json_nesting_within_limit, decode_provider_envelope
    from capcore.httptool import ProviderProtocolError

    deep = ('{"response":%s}' % nest(10000)).encode()
    assert not json_nesting_within_limit(deep.decode())

    with pytest.raises(ProviderProtocolError) as exc:
        decode_provider_envelope(deep)
    assert "nesting limit" in str(exc.value), (
        "the envelope was rejected by the DECODER, not by the pre-decode cap"
    )


def test_provider_envelope_still_accepts_a_normal_response():
    """Guards against a cap that rejects every envelope."""
    from capcore.adapters import decode_provider_envelope
    out = decode_provider_envelope(
        b'{"response": "{\\"verb\\":\\"read\\"}"}')
    assert out == '{"verb":"read"}'


def test_flat_json_still_parses():
    """Guards against a fix that rejects legitimate output. The real schema is
    flat; a nesting limit must not break it."""
    out = parse_model_output(
        '{"verb":"read","resource":"acme/api/x","tool":"t"}')
    assert out.kind is ParsedOutputKind.PROPOSAL


# --------------------------------------------------------------------------- #
# F3. With count_denied_attempts=True the ATTEMPT budget must bound attempts.
# Review 8 moved the budget gate after authorization for BOTH modes, which is
# correct only for the non-counting mode.
# --------------------------------------------------------------------------- #

def counting_engine(mon, max_actions=1):
    b = TrustedExecutionBroker(mon)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()
    return ExecutionEngine(
        b, Budget(max_actions=max_actions, max_iterations=3,
                  count_denied_attempts=True))


def test_counted_denial_respects_exhausted_attempt_budget():
    """max_actions=1, one attempt already spent. A denied proposal must report
    BUDGET_EXHAUSTED and must NOT be authorized or counted: the attempt budget is
    what count_denied_attempts=True exists to enforce."""
    _, mon, ctx = build()
    eng = counting_engine(mon)
    rec = RunRecord(ctx=ctx)
    rec.steps_taken = 1

    res = eng.step(rec, ep(resource="acme/other/x"))  # out of capability scope

    assert res.outcome is StepOutcome.BUDGET_EXHAUSTED
    assert rec.steps_taken == 1


def test_counted_approval_respects_exhausted_attempt_budget():
    """Same for a REQUIRE_APPROVAL classification: with the attempt budget spent,
    the runtime must not spend another attempt classifying."""
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", "acme/api", frozenset({"read"}),
                           principal="p", run="r",
                           approval_actions=frozenset({"read"})))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "p", "r")
    eng = counting_engine(mon)
    rec = RunRecord(ctx=ctx)
    rec.steps_taken = 1

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.BUDGET_EXHAUSTED
    assert rec.steps_taken == 1


def test_non_counted_execution_budget_is_enforced():
    """The NON-COUNTING execution budget must still stop an allowed action.

    This test exists because splitting the single budget gate into two (one per
    mode) silently halved the coverage of the pre-existing budget_not_enforced
    mutation: every test that used to kill it exercises the COUNTING mode, which no
    longer reaches this branch. The mutation still matched its anchor and still
    passed check_stale, but it had stopped biting. An anchor that matches while no
    longer biting is the invisible failure mode; this is the test that restores it.
    """
    _, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()
    eng = ExecutionEngine(
        b, Budget(max_actions=1, max_iterations=5, count_denied_attempts=False))
    rec = RunRecord(ctx=ctx)

    first = eng.step(rec, ep())
    assert first.outcome is StepOutcome.EXECUTED
    assert rec.steps_taken == 1

    second = eng.step(rec, ep())            # in-scope, allowed, but no budget left
    assert second.outcome is StepOutcome.BUDGET_EXHAUSTED
    assert rec.state is RunState.ABORTED
    assert rec.steps_taken == 1


def test_counted_budget_exhaustion_aborts_the_run():
    """Exhausting the ATTEMPT budget must ABORT the run, not merely refuse one step
    and leave it RUNNING for the loop to keep asking.

    Same reason as above: after the gate split, no test asserted RunState.ABORTED on
    the counting path, so budget_gate_disabled stopped biting there.
    """
    _, mon, ctx = build()
    eng = counting_engine(mon, max_actions=1)
    rec = RunRecord(ctx=ctx)
    rec.steps_taken = 1

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.BUDGET_EXHAUSTED
    assert rec.state is RunState.ABORTED


def test_counted_mint_refusal_consumes_exactly_one_attempt():
    """A broker mint refusal (unknown tool, unauthorized tool) is an ATTEMPT: the
    model put a proposal to the runtime and it was refused.

    The non-obvious part is that it must count EXACTLY once. The pre-authorization
    gate now sits ahead of _authorize, and the mint-refusal handlers still
    increment, so the reordering had to not double-count. It doesn't: the gate only
    REJECTS, it never increments, and exactly one increment happens per attempt on
    each path (denial, approval, mint refusal, execution).
    """
    _, mon, ctx = build()
    eng = counting_engine(mon, max_actions=2)
    rec = RunRecord(ctx=ctx)

    first = eng.step(rec, ep(tool="nonexistent"))
    assert first.outcome is StepOutcome.TOOL_NOT_FOUND
    assert rec.steps_taken == 1          # one attempt, not two

    second = eng.step(rec, ep())
    assert second.outcome is StepOutcome.EXECUTED
    assert rec.steps_taken == 2

    third = eng.step(rec, ep())
    assert third.outcome is StepOutcome.BUDGET_EXHAUSTED
    assert rec.steps_taken == 2          # the gate rejects, it does not increment


def test_non_counted_denial_still_survives_execution_budget():
    """The Review 8 invariant must NOT regress. With count_denied_attempts=False
    an out-of-scope proposal is DENIED (its honest M1 classification), not
    BUDGET_EXHAUSTED, even once the execution budget is spent, and it consumes no
    budget."""
    _, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()
    eng = ExecutionEngine(
        b, Budget(max_actions=1, max_iterations=3, count_denied_attempts=False))
    rec = RunRecord(ctx=ctx)
    rec.steps_taken = 1

    res = eng.step(rec, ep(resource="acme/other/x"))

    assert res.outcome is StepOutcome.DENIED
    assert rec.steps_taken == 1


def test_counted_allow_still_hits_the_budget():
    """And an ALLOWed action past the budget is still BUDGET_EXHAUSTED, not
    executed. Guards against a fix that only reorders the denial path."""
    _, mon, ctx = build()
    eng = counting_engine(mon)
    rec = RunRecord(ctx=ctx)
    rec.steps_taken = 1

    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.BUDGET_EXHAUSTED
    assert rec.steps_taken == 1


# --------------------------------------------------------------------------- #
# F4. Sealing must hold through a RETAINED reference to an injected policy. This
# is the supported public constructor arg and the public grant() method: no
# private-field access, no object-graph attack.
# --------------------------------------------------------------------------- #

def test_broker_refuses_a_post_seal_grant_at_its_own_boundary():
    """The broker must refuse a post-seal grant AT ITS OWN API BOUNDARY, not lean on
    ToolPolicy to catch it one layer down.

    This test exists because the F4 fix silently disarmed the pre-existing
    grant_after_seal_allowed mutation. Before F4, the broker's `if self._config_
    sealed:` check was the ONLY thing refusing a post-seal grant_tool(), so removing
    it was observable. Now ToolPolicy.grant() refuses too, so removing the broker's
    check changes nothing a type-only assertion can see, and the mutation survived a
    full harness run.

    The security invariant was never broken (defense in depth held). But a mutation
    that survives is a guard that nothing tests, so the redundancy has to be made
    FALSIFIABLE rather than left as a happy accident. Asserting on the message
    distinguishes the layers: the broker's guard is a distinct control from the
    policy's, and each is now separately killable.

    Same failure class as the F3 gate split: an existing mutation that still matched
    its anchor, still passed check_stale, and had quietly stopped biting.
    """
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.seal_configuration()

    with pytest.raises(CatalogError) as exc:
        b.grant_tool("t", "acme/api")

    # The BROKER's message, not the policy's ("tool policy is sealed..."). If the
    # broker's own guard is removed, the call still raises CatalogError, but from
    # the wrong layer, and this assertion is what notices.
    assert "configuration is sealed" in str(exc.value)


def test_retained_policy_reference_cannot_grant_after_seal():
    _, mon, ctx = build()
    policy = ToolPolicy()
    b = TrustedExecutionBroker(mon, policy=policy)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "late", "1"))
    b.seal_configuration()

    # The caller still holds the policy object it passed in.
    with pytest.raises(CatalogError):
        policy.grant("t", "acme/api")

    # And no authorization may be minted for the ungranted tool.
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    res = eng.step(rec, ep())
    assert res.outcome is not StepOutcome.EXECUTED
    assert res.outcome is StepOutcome.TOOL_NOT_AUTHORIZED


def test_policy_seal_is_idempotent():
    """Sealing twice is not an error. A seal is a state, not an event."""
    policy = ToolPolicy()
    policy.seal()
    policy.seal()
    with pytest.raises(CatalogError):
        policy.grant("t", "acme/api")


def test_grants_made_before_seal_still_work():
    """The seal must freeze the policy, not empty it."""
    _, mon, ctx = build()
    policy = ToolPolicy()
    b = TrustedExecutionBroker(mon, policy=policy)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()

    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    res = eng.step(rec, ep())
    assert res.outcome is StepOutcome.EXECUTED


# --------------------------------------------------------------------------- #
# F5. The clock's OUTPUT is security-load-bearing, not just its identity. NaN
# makes every expiry comparison False, so a finite TTL stops expiring.
# --------------------------------------------------------------------------- #

class NaNClock:
    def now(self) -> float:
        return float("nan")


class InfClock:
    def now(self) -> float:
        return float("inf")


class StringClock:
    def now(self):
        return "0.0"


class BackwardClock:
    """Monotonic is the documented Clock contract. This one is not: it runs
    backwards, which extends every authorization and credential lifetime even
    when all the values are finite."""
    def __init__(self, start=1000.0, step=-10.0):
        self.value = start
        self.step = step

    def now(self) -> float:
        v = self.value
        self.value += self.step
        return v


def clock_broker(mon, clock):
    b = TrustedExecutionBroker(mon, clock=clock)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ran", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()
    return b


def test_nan_clock_fails_closed_at_mint():
    """`now >= expires_at` is False when both are NaN, so a NaN-stamped
    authorization never expires. Minting against a non-finite clock must fail
    closed rather than produce a permanent authorization."""
    _, mon, ctx = build()
    b = clock_broker(mon, NaNClock())
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is not StepOutcome.EXECUTED


def test_infinite_clock_fails_closed_at_mint():
    """+inf is broken DIFFERENTLY from NaN, and the difference is why the control
    must reject all non-finite values rather than special-casing NaN.

    Authorization gate:  now >= expires_at  is  inf >= inf  -> True, so an
    authorization reads as ALREADY EXPIRED and happens to fail closed. That
    accidental correctness is why this test PASSED on main while the defect was
    present, and why an inf test alone proves nothing.

    Credential TTL gate:  now - issued_at  is  inf - inf  -> NaN, and NaN >= ttl is
    False, so the credential NEVER expires. Fails closed in one place and open in
    the other, by luck rather than design. See test_infinite_clock_does_not_disable
    _credential_ttl, which is the half that was actually broken.
    """
    _, mon, ctx = build()
    b = clock_broker(mon, InfClock())
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is not StepOutcome.EXECUTED


def test_infinite_clock_does_not_disable_credential_ttl():
    """The half of the inf defect that was genuinely open.

    Neither the review (which said 'non-finite disables expiry', true for
    credentials, false for authorizations) nor my first reading (which said 'it is
    NaN specifically', true for authorizations, false for credentials) had this
    right. inf - inf is NaN, so a credential issued under an inf clock has a finite
    TTL that can never elapse. Refuse at ISSUE, when it is a configuration error,
    not at redemption, when a secret is already in play.
    """
    from capcore.broker import ClockError
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon, clock=InfClock())

    with pytest.raises(ClockError):
        b.issue_credential(
            Credential("c", "read", "acme/api", Secret("tok"), ttl_seconds=60))


def test_clock_failure_is_an_honest_outcome_not_a_crash():
    """A broken clock must produce a TYPED terminal state, not an escaping
    exception.

    The first cut of this fix let ClockError propagate out of the broker into the
    engine. Nothing executed, so it was 'fail closed' in the narrow sense, but the
    run died with a traceback instead of reporting why. That is precisely the
    dishonest-terminal-state defect this review round is about (see F1), so the
    broker refuses the mint with a typed code and the engine maps it like any other
    refusal.
    """
    _, mon, ctx = build()
    b = clock_broker(mon, NaNClock())
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())          # must not raise

    assert res.outcome is StepOutcome.AUTHORIZATION_REFUSED
    assert any("clock" in a.reason for a in b.audit)


def test_nan_clock_fails_closed_at_credential_issue():
    """A credential issued under a NaN clock gets a NaN issued_at, so
    `now - issued_at >= ttl` is False forever: a finite TTL that never expires.
    Refuse at issue, when it is a configuration error, not at redemption, when a
    secret is already in play."""
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon, clock=NaNClock())

    with pytest.raises(Exception) as exc:
        b.issue_credential(
            Credential("c", "read", "acme/api", Secret("tok"), ttl_seconds=60))
    assert not isinstance(exc.value, AssertionError)


def test_non_numeric_clock_is_rejected():
    """A clock returning a str makes every comparison a TypeError at redemption,
    mid-action. Fail closed on the value's TYPE, at the read."""
    _, mon, ctx = build()
    b = clock_broker(mon, StringClock())
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)

    res = eng.step(rec, ep())

    assert res.outcome is not StepOutcome.EXECUTED


def test_backward_clock_is_rejected():
    """Clock is documented as MONOTONIC. A clock that moves backward extends
    credential and authorization lifetimes even with entirely finite values, so
    the broker must not accept time that went backwards on a security read."""
    _, mon, ctx = build()
    b = clock_broker(mon, BackwardClock())
    eng = ExecutionEngine(b, Budget(5))
    rec = RunRecord(ctx=ctx)

    # The first read establishes the watermark; a later, EARLIER read must fail.
    outcomes = [eng.step(rec, ep()).outcome for _ in range(3)]

    assert StepOutcome.EXECUTED not in outcomes[1:]


def test_a_normal_finite_clock_still_works():
    """Guards against a fix that fails every clock closed. FakeClock is the
    control the whole suite uses; it must keep working, and advancing it forward
    must not trip the monotonicity guard."""
    _, mon, ctx = build()
    clock = FakeClock(1000.0)
    b = clock_broker(mon, clock)
    eng = ExecutionEngine(b, Budget(5))
    rec = RunRecord(ctx=ctx)

    first = eng.step(rec, ep())
    clock.advance(1.0)
    second = eng.step(rec, ep())

    assert first.outcome is StepOutcome.EXECUTED
    assert second.outcome is StepOutcome.EXECUTED
