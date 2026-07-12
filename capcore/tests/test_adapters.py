"""Tests for the model adapter's PARSING logic only.

The network call to Ollama is not tested here (no server in CI, nondeterministic
output). These tests pin the text->Proposal parsing so a malformed or hostile
model response is turned into a safe outcome (a valid Proposal the monitor will
judge, or None to stop), never a crash.
"""

from capcore import Proposal
from capcore.broker import ExecutionProposal
from capcore.adapters import parse_proposal


def test_parses_clean_json():
    p = parse_proposal('{"verb": "read", "resource": "acme/records/x", "tool": "t1"}')
    assert p == ExecutionProposal(
        action=Proposal(resource="acme/records/x", verb="read"),
        tool_registration_id="t1")


def test_parses_json_wrapped_in_prose():
    # small models often add chatter around the JSON
    text = ('Sure! Here is my action:\n'
            '{"verb": "send", "resource": "a/b", "tool": "t1"}\nHope that helps.')
    p = parse_proposal(text)
    assert p == ExecutionProposal(
        action=Proposal(resource="a/b", verb="send"), tool_registration_id="t1")


def test_parses_json_in_markdown_fence():
    text = '```json\n{"verb": "read", "resource": "a/b/c", "tool": "t1"}\n```'
    p = parse_proposal(text)
    assert p == ExecutionProposal(
        action=Proposal(resource="a/b/c", verb="read"), tool_registration_id="t1")


def test_missing_tool_field_is_rejected():
    """An ExecutionProposal without an executor is unrepresentable, so a model
    that omits the tool yields None (the engine treats that as 'stop'), never a
    half-built proposal with an empty sentinel."""
    assert parse_proposal('{"verb": "read", "resource": "a/b"}') is None
    assert parse_proposal('{"verb": "read", "resource": "a/b", "tool": ""}') is None


def test_model_named_tool_is_untrusted():
    """Parsing accepts whatever executor the model names. Naming is not
    authorization: the broker's deny-by-default ToolPolicy decides."""
    p = parse_proposal(
        '{"verb": "read", "resource": "a/b", "tool": "read-payroll-database"}')
    assert p.tool_registration_id == "read-payroll-database"


def test_done_signal_returns_none():
    assert parse_proposal('{"done": true}') is None


def test_no_json_returns_none():
    assert parse_proposal("I refuse to answer in JSON.") is None
    assert parse_proposal("") is None


def test_missing_fields_return_none():
    assert parse_proposal('{"verb": "read", "tool": "t1"}') is None      # no resource
    assert parse_proposal('{"resource": "a/b", "tool": "t1"}') is None   # no verb
    assert parse_proposal('{"verb": "", "resource": "a/b", "tool": "t1"}') is None
    assert parse_proposal('{"verb": "read", "resource": "", "tool": "t1"}') is None


def test_malformed_json_returns_none():
    assert parse_proposal('{"verb": "read", "resource":}') is None
    assert parse_proposal('{verb: read}') is None


def test_hostile_traversal_resource_becomes_proposal_not_crash():
    """A model emitting a traversal path yields a Proposal (the MONITOR then
    denies it). Parsing must not crash or pre-judge; it only shapes text.
    """
    p = parse_proposal('{"verb": "read", "resource": "acme/../secret", "tool": "t1"}')
    assert p == ExecutionProposal(
        action=Proposal(resource="acme/../secret", verb="read"),
        tool_registration_id="t1")
    # the monitor is what rejects this at authorize time (tested elsewhere)


# --------------------------------------------------------------------------- #
# OllamaModel must not convert a provider failure into a clean stop.
# --------------------------------------------------------------------------- #

from capcore.runtime import ModelOutcome
from capcore.adapters import OllamaModel


class _View:
    run_id = "r1"
    remaining_steps = 3
    history = ()


def test_ollama_transport_failure_is_an_error_not_a_completion():
    class Broken(OllamaModel):
        def _call(self, prompt):
            raise RuntimeError("connection refused")

    result = Broken().next_proposal(_View())

    assert result.outcome is ModelOutcome.ERROR
    assert result.outcome is not ModelOutcome.FINISHED


def test_ollama_explicit_done_is_a_completion():
    class Done(OllamaModel):
        def _call(self, prompt):
            return '{"done": true}'

    result = Done().next_proposal(_View())

    assert result.outcome is ModelOutcome.FINISHED


def test_ollama_garbage_is_an_error_not_a_completion():
    """A model emitting prose completed nothing. It must not look like a model
    that said it was done."""
    class Garbage(OllamaModel):
        def _call(self, prompt):
            return "I don't feel like answering in JSON today."

    result = Garbage().next_proposal(_View())

    assert result.outcome is ModelOutcome.ERROR


def test_ollama_valid_proposal_is_a_proposal():
    class Good(OllamaModel):
        def _call(self, prompt):
            return '{"verb": "read", "resource": "acme/records/x", "tool": "t1"}'

    result = Good().next_proposal(_View())

    assert result.outcome is ModelOutcome.PROPOSAL
    assert result.proposal.tool_registration_id == "t1"


def test_ollama_max_proposals_is_a_limit_not_a_completion():
    """Reaching max_proposals reports LIMIT_REACHED, not FINISHED: the model did
    not say it was done, the adapter just stopped asking."""
    from capcore.runtime import ModelOutcome
    from capcore.adapters import OllamaModel

    class Chatty(OllamaModel):
        def _call(self, prompt):
            return '{"verb": "read", "resource": "acme/records/x", "tool": "t1"}'

    m = Chatty(max_proposals=1)

    class _V:
        run_id = "r"; remaining_steps = 5; history = ()

    first = m.next_proposal(_V())
    second = m.next_proposal(_V())      # now at the cap

    assert first.outcome is ModelOutcome.PROPOSAL
    assert second.outcome is ModelOutcome.LIMIT_REACHED
    assert second.outcome is not ModelOutcome.FINISHED
