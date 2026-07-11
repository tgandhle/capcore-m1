"""Tests for the model adapter's PARSING logic only.

The network call to Ollama is not tested here (no server in CI, nondeterministic
output). These tests pin the text->Proposal parsing so a malformed or hostile
model response is turned into a safe outcome (a valid Proposal the monitor will
judge, or None to stop), never a crash.
"""

from capcore import Proposal
from capcore.adapters import parse_proposal


def test_parses_clean_json():
    p = parse_proposal('{"verb": "read", "resource": "acme/records/x"}')
    assert p == Proposal(resource="acme/records/x", verb="read")


def test_parses_json_wrapped_in_prose():
    # small models often add chatter around the JSON
    text = 'Sure! Here is my action:\n{"verb": "send", "resource": "a/b"}\nHope that helps.'
    p = parse_proposal(text)
    assert p == Proposal(resource="a/b", verb="send")


def test_parses_json_in_markdown_fence():
    text = '```json\n{"verb": "read", "resource": "a/b/c"}\n```'
    p = parse_proposal(text)
    assert p == Proposal(resource="a/b/c", verb="read")


def test_done_signal_returns_none():
    assert parse_proposal('{"done": true}') is None


def test_no_json_returns_none():
    assert parse_proposal("I refuse to answer in JSON.") is None
    assert parse_proposal("") is None


def test_missing_fields_return_none():
    assert parse_proposal('{"verb": "read"}') is None            # no resource
    assert parse_proposal('{"resource": "a/b"}') is None         # no verb
    assert parse_proposal('{"verb": "", "resource": "a/b"}') is None
    assert parse_proposal('{"verb": "read", "resource": ""}') is None


def test_malformed_json_returns_none():
    assert parse_proposal('{"verb": "read", "resource":}') is None
    assert parse_proposal('{verb: read}') is None


def test_hostile_traversal_resource_becomes_proposal_not_crash():
    """A model emitting a traversal path yields a Proposal (the MONITOR then
    denies it). Parsing must not crash or pre-judge; it only shapes text.
    """
    p = parse_proposal('{"verb": "read", "resource": "acme/../secret"}')
    assert p == Proposal(resource="acme/../secret", verb="read")
    # the monitor is what rejects this at authorize time (tested elsewhere)
