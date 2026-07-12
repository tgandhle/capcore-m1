"""HttpTool tests (credentialed tool, mock transport, no network, no real secret).

Proves the broker-injected secret is sent ONLY to the tool's fixed allowed URL,
in the Authorization header, and nowhere else. The tool is exercised through the
broker's redemption path, which is the only path that ever hands it a secret.
"""

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.broker import (
    Secret, Credential, TrustedExecutionBroker, ToolKind, ToolRegistration,
    ExecutionProposal,
)
from capcore.httptool import HttpTool, MockTransport

MOCK_SECRET = "SEKRET-TOKEN-12345"


def build():
    store = CapabilityStore()
    store.issue(Capability("cap-run", "acme", "acme/records",
                           frozenset({"read"}), principal="p1", run="r1"))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "p1", "r1")
    return store, mon, ctx


def wired(mon, transport, url="https://api.example.com/data"):
    broker = TrustedExecutionBroker(mon)
    broker.issue_credential(Credential("cred-1", "read", "acme/records",
                                       Secret(MOCK_SECRET)))
    broker.register_tool(ToolRegistration(
        registration_id="http-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=HttpTool(url, transport), version="1", credential_id="cred-1",
    ))
    broker.grant_tool("http-1", "acme/records")
    return broker


def mint(broker, mon, ctx, prop):
    return broker.register_authorized_execution(
        ctx, ExecutionProposal(action=prop, tool_registration_id="http-1"))


def test_secret_sent_only_to_allowed_url_in_auth_header():
    store, mon, ctx = build()
    transport = MockTransport(status=200)
    url = "https://api.example.com/data"
    broker = wired(mon, transport, url)
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))

    result = broker.redeem_and_execute(action_id)

    assert result.ok is True
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == url                                  # only the allowed URL
    assert call["headers"]["Authorization"] == f"Bearer {MOCK_SECRET}"


def test_secret_appears_in_exactly_one_place():
    store, mon, ctx = build()
    transport = MockTransport()
    broker = wired(mon, transport)
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))

    result = broker.redeem_and_execute(action_id)

    # the secret is in the auth header of the single outbound call, and not in
    # the sanitized result the caller sees
    assert MOCK_SECRET in transport.calls[0]["headers"]["Authorization"]
    assert MOCK_SECRET not in (result.body or "")
    # and not in the URL or method
    assert MOCK_SECRET not in transport.calls[0]["url"]


def test_no_transport_call_when_action_is_refused():
    store, mon, ctx = build()
    transport = MockTransport()
    broker = wired(mon, transport)
    action_id = mint(broker, mon, ctx, Proposal("acme/records/x", "read"))

    store.revoke("cap-run")                 # revoke before redemption
    result = broker.redeem_and_execute(action_id)

    assert result.ok is False
    assert len(transport.calls) == 0        # no network attempt for a revoked action


# --------------------------------------------------------------------------- #
# Destination policy. The URL is where a real credential goes, so it is validated
# at CONSTRUCTION: a tool that exists is a tool whose destination is safe.
# --------------------------------------------------------------------------- #

import pytest

from capcore.httptool import DestinationError, validate_destination


@pytest.mark.parametrize("bad_url,why", [
    ("http://example.com/api",            "cleartext: Authorization header on the wire"),
    ("ftp://example.com/api",             "not a credential transport"),
    ("gopher://example.com/api",          "not a credential transport"),
    ("file:///etc/passwd",                "turns a network tool into arbitrary file read"),
    ("https://user:pw@example.com/api",   "credentials in a URL leak into logs and proxies"),
    ("https://:pw@example.com/api",       "embedded password"),
    ("https:///api",                      "no host"),
    ("",                                  "empty"),
    ("not-a-url",                         "no scheme"),
])
def test_unsafe_destinations_are_rejected_at_construction(bad_url, why):
    with pytest.raises(DestinationError):
        HttpTool(bad_url, MockTransport())


def test_nonstandard_port_is_rejected_by_default():
    with pytest.raises(DestinationError):
        HttpTool("https://example.com:8443/api", MockTransport())


def test_nonstandard_port_can_be_explicitly_permitted():
    tool = HttpTool("https://example.com:8443/api", MockTransport(),
                    allowed_ports=frozenset({8443}))
    assert tool.allowed_url == "https://example.com:8443/api"


def test_host_allowlist_is_enforced():
    """Even a valid https URL must name a permitted host, when a list is given."""
    with pytest.raises(DestinationError):
        HttpTool("https://evil.example/api", MockTransport(),
                 allowed_hosts=frozenset({"api.example.com"}))

    tool = HttpTool("https://api.example.com/data", MockTransport(),
                    allowed_hosts=frozenset({"api.example.com"}))
    assert tool.allowed_url == "https://api.example.com/data"


def test_destination_is_normalized_before_comparison():
    """Two spellings of the same destination must not be able to disagree."""
    assert (validate_destination("HTTPS://Example.COM:443/api")
            == "https://example.com/api")
    # the default port is dropped, so :443 and no-port are the same destination
    assert (validate_destination("https://example.com:443/api")
            == validate_destination("https://example.com/api"))


def test_redirects_are_disabled_in_the_real_transport():
    """A 3xx from the pinned host would otherwise re-send the Authorization header
    to an attacker-chosen Location. A redirect is a NEW destination and needs its
    own authorization."""
    import inspect
    from capcore.httptool import real_requests_transport
    src = inspect.getsource(real_requests_transport)
    assert "allow_redirects=False" in src
