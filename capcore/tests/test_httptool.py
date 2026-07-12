"""HttpTool tests (credentialed tool, mock transport, no network, no real secret).

Proves the broker-injected secret is sent ONLY to the tool's fixed allowed URL,
in the Authorization header, and nowhere else. The tool is exercised through the
broker's redemption path, which is the only path that ever hands it a secret.
"""

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.broker import (
    Secret, Credential, CredentialBroker, ToolKind, ToolRegistration,
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
    broker = CredentialBroker(mon)
    broker.issue(Credential("cred-1", "cap-run", "read", "acme/records",
                            Secret(MOCK_SECRET)))
    broker.register_tool(ToolRegistration(
        registration_id="http-1", kind=ToolKind.CREDENTIALED,
        adapter=HttpTool(url, transport), version="1", credential_id="cred-1",
    ))
    return broker


def mint(broker, mon, ctx, prop):
    d = mon.authorize(ctx, prop)
    return broker.register_authorized_execution(ctx, prop, d, "http-1")


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
