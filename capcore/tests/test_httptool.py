"""HTTP tool tests, mock transport only (no network, no real secret).

Proves: the broker-released secret is sent ONLY to the tool's allowed URL, in
the Authorization header, and the tool's returned summary never echoes it. The
tool ignores any URL the (untrusted) proposal might imply, it uses its fixed
allowed URL.
"""

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext, Verdict,
)
from capcore.broker import Secret, Credential, CredentialBroker
from capcore.httptool import HttpTool, MockTransport

MOCK_SECRET = "SEKRET-HTTP-999"


def setup():
    store = CapabilityStore()
    store.issue(Capability("cap-run", "acme", "acme/api",
                           frozenset({"read"}), principal="p1", run="r1"))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "p1", "r1")
    broker = CredentialBroker()
    broker.issue(Credential("cred-1", "cap-run", "read", "acme/api",
                            Secret(MOCK_SECRET)))
    return store, mon, ctx, broker


def test_secret_sent_only_to_allowed_url_in_auth_header():
    store, mon, ctx, broker = setup()
    transport = MockTransport(status=200)
    tool = HttpTool("https://api.example.com/data", transport)

    prop = Proposal("acme/api/data", "read")
    decision = mon.authorize(ctx, prop)
    secret = broker.release("cred-1", "cap-run", prop, decision)
    result = tool(prop, secret)

    # exactly one outbound call, to the allowed URL
    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://api.example.com/data"
    # the secret is in the auth header of THAT call...
    assert MOCK_SECRET in call["headers"]["Authorization"]
    # ...and nowhere in the tool's returned summary
    assert MOCK_SECRET not in result
    assert "http 200" in result


def test_no_secret_no_request_body_leak():
    store, mon, ctx, broker = setup()
    transport = MockTransport()
    tool = HttpTool("https://api.example.com/data", transport)
    prop = Proposal("acme/api/data", "read")
    decision = mon.authorize(ctx, prop)
    secret = broker.release("cred-1", "cap-run", prop, decision)
    tool(prop, secret)
    # the secret appears in exactly one place: the Authorization header of the
    # single allowed call. Not in the URL, not in the method.
    call = transport.calls[0]
    assert MOCK_SECRET not in call["url"]
    assert MOCK_SECRET not in call["method"]
    assert sum(MOCK_SECRET in str(v) for v in call["headers"].values()) == 1


def test_tool_refuses_without_released_secret():
    store, mon, ctx, broker = setup()
    transport = MockTransport()
    tool = HttpTool("https://api.example.com/data", transport)
    # a denied action yields no secret; tool must not call the transport
    prop = Proposal("acme/api/data", "write")  # write not granted
    decision = mon.authorize(ctx, prop)
    assert decision.verdict == Verdict.DENY
    secret = broker.release("cred-1", "cap-run", prop, decision)  # None
    result = tool(prop, secret)
    assert "refused" in result
    assert len(transport.calls) == 0  # no network attempt without a secret


def test_tool_uses_fixed_url_not_proposal():
    """The tool sends to its CONFIGURED url, never a url implied by the
    untrusted proposal resource. Even a proposal naming another host does not
    redirect the request.
    """
    store, mon, ctx, broker = setup()
    transport = MockTransport()
    tool = HttpTool("https://api.example.com/data", transport)
    prop = Proposal("acme/api/data", "read")
    decision = mon.authorize(ctx, prop)
    secret = broker.release("cred-1", "cap-run", prop, decision)
    tool(prop, secret)
    assert transport.calls[0]["url"] == "https://api.example.com/data"
