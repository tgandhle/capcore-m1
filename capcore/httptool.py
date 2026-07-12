"""HTTP tool for M3: executes an authorized network action using a broker-
released secret. The transport is injectable so the tested path uses a mock
(deterministic, no network, no real secret) and the live demo uses real HTTP.

Security shape: the tool receives the raw secret ONLY via a Secret released by
the broker at call time. The secret is placed in the outbound Authorization
header and sent to the tool's configured allowed URL, nowhere else. The tool
returns a redacted result (never echoing the secret).
"""

from __future__ import annotations

from typing import Callable, Optional

from capcore import Proposal
from capcore.broker import Secret


# A transport takes (method, url, headers) and returns a response dict.
Transport = Callable[[str, str, dict], dict]


class MockTransport:
    """Records the outbound call so tests can assert exactly what was sent
    (including that the secret went ONLY here). No network.
    """
    def __init__(self, status=200, body="mock-ok"):
        self.calls: list[dict] = []
        self._status = status
        self._body = body

    def __call__(self, method: str, url: str, headers: dict) -> dict:
        self.calls.append({"method": method, "url": url, "headers": dict(headers)})
        return {"status": self._status, "body": self._body}


def real_requests_transport(method: str, url: str, headers: dict) -> dict:
    """Live transport using requests. Imported lazily; only used by the demo."""
    import requests
    resp = requests.request(method, url, headers=headers, timeout=30)
    return {"status": resp.status_code, "body": resp.text}


class HttpTool:
    """A tool that makes ONE authorized outbound request to a fixed allowed URL,
    authenticating with a broker-released secret. It will not send to any other
    URL: the URL is set at construction, not taken from the (untrusted) proposal.
    """
    def __init__(self, allowed_url: str, transport: Transport, method: str = "GET"):
        self.allowed_url = allowed_url
        self.transport = transport
        self.method = method

    def execute_with_credential(self, proposal: Proposal, secret: Secret) -> str:
        """A CredentialedTool. Called ONLY by the broker, inside its boundary.

        This adapter is inside the TCB: it holds the raw secret in order to use
        it. It must not log it, retain it, or put it anywhere an exception could
        pick it up. Note the transport may still raise with the header in the
        message (a hostile or careless transport will), which is exactly why the
        BROKER catches and discards every exception from this call rather than
        trusting adapters to sanitize their own errors.
        """
        headers = {"Authorization": f"Bearer {secret.reveal()}"}
        resp = self.transport(self.method, self.allowed_url, headers)
        # redacted summary; never echo the secret
        return f"http {resp['status']} from {self.allowed_url}"
