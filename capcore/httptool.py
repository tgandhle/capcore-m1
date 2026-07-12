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
from urllib.parse import urlsplit, urlunsplit

from capcore import Proposal
from capcore.broker import Secret


class DestinationError(ValueError):
    """The configured destination is not one a credential may be sent to."""
    pass


# A credential may only be sent over TLS, to an explicitly named host.
ALLOWED_SCHEMES = frozenset({"https"})
DEFAULT_ALLOWED_PORTS = frozenset({443})


def validate_destination(
    url: str,
    allowed_hosts: Optional[frozenset[str]] = None,
    allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS,
) -> str:
    """Validate and canonicalize the URL a credential may be sent to.

    This runs at CONSTRUCTION, not at call time. A tool that cannot be built with
    an unsafe destination cannot later send a secret to one, and the failure shows
    up in configuration rather than mid-action with a live credential in hand.

    Rejected, and why each matters for a tool that carries a bearer token:

      - non-https schemes. `http://` puts the Authorization header on the wire in
        cleartext. `file://`, `ftp://`, `gopher://` and friends are not transports
        a credential belongs on at all, and `file://` in particular turns a
        "network" tool into an arbitrary-file-read primitive.
      - embedded userinfo (`https://user:pw@host`). Credentials in a URL leak into
        logs, proxies, Referer headers, and exception messages. It is also a
        classic phishing/parsing-confusion vector: some parsers read the host as
        `user`, others as `host`.
      - a host that is not on the explicit allowlist, when one is given.
      - a non-standard port, unless explicitly permitted.
      - anything without a hostname at all.

    Returns the normalized URL. Normalization happens BEFORE comparison so that
    two spellings of the same destination cannot disagree (lowercased scheme and
    host, default port dropped).
    """
    if not isinstance(url, str) or not url:
        raise DestinationError("destination URL must be a non-empty string")

    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise DestinationError(f"unparseable destination URL: {url!r}") from exc

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise DestinationError(
            f"credential destination must use https, got {scheme or 'no scheme'!r}"
        )

    # urlsplit puts user:pass in .username/.password
    if parts.username is not None or parts.password is not None:
        raise DestinationError(
            "credential destination must not embed a username or password"
        )

    host = (parts.hostname or "").lower()
    if not host:
        raise DestinationError("credential destination must name a host")

    try:
        port = parts.port
    except ValueError as exc:
        raise DestinationError(f"invalid port in destination: {url!r}") from exc
    effective_port = port if port is not None else 443
    if effective_port not in allowed_ports:
        raise DestinationError(
            f"credential destination port {effective_port} is not permitted"
        )

    if allowed_hosts is not None and host not in allowed_hosts:
        raise DestinationError(f"host {host!r} is not on the destination allowlist")

    # Normalize: lowercase scheme+host, drop the default port, keep path/query.
    netloc = host if effective_port == 443 else f"{host}:{effective_port}"
    return urlunsplit((scheme, netloc, parts.path or "", parts.query or "", ""))


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
    """Live transport using requests. Imported lazily; only used by the demo.

    allow_redirects=False is load-bearing, not a default worth inheriting: a 3xx
    from the pinned host would otherwise re-send the Authorization header to an
    attacker-chosen Location, defeating destination pinning entirely. A redirect
    is a new destination and needs its own authorization.
    """
    import requests
    resp = requests.request(method, url, headers=headers, timeout=30,
                            allow_redirects=False)
    return {"status": resp.status_code, "body": resp.text}


class HttpTool:
    """A tool that makes ONE authorized outbound request to a fixed allowed URL,
    authenticating with a broker-injected secret. It will not send anywhere else:
    the URL is set at CONSTRUCTION and validated there, never taken from the
    (untrusted) proposal.

    `allowed_hosts` narrows further: even a valid https URL must name a host on
    the list, if one is given. Pass it whenever the destination is known, which is
    every case where a real credential is involved.

    REDIRECTS. This tool does not follow them, and a transport used with it must
    not either. A 3xx from the allowed host would otherwise send the Authorization
    header to whatever Location says, which defeats the entire point of pinning a
    destination. `real_requests_transport` sets allow_redirects=False.
    """
    def __init__(self, allowed_url: str, transport: Transport, method: str = "GET",
                 allowed_hosts: Optional[frozenset[str]] = None,
                 allowed_ports: frozenset[int] = DEFAULT_ALLOWED_PORTS):
        # Validate and normalize BEFORE storing. An HttpTool that exists is an
        # HttpTool whose destination is safe.
        self.allowed_url = validate_destination(
            allowed_url, allowed_hosts=allowed_hosts, allowed_ports=allowed_ports
        )
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
