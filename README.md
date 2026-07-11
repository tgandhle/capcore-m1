# MCP Auth Gateway

An OAuth 2.1 / JWT-enforcing reverse proxy that sits in front of a Model
Context Protocol (MCP) server. It authenticates inbound requests, enforces
per-method scopes, and forwards verified identity to the upstream MCP server.

The MCP transport is JSON-RPC 2.0 over HTTP. MCP servers themselves usually do
no authorization. This gateway adds that layer without modifying the server:
point your MCP clients at the gateway, point the gateway at the server.

## What it does

- **Token verification.** Validates inbound bearer JWTs against a JWKS
  (RFC 7517) published by your authorization server. Enforces `iss`, `aud`,
  `exp`, `iat` (and `nbf` when present). Pins acceptable signing algorithms to asymmetric only
  (RS/ES/PS); `none` and HMAC algs are refused at construction time, which
  closes the algorithm-confusion class of bypass.
- **Key rotation.** Selects the verification key by the token's `kid`. On a
  `kid` miss it force-refreshes the JWKS once before failing closed, rate-limited
  to at most one forced refresh per cooldown window so unknown-`kid` traffic
  cannot amplify into repeated JWKS fetches.
- **Per-method scope enforcement.** MCP methods (`tools/call`, `tools/list`,
  `resources/read`, ...) are mapped to required scopes by a policy. Read vs.
  invoke is separated by default. Unknown methods are denied by default.
- **Protected-resource metadata.** Serves RFC 9728
  `/.well-known/oauth-protected-resource` so spec-compliant MCP clients can
  discover which authorization server guards this resource. 401 responses
  carry a `WWW-Authenticate` header pointing at it.
- **Identity forwarding.** Strips the inbound `Authorization` header before
  proxying and passes verified `sub` / scopes to the upstream via
  `X-Forwarded-Sub` / `X-Forwarded-Scopes`. The upstream trusts these only
  because it sits behind this gateway on a private network.
- **PKCE helper.** RFC 7636 verifier/challenge generation and authorization-URL
  building, for clients that need to acquire tokens.
- **Audit logging.** Every authorization decision emits one structured JSON line
  on the `mcp_gateway.audit` logger: request id, subject, method, decision,
  required scopes, held-scope count, upstream status, latency, source IP. Raw
  tokens and PKCE verifiers are never logged. Scope *values* appear only at
  DEBUG; INFO logs the count.
- **Resilience guards.** Configurable max request body size (default 5 MiB,
  returns `413`) and per-phase upstream timeouts (connect/read/write/pool).

## Why these choices

The gateway verifies tokens; it does not issue them. In an enterprise setup an
IdP (PingFederate, Entra, Auth0, Okta) runs the authorization-code + PKCE flow
and issues the JWT. The gateway's job is the resource-server half of OAuth:
verify the token and enforce scope. That separation is deliberate and matches
how this is deployed in practice.

## Configuration

All config is environment-driven (prefix `GATEWAY_`) or via a `.env` file.

| Variable | Required | Meaning |
|---|---|---|
| `GATEWAY_UPSTREAM_URL` | yes | Backend MCP server URL, e.g. `http://127.0.0.1:9000/mcp` |
| `GATEWAY_ISSUER` | yes | Required `iss` claim; also the auth-server id in metadata |
| `GATEWAY_AUDIENCE` | yes | Required `aud` claim; this gateway's resource id |
| `GATEWAY_JWKS_URL` | yes (if auth on) | JWKS endpoint of the authorization server |
| `GATEWAY_JWKS_MIN_REFRESH_INTERVAL` | no | Min seconds between forced JWKS refreshes on a `kid` miss; default `10`. Caps JWKS refetch rate under unknown-`kid` traffic |
| `GATEWAY_ALLOWED_ALGORITHMS` | no | Default `["RS256","ES256"]` |
| `GATEWAY_SCOPE_POLICY_FILE` | no | JSON scope policy; built-in default if unset |
| `GATEWAY_REQUIRE_AUTH` | no | Default `true`; set `false` only for local dev |
| `GATEWAY_HOST` / `GATEWAY_PORT` | no | Default `127.0.0.1:8080` |
| `GATEWAY_PUBLIC_BASE_URL` | no | External URL (e.g. `https://mcp.example.com`) for metadata/`WWW-Authenticate` when behind TLS or a load balancer |
| `GATEWAY_MAX_REQUEST_BYTES` | no | Reject bodies larger than this; default 5 MiB, `0` disables |
| `GATEWAY_CONNECT_TIMEOUT` / `_READ_TIMEOUT` / `_WRITE_TIMEOUT` / `_POOL_TIMEOUT` | no | Per-phase upstream timeouts; fall back to `GATEWAY_UPSTREAM_TIMEOUT` |

## Run

```bash
pip install -e ".[dev]"

export GATEWAY_UPSTREAM_URL=http://127.0.0.1:9000/mcp
export GATEWAY_ISSUER=https://login.example.com/
export GATEWAY_AUDIENCE=mcp-gateway
export GATEWAY_JWKS_URL=https://login.example.com/.well-known/jwks.json

mcp-gateway
```

The gateway validates its configuration at startup and refuses to run on an
unsafe or unusable config (auth enabled with no JWKS URL, a symmetric or `none`
signing algorithm, a missing scope-policy file, out-of-range port or timeouts,
a `public_base_url` with no scheme). All problems are reported together and the
process exits non-zero, so misconfiguration is caught at boot rather than on the
first request.

## Scope policy file format

```json
{
  "rules": {
    "initialize": [],
    "tools/list": ["mcp:read"],
    "tools/call": ["mcp:invoke"],
    "resources/": ["mcp:read"]
  },
  "default": [],
  "deny_by_default": true
}
```

A key ending in `/` is a prefix rule covering every method beneath it. An exact
method rule overrides a prefix rule. All scopes listed for a rule are required
(AND).

## Tests

```bash
pytest
```

Tests sign real RS256 JWTs with a generated RSA key and exercise the verifier,
the scope policy, the PKCE helper, and the full proxy path (including that the
`Authorization` header is not forwarded upstream and that a read-scoped token
cannot invoke a tool).

## Status and limits

- JSON-RPC batch requests (arrays) are rejected with `400 batch_not_supported`,
  because per-item authorization is not implemented and forwarding an
  unchecked batch would let a caller smuggle a method past the scope check.
  Malformed JSON and JSON-RPC objects without a string `method` are likewise
  rejected with `400` rather than proxied. The authorization path fails closed.
- Streaming (SSE) MCP responses are not yet proxied as true streams: this build
  buffers the upstream response body before returning it. Streaming pass-through
  and an explicit cap on upstream response size are known next steps (the request
  side is already capped).
- The protected-resource metadata and `WWW-Authenticate` URLs honor
  `GATEWAY_PUBLIC_BASE_URL` when set, and fall back to the bind host/port. Set
  it when running behind TLS or a load balancer.

## Security

The [threat model](docs/THREAT-MODEL.md) states what the gateway defends
against, what it does not, and the preconditions its security depends on (most
importantly, that the upstream is not reachable directly by clients). Each
defense points at the code or CI that backs it.

To report a vulnerability, see [`SECURITY.md`](SECURITY.md).

## License

MIT. See `LICENSE`.
