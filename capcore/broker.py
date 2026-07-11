"""M3 credential broker: releases real secrets to authorized tools only.

When a tool needs a real secret (API key, token) to execute an authorized
action, the broker releases it ONLY for that action, and only when the reference
monitor has authorized it. The security properties this module enforces:

  - Secret non-exposure: a Secret's value never appears in repr/str, so it
    cannot leak into a log line, an exception, a trace, or a model-facing
    reason. The raw value is reachable only through an explicit .reveal() call.
  - Capability binding: a credential is bound to a capability id + verb + a
    resource scope. release() hands over the secret only when the proposal
    matches the binding AND the monitor authorized it.
  - Scoped lifetime: credentials may be single-use (consumed after one release)
    and/or TTL-expiring (denied after a deadline). Expired/consumed => no secret.
  - Audit: every release attempt (granted or refused) is recorded WITHOUT the
    secret value.

The tested path uses mock secrets and a mock transport so containment is
provable and deterministic (a known mock secret must appear in the authorized
call and NOWHERE else). Real secrets + real HTTP live in scripts/demo_live_m3.py,
read from an environment variable, never committed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from capcore import Proposal, RunContext, Verdict, Decision

# We reuse capcore's segment-aware scope check for credential scoping.
from capcore import scope_covers


# --------------------------------------------------------------------------- #
# Secret: a value that never prints itself.
# --------------------------------------------------------------------------- #

class Secret:
    """Wraps a secret string so it cannot leak via repr/str/format/logging.

    The raw value is accessible ONLY through .reveal(), which is the single
    audited chokepoint. Everything else, printing, f-strings, exception
    messages, sees a redaction.
    """
    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or value == "":
            raise ValueError("secret must be a non-empty string")
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        """Return the raw secret. The ONLY way to get the value. Callers that
        reveal are responsible for not then leaking it.
        """
        return self._value

    def __repr__(self) -> str:
        return "<Secret [REDACTED]>"

    __str__ = __repr__

    def __format__(self, spec) -> str:
        return "<Secret [REDACTED]>"

    def __eq__(self, other) -> bool:
        # constant-time-ish compare only against another Secret; never expose
        return isinstance(other, Secret) and self._value == other._value

    def __hash__(self):
        return hash(("Secret", self._value))


# --------------------------------------------------------------------------- #
# Credential: a secret bound to a capability + action + scope, with lifetime.
# --------------------------------------------------------------------------- #

class CredentialError(Exception):
    pass


@dataclass
class Credential:
    id: str
    capability_id: str          # must match the authorizing capability
    verb: str                   # the action this credential is for
    scope: str                  # resource scope this credential covers
    secret: Secret
    single_use: bool = False
    ttl_seconds: Optional[float] = None
    # internal lifetime state
    _issued_at: float = field(default_factory=time.monotonic)
    _consumed: bool = False

    def __post_init__(self):
        if not self.id or not self.capability_id or not self.verb or not self.scope:
            raise CredentialError("credential id/capability_id/verb/scope must be non-empty")
        if not isinstance(self.secret, Secret):
            raise CredentialError("credential secret must be a Secret")
        if self.ttl_seconds is not None and self.ttl_seconds <= 0:
            raise CredentialError("ttl_seconds must be positive if set")

    def is_expired(self, now: Optional[float] = None) -> bool:
        if self.ttl_seconds is None:
            return False
        now = time.monotonic() if now is None else now
        return (now - self._issued_at) >= self.ttl_seconds

    def is_available(self, now: Optional[float] = None) -> bool:
        return not self._consumed and not self.is_expired(now)


# --------------------------------------------------------------------------- #
# Audit record (never contains the secret).
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ReleaseAudit:
    credential_id: str
    capability_id: str
    verb: str
    resource: str
    granted: bool
    reason: str   # never contains a secret value


# --------------------------------------------------------------------------- #
# Broker.
# --------------------------------------------------------------------------- #

class CredentialBroker:
    def __init__(self):
        self._creds: dict[str, Credential] = {}
        self.audit: list[ReleaseAudit] = []

    def issue(self, cred: Credential) -> str:
        if cred.id in self._creds:
            raise CredentialError(f"duplicate credential id: {cred.id}")
        self._creds[cred.id] = cred
        return cred.id

    def _record(self, cred_id, cap_id, verb, resource, granted, reason):
        self.audit.append(ReleaseAudit(cred_id, cap_id, verb, resource, granted, reason))

    def release(
        self,
        credential_id: str,
        authorizing_capability_id: str,
        proposal: Proposal,
        decision: Decision,
        now: Optional[float] = None,
    ) -> Optional[Secret]:
        """Release the secret for an authorized action, or None (refused).

        A secret is released ONLY when ALL hold:
          - the credential exists and is available (not consumed, not expired)
          - the monitor's decision for this proposal is ALLOW
          - the credential is bound to the authorizing capability
          - the credential's verb matches the proposal's verb
          - the credential's scope covers the proposal's resource

        On success a single-use credential is consumed. Every attempt is audited
        WITHOUT the secret value.
        """
        cred = self._creds.get(credential_id)
        if cred is None:
            self._record(credential_id, authorizing_capability_id,
                         proposal.verb, proposal.resource, False,
                         "no such credential")
            return None

        if decision.verdict != Verdict.ALLOW:
            self._record(cred.id, authorizing_capability_id, proposal.verb,
                         proposal.resource, False,
                         f"action not authorized (verdict={decision.verdict.value})")
            return None

        if cred.capability_id != authorizing_capability_id:
            self._record(cred.id, authorizing_capability_id, proposal.verb,
                         proposal.resource, False,
                         "credential not bound to the authorizing capability")
            return None

        if cred.verb != proposal.verb:
            self._record(cred.id, authorizing_capability_id, proposal.verb,
                         proposal.resource, False,
                         "credential verb does not match action")
            return None

        if not scope_covers(cred.scope, proposal.resource):
            self._record(cred.id, authorizing_capability_id, proposal.verb,
                         proposal.resource, False,
                         "credential scope does not cover resource")
            return None

        if not cred.is_available(now):
            why = "expired" if cred.is_expired(now) else "already consumed"
            self._record(cred.id, authorizing_capability_id, proposal.verb,
                         proposal.resource, False, f"credential {why}")
            return None

        # all checks pass: release, consuming single-use
        if cred.single_use:
            cred._consumed = True
        self._record(cred.id, authorizing_capability_id, proposal.verb,
                     proposal.resource, True, "released")
        return cred.secret
