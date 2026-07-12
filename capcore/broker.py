"""M3 credential broker: a credential BOUNDARY, not a secret getter.

WHY THIS IS SHAPED THIS WAY.

The previous broker took a caller-supplied `Decision` and checked
`decision.verdict == ALLOW`. That is authorization by INSPECTION, and inspection
cannot establish authenticity in Python: `Decision(Verdict.ALLOW, "authorized")`
is one constructor call away, so any caller could mint an ALLOW and obtain a real
secret. Enriching the object does not help. A frozen dataclass carrying a digest,
a capability version and an expiry is integrity-preserving after construction,
but it is still not AUTHENTIC: an attacker who can call the constructor can set
whatever fields the broker wants to see.

So the broker REDEEMS rather than INSPECTS.

  1. The engine, having obtained a real ALLOW from the reference monitor, asks
     the broker to register the exact execution it intends. The broker builds a
     PendingAuthorization in ITS OWN state and returns an opaque random
     `action_id`.
  2. To execute, the caller presents ONLY that id: redeem_and_execute(id). The
     broker looks it up in its own table. A forged authorization object is
     irrelevant, because the broker never reads a caller-supplied one.

The action_id is not the authority. It is a lookup key. The authority is the
broker-held record.

This closes four attacks at once:

  FORGERY       A fabricated authorization has no record. Lookup fails.
  REPLAY        Redemption atomically claims PENDING -> EXECUTING. A second
                redemption finds a non-PENDING record and is refused. Single-use
                is a state machine, not a deletion.
  STALENESS     The broker re-authorizes through the LIVE monitor immediately
                before touching the secret. A capability revoked after mint means
                the secret never leaves.
  SUBSTITUTION  The caller supplies neither the tool nor the credential at
                redemption. Both are bound at mint time and resolved by the
                broker from its own registries. A valid action_id cannot be aimed
                at a different credential, a different adapter, or a same-named
                tool swapped out in between (the record pins registration id AND
                version).

And the secret never leaves the boundary: redeem_and_execute injects the
credential, calls the trusted adapter itself, catches everything, and returns a
sanitized result. There is no API that hands a Secret back to general code.

RE-AUTHORIZATION SEMANTICS (a deliberate choice, documented).
The broker asks the monitor: "is this action authorized RIGHT NOW, through any
valid capability path?" That is CURRENT-AUTHORITY semantics. It is NOT
original-capability-continuity: if the capability that originally authorized the
action is revoked but a different valid capability would independently authorize
the same action, redemption still succeeds. That is intended for v1 and it is the
question a revocation check is actually asking. Binding to the exact original
capability path would need the monitor to return the granting capability ids,
which it does not currently do.

KNOWN LIMIT (stated, not hidden).
The broker keeps the credential away from the engine, the model, and general
application code. It CANNOT protect the credential from a malicious credentialed
adapter in the same process: the adapter receives the secret in order to use it,
and could log, retain, or exfiltrate it. Every CredentialedTool is therefore
inside the trusted computing base. Acceptable for v1, but it must stay explicit.
Real isolation means running credentialed adapters in a separate process behind
restricted IPC.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional, Protocol

from capcore import (
    Proposal, ReferenceMonitor, RunContext, Verdict, scope_covers,
    valid_proposal,
)


# --------------------------------------------------------------------------- #
# Secret.
# --------------------------------------------------------------------------- #

class Secret:
    """Wraps a secret string so it cannot leak via repr/str/format/logging.

    SCOPE OF THIS PROTECTION. This protects the WRAPPER. Once .reveal() is called
    and the value is interpolated into (say) an Authorization header, the result
    is an ordinary Python string with no protection at all, and any exception
    carrying it carries the credential. That is precisely why .reveal() is now
    called ONLY inside the broker's execution boundary, where exceptions are
    caught and discarded. The wrapper defends against accidental logging, not
    against a hostile adapter.
    """
    __slots__ = ("_value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or value == "":
            raise ValueError("secret must be a non-empty string")
        object.__setattr__(self, "_value", value)

    def reveal(self) -> str:
        """Return the raw secret. Called only inside the broker boundary."""
        return self._value

    def __repr__(self) -> str:
        return "<Secret [REDACTED]>"

    __str__ = __repr__

    def __format__(self, spec) -> str:
        return "<Secret [REDACTED]>"

    def __eq__(self, other) -> bool:
        return isinstance(other, Secret) and self._value == other._value

    def __hash__(self):
        return hash(("Secret", self._value))


class CredentialError(Exception):
    pass


class AuthorizationError(Exception):
    """Redemption refused. Never carries a secret or a boundary detail."""
    pass


# --------------------------------------------------------------------------- #
# Credential.
# --------------------------------------------------------------------------- #

@dataclass
class Credential:
    id: str
    capability_id: str
    verb: str
    scope: str
    secret: Secret
    single_use: bool = False
    ttl_seconds: Optional[float] = None
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
# Tools. A plain tool never sees a credential. A credentialed tool does, and is
# therefore inside the TCB.
# --------------------------------------------------------------------------- #

class ToolKind(Enum):
    PLAIN = "plain"
    CREDENTIALED = "credentialed"


class PlainTool(Protocol):
    def __call__(self, proposal: Proposal) -> str: ...


class CredentialedTool(Protocol):
    """Executes an authorized action WITH a credential.

    A distinct method name, not an optional `secret=None` on PlainTool. Making
    the secret optional would let a credentialed adapter be dispatched down the
    plain path (running silently unauthenticated) and would bury the trust
    boundary in a default argument. These are different kinds of thing and the
    types say so.
    """
    def execute_with_credential(self, proposal: Proposal, secret: Secret) -> str: ...


@dataclass(frozen=True)
class ToolRegistration:
    """A tool as the broker knows it.

    `version` exists so an authorization cannot be redeemed against a tool that
    was swapped out after the authorization was minted. The record pins
    registration_id AND version; if either moved, redemption is refused.
    """
    registration_id: str
    kind: ToolKind
    adapter: object                       # PlainTool | CredentialedTool
    version: str = "1"
    credential_id: Optional[str] = None   # required iff kind is CREDENTIALED

    def __post_init__(self):
        if self.kind is ToolKind.CREDENTIALED and not self.credential_id:
            raise CredentialError("a credentialed tool must name its credential")
        if self.kind is ToolKind.PLAIN and self.credential_id:
            raise CredentialError("a plain tool must not name a credential")


# --------------------------------------------------------------------------- #
# Authorization state machine.
# --------------------------------------------------------------------------- #

class AuthorizationState(Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class PendingAuthorization:
    """Broker-held record of one authorized execution. Never leaves the broker.

    NOT a token the caller carries. Trusted state the broker keeps. The caller
    receives only `action_id`: an opaque random key with no authority of its own.
    """
    action_id: str
    context: RunContext
    proposal: Proposal
    proposal_digest: str
    tool_registration_id: str
    tool_version: str
    credential_id: Optional[str]
    issued_at: float
    expires_at: float
    state: AuthorizationState = AuthorizationState.PENDING


def proposal_digest(proposal: Proposal) -> str:
    """Canonical digest of a proposal, computed BY THE BROKER.

    A caller-supplied digest would be worthless: an attacker who can forge an
    authorization can forge its digest too. The broker computes this from the
    proposal it stored, so the digest is an internal integrity check, never an
    authorization input.
    """
    canonical = f"{proposal.verb}\x00{proposal.resource}".encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------- #
# Sanitized result. Nothing crossing this boundary carries a secret.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SanitizedToolResult:
    ok: bool
    body: Optional[str] = None
    code: Optional[str] = None   # stable generic failure code, never a message

    @staticmethod
    def succeeded(body: str) -> "SanitizedToolResult":
        return SanitizedToolResult(ok=True, body=body)

    @staticmethod
    def failed(code: str) -> "SanitizedToolResult":
        return SanitizedToolResult(ok=False, code=code)


@dataclass(frozen=True)
class ReleaseAudit:
    action_id: str
    credential_id: Optional[str]
    verb: str
    resource: str
    granted: bool
    reason: str   # never contains a secret value


# --------------------------------------------------------------------------- #
# Broker.
# --------------------------------------------------------------------------- #

DEFAULT_ACTION_TTL_SECONDS = 30.0


class CredentialBroker:
    """Owns credentials, tool registrations, pending authorizations, dispatch.

    This is a large TCB surface and that is a real cost. The alternative, a broker
    that only hands out secrets, cannot structurally stop the secret escaping into
    general code, surfacing in an exception, or being reused after revocation. For
    a project whose central claim is a credential boundary, the boundary has to
    actually be one.
    """

    def __init__(self, monitor: ReferenceMonitor,
                 action_ttl_seconds: float = DEFAULT_ACTION_TTL_SECONDS):
        if not isinstance(monitor, ReferenceMonitor):
            raise TypeError("broker requires a ReferenceMonitor for re-authorization")
        if action_ttl_seconds <= 0:
            raise ValueError("action_ttl_seconds must be positive")
        self._monitor = monitor
        self._action_ttl = action_ttl_seconds
        self._creds: dict[str, Credential] = {}
        self._tools: dict[str, ToolRegistration] = {}
        self._pending: dict[str, PendingAuthorization] = {}
        self.audit: list[ReleaseAudit] = []

    # -- registration ------------------------------------------------------- #

    def issue(self, cred: Credential) -> str:
        if cred.id in self._creds:
            raise CredentialError(f"duplicate credential id: {cred.id}")
        self._creds[cred.id] = cred
        return cred.id

    def register_tool(self, reg: ToolRegistration) -> str:
        if reg.registration_id in self._tools:
            raise CredentialError(f"duplicate tool registration: {reg.registration_id}")
        if reg.kind is ToolKind.CREDENTIALED and reg.credential_id not in self._creds:
            raise CredentialError("credentialed tool names an unknown credential")
        self._tools[reg.registration_id] = reg
        return reg.registration_id

    def get_tool(self, registration_id: str) -> Optional[ToolRegistration]:
        return self._tools.get(registration_id)

    # -- mint --------------------------------------------------------------- #

    def register_authorized_execution(
        self,
        context: RunContext,
        proposal: Proposal,
        decision,
        tool_registration_id: str,
        now: Optional[float] = None,
    ) -> str:
        """Record an authorized execution; return an opaque action_id.

        Called ONLY by the trusted execution engine, after the monitor returned
        ALLOW. Registration by itself releases nothing: no credential is touched
        here, and redemption re-authorizes independently. So even if this were
        called with a bogus decision, the secret still would not leave, because
        redeem_and_execute asks the live monitor again.
        """
        if decision is None or decision.verdict != Verdict.ALLOW:
            raise AuthorizationError("cannot register an unauthorized action")
        if not valid_proposal(proposal):
            raise AuthorizationError("cannot register a malformed proposal")

        reg = self._tools.get(tool_registration_id)
        if reg is None:
            raise AuthorizationError("unknown tool registration")

        now = time.monotonic() if now is None else now
        action_id = secrets.token_urlsafe(32)

        self._pending[action_id] = PendingAuthorization(
            action_id=action_id,
            context=context,
            proposal=proposal,
            proposal_digest=proposal_digest(proposal),
            tool_registration_id=reg.registration_id,
            tool_version=reg.version,          # pinned: a swapped tool is refused
            credential_id=reg.credential_id,   # bound: cannot be substituted
            issued_at=now,
            expires_at=now + self._action_ttl,
            state=AuthorizationState.PENDING,
        )
        return action_id

    # -- redeem ------------------------------------------------------------- #

    def _claim(self, action_id: str, now: float) -> PendingAuthorization:
        """Atomically move PENDING -> EXECUTING, or refuse.

        The transition happens BEFORE the secret is resolved and before any
        external side effect. If execution later crashes, the record stays
        non-PENDING and cannot be redeemed again. That deliberately favours
        preventing a duplicate side effect over automatic retry: an ambiguous
        remote failure must NOT silently return the authorization to PENDING. A
        retry needs a fresh authorization.
        """
        record = self._pending.get(action_id)
        if record is None:
            # Forged or unknown id: the broker holds no record, so there is no
            # authorization, whatever object the caller may have constructed.
            raise AuthorizationError("unknown authorization")
        if record.state is not AuthorizationState.PENDING:
            raise AuthorizationError("authorization is not redeemable")
        if now >= record.expires_at:
            self._pending[action_id] = replace(record, state=AuthorizationState.FAILED)
            raise AuthorizationError("authorization expired")

        claimed = replace(record, state=AuthorizationState.EXECUTING)
        self._pending[action_id] = claimed
        return claimed

    def _settle(self, action_id: str, state: AuthorizationState) -> None:
        record = self._pending.get(action_id)
        if record is not None:
            self._pending[action_id] = replace(record, state=state)

    def _record(self, action_id, cred_id, proposal, granted, reason):
        self.audit.append(ReleaseAudit(
            action_id=action_id,
            credential_id=cred_id,
            verb=proposal.verb if proposal is not None else "?",
            resource=proposal.resource if proposal is not None else "?",
            granted=granted,
            reason=reason,
        ))

    def redeem_and_execute(
        self,
        action_id: str,
        now: Optional[float] = None,
    ) -> SanitizedToolResult:
        """Execute exactly the authorization identified by action_id.

        The caller supplies ONLY the id. Not the tool, not the credential, not
        the proposal. All three were bound at mint time and are resolved here
        from the broker's own state. That is what closes substitution: a valid
        action_id cannot be aimed at a different credential or a different
        adapter.
        """
        now = time.monotonic() if now is None else now

        try:
            record = self._claim(action_id, now)
        except AuthorizationError as e:
            self._record(action_id, None, None, False, str(e))
            return SanitizedToolResult.failed("authorization_refused")

        try:
            # 1. LIVE re-authorization (current-authority semantics; see module
            #    docstring). A capability revoked since mint stops us here,
            #    BEFORE the secret is resolved.
            live = self._monitor.authorize(record.context, record.proposal)
            if live.verdict != Verdict.ALLOW:
                self._settle(action_id, AuthorizationState.FAILED)
                self._record(action_id, record.credential_id, record.proposal,
                             False, "re-authorization failed at redemption")
                return SanitizedToolResult.failed("authorization_refused")

            # 2. Internal integrity check. The stored proposal must still hash to
            #    the digest minted with it. The caller cannot influence either.
            if proposal_digest(record.proposal) != record.proposal_digest:
                self._settle(action_id, AuthorizationState.FAILED)
                self._record(action_id, record.credential_id, record.proposal,
                             False, "proposal digest mismatch")
                return SanitizedToolResult.failed("authorization_refused")

            # 3. Resolve the tool from the BROKER's registry, pinned to the exact
            #    version bound at mint. A tool swapped out in between is refused.
            reg = self._tools.get(record.tool_registration_id)
            if reg is None or reg.version != record.tool_version:
                self._settle(action_id, AuthorizationState.FAILED)
                self._record(action_id, record.credential_id, record.proposal,
                             False, "tool registration changed since authorization")
                return SanitizedToolResult.failed("authorization_refused")

            # 4. Dispatch on the REGISTERED kind, not isinstance against a
            #    Protocol (which is structural and would match any object with
            #    the right attribute names).
            if reg.kind is ToolKind.PLAIN:
                return self._execute_plain(action_id, reg, record)
            return self._execute_credentialed(action_id, reg, record, now)

        except Exception:
            # Exception, not BaseException: KeyboardInterrupt and SystemExit must
            # not be swallowed by the credential boundary.
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, record.credential_id, record.proposal,
                         False, "execution failed")
            return SanitizedToolResult.failed("execution_failed")

    def _execute_plain(self, action_id, reg, record) -> SanitizedToolResult:
        try:
            out = reg.adapter(record.proposal)
        except Exception:
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, None, record.proposal, False, "tool raised")
            return SanitizedToolResult.failed("tool_failed")
        self._settle(action_id, AuthorizationState.COMPLETED)
        self._record(action_id, None, record.proposal, True, "executed")
        return SanitizedToolResult.succeeded(out)

    def _execute_credentialed(self, action_id, reg, record, now) -> SanitizedToolResult:
        cred = self._creds.get(record.credential_id)
        if cred is None:
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, record.credential_id, record.proposal,
                         False, "no such credential")
            return SanitizedToolResult.failed("authorization_refused")

        # The credential's own binding must hold independently of the capability
        # check: credential scope is not capability scope, and a credential may
        # be strictly narrower than the capability that authorized the action.
        if cred.verb != record.proposal.verb:
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, record.proposal, False,
                         "credential verb does not match action")
            return SanitizedToolResult.failed("authorization_refused")

        if not scope_covers(cred.scope, record.proposal.resource):
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, record.proposal, False,
                         "credential scope does not cover resource")
            return SanitizedToolResult.failed("authorization_refused")

        if not cred.is_available(now):
            why = "expired" if cred.is_expired(now) else "already consumed"
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, record.proposal, False,
                         f"credential {why}")
            return SanitizedToolResult.failed("authorization_refused")

        if cred.single_use:
            cred._consumed = True

        # THE CREDENTIAL BOUNDARY.
        # The secret is revealed only inside this try, only to the trusted
        # adapter, and every exception is caught and DISCARDED here. The exception
        # object is never inspected, formatted, re-raised, chained, or logged: a
        # transport that raises RuntimeError(headers["Authorization"]) carries the
        # credential in its message, and the only safe thing to do with such an
        # object is drop it on the floor. This is why the failure code below is a
        # constant and not derived from the exception in any way.
        try:
            out = reg.adapter.execute_with_credential(record.proposal, cred.secret)
        except Exception:
            self._settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, record.proposal, False,
                         "credentialed tool failed")
            return SanitizedToolResult.failed("credentialed_tool_execution_failed")

        self._settle(action_id, AuthorizationState.COMPLETED)
        self._record(action_id, cred.id, record.proposal, True, "executed")
        return SanitizedToolResult.succeeded(out)

    # -- introspection (trusted callers; carries no secret) ------------------ #

    def authorization_state(self, action_id: str) -> Optional[AuthorizationState]:
        record = self._pending.get(action_id)
        return record.state if record else None
