"""M3: the trusted execution boundary.

The engine does not execute tools. It asks THIS component to, and receives only a
sanitized result. That is the whole point: there is exactly one path from an
authorized proposal to a running adapter, and it goes through here.

WHY THE BROKER REDEEMS INSTEAD OF INSPECTING.

An earlier broker took a caller-supplied `Decision` and checked
`decision.verdict == ALLOW`. That is authorization by INSPECTION, and inspection
cannot establish authenticity in Python: `Decision(Verdict.ALLOW, "authorized")`
is one constructor call away. Enriching the object does not help. A frozen
dataclass carrying a digest, a version and an expiry is integrity-preserving
after construction but still not AUTHENTIC, because an attacker who can call the
constructor sets whatever fields the checker wants to see.

So this component REDEEMS:

  1. register_authorized_execution(context, execution_proposal) -> action_id
     The broker authorizes INDEPENDENTLY through its own monitor (it does not
     accept a decision from the caller at all), resolves the tool from its own
     catalog, checks the tool policy, and stores a PendingAuthorization in its
     own state. It returns an opaque random id.
  2. redeem_and_execute(action_id) -> SanitizedToolResult
     The caller presents ONLY the id. Everything else, the proposal, the tool,
     the version, the credential, is read from the stored record.

The action_id is not the authority. It is a lookup key. The authority is the
broker-held record.

This closes:

  FORGERY       A fabricated authorization has no record; lookup fails. And a
                forged Decision buys nothing because the broker never reads one.
  REPLAY        Redemption atomically claims PENDING -> EXECUTING. A second
                redemption finds a non-PENDING record. Single-use is a state
                machine, not a deletion.
  STALENESS     The broker re-authorizes through the LIVE monitor immediately
                before touching the credential. Revoked after mint means the
                secret never leaves.
  SUBSTITUTION  The caller supplies neither tool nor credential at redemption.
                Both are bound at mint and resolved from broker state. The record
                pins registration id AND version, so a tool swapped out after
                authorization is refused.
  MIS-ROUTING   Catalog existence is NOT authorization. `read_customer_record`
                and `read_payroll_database` may both satisfy verb=read. A model
                that picks its own executor must not thereby choose which one
                runs. ToolPolicy authorizes the exact registration for the exact
                action, deny-by-default.

STRUCTURE. One interface outward, separated responsibilities inward:

    TrustedExecutionBroker
      ├── ToolCatalog                registration_id -> ToolRegistration
      ├── ToolPolicy                 may THIS registration serve THIS action?
      ├── PendingAuthorizationStore  action_id -> record + state machine
      ├── CredentialVault            credential_id -> Credential (secret logic)
      └── ReferenceMonitor           authorizes at register AND at redeem

RE-AUTHORIZATION SEMANTICS (deliberate, documented).
Redemption asks the monitor: "is this action authorized RIGHT NOW, through any
valid capability path?" That is CURRENT-AUTHORITY semantics, not
original-capability-continuity: if the capability that originally authorized the
action is revoked but a different valid capability would independently authorize
it, redemption still succeeds. Intended for v1; it is the question a revocation
check actually asks. Binding to the exact original capability path would need the
monitor to return granting capability ids, which it does not.

KNOWN LIMIT (stated, not hidden).
This boundary keeps the credential away from the engine, the model, and general
application code. It CANNOT protect the credential from a malicious credentialed
adapter in the same process: the adapter receives the secret in order to use it,
and could log, retain, or exfiltrate it. Every CredentialedTool is therefore
inside the trusted computing base. Acceptable for v1, and it must stay explicit.
Real isolation means running credentialed adapters in a separate process behind
restricted IPC.
"""

from __future__ import annotations

import hashlib
import threading
import secrets
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional, Protocol

from capcore import (
    Proposal, ReferenceMonitor, ResourceError, RunContext, Verdict,
    _covers_safe, scope_covers, valid_proposal, validate_resource,
)

# Bound on the untrusted tool-registration id the model names.
MAX_TOOL_ID_BYTES = 128


# --------------------------------------------------------------------------- #
# Errors.
# --------------------------------------------------------------------------- #

class CredentialError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Clock. Security time comes from HERE, never from a caller.
# --------------------------------------------------------------------------- #

class Clock(Protocol):
    """A monotonic time source. TTL and expiry decisions read it.

    The broker owns one clock, injected at construction. Production methods do
    NOT accept a `now` argument: an earlier version did, which let a caller mint a
    far-future expiry or make an expired authorization look current at redemption.
    Security time must not be caller-controllable.
    """
    def now(self) -> float: ...


class SystemClock:
    """The real monotonic clock. The production default."""
    def now(self) -> float:
        return time.monotonic()


class FakeClock:
    """A controllable clock for tests. Replaces the removed `now=` backdoor.

    Tests advance time explicitly instead of passing timestamps into production
    methods, so there is no path through which a caller could do the same.
    """
    def __init__(self, value: float = 0.0):
        self.value = value

    def now(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class AuthorizationError(Exception):
    """Registration or redemption refused. Never carries a secret."""
    pass


class CatalogError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Secret.
# --------------------------------------------------------------------------- #

class Secret:
    """Wraps a secret string so it cannot leak via repr/str/format/logging.

    SCOPE OF THIS PROTECTION. This protects the WRAPPER. Once .reveal() is called
    and the value is interpolated into (say) an Authorization header, the result
    is an ordinary Python string with no protection at all, and any exception
    carrying that string carries the credential. That is exactly why .reveal() is
    called ONLY inside this module's execution boundary, where exceptions are
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


# --------------------------------------------------------------------------- #
# ExecutionProposal: an M1 action PLUS the concrete executor to run it.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ExecutionProposal:
    """What the model proposes at the execution layer.

    Deliberately a SEPARATE type from M1's `Proposal`, not an extra optional
    field on it. The layers mean different things:

        Proposal            the requested security ACTION (verb + resource)
        ExecutionProposal   that action, plus WHICH concrete executor runs it

    M1's Proposal stays exactly as reviewed: the reference monitor authorizes
    `.action` and knows nothing about executors. Making the registration id an
    optional field with an empty default would have created two definitions of a
    valid proposal and left `Proposal(resource=..., verb=..., tool_registration_id="")`
    passing M1 validation while being unusable for execution. A required field on
    a separate type makes an incomplete executable proposal unrepresentable.

    `tool_registration_id` is UNTRUSTED. The model may name whichever executor it
    likes; naming it does not authorize it. ToolPolicy decides.
    """
    action: Proposal
    tool_registration_id: str

    def __post_init__(self):
        # EXACT types. A Proposal subclass or a str-subclass tool id could carry
        # different semantics into execution than authorization validated.
        if type(self.action) is not Proposal:
            raise AuthorizationError("execution proposal requires an exact Proposal action")
        if type(self.tool_registration_id) is not str or not self.tool_registration_id:
            raise AuthorizationError("execution proposal requires an exact str tool_registration_id")
        if len(self.tool_registration_id.encode("utf-8")) > MAX_TOOL_ID_BYTES:
            raise AuthorizationError("tool_registration_id exceeds maximum length")


# --------------------------------------------------------------------------- #
# Credentials and the vault that holds them.
# --------------------------------------------------------------------------- #

@dataclass
class Credential:
    """A secret plus its binding, under current-authority semantics.

    NOTE: there is deliberately NO `capability_id` field. An earlier version had
    one, but the broker never checked it: under current-authority semantics a
    credential is constrained by verb, scope, TTL, single-use state, its tool
    binding, and LIVE re-authorization through the monitor. `capability_id` was
    never inspected on any path, so it was dead state that implied an
    exact-capability binding the system does not enforce, a false security claim.
    It has been removed rather than enforced, to keep the credential model honest.
    If issuance provenance is ever needed for audit, add a clearly non-authoritative
    field (e.g. `provenance`) that the authorization path never reads.
    """
    id: str
    verb: str
    scope: str
    secret: Secret
    single_use: bool = False
    ttl_seconds: Optional[float] = None
    # NOT a constructor field. A caller must not be able to backdate the TTL clock
    # by supplying _issued_at. The vault stamps it at issue time from the broker's
    # trusted clock. -1.0 is the "not yet issued" sentinel; is_expired treats an
    # unissued credential as not-expired (it cannot be redeemed before issue).
    _issued_at: float = field(init=False, default=-1.0)
    _consumed: bool = False

    def __post_init__(self):
        if not self.id or not self.verb or not self.scope:
            raise CredentialError("credential id/verb/scope must be non-empty")
        if not isinstance(self.secret, Secret):
            raise CredentialError("credential secret must be a Secret")
        if self.ttl_seconds is not None and self.ttl_seconds <= 0:
            raise CredentialError("ttl_seconds must be positive if set")
        # FAIL CLOSED AT ISSUANCE, not at use.
        #
        # A credential scope of "../bad" used to be accepted here and only blow up
        # later, inside redeem, as a ResourceError from scope_covers. That is the
        # wrong place and the wrong time: a malformed scope is a configuration
        # defect, and it should be impossible to hold a credential whose binding
        # cannot be evaluated. Deferring the check to use also means the failure
        # surfaces during a live action, when a secret is already in play.
        #
        # validate_resource is the same canonicalizer M1 uses for capabilities and
        # deny policies: it rejects traversal, encoded separators, empty segments,
        # backslashes, control characters, and wildcards.
        try:
            validate_resource(self.scope)
        except ResourceError as exc:
            raise CredentialError(f"invalid credential scope: {self.scope!r}") from exc

    def is_expired(self, now: float) -> bool:
        if self.ttl_seconds is None:
            return False
        if self._issued_at < 0:
            return False   # not yet issued; cannot be expired
        return (now - self._issued_at) >= self.ttl_seconds

    def is_available(self, now: float) -> bool:
        return not self._consumed and not self.is_expired(now)


@dataclass(frozen=True)
class _StoredCredential:
    """The vault's OWN copy of a credential. Immutable and not caller-reachable.

    The vault copies the caller's `Credential` values into this at issue time and
    stores THIS, never the caller's object. So a caller who retains a reference to
    the original `Credential` and mutates it (widening scope, resetting single-use,
    backdating the TTL, or swapping `secret._value`) changes nothing the broker
    reads. Consumption state lives in the vault (a set of consumed ids), not on
    this record, so even the vault does not mutate it.

    The secret is a FRESH `Secret` built from a copied value, so mutating the
    caller's original `Secret._value` after issuance does not affect this one.
    """
    id: str
    verb: str
    scope: str
    secret: Secret
    single_use: bool
    ttl_seconds: Optional[float]
    issued_at: float

    def is_expired(self, now: float) -> bool:
        if self.ttl_seconds is None:
            return False
        return (now - self.issued_at) >= self.ttl_seconds


class CredentialVault:
    """Holds credentials. The ONLY place raw secrets live.

    Stores immutable, vault-owned copies (`_StoredCredential`), never the caller's
    object, so no retained caller reference can mutate trusted credential state
    after issuance. Consumption is tracked in a vault-owned set under the lock.
    """

    def __init__(self, clock: Clock):
        self._creds: dict[str, _StoredCredential] = {}
        self._consumed_ids: set[str] = set()
        self._clock = clock
        # Serializes availability-check + consume for single-use credentials, so
        # two concurrent redemptions cannot both see an unconsumed credential and
        # both deliver the secret. Same reasoning as the pending-store lock.
        self._lock = threading.Lock()

    def issue(self, cred: Credential) -> str:
        if cred.id in self._creds:
            raise CredentialError(f"duplicate credential id: {cred.id}")
        # COPY the caller's values into a vault-owned immutable record. The secret
        # value is copied into a fresh Secret, so mutating the caller's original
        # (even secret._value) cannot reach the stored copy. The TTL clock is
        # stamped HERE from the trusted clock, never from the caller.
        stored = _StoredCredential(
            id=cred.id,
            verb=cred.verb,
            scope=cred.scope,
            secret=Secret(cred.secret.reveal()),   # fresh, copied value
            single_use=cred.single_use,
            ttl_seconds=cred.ttl_seconds,
            issued_at=self._clock.now(),
        )
        self._creds[cred.id] = stored
        return cred.id

    def resolve(self, credential_id: str) -> Optional[_StoredCredential]:
        return self._creds.get(credential_id)

    def claim_credential(self, credential_id: str, now: float) -> tuple[bool, str]:
        """Atomically check availability and consume a single-use credential.

        Availability and consumption are decided against vault-owned state (the
        immutable record plus the consumed-id set), under the lock. Nothing here
        reads or writes a caller-reachable object.
        """
        with self._lock:
            cred = self._creds.get(credential_id)
            if cred is None:
                return False, "no such credential"
            if cred.id in self._consumed_ids:
                return False, "already consumed"
            if cred.is_expired(now):
                return False, "expired"
            if cred.single_use:
                self._consumed_ids.add(cred.id)
            return True, "ok"


# --------------------------------------------------------------------------- #
# Tools and the catalog that holds them.
# --------------------------------------------------------------------------- #

class ToolKind(Enum):
    PLAIN = "plain"
    CREDENTIALED = "credentialed"


class PlainTool(Protocol):
    def __call__(self, proposal: Proposal) -> str: ...


class CredentialedTool(Protocol):
    """Executes an authorized action WITH a credential.

    A distinct method name, not an optional `secret=None` on PlainTool. An
    optional secret would let a credentialed adapter be dispatched down the plain
    path (running silently unauthenticated) and would bury the trust boundary in
    a default argument. These are different kinds of thing; the types say so.
    """
    def execute_with_credential(self, proposal: Proposal, secret: Secret) -> str: ...


@dataclass(frozen=True)
class ToolRegistration:
    """A concrete executor.

    `verb` is the action class this executor serves; it must match the proposed
    action's verb. `version` is pinned into an authorization so a tool swapped out
    between authorization and redemption cannot inherit the old grant.
    """
    registration_id: str
    verb: str
    kind: ToolKind
    adapter: object                        # PlainTool | CredentialedTool
    version: str = "1"
    credential_id: Optional[str] = None    # required iff CREDENTIALED

    def __post_init__(self):
        if not self.registration_id:
            raise CatalogError("tool registration_id must be non-empty")
        if not self.verb:
            raise CatalogError("tool registration must name a verb")
        if self.kind is ToolKind.CREDENTIALED and not self.credential_id:
            raise CatalogError("a credentialed tool must name its credential")
        if self.kind is ToolKind.PLAIN and self.credential_id:
            raise CatalogError("a plain tool must not name a credential")


class ToolCatalog:
    """The SOLE tool registry.

    The engine does not have one. There is exactly one mapping from a
    registration id to an adapter, and it lives here. Two registries that must be
    kept in sync is the same split-authority defect as a monitor and an engine
    holding different capability stores; it is not repeated.
    """

    def __init__(self):
        # registration_id -> (registration, generation). The generation is a
        # monotonic counter the CATALOG owns and the caller cannot set. It is the
        # authenticity marker for "is this the same tool the authorization was
        # minted against", replacing the caller-supplied `version` string, which a
        # caller can repeat or forget to bump and therefore cannot be trusted.
        self._tools: dict[str, tuple[ToolRegistration, int]] = {}
        self._next_gen = 0

    def register(self, reg: ToolRegistration) -> str:
        if reg.registration_id in self._tools:
            raise CatalogError(f"duplicate tool registration: {reg.registration_id}")
        self._tools[reg.registration_id] = (reg, self._next_gen)
        self._next_gen += 1
        return reg.registration_id

    def resolve(self, registration_id: str) -> Optional[ToolRegistration]:
        entry = self._tools.get(registration_id)
        return entry[0] if entry else None

    def generation(self, registration_id: str) -> Optional[int]:
        """The catalog-owned generation for a registration, or None if absent.

        A pending authorization stores this. At redemption the current generation
        must equal the stored one, so any replacement (even under the same id and
        the same `version` string) breaks the binding: the replacement gets a new
        generation the caller cannot forge.
        """
        entry = self._tools.get(registration_id)
        return entry[1] if entry else None

    def _replace_unsafe(self, reg: ToolRegistration) -> None:
        """Force a registration in place, bumping the generation.

        This exists ONLY so tests can prove that a post-authorization swap is
        refused. It is deliberately named _replace_unsafe (not replace_for_test)
        and underscored: it is not part of the setup API, and it increments the
        generation exactly as a real out-of-band mutation would, so the test
        exercises the real defence rather than a mock of it. Production setup uses
        register(), which refuses a duplicate id outright.
        """
        self._tools[reg.registration_id] = (reg, self._next_gen)
        self._next_gen += 1


# --------------------------------------------------------------------------- #
# Tool policy: catalog existence is NOT authorization.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ToolGrant:
    """Permission for ONE registration to serve actions under ONE scope.

    Validated at construction and FAILS CLOSED on a malformed scope, mirroring
    DenyPolicy in M1: a grant that silently vanished at check time would be an
    allow-by-omission, which is the wrong direction for an authorization rule.
    """
    registration_id: str
    scope: str

    def __post_init__(self):
        if not isinstance(self.registration_id, str) or not self.registration_id:
            raise ValueError("tool-grant registration_id must be a non-empty string")
        try:
            validate_resource(self.scope)
        except ResourceError as exc:
            raise ValueError(f"invalid tool-grant scope: {self.scope!r}") from exc


class ToolPolicy:
    """Which registration may serve which action. DENY BY DEFAULT.

    Resolving a tool from the catalog proves only that it EXISTS. It does not
    prove the model may route this action to that executor. Consider:

        tool A: read_customer_record   verb=read
        tool B: read_payroll_database  verb=read

    Both satisfy verb=read. If resource scope does not happen to separate them,
    an unconstrained model picks its own executor. That is a real escalation and
    a catalog lookup does not catch it.

    So: nothing is permitted unless explicitly granted. An empty policy authorizes
    no tool at all. This is the same posture as capability default-deny in M1, and
    it is deliberately strict: an allow-unless-denied default would reintroduce
    exactly the hole above for every newly registered tool.
    """

    def __init__(self, grants: Optional[list[ToolGrant]] = None):
        self._grants: list[ToolGrant] = list(grants or [])

    def grant(self, registration_id: str, scope: str) -> None:
        self._grants.append(ToolGrant(registration_id, scope))

    def allows(self, registration_id: str, action: Proposal) -> bool:
        for g in self._grants:
            if g.registration_id != registration_id:
                continue
            # _covers_safe: the RESOURCE is model-supplied, so a malformed one
            # must deny rather than match a grant by raising.
            if _covers_safe(g.scope, action.resource):
                return True
        return False


# --------------------------------------------------------------------------- #
# Pending authorizations and their state machine.
# --------------------------------------------------------------------------- #

class AuthorizationState(Enum):
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class PendingAuthorization:
    """Broker-held record of one authorized execution. Never leaves the broker.

    NOT a token the caller carries: trusted state the broker keeps. The caller
    gets only `action_id`, an opaque random key with no authority of its own.
    """
    action_id: str
    context: RunContext
    action: Proposal
    action_digest: str
    tool_registration_id: str
    tool_version: str            # audit only; NOT the authenticity check
    tool_generation: int         # catalog-owned; the authenticity check
    credential_id: Optional[str]
    issued_at: float
    expires_at: float
    state: AuthorizationState = AuthorizationState.PENDING


def action_digest(action: Proposal) -> str:
    """Canonical digest, computed BY THE BROKER from the action it stored.

    A caller-supplied digest is worthless: whoever can forge an authorization can
    forge its digest. This is an internal integrity check, never an authorization
    input.
    """
    canonical = f"{action.verb}\x00{action.resource}".encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class PendingAuthorizationStore:
    """Holds pending authorizations and owns the single-use state transition."""

    def __init__(self):
        self._records: dict[str, PendingAuthorization] = {}
        # Serializes the PENDING -> EXECUTING transition. Without it, the
        # read-check-write in claim() is a compound operation that the language
        # does not guarantee to be atomic: CPython can switch threads between
        # bytecode ops, so two redemptions of one action_id could both observe
        # PENDING and both proceed. The GIL happens to mask this on stock CPython
        # today, but that is an interpreter side effect, not a control, and it
        # disappears under free-threaded builds. The lock makes atomicity a
        # property of the code, not of the runtime.
        self._lock = threading.Lock()

    def put(self, record: PendingAuthorization) -> None:
        """Insert a pending authorization. FAILS CLOSED on an id collision.

        Under the store lock, so the check-and-insert is atomic. A security
        identifier must never silently overwrite an existing authority: an
        action_id collision (astronomically unlikely with 32 random bytes, but not
        to be trusted to luck) raises rather than replacing the prior record. The
        minting caller retries with a fresh id.
        """
        with self._lock:
            if record.action_id in self._records:
                raise AuthorizationError("action_id collision")
            self._records[record.action_id] = record

    def get(self, action_id: str) -> Optional[PendingAuthorization]:
        return self._records.get(action_id)

    def state_of(self, action_id: str) -> Optional[AuthorizationState]:
        rec = self._records.get(action_id)
        return rec.state if rec else None

    def settle(self, action_id: str, state: AuthorizationState) -> None:
        with self._lock:
            rec = self._records.get(action_id)
            if rec is not None:
                self._records[action_id] = replace(rec, state=state)

    def claim(self, action_id: str, now: float) -> PendingAuthorization:
        """Atomically move PENDING -> EXECUTING, or refuse.

        The whole read-check-write runs under the store lock, so exactly one
        caller can move a given action_id out of PENDING. The transition happens
        BEFORE the credential is resolved and before any external side effect. If
        execution later crashes, the record stays non-PENDING and cannot be
        redeemed again. That deliberately favours preventing a duplicate side
        effect over automatic retry: an ambiguous remote failure must NOT silently
        return the authorization to PENDING. A retry needs a fresh authorization.
        """
        with self._lock:
            rec = self._records.get(action_id)
            if rec is None:
                # Forged or unknown id: no record, therefore no authorization,
                # whatever object the caller may have constructed.
                raise ClaimRefused(BrokerRefusal.UNKNOWN_ACTION_ID,
                                   "unknown authorization")
            if rec.state is not AuthorizationState.PENDING:
                raise ClaimRefused(BrokerRefusal.ACTION_ALREADY_REDEEMED,
                                   "authorization is not redeemable")
            if now >= rec.expires_at:
                self._records[action_id] = replace(rec, state=AuthorizationState.FAILED)
                raise ClaimRefused(BrokerRefusal.ACTION_EXPIRED,
                                   "authorization expired")

            claimed = replace(rec, state=AuthorizationState.EXECUTING)
            self._records[action_id] = claimed
            return claimed


# --------------------------------------------------------------------------- #
# Results and audit. Nothing crossing this boundary carries a secret.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SanitizedToolResult:
    ok: bool
    body: Optional[str] = None
    code: Optional[str] = None        # generic, MODEL-facing. Never a message.
    audit_code: Optional[str] = None  # specific, TRUSTED-facing. Distinguishes
    #                                   WHY a refusal happened so trusted history
    #                                   is honest. Never shown to the model.

    @staticmethod
    def succeeded(body: str) -> "SanitizedToolResult":
        return SanitizedToolResult(ok=True, body=body)

    @staticmethod
    def failed(code: str, audit_code: Optional[str] = None) -> "SanitizedToolResult":
        return SanitizedToolResult(ok=False, code=code, audit_code=audit_code or code)


class BrokerRefusal:
    """Specific refusal reasons the broker reports in `audit_code`.

    The MODEL always sees the generic "authorization_refused" (via `code`);
    trusted history sees the real reason (via `audit_code`). Only
    REAUTHORIZATION_FAILED corresponds to a live capability re-authorization
    failure, i.e. an actual revoke race. Everything else must NOT be labeled a
    revoke race downstream.
    """
    REAUTHORIZATION_FAILED = "reauthorization_failed"   # the real revoke race
    ACTION_DIGEST_MISMATCH = "action_digest_mismatch"
    TOOL_CHANGED = "tool_changed"
    NO_CREDENTIAL = "no_credential"
    CREDENTIAL_VERB_MISMATCH = "credential_verb_mismatch"
    CREDENTIAL_SCOPE_MISMATCH = "credential_scope_mismatch"
    CREDENTIAL_EXPIRED = "credential_expired"
    CREDENTIAL_CONSUMED = "credential_consumed"
    # Typed claim-refusal reasons. An expired PENDING authorization, an unknown
    # id, or a non-redeemable state are DISTINCT conditions and none of them is a
    # revoke race. They previously collapsed into the generic CLAIM_REFUSED, which
    # the engine mapped to REVOKED_RACE.
    UNKNOWN_ACTION_ID = "unknown_action_id"
    ACTION_EXPIRED = "action_expired"
    ACTION_ALREADY_REDEEMED = "action_already_redeemed"
    CLAIM_REFUSED = "claim_refused"                     # fallback, unspecified


class ClaimRefused(AuthorizationError):
    """Raised by PendingAuthorizationStore.claim with a TYPED reason.

    Carries a BrokerRefusal code so the redemption path classifies the refusal
    from a value, not by parsing an exception message.
    """
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ReleaseAudit:
    action_id: str
    credential_id: Optional[str]
    verb: str
    resource: str
    granted: bool
    reason: str   # never contains a secret value


# --------------------------------------------------------------------------- #
# The trusted execution boundary.
# --------------------------------------------------------------------------- #

DEFAULT_ACTION_TTL_SECONDS = 30.0

# A tool's return value is UNTRUSTED and crosses into trusted run state (it is
# stored in RunRecord.history and shown to the model via ModelView). ModelView is
# only shallowly frozen, so a mutable return value (a dict, a list, a custom
# object) would give the model a live handle into trusted history. The boundary
# therefore accepts only an inert value: a bounded str. Anything else is a
# sanitized failure, not a stored object.
MAX_TOOL_RESULT_BYTES = 64 * 1024


def _normalize_tool_result(out) -> tuple[bool, Optional[str]]:
    """Validate an adapter's return value for storage in trusted state.

    Returns (ok, body). A tool may legitimately return None (it did something and
    has nothing to say); that is an inert, immutable value and is allowed, with a
    None body. A str under the size cap is allowed as-is. Anything else, a dict, a
    list, a custom object, an oversized str, cannot be trusted to be immutable or
    bounded and is rejected: (False, None).

    A str and None are both inert, so neither gives the model a handle into
    trusted history. A structured-result path (canonical JSON into a fresh
    immutable value) is a future extension; the inert-str-or-None rule is the v1
    floor.

    EXACT TYPE, not isinstance. A str SUBCLASS can override `encode()` to fake its
    size (beating the byte cap) and can carry mutable attributes into trusted
    history. The containment property depends on the built-in's immutability and
    its real `encode`, so only the exact built-in `str` is accepted. This is the
    one place exact-type checking is correct rather than overly strict.
    """
    if out is None:
        return True, None
    if type(out) is not str:
        return False, None
    if len(out.encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
        return False, None
    return True, out


class TrustedExecutionBroker:
    """The one interface the engine sees. Internally separated; externally single.

    This is a large TCB surface and that is a real, acknowledged cost. The
    alternative, a component that merely hands out secrets, cannot structurally
    stop the secret escaping into general code, surfacing in an exception, or
    being reused after revocation. And splitting the tool catalog between engine
    and broker would recreate the split-authority defect this project exists to
    prevent. One boundary, deliberately.
    """

    def __init__(
        self,
        monitor: ReferenceMonitor,
        catalog: Optional[ToolCatalog] = None,
        policy: Optional[ToolPolicy] = None,
        vault: Optional[CredentialVault] = None,
        action_ttl_seconds: float = DEFAULT_ACTION_TTL_SECONDS,
        clock: Optional[Clock] = None,
    ):
        if not isinstance(monitor, ReferenceMonitor):
            raise TypeError("broker requires a ReferenceMonitor for authorization")
        if action_ttl_seconds <= 0:
            raise ValueError("action_ttl_seconds must be positive")
        # ONE clock, owned here. All TTL and expiry decisions read it. Production
        # methods do not accept a caller `now`; tests inject a FakeClock instead.
        self._clock = clock or SystemClock()
        self._monitor = monitor
        self._catalog = catalog or ToolCatalog()
        self._policy = policy or ToolPolicy()      # deny-by-default when empty
        # The vault stamps credential issue-time from the same trusted clock, so a
        # supplied vault must share it. A caller-supplied vault with a different
        # clock would reintroduce clock divergence, so we hand it ours.
        self._vault = vault or CredentialVault(self._clock)
        if vault is not None:
            self._vault._clock = self._clock
        self._pending = PendingAuthorizationStore()
        self._action_ttl = action_ttl_seconds
        self.audit: list[ReleaseAudit] = []

    @property
    def monitor(self) -> ReferenceMonitor:
        """The broker's reference monitor. The engine derives its authorization
        authority from THIS, so engine and broker cannot diverge onto different
        monitors/stores (the split-authority defect)."""
        return self._monitor

    # -- wiring (trusted setup) --------------------------------------------- #

    def issue_credential(self, cred: Credential) -> str:
        return self._vault.issue(cred)

    def register_tool(self, reg: ToolRegistration) -> str:
        if reg.kind is ToolKind.CREDENTIALED and self._vault.resolve(reg.credential_id) is None:
            raise CatalogError("credentialed tool names an unknown credential")
        return self._catalog.register(reg)

    def grant_tool(self, registration_id: str, scope: str) -> None:
        """Authorize a registration to serve actions under `scope`.

        Required: registering a tool does NOT authorize it. Deny-by-default.
        """
        if self._catalog.resolve(registration_id) is None:
            raise CatalogError("cannot grant an unregistered tool")
        self._policy.grant(registration_id, scope)

    @property
    def catalog(self) -> ToolCatalog:
        return self._catalog

    def authorization_state(self, action_id: str) -> Optional[AuthorizationState]:
        return self._pending.state_of(action_id)

    # -- audit -------------------------------------------------------------- #

    def _record(self, action_id, cred_id, action, granted, reason):
        self.audit.append(ReleaseAudit(
            action_id=action_id,
            credential_id=cred_id,
            verb=action.verb if action is not None else "?",
            resource=action.resource if action is not None else "?",
            granted=granted,
            reason=reason,
        ))

    # -- mint --------------------------------------------------------------- #

    def register_authorized_execution(
        self,
        context: RunContext,
        proposal: ExecutionProposal,
    ) -> str:
        """Authorize an execution and return an opaque action_id.

        Takes NO caller-supplied Decision. The broker authorizes independently
        through its own monitor. A caller cannot hand it a verdict to trust,
        because it does not read one.

        Three separate checks, all of which must pass:
          1. The MONITOR authorizes the ACTION (verb + resource).
          2. The registered tool's verb MATCHES the proposed action's verb.
          3. The POLICY authorizes THIS registration for THIS action. Catalog
             existence is not authorization.
        """
        if not isinstance(proposal, ExecutionProposal):
            raise AuthorizationError("register requires an ExecutionProposal")
        action = proposal.action
        if not valid_proposal(action):
            raise AuthorizationError("cannot register a malformed action")

        # 1. Independent authorization of the ACTION.
        decision = self._monitor.authorize(context, action)
        if decision.verdict is not Verdict.ALLOW:
            self._record("-", None, action, False, "action is not authorized")
            raise AuthorizationError("action is not authorized")

        # 2. The executor must exist...
        reg = self._catalog.resolve(proposal.tool_registration_id)
        if reg is None:
            self._record("-", None, action, False, "unknown tool registration")
            raise AuthorizationError("unknown tool registration")
        gen = self._catalog.generation(proposal.tool_registration_id)

        # ...and serve this action class.
        if reg.verb != action.verb:
            self._record("-", None, action, False, "tool verb does not match action")
            raise AuthorizationError("tool verb does not match proposed action")

        # 3. ...and be POLICY-AUTHORIZED for this exact action. This is the check
        #    that stops a model routing `read` at read_payroll_database when it
        #    was only ever meant to reach read_customer_record.
        if not self._policy.allows(reg.registration_id, action):
            self._record("-", None, action, False, "tool registration is not authorized")
            raise AuthorizationError("tool registration is not authorized")

        now = self._clock.now()
        # A colliding action_id must not overwrite an existing authorization. put()
        # fails closed on a duplicate; retry with a fresh random id a bounded
        # number of times, then give up (a persistent collision means the RNG is
        # broken, which is a fail-closed condition, not something to paper over).
        for _attempt in range(8):
            aid = secrets.token_urlsafe(32)
            record = PendingAuthorization(
                action_id=aid,
                context=context,
                action=action,
                action_digest=action_digest(action),
                tool_registration_id=reg.registration_id,
                tool_version=reg.version,         # audit only
                tool_generation=gen,              # authenticity: catalog-owned
                credential_id=reg.credential_id,  # bound: cannot be substituted
                issued_at=now,
                expires_at=now + self._action_ttl,
                state=AuthorizationState.PENDING,
            )
            try:
                self._pending.put(record)
            except AuthorizationError:
                continue   # collision: mint a new id and retry
            return aid
        raise AuthorizationError("could not mint a unique action_id")

    # -- redeem ------------------------------------------------------------- #

    def redeem_and_execute(
        self,
        action_id: str,
    ) -> SanitizedToolResult:
        """Execute exactly the authorization identified by action_id.

        The caller supplies ONLY the id. Not the tool, not the credential, not the
        action. All three were bound at mint and are resolved here from broker
        state. That is what closes substitution: a valid action_id cannot be aimed
        at a different credential or a different adapter.
        """
        now = self._clock.now()

        try:
            rec = self._pending.claim(action_id, now)
        except ClaimRefused as e:
            self._record(action_id, None, None, False, str(e))
            return SanitizedToolResult.failed("authorization_refused", e.code)

        try:
            # 1. LIVE re-authorization. Current-authority semantics. A capability
            #    revoked since mint stops us here, BEFORE the credential is
            #    resolved.
            live = self._monitor.authorize(rec.context, rec.action)
            if live.verdict is not Verdict.ALLOW:
                self._pending.settle(action_id, AuthorizationState.FAILED)
                self._record(action_id, rec.credential_id, rec.action, False,
                             "re-authorization failed at redemption")
                return SanitizedToolResult.failed(
                    "authorization_refused", BrokerRefusal.REAUTHORIZATION_FAILED)

            # 2. Internal integrity check on stored state.
            if action_digest(rec.action) != rec.action_digest:
                self._pending.settle(action_id, AuthorizationState.FAILED)
                self._record(action_id, rec.credential_id, rec.action, False,
                             "action digest mismatch")
                return SanitizedToolResult.failed(
                    "authorization_refused", BrokerRefusal.ACTION_DIGEST_MISMATCH)

            # 3. Resolve the tool from the CATALOG, pinned to the exact version
            #    bound at mint. A tool swapped out in between is refused.
            reg = self._catalog.resolve(rec.tool_registration_id)
            gen = self._catalog.generation(rec.tool_registration_id)
            if reg is None or gen != rec.tool_generation:
                # The tool was replaced (or removed) after this authorization was
                # minted. The catalog-owned generation moved; the caller cannot
                # forge a match. Refuse, even if the `version` string is identical.
                self._pending.settle(action_id, AuthorizationState.FAILED)
                self._record(action_id, rec.credential_id, rec.action, False,
                             "tool registration changed since authorization")
                return SanitizedToolResult.failed(
                    "authorization_refused", BrokerRefusal.TOOL_CHANGED)

            # 4. Dispatch on the REGISTERED kind, not isinstance against a
            #    Protocol (structural, and would match any object with the right
            #    attribute names).
            if reg.kind is ToolKind.PLAIN:
                return self._execute_plain(action_id, reg, rec)
            return self._execute_credentialed(action_id, reg, rec, now)

        except Exception:
            # Exception, not BaseException: KeyboardInterrupt and SystemExit must
            # not be swallowed by the credential boundary.
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, rec.credential_id, rec.action, False,
                         "execution failed")
            return SanitizedToolResult.failed("execution_failed")

    def _execute_plain(self, action_id, reg, rec) -> SanitizedToolResult:
        try:
            out = reg.adapter(rec.action)
        except Exception:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, None, rec.action, False, "tool raised")
            return SanitizedToolResult.failed("tool_failed")
        ok, body = _normalize_tool_result(out)
        if not ok:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, None, rec.action, False,
                         "tool returned an unacceptable result")
            return SanitizedToolResult.failed("invalid_tool_result")
        self._pending.settle(action_id, AuthorizationState.COMPLETED)
        self._record(action_id, None, rec.action, True, "executed")
        return SanitizedToolResult.succeeded(body)

    def _execute_credentialed(self, action_id, reg, rec, now) -> SanitizedToolResult:
        cred = self._vault.resolve(rec.credential_id)
        if cred is None:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, rec.credential_id, rec.action, False,
                         "no such credential")
            return SanitizedToolResult.failed(
                "authorization_refused", BrokerRefusal.NO_CREDENTIAL)

        # The credential's own binding must hold independently of the capability
        # check: credential scope is not capability scope, and a credential may be
        # strictly narrower than the capability that authorized the action.
        if cred.verb != rec.action.verb:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, rec.action, False,
                         "credential verb does not match action")
            return SanitizedToolResult.failed(
                "authorization_refused", BrokerRefusal.CREDENTIAL_VERB_MISMATCH)

        if not scope_covers(cred.scope, rec.action.resource):
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, rec.action, False,
                         "credential scope does not cover resource")
            return SanitizedToolResult.failed(
                "authorization_refused", BrokerRefusal.CREDENTIAL_SCOPE_MISMATCH)

        # Availability check AND consume, atomically. Two concurrent redemptions
        # of a single-use credential cannot both pass here: the vault lock
        # serializes the check-and-consume, so exactly one wins and the other
        # sees "already consumed".
        ok, why = self._vault.claim_credential(cred.id, now)
        if not ok:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, rec.action, False, f"credential {why}")
            audit = (BrokerRefusal.CREDENTIAL_EXPIRED if why == "expired"
                     else BrokerRefusal.CREDENTIAL_CONSUMED if why == "already consumed"
                     else BrokerRefusal.NO_CREDENTIAL)
            return SanitizedToolResult.failed("authorization_refused", audit)

        # THE CREDENTIAL BOUNDARY.
        # The secret is revealed only inside this try, only to the trusted
        # adapter, and every exception is caught and DISCARDED here. The exception
        # object is never inspected, formatted, re-raised, chained, or logged: a
        # transport that raises RuntimeError(headers["Authorization"]) carries the
        # credential in its message, and the only safe thing to do with such an
        # object is drop it. That is why the failure code below is a constant and
        # is not derived from the exception in any way.
        try:
            out = reg.adapter.execute_with_credential(rec.action, cred.secret)
        except Exception:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, rec.action, False,
                         "credentialed tool failed")
            return SanitizedToolResult.failed("credentialed_tool_execution_failed")

        ok, body = _normalize_tool_result(out)
        if not ok:
            self._pending.settle(action_id, AuthorizationState.FAILED)
            self._record(action_id, cred.id, rec.action, False,
                         "tool returned an unacceptable result")
            return SanitizedToolResult.failed("invalid_tool_result")
        self._pending.settle(action_id, AuthorizationState.COMPLETED)
        self._record(action_id, cred.id, rec.action, True, "executed")
        return SanitizedToolResult.succeeded(body)
