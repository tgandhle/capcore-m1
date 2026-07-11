"""M1 capability core — capability-enforced agent runtime.

This is the trusted decision path: given a RunContext (trusted identity) and a
Proposal (untrusted, model-emitted), the ReferenceMonitor returns a Decision of
ALLOW / REQUIRE_APPROVAL / DENY. Deny is the default; any ambiguity, staleness,
or malformed input resolves to deny.

The security properties this module claims are backed by the property-based and
enumeration tests in tests/. See MODEL.md for the precise semantics and which
claims are proof (finite/enumerated) versus evidence (property-tested).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Optional


# --------------------------------------------------------------------------- #
# Resource scope: segment-aware containment.
# --------------------------------------------------------------------------- #

def segments(path: str) -> tuple[str, ...]:
    """Split a resource path into non-empty path segments.

    'acme/records/' -> ('acme', 'records')
    """
    return tuple(s for s in str(path).split("/") if s)


def scope_covers(scope: str, resource: str) -> bool:
    """True iff `scope` is a path-segment prefix of `resource`.

    Segment-aware, NOT raw string prefix: scope 'acme/data' covers
    'acme/data/x' but does NOT cover 'acme/database' — 'data' != 'database'.
    This is the fix for the prefix-confusion class of bug.
    """
    s = segments(scope)
    r = segments(resource)
    if len(s) > len(r):
        return False
    return all(s[i] == r[i] for i in range(len(s)))


# --------------------------------------------------------------------------- #
# Decision types.
# --------------------------------------------------------------------------- #

class Verdict(Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    # public_reason is the ONLY field safe to return to the model. It is generic
    # and must not reveal why authorization failed (which tenant owns a resource,
    # whether a capability exists, etc.), since that maps the boundary for an
    # adversarial model.
    public_reason: str
    # audit_reason carries the detailed diagnostic. It belongs in trusted audit
    # state and must NOT be surfaced to the model. Defaults to public_reason.
    audit_reason: str = ""
    # trace: list of (stage, detail) for auditability. Audit-only, like audit_reason.
    trace: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if not self.audit_reason:
            object.__setattr__(self, "audit_reason", self.public_reason)

    def for_model(self) -> "Decision":
        """Return a copy safe to hand to the model: verdict + generic reason only,
        with all audit detail stripped. The runtime returns THIS to the agent loop
        and logs the full Decision to audit.
        """
        return Decision(self.verdict, self.public_reason, self.public_reason, ())


# Generic model-facing reasons, keyed by verdict. These never vary with the
# specific cause of a denial.
_PUBLIC_REASON = {
    Verdict.ALLOW: "authorized",
    Verdict.REQUIRE_APPROVAL: "approval required",
    Verdict.DENY: "no applicable authority",
}


# --------------------------------------------------------------------------- #
# Capability: immutable authority. It narrows; it never widens.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Capability:
    id: str
    tenant: str
    resource: str                       # scope, segment-prefix
    actions: frozenset[str]
    approval_actions: frozenset[str] = frozenset()
    parent: Optional[str] = None
    # runtime=False => derivation-only: authorizes deriving children, but is NOT
    # live runtime authority. A revoked child never falls back to it.
    runtime: bool = True

    def __post_init__(self):
        # normalize sets to frozensets even if constructed with sets
        object.__setattr__(self, "actions", frozenset(self.actions))
        object.__setattr__(self, "approval_actions", frozenset(self.approval_actions))


# --------------------------------------------------------------------------- #
# RunContext: TRUSTED identity. Supplied by the runtime, never by the model.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RunContext:
    tenant: str
    principal: str
    run: str


# --------------------------------------------------------------------------- #
# Proposal: UNTRUSTED request emitted by the model. Carries no identity.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Proposal:
    resource: str
    verb: str


def valid_proposal(obj) -> bool:
    """A well-formed proposal has non-empty string resource and verb.

    Anything else must resolve to a deterministic deny, never an exception.
    """
    return (
        isinstance(obj, Proposal)
        and isinstance(obj.resource, str) and len(obj.resource) > 0
        and isinstance(obj.verb, str) and len(obj.verb) > 0
    )


# --------------------------------------------------------------------------- #
# Errors.
# --------------------------------------------------------------------------- #

class StoreError(Exception):
    """Raised for store-integrity violations (e.g. duplicate id)."""


@dataclass(frozen=True)
class DeriveResult:
    ok: bool
    id: Optional[str] = None
    reason: Optional[str] = None


# --------------------------------------------------------------------------- #
# CapabilityStore: unique ids, revoke, and issue-time attenuation.
# --------------------------------------------------------------------------- #

class CapabilityStore:
    def __init__(self):
        self._caps: dict[str, Capability] = {}
        self._revoked: set[str] = set()

    def issue(self, cap: Capability) -> str:
        """Issue a ROOT capability. Fails closed on duplicate id."""
        if cap.id in self._caps:
            raise StoreError(f"duplicate capability id: {cap.id}")
        self._caps[cap.id] = cap
        return cap.id

    def derive_child(self, parent_id: str, child: Capability) -> DeriveResult:
        """Derive a child from a parent, validating child <= parent on every axis.

        This is where attenuation is ENFORCED. The runtime never re-simulates
        attenuation at authorize time. Axes checked:
          - id uniqueness
          - tenant identity (child.tenant == parent.tenant)
          - scope containment (parent scope covers child scope)
          - action subset (child.actions <= parent.actions)
          - approval preservation (child may not drop an approval requirement
            the parent imposes on a shared action)
        """
        parent = self._caps.get(parent_id)
        if parent is None:
            return DeriveResult(ok=False, reason="parent does not exist")
        # A revoked capability is dead as an authority source, including for
        # deriving new children. This holds regardless of cascade policy on
        # EXISTING descendants (that is a separate architecture decision).
        if self.is_revoked(parent_id):
            return DeriveResult(ok=False, reason="parent is revoked")
        if child.id in self._caps:
            return DeriveResult(ok=False, reason="duplicate capability id")
        if child.tenant != parent.tenant:
            return DeriveResult(ok=False, reason="child tenant differs from parent")
        if not scope_covers(parent.resource, child.resource):
            return DeriveResult(ok=False, reason="child scope escapes parent scope")
        if not child.actions <= parent.actions:
            extra = child.actions - parent.actions
            return DeriveResult(
                ok=False,
                reason=f"child action(s) not held by parent: {sorted(extra)}",
            )
        # child may not drop approval that parent requires on a shared action
        for a in parent.approval_actions:
            if a in child.actions and a not in child.approval_actions:
                return DeriveResult(
                    ok=False, reason=f"child drops approval requirement on {a!r}"
                )
        stored = replace(child, parent=parent_id)
        self._caps[stored.id] = stored
        return DeriveResult(ok=True, id=stored.id)

    def revoke(self, cap_id: str) -> None:
        self._revoked.add(cap_id)

    def is_revoked(self, cap_id: str) -> bool:
        return cap_id not in self._caps or cap_id in self._revoked

    def get(self, cap_id: str) -> Optional[Capability]:
        return self._caps.get(cap_id)

    def all_caps(self) -> list[Capability]:
        return list(self._caps.values())

    def get_applicable(self, tenant: str, resource: str) -> list[Capability]:
        """Live, runtime-bound caps for THIS tenant whose scope covers resource.

        Not verb-filtered: the per-grant verb check happens in the monitor, so
        union-of-alternative-grants can be expressed correctly.
        """
        out = []
        for cap in self._caps.values():
            if self.is_revoked(cap.id):
                continue
            if not cap.runtime:
                continue
            if cap.tenant != tenant:
                continue
            if not scope_covers(cap.resource, resource):
                continue
            out.append(cap)
        return out


# --------------------------------------------------------------------------- #
# Platform deny policies: mandatory rules that DENY regardless of capability.
# Demonstrates deny > require_approval > allow.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class DenyPolicy:
    verb: str
    scope: str
    reason: str


def platform_denies(policies: list[DenyPolicy], resource: str, verb: str) -> Optional[str]:
    for p in policies:
        if p.verb == verb and scope_covers(p.scope, resource):
            return p.reason
    return None


# --------------------------------------------------------------------------- #
# ReferenceMonitor.
# --------------------------------------------------------------------------- #

class ReferenceMonitor:
    """Authorization decision path.

    Precedence (total order): explicit-deny > require-approval > allow.
    Default deny. Identity comes from the trusted RunContext, never the Proposal.
    """

    def __init__(self, store: CapabilityStore, deny_policies: Optional[list[DenyPolicy]] = None):
        self.store = store
        self.deny_policies = deny_policies or []

    def authorize(self, ctx: RunContext, proposal) -> Decision:
        """Return the full Decision (public + audit detail). The runtime is
        responsible for logging the full Decision to audit and returning only
        decision.for_model() to the agent loop. Callers that may hand the result
        to the model directly should use authorize_for_model().
        """
        trace: list[tuple[str, str]] = []

        def deny(audit_detail: str) -> Decision:
            return Decision(Verdict.DENY, _PUBLIC_REASON[Verdict.DENY],
                            audit_detail, tuple(trace))

        # 0. Schema — malformed proposals fail closed, never throw.
        if not valid_proposal(proposal):
            trace.append(("schema", "resource/verb must be non-empty strings"))
            return deny("invalid proposal schema")

        tenant = ctx.tenant                 # TRUSTED. Not from proposal.
        resource = proposal.resource
        verb = proposal.verb
        trace.append(("identity", f"tenant={tenant} (trusted context)"))

        # 1. Explicit platform deny wins over everything.
        deny_reason = platform_denies(self.deny_policies, resource, verb)
        if deny_reason:
            trace.append(("platform", deny_reason))
            trace.append(("precedence", "explicit deny beats allow and approval"))
            return deny(deny_reason)

        # 2. Applicable grants for this trusted tenant + resource.
        applicable = self.store.get_applicable(tenant, resource)
        if not applicable:
            trace.append(("applicable", "none"))
            return deny(self._why_none(tenant, resource))
        trace.append(("applicable", ", ".join(c.id for c in applicable)))

        # 3. UNION of alternative grants: any single grant that includes verb?
        granting = [c for c in applicable if verb in c.actions]
        if not granting:
            trace.append(("grants", "no applicable grant includes verb"))
            return deny(f"verb {verb!r} not granted by any applicable capability")
        trace.append(("grants", ", ".join(c.id for c in granting)))

        # 4. Approval: if at least one granting cap permits the verb WITHOUT
        #    approval, allow. Only if EVERY granting cap gates it -> approval.
        unconditional = [c for c in granting if verb not in c.approval_actions]
        if not unconditional:
            trace.append(("approval", "all granting caps classify verb as approval-gated"))
            return Decision(Verdict.REQUIRE_APPROVAL,
                            _PUBLIC_REASON[Verdict.REQUIRE_APPROVAL],
                            "human approval required for this action class",
                            tuple(trace))

        trace.append(("precedence", "no deny; unconditional grant exists -> allow"))
        return Decision(Verdict.ALLOW, _PUBLIC_REASON[Verdict.ALLOW],
                        "authorized", tuple(trace))

    def authorize_for_model(self, ctx: RunContext, proposal) -> Decision:
        """Convenience: authorize and return only the model-safe Decision.
        Use this anywhere the result may reach the model without an audit hop.
        """
        return self.authorize(ctx, proposal).for_model()

    def _why_none(self, tenant: str, resource: str) -> str:
        wrong_tenant = False
        revoked_hit = False
        for cap in self.store.all_caps():
            if not cap.runtime:
                continue
            cover = scope_covers(cap.resource, resource)
            if cover and cap.tenant != tenant:
                wrong_tenant = True
            if cover and cap.tenant == tenant and self.store.is_revoked(cap.id):
                revoked_hit = True
        if revoked_hit:
            return "the runtime capability for this scope is revoked"
        if wrong_tenant:
            return ("a capability covers this resource under a DIFFERENT tenant "
                    "(cross-tenant escape blocked; identity from trusted context)")
        return "no live runtime capability covers this resource for this tenant"
