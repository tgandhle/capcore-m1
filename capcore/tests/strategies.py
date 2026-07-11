"""Hypothesis strategies for the capability core.

These generate the adversarial input space: random tenants, resource paths,
action sets, and derivations. The property tests draw from these so the
invariants are checked across thousands of structured inputs rather than the
handful a human would script.
"""

from hypothesis import strategies as st

from capcore import Capability, RunContext, Proposal, segments

# Ordered tuples: Hypothesis requires sampled_from over ordered collections for
# reproducibility. (A prior bug used a set here.)
TENANT_LIST = ("acme", "globex", "initech")
VERB_LIST = ("read", "write", "send", "delete", "admin")
SEGMENT_LIST = ("records", "customers", "orders", "data", "x", "y")

TENANTS = st.sampled_from(TENANT_LIST)
VERBS = st.sampled_from(VERB_LIST)
SEGMENTS = st.sampled_from(SEGMENT_LIST)


@st.composite
def resource_paths(draw, min_len=1, max_len=4):
    """A path like 'acme/records/customers'. First segment is a tenant-ish root."""
    n = draw(st.integers(min_value=min_len, max_value=max_len))
    parts = draw(st.lists(SEGMENTS, min_size=n, max_size=n))
    return "/".join(parts)


@st.composite
def action_sets(draw, min_size=0, max_size=5):
    return frozenset(draw(st.sets(VERBS, min_size=min_size, max_size=max_size)))


@st.composite
def capabilities(draw, tenant=None, runtime=True):
    t = tenant if tenant is not None else draw(TENANTS)
    actions = draw(action_sets(min_size=1))
    # approval_actions is a subset of actions
    approval = frozenset(
        draw(st.sets(st.sampled_from(sorted(actions)), max_size=len(actions)))
    ) if actions else frozenset()
    return Capability(
        id=draw(st.text(min_size=1, max_size=8, alphabet="abcdefghij")),
        tenant=t,
        resource=draw(resource_paths()),
        actions=actions,
        approval_actions=approval,
        runtime=runtime,
    )


@st.composite
def run_contexts(draw):
    return RunContext(
        tenant=draw(TENANTS),
        principal=draw(st.text(min_size=1, max_size=6, alphabet="pqrs")),
        run=draw(st.text(min_size=1, max_size=6, alphabet="0123456789")),
    )


@st.composite
def proposals(draw):
    return Proposal(resource=draw(resource_paths()), verb=draw(VERBS))


@st.composite
def narrowings(draw, parent):
    """A child spec generated LOOSELY: random tenant, scope, and actions, NOT
    guaranteed within-parent. Used to exercise derive_child's rejection logic on
    the full space of widening attempts. Most draws will (correctly) be rejected.
    """
    child_actions = draw(action_sets(min_size=1))
    child_approval = frozenset(
        draw(st.sets(st.sampled_from(sorted(child_actions)), max_size=len(child_actions)))
    ) if child_actions else frozenset()
    return Capability(
        id=draw(st.text(min_size=1, max_size=8, alphabet="klmnop")),
        tenant=draw(TENANTS),                 # may differ from parent (must be rejected)
        resource=draw(resource_paths()),       # may escape parent scope (must be rejected)
        actions=child_actions,
        approval_actions=child_approval,
        runtime=True,
    )


@st.composite
def valid_narrowings(draw, parent):
    """A child spec CONSTRUCTED to be genuinely within-parent on every axis, so
    derive_child accepts it. Used to test properties of accepted children without
    filtering the whole input space away.
    """
    # actions: a subset of the parent's actions (parent.actions is non-empty by
    # our capabilities() strategy)
    parent_actions = sorted(parent.actions)
    k = draw(st.integers(min_value=1, max_value=len(parent_actions)))
    child_actions = frozenset(draw(st.lists(
        st.sampled_from(parent_actions), min_size=k, max_size=k, unique=True)))
    # approval: must preserve any parent approval on shared actions; may add more
    forced = frozenset(a for a in parent.approval_actions if a in child_actions)
    extra = frozenset(draw(st.sets(st.sampled_from(sorted(child_actions)),
                                   max_size=len(child_actions)))) if child_actions else frozenset()
    child_approval = forced | extra
    # scope: parent scope plus zero or more extra segments (stays within parent)
    extra_segs = draw(st.lists(SEGMENTS, min_size=0, max_size=2))
    child_resource = "/".join(list(segments(parent.resource)) + extra_segs) if parent.resource else "/".join(extra_segs)
    if not child_resource:
        child_resource = draw(SEGMENTS)
    return Capability(
        id=draw(st.text(min_size=1, max_size=8, alphabet="klmnop")),
        tenant=parent.tenant,                 # same tenant
        resource=child_resource,
        actions=child_actions,
        approval_actions=child_approval,
        runtime=True,
    )
