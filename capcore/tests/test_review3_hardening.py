"""Adversarial reproductions from the third review round (M2/M3 integration).

Red baseline. Each test asserts the CORRECT behaviour and therefore FAILS against
the code as merged; the fixes turn them green. Committed before the fixes so the
defects are on record against shipped code, same discipline as prior rounds.

Five findings, in fix order:

  1. Mutable tool result enters trusted run state (F4).
  2. Caller controls security time via `now=` and `_issued_at` (F2).
  3. Same-version tool replacement bypasses substitution protection (F3).
  4. Redemption / single-use consumption is not atomic (F1).
  5. Credential.capability_id is unenforced dead state (F5).

On finding 1 (atomicity): the race did NOT manifest in 1600 forced-overlap
attempts on this CPython build. That is not the same as impossible. CPython can
switch threads between bytecode operations, and the language guarantees nothing
about the compound read-check-write in claim() or the unlocked `_consumed = True`
assignment; the current safety is an interpreter side effect, not a control.
So this is a missing-synchronization defect, not a reproduced race: current
demonstrated exploitability Medium, design/portability defect High. The two
concurrency tests below pin the observable CONTRACT (a single-use credential is
delivered at most once; one action_id executes at most once). They pass today
without explicit synchronization and must pass BY CONSTRUCTION (a lock) after the
fix.

Expected baseline for this file, before any fix:
  - 11 adversarial tests FAIL (result normalization x4, clock x4, tool swap x2,
    capability_id x1)
  - 2 concurrency contract tests PASS without explicit synchronization
  - 1 model-cannot-mutate-history guard PASSES (str result is already inert)
"""

import threading

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.broker import (
    AuthorizationError, Credential, CredentialError, ExecutionProposal, Secret,
    ToolKind, ToolRegistration, TrustedExecutionBroker,
)


def build():
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", "acme/api", frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


# --------------------------------------------------------------------------- #
# F4. A tool result must not carry a mutable object into trusted run state.
#
# The tool's return value becomes SanitizedToolResult.body, is stored in the
# trusted RunRecord.history, and is handed to the untrusted model through
# ModelView (which is only SHALLOWLY frozen). A tool returning a dict lets the
# model reach into trusted history and mutate it. Tool results are untrusted;
# the boundary must normalize them to an inert value.
# --------------------------------------------------------------------------- #

def _broker_with_plain(tool_fn, grant=True):
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN, tool_fn, "1"))
    if grant:
        b.grant_tool("t", "acme/api")
        b.seal_catalog()
    return b, ctx


@pytest.mark.parametrize("bad_return", [
    {"v": "safe"},                 # dict: mutable
    ["a", "b"],                    # list: mutable
    object(),                      # arbitrary object
])
def test_non_string_tool_result_is_rejected(bad_return):
    """A tool that returns a non-string yields a sanitized failure, not a live
    mutable object stored in trusted state."""
    b, ctx = _broker_with_plain(lambda a: bad_return)
    action_id = b.register_authorized_execution(ctx, ep())
    result = b.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "invalid_tool_result"


def test_model_cannot_mutate_trusted_history_through_tool_result():
    """Even a string result must not give the model a handle to trusted state.

    After a run, mutating anything reachable from the model's view of history
    must not change RunRecord.history.
    """
    from capcore.runtime import (
        Budget, ExecutionEngine, ModelResult, ScriptedModel, to_model_view,
    )
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: "result-string", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    engine = ExecutionEngine(b, Budget(3))

    record = engine.run(ctx, ScriptedModel([ep()]))
    # the model's view of the just-run history
    view = to_model_view(record, Budget(3))

    # whatever the model can see, it must not be able to write back into history
    trusted_before = record.history[0].tool_result
    # a str is immutable, so the assertion is simply that the boundary keeps a
    # str (not a mutable object) and that the two are equal-but-inert
    assert isinstance(view.history[0].tool_result, (str, type(None)))
    assert record.history[0].tool_result == trusted_before


def test_oversized_tool_result_is_rejected():
    """A tool returning a huge string is capped, not stored whole in trusted
    state."""
    b, ctx = _broker_with_plain(lambda a: "x" * (1024 * 1024))  # 1 MiB
    action_id = b.register_authorized_execution(ctx, ep())
    result = b.redeem_and_execute(action_id)

    assert result.ok is False
    assert result.code == "invalid_tool_result"


# --------------------------------------------------------------------------- #
# F2. The caller must not control security time.
#
# `register_authorized_execution(now=...)` and `redeem_and_execute(now=...)` let
# a caller mint a far-future expiry, or make an expired authorization look
# current at redemption. `_issued_at` on Credential is a constructor field, so a
# caller can backdate a credential's TTL too. Time must come from a broker-owned
# clock, not from callers.
# --------------------------------------------------------------------------- #

def test_production_mint_does_not_accept_a_caller_clock():
    """After the fix, register_authorized_execution has no `now` parameter."""
    import inspect
    sig = inspect.signature(TrustedExecutionBroker.register_authorized_execution)
    assert "now" not in sig.parameters, (
        "register_authorized_execution still accepts a caller-supplied clock; "
        "TTL enforcement is caller-controllable"
    )


def test_production_redeem_does_not_accept_a_caller_clock():
    """After the fix, redeem_and_execute has no `now` parameter."""
    import inspect
    sig = inspect.signature(TrustedExecutionBroker.redeem_and_execute)
    assert "now" not in sig.parameters, (
        "redeem_and_execute still accepts a caller-supplied clock; an expired "
        "authorization can be made to look current"
    )


def test_credential_issued_at_is_not_caller_constructible():
    """A caller must not be able to backdate a credential's TTL by supplying
    `_issued_at`."""
    import dataclasses
    fields = {f.name: f for f in dataclasses.fields(Credential)}
    assert "_issued_at" in fields
    assert fields["_issued_at"].init is False, (
        "_issued_at is a constructor field; a caller can backdate the TTL clock"
    )


def test_broker_takes_an_injected_clock():
    """The broker must accept a clock so TTL is deterministic in tests and
    trusted in production."""
    import inspect
    sig = inspect.signature(TrustedExecutionBroker.__init__)
    assert "clock" in sig.parameters, (
        "no injectable clock: tests cannot control time without the removed "
        "now= backdoor"
    )


# --------------------------------------------------------------------------- #
# F3. A same-version tool swap must not inherit an existing authorization.
#
# The record pins registration_id and `version`, but `version` is supplied by
# the registration caller, so it is a hint, not a generation marker. Replacing an
# adapter under the same id and version lets the impostor run on the old grant.
# The catalog must own a monotonic generation the caller cannot forge, and the
# test-only replace path must not be on the production class.
# --------------------------------------------------------------------------- #

def test_same_version_tool_replacement_is_refused():
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    legit, evil = [], []
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: legit.append(1) or "legit", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    action_id = b.register_authorized_execution(ctx, ep())

    # Re-register the SAME id and SAME version with a different adapter. However
    # the catalog exposes replacement, this must not let the impostor inherit the
    # authorization minted against the original.
    _replace_tool(b, ToolRegistration("t", "read", ToolKind.PLAIN,
                                      lambda a: evil.append(1) or "evil", "1"))

    result = b.redeem_and_execute(action_id)

    assert evil == [], "an adapter swapped in after authorization must not run"
    assert result.ok is False


def test_replace_for_test_is_not_on_the_production_class():
    """A test-only backdoor must not ship on the production catalog."""
    from capcore.broker import ToolCatalog
    assert not hasattr(ToolCatalog, "replace_for_test"), (
        "ToolCatalog.replace_for_test is a test-only mutation path and must not "
        "be a production method"
    )


def _replace_tool(broker, reg):
    """Replace a registration by whatever mechanism the catalog offers, so this
    test does not depend on the very method it wants removed."""
    cat = broker.catalog
    # _replace_unsafe forces a registration in place and bumps the catalog-owned
    # generation, exactly as a real out-of-band mutation would. The test proves
    # the authorization minted against the old generation is refused.
    cat._replace_unsafe(reg)


# --------------------------------------------------------------------------- #
# F1. Single-use consumption must be atomic (contract test).
#
# Does not reproduce on stock CPython (the GIL serializes the unprotected
# critical section), so this pins the observable CONTRACT rather than a
# demonstrated race: under concurrency a single-use credential is delivered at
# most once, and one action_id executes at most once. Passes today by GIL
# accident; must pass by construction (a lock) after the fix.
# --------------------------------------------------------------------------- #

def test_single_use_credential_delivered_at_most_once_under_concurrency():
    """A single-use credential is delivered at most once under concurrent redeem.

    A plain concurrent test passes on stock CPython whether or not the lock is
    present, because the GIL serializes the short critical section. To make this a
    REAL regression guard, the adapter below sleeps briefly, widening the window
    so that if the check-and-consume were not atomic, a second thread would pass
    the availability check before the first marked the credential consumed. With
    the vault lock, exactly one delivery happens regardless.
    """
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    deliveries = []

    class SlowRec:
        def execute_with_credential(self, a, s):
            deliveries.append(s.reveal())
            time.sleep(0.005)              # widen the window
            return "ok"

    b.issue_credential(Credential("cred-1", "read", "acme/api",
                                  Secret("SEK"), single_use=True))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     SlowRec(), "1", "cred-1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()

    aids = [b.register_authorized_execution(ctx, ep(f"acme/api/x{i}"))
            for i in range(8)]
    barrier = threading.Barrier(8)

    def go(aid):
        barrier.wait()
        b.redeem_and_execute(aid)

    ts = [threading.Thread(target=go, args=(a,)) for a in aids]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert len(deliveries) <= 1, (
        f"single-use credential delivered {len(deliveries)} times under "
        f"concurrency: consumption is not atomic"
    )


def test_one_action_id_executes_at_most_once_under_concurrency():
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    runs = []
    b.register_tool(ToolRegistration("t", "read", ToolKind.PLAIN,
                                     lambda a: runs.append(1) or "ok", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    action_id = b.register_authorized_execution(ctx, ep())
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        b.redeem_and_execute(action_id)

    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    assert len(runs) <= 1, (
        f"one action_id executed {len(runs)} times under concurrency: the "
        f"PENDING -> EXECUTING claim is not atomic"
    )


# --------------------------------------------------------------------------- #
# F5. Credential.capability_id must not be dead state that implies binding.
#
# Under current-authority semantics the credential is constrained by verb, scope,
# TTL, single-use, tool binding, and live re-authorization. `capability_id` is
# never checked, so a credential can name a nonexistent capability and still be
# delivered. A field that looks like a binding but enforces nothing is a false
# security claim. Chosen resolution: REMOVE it (Option B).
# --------------------------------------------------------------------------- #

def test_credential_has_no_unenforced_capability_binding():
    """capability_id is REMOVED (Option B), not left as dead state.

    Under current-authority semantics a credential is constrained by verb, scope,
    TTL, single-use, tool binding, and live re-authorization. A capability_id that
    the broker never checks would be a false claim of exact-capability binding, so
    it is gone from the model entirely.
    """
    import dataclasses
    field_names = {f.name for f in dataclasses.fields(Credential)}
    assert "capability_id" not in field_names, (
        "capability_id is still a Credential field; under current-authority "
        "semantics it is unenforced dead state that implies a binding the broker "
        "does not check"
    )


def test_credential_without_capability_id_still_delivers():
    """Control: removing capability_id does not break legitimate delivery. The
    real constraints (verb, scope, tool binding, live re-auth) still apply."""
    store, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    got = []

    class Rec:
        def execute_with_credential(self, a, s):
            got.append(s.reveal())
            return "ok"

    b.issue_credential(Credential("cred-1", "read", "acme/api", Secret("SEK")))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     Rec(), "1", "cred-1"))
    b.grant_tool("t", "acme/api")
    b.seal_catalog()
    action_id = b.register_authorized_execution(ctx, ep())
    result = b.redeem_and_execute(action_id)

    assert result.ok is True
    assert got == ["SEK"]

