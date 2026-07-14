"""Adversarial reproductions from the tenth review round.

Three of these five are defects Review 9 INTRODUCED or failed to close, and saying
so is the point of keeping this file honest:

  F1  seal_configuration() seals the catalog and the policy, but NOT the credential
      vault. A caller retaining an injected vault can issue a credential AFTER the
      seal, and with an injected prepopulated catalog referencing it, execute
      through it. This is the Review 9 F4 fix left half-done: I sealed ToolPolicy
      because the review named ToolPolicy, and never asked which OTHER objects the
      broker accepts by reference and retains. The answer is catalog (sealed),
      policy (sealed in R9), vault (not sealed). A second, independent gap in the
      same finding: an injected prepopulated catalog skips register_tool's
      credential-existence check, so a credentialed registration can name a
      credential that does not exist at seal time.

  F2  the injected-vault clock check tests for a PRIVATE ATTRIBUTE NAME, not for a
      clock domain. Review 9 replaced `vault.clock is not self._clock` with
      `getattr(supplied, "_clock", supplied) is not raw_clock` and justified it as
      "the R8 invariant was about one clock domain, not one Python object". That
      justification was wrong. Any wrapper exposing a `_clock` attribute satisfies
      it while transforming the value arbitrarily (offset, scale, cache, epoch), so
      the Review 8 clock-domain split is fully reopened. This is a REGRESSION
      authored in R9 and documented as "unchanged; only the comparison moved".

  F3  MonotonicClock reads the underlying clock OUTSIDE its lock and only compares
      inside, so two valid reads can be linearized in the wrong order and a healthy
      clock is declared broken. Availability only: it fails CLOSED (spurious
      ClockError -> typed refusal), so it cannot extend a lifetime or bypass
      authorization. Also authored in R9.

  F4  checked_now validates the OPERANDS of a security time and never the DERIVED
      value. 1e308 + 1e308 = inf, both operands finite, so a finite clock and a
      finite TTL produce an authorization whose expires_at is inf. No finite clock
      value can ever reach inf, so it never expires.

  F5  Budget accepts bool limits (bool is an int subclass, so isinstance(True, int)
      is True) and a non-bool mode flag. count_denied_attempts="false" is TRUTHY, so
      a plausible config typo silently selects the OPPOSITE budget mode. The project
      already uses `type(x) is not str` elsewhere specifically to close subclass
      holes; Budget never got the same discipline.

  LOW the regex JSON extractor and the tool-id grammar accept different domains: a
      tool id containing '}' is a legal ExecutionProposal and a legal
      ToolRegistration, but makes parse_model_output return INVALID. Fixed at the
      REGISTRATION boundary (a slug grammar), not by changing the extractor. See
      the LOW block for why the reviewer's proposed extractor change is unsound.

Trust-model note. None of these is remotely reachable. F1, F2, F4, F5 need trusted
in-process configuration to be constructed wrongly; F3 needs concurrency. They are
CONFIGURATION-INTEGRITY and HONESTY defects: the supported public APIs contradict
documented invariants. That is exactly the class this project refuses to hand-wave,
because the documentation is the security claim.
"""

import math
import threading
import time

import pytest

from capcore import (
    Capability, CapabilityStore, Proposal, ReferenceMonitor, RunContext,
)
from capcore.adapters import ParsedOutputKind, parse_model_output
from capcore.broker import (
    AuthorizationError, CatalogError, ClockError, Credential, CredentialError,
    CredentialVault, ExecutionProposal,
    FakeClock, MonotonicClock, Secret, ToolCatalog, ToolKind, ToolPolicy,
    ToolRegistration, TrustedExecutionBroker,
)
from capcore.runtime import (
    Budget, ExecutionEngine, RunRecord, StepOutcome,
)


def build(scope="acme/api"):
    store = CapabilityStore()
    store.issue(Capability("cap-1", "acme", scope, frozenset({"read"}),
                           principal="p", run="r"))
    return store, ReferenceMonitor(store), RunContext("acme", "p", "r")


def ep(resource="acme/api/x", verb="read", tool="t"):
    return ExecutionProposal(action=Proposal(resource, verb),
                             tool_registration_id=tool)


class EchoSecretTool:
    """A credentialed tool that reveals what it was given. Used ONLY to prove a
    secret actually reached an adapter; never a pattern for a real tool."""
    def execute_with_credential(self, proposal, secret):
        return f"secret={secret.reveal()}"


# --------------------------------------------------------------------------- #
# F1. Sealing must seal the VAULT too, and the seal must validate that every
# credentialed registration names a credential that actually exists.
# --------------------------------------------------------------------------- #

def test_retained_vault_cannot_issue_after_configuration_seal():
    """The exact shape of the Review 9 F4 hole, one object over.

    The broker accepts a caller-supplied CredentialVault (a supported public
    constructor arg) and retains the reference. seal_configuration() refuses
    broker.issue_credential() afterwards, but the caller still holds a vault whose
    public issue() keeps working. "Sealing freezes credential issuance" is what the
    README claims; it was true only of the broker's own method.
    """
    _, mon, _ = build()
    clock = FakeClock(0.0)
    vault = CredentialVault(clock)
    b = TrustedExecutionBroker(mon, vault=vault, clock=clock)
    b.seal_configuration()

    with pytest.raises(CredentialError):
        vault.issue(Credential("late", "read", "acme/api", Secret("LATE"),
                               ttl_seconds=60))


def test_late_vault_credential_cannot_be_executed():
    """End to end: a credential added after the seal must never reach an adapter.

    The catalog is injected PREPOPULATED, which is what makes this reachable: a
    registration naming credential 'late' can be installed without register_tool
    ever checking that 'late' exists.

    Written as an explicit two-branch assertion rather than a blanket
    pytest.raises around the whole scenario. The fix may legitimately stop this at
    EITHER of two points (the seal rejecting a dangling credential_id, or the vault
    refusing a post-seal issue), and a blanket raises() would pass on a fix that
    happened to throw for some THIRD, unrelated reason. What must be true is the
    security property: the secret does not reach the adapter.
    """
    _, mon, ctx = build()
    clock = FakeClock(0.0)
    vault = CredentialVault(clock)
    catalog = ToolCatalog()
    catalog.register(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                      EchoSecretTool(), "1", credential_id="late"))
    policy = ToolPolicy()
    policy.grant("t", "acme/api")
    b = TrustedExecutionBroker(mon, catalog=catalog, policy=policy,
                               vault=vault, clock=clock)

    try:
        b.seal_configuration()
    except (CredentialError, ValueError):
        return          # stopped at the seal: the dangling credential_id was caught

    try:
        vault.issue(Credential("late", "read", "acme/api", Secret("LATE"),
                               ttl_seconds=60))
    except CredentialError:
        return          # stopped at the vault: the post-seal issue was refused

    # Neither guard fired, so the only thing left is the execution itself, and it
    # must not deliver the secret.
    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    res = eng.step(rec, ep())
    assert res.outcome is not StepOutcome.EXECUTED, (
        f"a credential issued AFTER seal_configuration() reached an adapter: "
        f"{res.tool_result!r}")


def test_seal_rejects_credentialed_registration_without_credential():
    """The independent half of F1: an injected prepopulated catalog skips the
    credential-existence check that register_tool performs.

    register_tool validates that a CREDENTIALED registration's credential_id exists.
    A caller-supplied catalog never passes through it, so the check is simply not
    run. Sealing is the last point at which the configuration can be validated as a
    whole, so it is where the check belongs.
    """
    _, mon, _ = build()
    clock = FakeClock(0.0)
    catalog = ToolCatalog()
    catalog.register(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                      EchoSecretTool(), "1",
                                      credential_id="does-not-exist"))
    b = TrustedExecutionBroker(mon, catalog=catalog, clock=clock)

    with pytest.raises((CredentialError, ValueError)):
        b.seal_configuration()


def test_broker_refuses_post_seal_issuance_at_its_own_boundary():
    """The broker must refuse a post-seal credential issuance AT ITS OWN API
    BOUNDARY, not lean on the vault to catch it one layer down.

    Sealing the vault (F1) makes the broker's own `if self._config_sealed:` guard in
    issue_credential() redundant, which is exactly what disarmed
    grant_after_seal_allowed in Review 9 when ToolPolicy got its seal. It has NOT
    happened here, but only by luck: the broker raises CatalogError and the vault
    raises CredentialError, so the existing test's type assertion still
    distinguishes them.

    Relying on two exception classes happening to differ is not a guarantee. This
    pins the layering deliberately: the broker's guard is its own control, with its
    own message, and is separately killable.
    """
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon)
    b.seal_configuration()

    with pytest.raises(Exception) as exc:
        b.issue_credential(
            Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=60))

    # The BROKER's message, not the vault's ("credential vault is sealed...").
    assert "configuration is sealed" in str(exc.value)


def test_vault_seal_is_idempotent():
    """A seal is a STATE, not an event."""
    vault = CredentialVault(FakeClock(0.0))
    vault.seal()
    vault.seal()
    with pytest.raises(CredentialError):
        vault.issue(Credential("c", "read", "acme/api", Secret("S")))


def test_credentials_issued_before_seal_still_work():
    """Control. The seal must FREEZE the vault, not empty it. Guards against a fix
    that fails every credentialed tool closed."""
    _, mon, ctx = build()
    b = TrustedExecutionBroker(mon)
    b.issue_credential(
        Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=60))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     EchoSecretTool(), "1", credential_id="c"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()

    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    res = eng.step(rec, ep())

    assert res.outcome is StepOutcome.EXECUTED
    assert res.tool_result == "secret=S"


# --------------------------------------------------------------------------- #
# F2. "Shares a private _clock attribute" is not "is in the same clock domain".
# This reverts a Review 9 regression.
# --------------------------------------------------------------------------- #

class OffsetClock:
    """A wrapper that shares the underlying clock object and applies an offset.

    This is not exotic. It has the same SHAPE as MonotonicClock (a `_clock`
    attribute pointing at the real source), which is precisely why the Review 9
    check accepts it: that check asks 'do you have a private attribute named _clock
    pointing at mine', which is a duck-type test, not an identity test. Offset,
    scale, cache, round, and re-epoch wrappers all satisfy it while returning
    entirely different time.
    """
    def __init__(self, raw, offset):
        self._clock = raw
        self.offset = offset

    def now(self):
        return self._clock.now() + self.offset


def test_offset_clock_wrapper_is_not_the_same_clock_domain():
    """A vault whose clock merely WRAPS the broker's clock must be refused."""
    _, mon, _ = build()
    raw = FakeClock(0.0)
    vault = CredentialVault(OffsetClock(raw, 1000.0))

    with pytest.raises(ValueError):
        TrustedExecutionBroker(mon, vault=vault, clock=raw)


def test_preissued_vault_credential_cannot_survive_clock_rebinding():
    """The Review 8 defect, reopened by the Review 9 check and reproduced here.

    A credential pre-issued in the OFFSET domain carries issued_at=1000. The broker
    accepts the vault (its _clock points at the raw clock), rebinds it to the
    broker's wrapper, and now measures a 10s TTL against a raw clock that starts at
    0. At raw time 20 the credential is 20s old and must be refused; instead
    issued_at=1000 is in the future, elapsed time is negative, and the TTL never
    fires.

    The fix makes this UNCONSTRUCTIBLE: an injected vault must use the broker's
    exact clock object, which means it cannot have been used to issue anything
    beforehand (the broker's wrapped clock does not exist until the broker does).
    So a prepopulated injected vault is no longer a supported configuration, and
    that narrowing is the point.
    """
    _, mon, _ = build()
    raw = FakeClock(0.0)
    vault = CredentialVault(OffsetClock(raw, 1000.0))
    vault.issue(Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=10))

    with pytest.raises(ValueError):
        TrustedExecutionBroker(mon, vault=vault, clock=raw)


def test_vault_with_the_exact_broker_clock_is_still_accepted():
    """Control: the supported pattern (the ONLY one the suite has ever used) must
    keep working. An EMPTY vault constructed with the same raw clock object."""
    _, mon, ctx = build()
    clock = FakeClock(0.0)
    vault = CredentialVault(clock)
    b = TrustedExecutionBroker(mon, vault=vault, clock=clock)
    b.issue_credential(
        Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=60))
    b.register_tool(ToolRegistration("t", "read", ToolKind.CREDENTIALED,
                                     EchoSecretTool(), "1", credential_id="c"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()

    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    assert eng.step(rec, ep()).outcome is StepOutcome.EXECUTED


def test_a_prepopulated_injected_vault_is_refused():
    """Stating the API narrowing as a test, so it is a decision and not an accident.

    A vault that already holds credentials cannot have been stamped by the broker's
    clock (which does not exist yet), so its issue-time domain is unverifiable. That
    is the whole Review 8 defect. Refuse it rather than infer.
    """
    _, mon, _ = build()
    clock = FakeClock(0.0)
    vault = CredentialVault(clock)
    vault.issue(Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=60))

    with pytest.raises(ValueError):
        TrustedExecutionBroker(mon, vault=vault, clock=clock)


# --------------------------------------------------------------------------- #
# F3. MonotonicClock must be atomic. Read and compare under ONE lock.
# --------------------------------------------------------------------------- #

class StallingClock:
    """Hands 100.0 to the first caller and stalls it, then 101.0 to the second.

    Both reads are VALID and forward-moving. The only question is whether the wrapper
    linearizes them correctly, or lets a scheduler reordering look like a time source
    that went backward.

    Two Events rather than a sleep, so the interleaving is DETERMINISTIC (an earlier
    version used time.sleep(0.2) to order the threads and then let the gate time out,
    which both raced on slow CI and burned 3 seconds every run):

        a_has_read   set by A once it has taken its reading; the test waits on this
                     before starting B, so B cannot possibly read first.
        gate         held closed until the test releases it, so A is guaranteed to be
                     stalled INSIDE the read when B tries to take the lock.

    NOTE ON THE DELAY. Post-fix this test takes as long as the gate is held, and that
    is not waste, it is the invariant: with the read INSIDE the lock, A holds the lock
    while it is stalled, so B genuinely blocks. Serializing them is the whole point.
    Pre-fix, A stalls without the lock, B sails through, records 101, and A then
    raises. The gate is therefore kept short (0.3s) rather than removed: the cost is
    bounded and the interleaving stays deterministic.
    """
    def __init__(self):
        self.values = [100.0, 101.0]
        self.index = 0
        self.gate = threading.Event()
        self.a_has_read = threading.Event()
        self.hold = 0.3   # how long A stalls mid-read; see the note above

    def now(self):
        i = self.index
        self.index += 1
        if i == 0:
            self.a_has_read.set()
            self.gate.wait(self.hold)   # stall INSIDE the read
        return self.values[i]


def test_concurrent_monotonic_reads_do_not_false_detect_backward_time():
    """A healthy clock must not be declared broken by concurrent access.

    MonotonicClock.now() calls checked_now OUTSIDE the lock and only compares
    INSIDE, so thread A can read 100, be descheduled, thread B can read 101 and
    record the watermark, and then A compares its (valid, earlier) 100 against 101
    and raises. The underlying clock never moved backward.

    Fails CLOSED (a spurious refusal), so it is availability, not integrity: it
    cannot extend a lifetime or bypass authorization. But it intermittently breaks
    valid concurrent mints, issuances, and redemptions.
    """
    clock = StallingClock()
    mc = MonotonicClock(clock)
    results = {}

    def read(name):
        try:
            results[name] = mc.now()
        except ClockError as exc:
            results[name] = exc

    a = threading.Thread(target=read, args=("A",))
    b = threading.Thread(target=read, args=("B",))
    a.start()
    clock.a_has_read.wait(3)   # deterministic: A is now stalled mid-read
    b.start()
    b.join(5)
    a.join(5)

    assert not isinstance(results.get("A"), ClockError), (
        "a valid forward-moving clock was reported as moving backward, because the "
        "read happened outside the lock")
    assert not isinstance(results.get("B"), ClockError)


# NOT WRITTEN, deliberately: a "many threads mint at once against SystemClock" load
# test. It was drafted and dropped because it PASSED against the unfixed code: 8
# threads x 20 mints never hit the race window, so it would have passed whether the
# bug was present or not, while adding nondeterminism to CI. A test that cannot fail
# for the reason it exists is worse than no test: it is false comfort. The
# StallingClock test above forces the exact interleaving deterministically, which is
# what actually pins the invariant.


def test_vault_issue_under_the_clock_lock_does_not_deadlock():
    """Lock ORDERING, pinned as a test rather than left as an argument in a comment.

    Review 10 put a lock around CredentialVault.issue() (F1) and moved the clock read
    inside MonotonicClock's lock (F3). issue() reads the clock while holding the vault
    lock, so the acquisition order is vault -> clock. That is only safe while nothing
    acquires them the other way round.

    Today nothing does: MonotonicClock touches only the raw clock, and SystemClock and
    FakeClock never call back into the broker. But that is a property of the CURRENT
    clock implementations, not of the design, and a future injected clock that reaches
    back into the broker would deadlock. This test is the tripwire.
    """
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon)
    done = threading.Event()

    def issue_many():
        for i in range(50):
            b.issue_credential(
                Credential(f"c{i}", "read", "acme/api", Secret("S"), ttl_seconds=60))
        done.set()

    t = threading.Thread(target=issue_many, daemon=True)
    t.start()
    assert done.wait(10), (
        "credential issuance deadlocked: the vault lock and the clock lock were "
        "acquired in conflicting orders")


def test_sequential_backward_clock_is_still_rejected():
    """Control: the R9 invariant must not regress. A clock that GENUINELY moves
    backward is still refused."""
    class Backward:
        def __init__(self):
            self.v = 100.0

        def now(self):
            v = self.v
            self.v -= 10.0
            return v

    mc = MonotonicClock(Backward())
    assert mc.now() == 100.0
    with pytest.raises(ClockError):
        mc.now()


# --------------------------------------------------------------------------- #
# F4. Validating the OPERANDS of a security time is not validating the RESULT.
# --------------------------------------------------------------------------- #

def test_finite_time_and_ttl_cannot_create_infinite_action_expiry():
    """1e308 + 1e308 = inf. Both operands are finite and both pass checked_now and
    the TTL validation, so the guard never fires, and the derived expires_at is inf.

    No finite float can ever be >= inf, so the authorization NEVER expires. This is
    the same class as the Round 6 -> Round 9 progression: each round validated the
    inputs one level down and never the value actually used in the comparison.
    """
    _, mon, ctx = build()
    clock = FakeClock(1e308)
    b = TrustedExecutionBroker(mon, clock=clock, action_ttl_seconds=1e308)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ran", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()

    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    res = eng.step(rec, ep())

    assert res.outcome is not StepOutcome.EXECUTED


def test_finite_time_and_ttl_cannot_create_infinite_credential_expiry():
    """The same overflow on the credential side: issued_at + ttl must be finite."""
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon, clock=FakeClock(1e308))

    with pytest.raises((ClockError, CredentialError, ValueError)):
        b.issue_credential(
            Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=1e308))


def test_the_clock_read_itself_refuses_a_non_finite_value():
    """`checked_now`'s finiteness guard must be its OWN control, not one that leans on
    `checked_expiry` to catch the same input one layer down.

    This test exists because the F4 fix silently disarmed the R9
    clock_finiteness_unchecked mutation. With checked_now's finiteness check removed, a
    NaN clock still produces `nan + ttl = nan`, checked_expiry rejects it, and the mint
    is still refused with the same CLOCK_UNUSABLE outcome. Every R9 test asserts the
    OUTCOME, which is unchanged, so nothing went red and the mutation survived a full
    harness run.

    Defense in depth held: the security property was never broken. Falsifiability did
    not. Fourth instance in this project of a new guard silently disarming an older one
    (R9: policy seal vs broker seal; R10: budget gate split, vault seal vs broker seal,
    now this), and the resolution is the same each time: make the LAYERING observable
    rather than deleting a guard or accepting an untested one. The two refusals carry
    distinct messages; asserting on the message is what separates them.
    """
    from capcore.broker import checked_now

    class NaNClock:
        def now(self):
            return float("nan")

    with pytest.raises(ClockError) as exc:
        checked_now(NaNClock())
    assert "non-finite time" in str(exc.value), (
        "the clock READ must refuse this, not the downstream expiry derivation")


def test_a_ttl_less_credential_cannot_be_stamped_with_a_non_finite_time():
    """The sharper falsifier, and a real gap the layering exposes.

    checked_expiry only runs when `ttl_seconds is not None`. A credential with NO TTL
    therefore never reaches it, so checked_now's finiteness guard is the ONLY thing
    stopping `issued_at = nan`. A NaN issue-time on a TTL-less credential is inert
    today (nothing compares against it), but it is silently corrupt trusted state, and
    it would become live the moment anything started measuring age.

    So the guard is not merely redundant with checked_expiry: there is an input for
    which it is the only guard at all.
    """
    _, mon, _ = build()

    class NaNClock:
        def now(self):
            return float("nan")

    b = TrustedExecutionBroker(mon, clock=NaNClock())

    with pytest.raises(ClockError):
        b.issue_credential(Credential("c", "read", "acme/api", Secret("S")))


def test_a_ttl_too_small_to_change_the_clock_is_rejected():
    """A TTL so small it vanishes into float rounding produces a ZERO-length lifetime.

    Found by the `expires_at <= now` check while testing the overflow fix, not named
    in the review. 100.0 + 1e-320 == 100.0 exactly in float64: the TTL is positive and
    finite (so _is_positive_finite_ttl accepts it) but adds nothing, and the credential
    is born already expired.

    That would surface as a mystifying CREDENTIAL_REFUSED at redemption. It is a
    configuration error and belongs at issue time, which is what the strictly-later
    half of checked_expiry is for. The finiteness check alone would NOT catch this,
    which is why both checks are there.
    """
    _, mon, _ = build()
    b = TrustedExecutionBroker(mon, clock=FakeClock(100.0))

    with pytest.raises(ClockError):
        b.issue_credential(
            Credential("c", "read", "acme/api", Secret("S"), ttl_seconds=1e-320))


def test_ordinary_finite_times_still_work():
    """Control: guards against a fix that rejects every normal configuration."""
    _, mon, ctx = build()
    clock = FakeClock(1000.0)
    b = TrustedExecutionBroker(mon, clock=clock, action_ttl_seconds=30.0)
    b.register_tool(
        ToolRegistration("t", "read", ToolKind.PLAIN, lambda a: "ran", "1"))
    b.grant_tool("t", "acme/api")
    b.seal_configuration()

    eng = ExecutionEngine(b, Budget(3))
    rec = RunRecord(ctx=ctx)
    assert eng.step(rec, ep()).outcome is StepOutcome.EXECUTED


# --------------------------------------------------------------------------- #
# F5. bool is an int subclass. isinstance(True, int) is True.
# --------------------------------------------------------------------------- #

def test_budget_rejects_boolean_limits():
    """`isinstance(True, int)` is True, so Budget(max_actions=True) is accepted and
    silently becomes the budget 1.

    This project ALREADY legislates against exactly this: `type(x) is not str` is
    used elsewhere specifically to close subclass holes (see the existing
    proposal_accepts_str_subclass_resource mutation). Budget never got the same
    discipline.
    """
    with pytest.raises(ValueError):
        Budget(max_actions=True, max_iterations=2)
    with pytest.raises(ValueError):
        Budget(max_actions=2, max_iterations=True)


def test_budget_requires_boolean_count_mode():
    """The nastier half. `count_denied_attempts="false"` is a plausible config typo,
    and the string "false" is TRUTHY, so the runtime selects COUNTED mode: the exact
    opposite of what was written. A silently inverted budget mode.
    """
    with pytest.raises(ValueError):
        Budget(max_actions=1, max_iterations=1, count_denied_attempts="false")
    with pytest.raises(ValueError):
        Budget(max_actions=1, max_iterations=1, count_denied_attempts=1)


def test_budget_type_check_covers_the_deprecated_alias():
    """max_steps propagates into max_actions and max_iterations, so validating only
    the destinations would let Budget(max_steps=True) through.

    Not named in the review. Found by writing the fix: the alias is resolved BEFORE
    the old validation ran, so a bool alias became a bool budget. The type checks
    therefore run first, on every field, including the one that is only a shim.
    """
    with pytest.raises(ValueError):
        Budget(max_steps=True)
    with pytest.raises(ValueError):
        Budget(max_steps=3.0)


def test_budget_requires_a_limit():
    """Budget() with nothing set left max_actions=None, and `steps_taken >= None`
    raises TypeError deep in step(). A budget with no limit is a configuration error,
    not a default. Nothing in the codebase constructs a bare Budget(), so this costs
    nothing and closes a latent crash."""
    with pytest.raises(ValueError):
        Budget()


def test_budget_still_accepts_its_documented_types():
    """Control: real ints and real bools must keep working, both modes."""
    b1 = Budget(max_actions=3, max_iterations=5, count_denied_attempts=True)
    assert b1.max_actions == 3 and b1.count_denied_attempts is True
    b2 = Budget(max_actions=3, max_iterations=5, count_denied_attempts=False)
    assert b2.count_denied_attempts is False
    b3 = Budget(2)                       # single positional still defaults iterations
    assert b3.max_actions == 2 and b3.max_iterations == 2


# --------------------------------------------------------------------------- #
# LOW. The parser's accept-set and the catalog's accept-set must agree.
#
# The reviewer proposed replacing the regex extraction with `text.strip()`, on the
# grounds that "the system prompt already requires exactly one JSON object and no
# surrounding prose". That reasoning is UNSOUND and the fix is not taken: the model
# is UNTRUSTED, so what the system prompt ASKS FOR is not a constraint on what
# arrives. Small local models routinely wrap JSON in prose, and text.strip() would
# turn every such response from a recoverable parse into an INVALID: a real
# regression in a live path, for a cosmetic gain.
#
# Fixed at the REGISTRATION boundary instead. A slug grammar for tool ids is a
# strictly narrower accept-set (deny by default), closes the mismatch where it
# belongs, and needs no change to the extractor. A registered tool id containing
# '}' or '"' is a configuration smell regardless of any parser.
# --------------------------------------------------------------------------- #

def test_tool_registration_id_must_be_a_slug():
    """A tool id containing JSON metacharacters is refused AT REGISTRATION.

    CatalogError, not ValueError: a registration is TRUSTED CONFIG, so a bad id is a
    configuration error. The proposal side raises AuthorizationError for the same
    grammar violation, because there it is untrusted model output. One grammar, two
    meanings, and the error type says which layer caught it.
    """
    for bad in ('t}', 't"', "t{", "t\\", "a b", "", "t\n", "-lead", ".lead",
                "a/b", "a\tb"):
        with pytest.raises(CatalogError):
            ToolRegistration(bad, "read", ToolKind.PLAIN, lambda a: "ok", "1")


def test_execution_proposal_tool_id_must_be_a_slug():
    """And the proposal side agrees, so the two accept-sets cannot drift apart again.
    A model that names a non-slug tool is producing a MALFORMED proposal, not merely
    naming an unknown tool."""
    for bad in ('t}', 't"', "a b", "a/b"):
        with pytest.raises(AuthorizationError):
            ExecutionProposal(action=Proposal("acme/api/x", "read"),
                              tool_registration_id=bad)


def test_ordinary_tool_ids_still_register_and_parse():
    """Control. The ids the project actually uses must keep working, and a proposal
    naming one must still parse out of model output."""
    for good in ("t", "read-records", "send_records", "tool.v2", "a1-b2_c3.d4"):
        ToolRegistration(good, "read", ToolKind.PLAIN, lambda a: "ok", "1")

    out = parse_model_output(
        '{"verb":"read","resource":"acme/api/x","tool":"read-records"}')
    assert out.kind is ParsedOutputKind.PROPOSAL
    assert out.proposal.tool_registration_id == "read-records"
