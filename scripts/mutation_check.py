#!/usr/bin/env python3
"""Reproducible, crash-safe, reliable mutation check for capcore.

For each known defect, this reintroduces the bug into a FRESH TEMPORARY COPY of
the package (never the live source), runs tests against that copy, and asserts
the tests FAIL. If any mutation is not caught, it is a survivor and the script
exits non-zero.

MODES:
  python scripts/mutation_check.py            # full (default): whole suite per mutation
  python scripts/mutation_check.py --full     # same as default
  python scripts/mutation_check.py --focused  # fast: only each mutation's declared selectors

  Full mode is the deep, always-correct path (nightly / release). Focused mode is
  the fast path for routine feedback (PRs): each mutation runs only the specific
  tests declared to prove its invariant. A mutation with no declared selectors
  falls back to the full suite even in focused mode (safe: slower, never wrong).

SELECTORS:
  A mutation entry may carry a 5th element: a tuple of pytest node ids that prove
  its invariant, e.g.
    ("resource_size_unbounded", find, replace, "capcore/__init__.py",
     ("capcore/tests/test_review5_hardening.py::test_proposal_resource_length_is_bounded",))

SAFETY (why a mispaired selector cannot create false confidence):
  For every focused mutation the harness enforces, in order:
    1. GREEN-BEFORE: the selected tests PASS on the unmutated copy. A selector
       that fails here is mispaired/broken; its red-after would be meaningless.
       Reported as a HARNESS ERROR, never a caught mutation.
    2. APPLIED ONCE: the anchor occurs exactly once (else 'stale').
    3. RED-AFTER: the selected tests FAIL on the mutated copy (that is 'caught').
    4. Collection/usage errors and timeouts are HARNESS ERRORS, not kills: a
       mutation is 'caught' only when tests RUN and FAIL (pytest exit code 1),
       never when they fail to collect (exit >= 2).
  The live working tree is never modified; all mutation happens in throwaway temp
  dirs. Interrupt/timeout/crash cannot leave your source mutated.

Reliability properties (unchanged):
  - A FRESH temp copy per mutation (no shared bytecode or Hypothesis state).
  - PYTHONDONTWRITEBYTECODE and an isolated Hypothesis storage dir per run.
  - A per-mutation subprocess timeout, reported as a harness error.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE_REL = Path("capcore") / "__init__.py"
PER_MUTATION_TIMEOUT = 120  # seconds; a caught mutation returns well under this

# (name, exact source snippet to find, replacement). `find` must occur exactly
# once; otherwise the mutation is reported stale. Covers all documented
# defects: original seven plus six from hardening review.
MUTATIONS = [
    ("untrusted_identity_from_proposal",
     "            if cap.tenant != ctx.tenant:\n                continue",
     "            if False:  # BUG: ignore tenant binding (confused deputy)\n                continue"),
    ("missing_action_attenuation",
     "        if not child.actions <= parent.actions:",
     "        if False:  # BUG"),
    ("intersection_instead_of_union",
     "        granting = [c for c in applicable if verb in c.actions]",
     "        granting = [c for c in applicable if all(verb in x.actions for x in applicable)]  # BUG"),
    ("raw_prefix_matching",
     "    return all(s[i] == r[i] for i in range(len(s)))",
     "    return resource.startswith(scope)  # BUG"),
    ("duplicate_id_overwrite",
     '        if cap.id in self._caps:\n            raise StoreError(f"duplicate capability id: {cap.id}")\n',
     ""),
    ("malformed_proposal_not_rejected",
     "        if not valid_proposal(proposal):",
     "        if False:  # BUG"),
    ("explicit_deny_ignored",
     "        if deny_reason:",
     "        if False:  # BUG"),
    ("revoked_parent_derivation_allowed",
     '        if self.is_revoked(parent_id):\n            return DeriveResult(ok=False, reason="parent is revoked")\n',
     ""),
    ("issue_root_accepts_child_shaped",
     '        if cap.parent is not None:\n            raise StoreError(\n                "root capability must not specify a parent; use derive_child()")\n',
     ""),
    # Untrusted proposal fields must be size-bounded. Removing the resource byte
    # limit lets a remote model amplify memory/CPU across the whole pipeline.
    # Exact-type at the proposal boundary. isinstance would accept a str subclass
    # that lies via split()/__str__(), diverging authorization from execution.
    # Raw model text must be bounded before parsing. Removing the cap lets a huge
    # provider blob through as long as the eventual proposal is small.
    # The unified parse gate must reject oversized text for ALL outcomes,
    # including completion. Removing the size check lets an oversized {"done"}
    # through as FINISHED.
    ("parse_model_output_size_unbounded",
     "    if n > MAX_GENERATED_MODEL_TEXT_BYTES:\n        return ParsedModelOutput(ParsedOutputKind.TOO_LARGE)",
     "    if False:\n        return ParsedModelOutput(ParsedOutputKind.TOO_LARGE)",
     "capcore/adapters.py"),
    # The unified gate must reject malformed utf-8 for ALL outcomes.
    ("parse_model_output_utf8_unchecked",
     "    if n is None:\n        return ParsedModelOutput(ParsedOutputKind.INVALID_UTF8)",
     "    if False:\n        return ParsedModelOutput(ParsedOutputKind.INVALID_UTF8)",
     "capcore/adapters.py"),
    # The transport must bound by bytes actually read. Removing the check lets an
    # unbounded body be buffered.
    # The provider transport must decode strictly. Reverting to errors="replace"
    # silently repairs malformed bytes, defeating the fail-closed unicode rule.
    ("provider_decode_repairs_malformed",
     "            decoded = raw.decode(\"utf-8\")",
     "            decoded = raw.decode(\"utf-8\", errors=\"replace\")  # BUG: repair",
     "capcore/adapters.py"),
    # The provider response field must be an exact str.
    ("provider_response_field_untyped",
     "        if type(text) is not str:\n            raise ProviderProtocolError(\"provider response field must be a string\")",
     "        if False:\n            raise ProviderProtocolError(\"provider response field must be a string\")",
     "capcore/adapters.py"),
    ("bounded_read_unbounded",
     "        if len(buf) > max_bytes:\n            raise ProviderResponseTooLarge(\n                f\"provider response exceeded {max_bytes} bytes\")",
     "        if False:\n            raise ProviderResponseTooLarge(\n                f\"provider response exceeded {max_bytes} bytes\")",
     "capcore/httptool.py"),
    ("proposal_accepts_str_subclass_resource",
     "    if type(path) is not str:\n        raise ResourceError(\"resource must be an exact built-in str\")",
     "    if False:\n        raise ResourceError(\"resource must be an exact built-in str\")",
     "capcore/__init__.py",
     ("capcore/tests/test_review5_hardening.py::test_resource_str_subclass_is_rejected",
      "capcore/tests/test_review5_hardening.py::test_validate_resource_directly_rejects_str_subclass")),
    # utf8_length must fail closed on un-encodable text (lone surrogate). Making
    # it re-raise instead of returning None turns a malformed proposal into an
    # exception, violating M1's valid|invalid contract.
    ("utf8_length_not_fail_closed",
     "    try:\n        return len(value.encode(\"utf-8\"))\n    except UnicodeEncodeError:\n        return None",
     "    return len(value.encode(\"utf-8\"))  # BUG: crash on un-encodable text",
     "capcore/__init__.py"),
    ("proposal_resource_size_unbounded",
     "    if _rlen > MAX_RESOURCE_BYTES:\n        raise ResourceError(\"resource exceeds maximum length\")",
     "    if False:\n        raise ResourceError(\"resource exceeds maximum length\")",
     "capcore/__init__.py",
     ("capcore/tests/test_review5_hardening.py::test_proposal_resource_length_is_bounded",)),
    ("proposal_segment_size_unbounded",
     "        if _slen > MAX_SEGMENT_BYTES:\n            raise ResourceError(\"path segment exceeds maximum length\")",
     "        if False:\n            raise ResourceError(\"path segment exceeds maximum length\")",
     "capcore/__init__.py",
     ("capcore/tests/test_review5_hardening.py::test_proposal_resource_segment_length_is_bounded",)),
    ("resource_traversal_allowed",
     '        if s in (".", ".."):\n            raise ResourceError("\'.\' and \'..\' segments not allowed (path traversal)")\n',
     ""),
    ("model_deny_reason_leaks",
     "        return Decision(self.verdict, self.public_reason, self.public_reason, ())",
     "        return Decision(self.verdict, self.audit_reason, self.audit_reason, self.trace)  # BUG"),
    ("asterisk_permitted_in_resource",
     'r"^[A-Za-z0-9._\\-]+$"',
     'r"^[A-Za-z0-9._\\-*]+$"  # BUG: permit wildcard'),
    ("deny_policy_scope_unvalidated",
     "        try:\n            validate_resource(self.scope)\n        except ResourceError as exc:\n            raise ValueError(f\"invalid deny-policy scope: {self.scope!r}\") from exc",
     "        pass  # BUG: skip deny-policy scope validation"),
    ("principal_binding_ignored",
     "            if cap.principal is not None and cap.principal != ctx.principal:\n                continue",
     "            if False:  # BUG: ignore principal binding\n                continue"),
    ("run_binding_ignored",
     "            if cap.run is not None and cap.run != ctx.run:\n                continue",
     "            if False:  # BUG: ignore run binding\n                continue"),
    # --- M2 runtime mutations (target capcore/runtime.py) ---
    # The engine's execute-time re-authorization MOVED into the broker in the
    # M2<->M3 integration: the re-check now happens at redemption, immediately
    # before the credential is touched. The revoke-race mutation therefore targets
    # the broker's live re-authorization (see broker_skips_reauthorization_at_
    # redemption below). What remains engine-side is the BUDGET.
    # A broker-denied action (nothing executed) must not consume the action
    # budget when count_denied_attempts is False. Counting it before the mint
    # re-conflates denial with execution.
    ("denied_action_consumes_budget",
     "        # The broker minted an authorization: execution is now being attempted,\n        # which may produce an external effect. Count it exactly once here, for\n        # BOTH budget modes.\n        record.steps_taken += 1",
     "        pass  # BUG: never count executed actions, or count them before mint",
     "capcore/runtime.py"),
    ("budget_not_enforced",
     "        if record.steps_taken >= self.budget.max_actions:\n            record.state = RunState.ABORTED\n            res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,",
     "        if False:  # BUG: never enforce budget\n            record.state = RunState.ABORTED\n            res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,",
     "capcore/runtime.py"),
    # The engine's independent loop ceiling: a hostile model must not be able to
    # produce an unbounded run even if trusted counter state were corrupted.
    # The action budget (step-level) and the iteration ceiling (loop) must be
    # separate. Making the loop bound on max_actions instead of max_iterations
    # re-conflates them: a denied attempt would consume the loop budget.
    ("loop_bounds_on_actions_not_iterations",
     "        for _ in range(self.budget.max_iterations):",
     "        for _ in range(self.budget.max_actions):  # BUG: conflate ceiling and budget",
     "capcore/runtime.py"),
    ("engine_loop_ceiling_removed",
     "        for _ in range(self.budget.max_iterations):",
     "        while True:  # BUG: unbounded loop, no independent ceiling",
     "capcore/runtime.py"),
    # The engine must derive its monitor from the broker, not accept a divergent
    # one. Mutating the guard to accept a mismatched monitor reopens split
    # authority at the engine/broker seam.
    # run() must validate the proposal type at the boundary, not trust the
    # adapter. Removing the check lets a malformed PROPOSAL crash the loop.
    # An outcome outside the explicit algebra must fail closed. Removing the
    # final else lets a bogus outcome fall through and execute as a proposal.
    ("unknown_model_outcome_executes",
     "            else:\n                # ANY outcome outside the explicit algebra fails closed. This is\n                # the whole point: unknown outcomes must not fall through and be\n                # treated as a proposal. Covers a bypassed __post_init__, a future\n                # enum member the loop does not handle, or a corrupted value.\n                record.state = RunState.FAILED\n                record.stop_reason = StopReason.MODEL_ERROR\n                return record",
     "            else:\n                pass  # BUG: unknown outcome falls through to proposal dispatch",
     "capcore/runtime.py"),
    # An invalid/oversized action must fail closed at the run boundary before it
    # can enter trusted history. Removing the valid_proposal check lets a raw
    # malformed action be retained and reach ModelView.
    # step() must validate the action before the budget check. Removing the
    # step-level check lets a raw malformed action into trusted history via the
    # public step() entry point.
    ("step_retains_invalid_proposal_in_history",
     "        if not valid_proposal(action):\n            record.state = RunState.FAILED\n            record.stop_reason = StopReason.MODEL_ERROR\n            res = StepResult(StepOutcome.MALFORMED_PROPOSAL,\n                             _redacted_action(action),\n                             audit_reason=\"model proposal was malformed or exceeded size limits\")\n            record.history.append(res)\n            return res\n\n        # 1. Budget.",
     "        # 1. Budget.",
     "capcore/runtime.py"),
    ("run_retains_invalid_proposal_in_history",
     "                if not valid_proposal(result.proposal.action):",
     "                if False:  # BUG: let a malformed action into history",
     "capcore/runtime.py"),
    ("run_skips_proposal_type_check",
     "                if type(result.proposal) is not ExecutionProposal:\n                    record.state = RunState.FAILED\n                    record.stop_reason = StopReason.MODEL_ERROR\n                    return record",
     "                if False:\n                    record.state = RunState.FAILED\n                    record.stop_reason = StopReason.MODEL_ERROR\n                    return record",
     "capcore/runtime.py"),
    # An expired/consumed credential must not be reported as a revoke race. If the
    # engine maps every refusal to REVOKED_RACE, trusted history lies about why.
    # An expired PENDING authorization must map to a neutral refusal, not
    # REVOKED_RACE. Collapsing the claim codes back to REVOKED_RACE re-lies in
    # trusted history.
    ("expired_pending_auth_is_revoke_race",
     "    return StepOutcome.AUTHORIZATION_REFUSED, f\"authorization refused: {audit_code}\"",
     "    return StepOutcome.REVOKED_RACE, f\"authorization refused: {audit_code}\"  # BUG",
     "capcore/runtime.py"),
    # The claim path must raise TYPED reasons, not one generic code. Collapsing
    # ACTION_EXPIRED into the fallback loses the distinction.
    ("claim_expiry_not_typed",
     "                raise ClaimRefused(BrokerRefusal.ACTION_EXPIRED,\n                                   \"authorization expired\")",
     "                raise ClaimRefused(BrokerRefusal.CLAIM_REFUSED,\n                                   \"authorization expired\")  # BUG: generic",
     "capcore/broker.py"),
    # Mint refusals must be classified by typed code. If the engine string-parses
    # again (or maps a non-authorization mint refusal to REVOKED_RACE), audit
    # integrity is lost.
    ("mint_refusal_not_typed",
     "        MintRefusal.UNKNOWN_TOOL: StepOutcome.TOOL_NOT_FOUND,",
     "        MintRefusal.UNKNOWN_TOOL: StepOutcome.REVOKED_RACE,  # BUG: mislabel",
     "capcore/runtime.py"),
    ("refusal_mislabeled_as_revoke_race",
     "    if audit_code == BrokerRefusal.REAUTHORIZATION_FAILED:\n        return StepOutcome.REVOKED_RACE, \"authorization lost before execution\"",
     "    if True:\n        return StepOutcome.REVOKED_RACE, \"authorization lost before execution\"  # BUG: every refusal a revoke race",
     "capcore/runtime.py"),
    ("engine_accepts_divergent_monitor",
     "        if passed_monitor is not None and passed_monitor is not broker.monitor:",
     "        if False:  # BUG: accept a monitor that differs from broker.monitor",
     "capcore/runtime.py"),
    # The vault must store a COPY, not the caller's mutable Credential. Storing
    # the caller's object lets a retained reference widen scope / reset single-use
    # / backdate TTL / swap the secret after issuance.
    ("vault_stores_caller_object",
     "        stored = _StoredCredential(",
     "        stored = cred  # BUG: alias the caller's mutable object\n        _ignore = _StoredCredential(",
     "capcore/broker.py"),
    # An action_id collision must fail closed, not overwrite an existing pending
    # authorization. Removing the duplicate check lets a colliding id silently
    # replace prior authority.
    ("pending_put_overwrites_on_collision",
     "            if record.action_id in self._records:\n                raise AuthorizationError(\"action_id collision\")",
     "            if False:\n                raise AuthorizationError(\"action_id collision\")",
     "capcore/broker.py"),
    # --- M3 broker mutations (target capcore/broker.py) ---
    # Re-authorization at redemption: if the live monitor no longer allows the
    # action, the secret must not leave. Mutating this to always-allow is the
    # stale-decision / revocation-bypass defect.
    ("broker_skips_reauthorization_at_redemption",
     "            if live.verdict is not Verdict.ALLOW:",
     "            if False:  # BUG: skip live re-authorization at redemption",
     "capcore/broker.py"),
    # Credential scope must cover the resource. Ignoring it lets a credential be
    # used outside its binding.
    ("broker_ignores_credential_scope",
     "        if not scope_covers(cred.scope, rec.action.resource):",
     "        if False:  # BUG: ignore credential scope",
     "capcore/broker.py"),
    # Catalog existence is NOT authorization. Bypassing ToolPolicy lets an
    # untrusted model route an authorized action to ANY registered executor.
    ("broker_ignores_tool_policy",
     "        if not self._policy.allows(reg.registration_id, action):",
     "        if False:  # BUG: any registered tool may serve any action",
     "capcore/broker.py"),
    # The tool must serve the proposed action class.
    ("broker_ignores_tool_verb_match",
     "        if reg.verb != action.verb:",
     "        if False:  # BUG: any tool may serve any verb",
     "capcore/broker.py"),
    # A malformed credential scope must fail closed AT ISSUANCE, not blow up
    # mid-action with a secret already in play.
    # TTLs must reject non-finite values. Removing isfinite lets nan/inf through
    # as "never expires", silently defeating expiry.
    ("ttl_accepts_non_finite",
     "    if not math.isfinite(value):\n        return False",
     "    if False:\n        return False  # BUG: accept nan/inf TTL",
     "capcore/broker.py"),
    ("credential_scope_not_validated_at_issue",
     "            raise CredentialError(f\"invalid credential scope: {self.scope!r}\") from exc",
     "            pass  # BUG: swallow an invalid credential scope (fail open)",
     "capcore/broker.py"),
    # A malformed TOOL GRANT scope must also fail closed at construction: a grant
    # that vanished at check time would be an allow-by-omission.
    ("tool_grant_scope_not_validated",
     "            raise ValueError(f\"invalid tool-grant scope: {self.scope!r}\") from exc",
     "            pass  # BUG: swallow an invalid tool-grant scope",
     "capcore/broker.py"),
    # A tool's untrusted return value must be normalized to an inert str before it
    # enters trusted run state. Accepting it raw lets a mutable object reach the
    # model through the shallowly-frozen ModelView.
    # Credential issue-time must be stamped from the trusted clock, not left at
    # the -1 sentinel or a caller value. Stamping from a fixed 0 would make every
    # credential appear issued at epoch, breaking TTL.
    # The tool's catalog-owned generation is the authenticity check at redemption.
    # Comparing the caller-supplied version string instead lets a same-version
    # swap inherit the authorization.
    # Mint must require a sealed catalog. Removing the check lets execution
    # proceed against a mutable catalog.
    ("mint_allows_unsealed_catalog",
     "        if not self._catalog.is_sealed:\n            self._record(\"-\", None, action, False, \"catalog not sealed\")\n            raise MintRefused(MintRefusal.CATALOG_NOT_SEALED, \"catalog is not sealed\")",
     "        if False:\n            self._record(\"-\", None, action, False, \"catalog not sealed\")\n            raise MintRefused(MintRefusal.CATALOG_NOT_SEALED, \"catalog is not sealed\")",
     "capcore/broker.py"),
    # Sealing must actually block registration. If seal() is a no-op, the
    # lifecycle guarantee is void.
    ("catalog_seal_is_noop",
     "        with self._lock:\n            self._sealed = True",
     "        with self._lock:\n            self._sealed = self._sealed  # BUG: seal does nothing",
     "capcore/broker.py"),
    ("redemption_ignores_tool_generation",
     "            if reg is None or gen != rec.tool_generation:",
     "            if reg is None:  # BUG: same-version swap inherits authorization",
     "capcore/broker.py"),
    ("credential_issue_time_not_stamped",
     "            issued_at=self._clock.now(),",
     "            issued_at=0.0,  # BUG: ignore the clock, every credential epoch-issued",
     "capcore/broker.py"),
    ("broker_stores_unnormalized_tool_result",
     "    if type(out) is not str:\n        return False, None",
     "    if False:\n        return False, None  # BUG: store raw adapter output",
     "capcore/broker.py"),
    # isinstance would accept a str SUBCLASS that fakes encode() and carries
    # mutable state. Exact-type is required.
    ("tool_result_accepts_str_subclass",
     "    if type(out) is not str:",
     "    if not isinstance(out, str):  # BUG: accept a hostile str subclass",
     "capcore/broker.py"),
    # A provider failure must not be reported as a completion. This is the
    # difference between "the work is done" and "nothing happened and we lied".
    ("provider_error_reported_as_completion",
     "            if outcome is ModelOutcome.ERROR:\n                record.state = RunState.FAILED",
     "            if outcome is ModelOutcome.ERROR:\n                record.state = RunState.COMPLETED  # BUG: failure looks like success",
     "capcore/runtime.py"),
    # An adapter that raises is a failed provider, not a finished one.
    ("model_exception_swallowed_as_completion",
     "            if type(result) is not ModelResult:\n                # An adapter that does not return an exact ModelResult cannot be\n                # trusted to mean \"finished\". A subclass could override behaviour;\n                # a None or look-alike is not the protocol. Fail closed.\n                record.state = RunState.FAILED",
     "            if type(result) is not ModelResult:\n                record.state = RunState.COMPLETED  # BUG: untyped result looks finished",
     "capcore/runtime.py"),
    # OllamaModel must not turn a transport failure into a clean stop.
    # An adapter hitting its own cap must not report task completion.
    ("adapter_limit_becomes_completion",
     "            elif outcome is ModelOutcome.LIMIT_REACHED:\n                # The adapter stopped asking; the model did not say it was done.\n                # That is an abort, not a completion: the task may be unfinished.\n                record.state = RunState.ABORTED",
     "            elif outcome is ModelOutcome.LIMIT_REACHED:\n                record.state = RunState.COMPLETED  # BUG: truncated run looks finished",
     "capcore/runtime.py"),
    ("ollama_error_becomes_finished",
     "        except Exception:\n            # Network, HTTP, timeout, malformed-JSON-from-the-server: the provider\n            # failed. NOT a completion.\n            return ModelResult.error()",
     "        except Exception:\n            # Network, HTTP, timeout, malformed-JSON-from-the-server: the provider\n            # failed. NOT a completion.\n            return ModelResult.finished()  # BUG: provider failure as completion",
     "capcore/adapters.py"),
    # --- M3 destination policy (target capcore/httptool.py) ---
    # The URL is where a real credential is SENT. https-only is what keeps the
    # Authorization header off a cleartext wire.
    ("httptool_allows_any_scheme",
     "    if scheme not in ALLOWED_SCHEMES:",
     "    if False:  # BUG: send credentials over any scheme",
     "capcore/httptool.py"),
    # Embedded userinfo leaks credentials into logs, proxies, and exceptions.
    ("httptool_allows_embedded_userinfo",
     "    if parts.username is not None or parts.password is not None:",
     "    if False:  # BUG: permit https://user:pw@host",
     "capcore/httptool.py"),
    # Consumed/expired credentials must be refused. Ignoring availability defeats
    # single-use and TTL.
    ("broker_ignores_credential_expiry",
     "            if cred.is_expired(now):",
     "            if False:  # BUG: ignore expired credential",
     "capcore/broker.py"),
    ("broker_ignores_single_use_consumption",
     "                self._consumed_ids.add(cred.id)",
     "                pass  # BUG: never record consumption, single-use reusable",
     "capcore/broker.py"),
    # The single-use consumption itself: if the record is not claimed atomically,
    # an authorization can be replayed. Mutating the claim guard opens replay.
    ("broker_allows_replay_of_claimed_action",
     "        if rec.state is not AuthorizationState.PENDING:",
     "        if False:  # BUG: allow redeeming a non-pending authorization",
     "capcore/broker.py"),
]


class HarnessError(Exception):
    pass


def _pytest_target(pkg_parent: Path, selectors):
    """The pytest target list: specific node ids if selectors given, else the
    whole tests dir. Node ids are made absolute against the temp copy so pytest
    resolves them inside the mutated tree, not the live tree."""
    if not selectors:
        return [str(pkg_parent / "capcore" / "tests")]
    targets = []
    for sel in selectors:
        # sel looks like "capcore/tests/test_x.py::test_y"; rebase the file part
        # onto pkg_parent so it points into the temp copy.
        if "::" in sel:
            path_part, node = sel.split("::", 1)
            targets.append(f"{pkg_parent / path_part}::{node}")
        else:
            targets.append(str(pkg_parent / sel))
    return targets


def run_suite(pkg_parent: Path, selectors=None):
    """Run tests against the copy at pkg_parent. Returns True iff they PASS.

    If `selectors` is given, only those pytest node ids run (focused mode);
    otherwise the whole tests dir runs (full mode). Raises HarnessError on
    timeout or on a pytest collection/usage error (exit code >= 2), which must
    NOT be mistaken for a caught mutation: a mutation is only 'caught' when the
    tests RUN and FAIL, never when they fail to collect.
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(pkg_parent) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HYPOTHESIS_STORAGE_DIRECTORY"] = str(pkg_parent / ".hypothesis")
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-x", "-q", "--no-header",
             "-p", "no:cacheprovider", *_pytest_target(pkg_parent, selectors)],
            cwd=pkg_parent, capture_output=True, text=True, env=env,
            timeout=PER_MUTATION_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise HarnessError("pytest exceeded per-mutation timeout")
    # pytest exit codes: 0 = all passed, 1 = tests failed, 2 = usage error,
    # 3 = internal error, 4 = usage error, 5 = no tests collected. Only 0 (pass)
    # and 1 (ran-and-failed) are meaningful for us; anything else is a harness
    # error (a bad selector, a collection failure), NOT a caught mutation.
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise HarnessError(
        f"pytest returned {result.returncode} (collection/usage error, not a "
        f"test failure): {result.stdout[-500:]}"
    )


def fresh_copy(dst: Path):
    shutil.copytree(
        ROOT / "capcore", dst / "capcore",
        ignore=shutil.ignore_patterns(
            "__pycache__", "*.pyc", ".hypothesis", ".pytest_cache",
            # The harness self-tests (test_mutation_harness.py) import this script
            # from scripts/, which is NOT copied into the mutated tree, and they
            # test the HARNESS, not capcore. Excluding them keeps the mutated-copy
            # suite focused on the package under mutation and avoids a spurious
            # collection failure in the temp copy.
            "test_mutation_harness.py",
        ),
    )


def _selectors_of(mut):
    """The optional test selectors for a mutation entry: the 5th element if
    present (a tuple/list of pytest node ids), else None."""
    if len(mut) >= 5 and mut[4]:
        return tuple(mut[4])
    return None


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    focused = "--focused" in argv
    full = "--full" in argv
    if focused and full:
        print("ABORT: choose --focused or --full, not both", file=sys.stderr)
        return 2
    # Default is full (the deep, always-correct path). --focused is the fast path
    # for routine feedback and requires each mutation to declare its selectors.
    mode_focused = focused

    original_ok = True
    survivors, stale, errors, no_selector = [], [], [], []
    src_cache: dict[str, str] = {}

    # baseline: a fresh unmutated copy must pass the FULL suite regardless of
    # mode. Focused mode still needs the whole tree green before it can trust any
    # per-mutation result.
    with tempfile.TemporaryDirectory(prefix="capcore-mut-base-") as td:
        base = Path(td)
        fresh_copy(base)
        try:
            if not run_suite(base):
                print("ABORT: suite does not pass on an unmutated copy", file=sys.stderr)
                return 2
        except HarnessError as e:
            print(f"ABORT: baseline run failed: {e}", file=sys.stderr)
            return 2

    for mut in MUTATIONS:
        name, find, replace = mut[0], mut[1], mut[2]
        target_rel = Path(mut[3]) if len(mut) > 3 and mut[3] else CORE_REL
        selectors = _selectors_of(mut)
        key = str(target_rel)
        if key not in src_cache:
            src_cache[key] = (ROOT / target_rel).read_text(encoding="utf-8")
        target_src = src_cache[key]
        if target_src.count(find) != 1:
            stale.append(name)
            print(f"[stale]   {name}: anchor found {target_src.count(find)} times (expected 1)")
            continue

        # In focused mode a mutation without selectors falls back to the FULL
        # suite (safe: slower but never wrong). Record it so the operator can see
        # coverage of the focused path.
        run_selectors = selectors if mode_focused else None
        if mode_focused and selectors is None:
            no_selector.append(name)
            run_selectors = None   # full suite for this one

        with tempfile.TemporaryDirectory(prefix=f"capcore-mut-{name}-") as td:
            tmp = Path(td)
            fresh_copy(tmp)

            # SAFETY: green-before. If we are about to trust a focused selector,
            # that selector MUST pass on the UNMUTATED copy first. A selector that
            # fails green-before is mispaired or broken; its later red-after would
            # be meaningless (it would "fail" regardless of the mutation). Treat as
            # a harness error, never a caught mutation.
            if run_selectors is not None:
                try:
                    if not run_suite(tmp, selectors=run_selectors):
                        errors.append(name)
                        print(f"[ERROR]   {name}: selectors do not pass on the "
                              f"unmutated copy (mispaired selector): {run_selectors}")
                        continue
                except HarnessError as e:
                    errors.append(name)
                    print(f"[ERROR]   {name}: selector green-before check failed: {e}")
                    continue

            # Apply the mutation and require red-after.
            (tmp / target_rel).write_text(
                target_src.replace(find, replace, 1), encoding="utf-8")
            try:
                caught = not run_suite(tmp, selectors=run_selectors)
            except HarnessError as e:
                errors.append(name)
                print(f"[ERROR]   {name}: {e}")
                continue

        if caught:
            print(f"[caught]  {name}")
        else:
            survivors.append(name)
            print(f"[SURVIVED]{name}  <-- not detected by any test")

    print()
    if mode_focused:
        covered = len(MUTATIONS) - len(no_selector) - len(stale)
        print(f"focused mode: {covered} mutation(s) ran against declared selectors, "
              f"{len(no_selector)} fell back to the full suite")
    if stale:
        print(f"{len(stale)} stale mutation(s): {', '.join(stale)}")
    if errors:
        print(f"FAIL: {len(errors)} mutation(s) errored "
              f"(timeout/harness/mispaired selector): {', '.join(errors)}")
    if survivors:
        print(f"FAIL: {len(survivors)} mutation(s) survived: {', '.join(survivors)}")
    if survivors or errors:
        return 1
    if stale:
        return 3
    print(f"OK: all {len(MUTATIONS)} mutations caught by the test suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
