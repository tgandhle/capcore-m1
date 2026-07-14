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

# (name, exact source snippet to find, replacement, file[, selectors]). `find` must
# occur exactly once; otherwise the mutation is reported stale (run
# scripts/check_stale.py). Covers every documented defect from every review round
# to date: 85 as of round 9.
#
# WHY THE FULL RUN MATTERS, not just check_stale. A mutation can still match its
# anchor, still pass check_stale, and have quietly STOPPED BITING, because a later
# fix made the guard it targets redundant or moved the code the killing test
# exercised. Round 9 hit this three times: splitting the budget gate per mode
# disarmed budget_not_enforced and budget_gate_disabled, and adding the ToolPolicy
# seal disarmed grant_after_seal_allowed (the policy refused, so removing the
# broker's own check changed nothing observable). In every case the suite was green
# and check_stale was clean. Only the full run caught it. A stale anchor is loud; an
# anchor that matches while no longer biting is silent.
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
    # The parser must be total: a non-str input must return INVALID, not raise.
    # R9-F2. The JSON nesting cap. RecursionError is NOT the control: 3.11-3.13
    # raise it at depth 10000 and 3.14 does not (it parses), so a fix relying on
    # the exception holds on some interpreters and not others. Only a pre-decode
    # cap is a pure function of the input and therefore identical everywhere.
    #
    # DELIBERATELY UNMUTATED: the `RecursionError` entries in the two except
    # tuples. They cannot be given a catchable mutation, and this is honest rather
    # than an oversight. Removing either is a no-op, because the cap has ALREADY
    # rejected any input deep enough to make the decoder recurse; falsifying them
    # would need an input the cap accepts (depth <= 16) but the decoder still blows
    # up on, which does not exist. They are unreachable-by-construction defense in
    # depth against a future bug in the cap itself. The alternative was deleting a
    # cheap guard to satisfy a metric, or writing a mutation that "passes" by
    # riding on unrelated red tests. Both are worse.
    ("model_output_nesting_uncapped",
     "    if not json_nesting_within_limit(candidate):",
     "    if False:  # BUG: let the decoder cope with arbitrary nesting",
     "capcore/adapters.py",
     ("capcore/tests/test_review9_hardening.py::test_deeply_nested_json_returns_invalid",
      "capcore/tests/test_review9_hardening.py::test_json_depth_one_past_the_limit_is_rejected")),
    # Off by one: depth == limit is LEGAL. `>=` silently rejects a payload at the
    # documented boundary, which is a compatibility break dressed as a control.
    ("json_nesting_limit_off_by_one",
     "            if depth > limit:",
     "            if depth >= limit:  # BUG: rejects the documented limit itself",
     "capcore/adapters.py",
     ("capcore/tests/test_review9_hardening.py::test_json_depth_at_the_limit_is_accepted",)),
    # A scanner that does not track string state counts brackets inside string
    # VALUES as structure, and rejects legitimate output (a resource path like
    # "acme/api/[x]"). A naive counter is WORSE than none.
    ("json_nesting_scanner_ignores_strings",
     "        if char == '\"':\n            in_string = True",
     "        if False:  # BUG: treat string content as structure\n            in_string = True",
     "capcore/adapters.py",
     ("capcore/tests/test_review9_hardening.py::test_brackets_inside_strings_do_not_count",
      "capcore/tests/test_review9_hardening.py::test_a_json_string_containing_brackets_still_parses")),
    # Not tracking escapes is the DANGEROUS direction: an escaped backslash before
    # a quote leaves the scanner stuck in string state, so it stops counting real
    # structure and ACCEPTS an over-deep payload.
    ("json_nesting_scanner_ignores_escapes",
     "            elif char == \"\\\\\":\n                escaped = True",
     "            elif False:  # BUG: ignore escapes\n                escaped = True",
     "capcore/adapters.py",
     ("capcore/tests/test_review9_hardening.py::test_escaped_backslash_before_quote_is_handled",
      "capcore/tests/test_review9_hardening.py::test_escaped_quote_does_not_end_string_state")),
    # The provider ENVELOPE is a second decoder on provider-controlled bytes.
    # next_proposal's `except Exception` catches a RecursionError there but not a
    # native stack overflow, so the envelope needs the cap too.
    ("provider_envelope_nesting_uncapped",
     "    if not json_nesting_within_limit(decoded):",
     "    if False:  # BUG: envelope may nest arbitrarily deep",
     "capcore/adapters.py",
     ("capcore/tests/test_review9_hardening.py::test_provider_envelope_depth_is_capped_before_decode",)),
    ("parse_model_output_non_string_raises",
     "    if type(text) is not str:\n        return ParsedModelOutput(ParsedOutputKind.INVALID)",
     "    if False:\n        return ParsedModelOutput(ParsedOutputKind.INVALID)",
     "capcore/adapters.py"),
    # A proposal-construction failure (e.g. oversized tool id) must become INVALID,
    # not escape as an exception.
    ("parse_model_output_construction_raises",
     "    except Exception:\n        return ParsedModelOutput(ParsedOutputKind.INVALID)\n    return ParsedModelOutput(ParsedOutputKind.PROPOSAL, proposal)",
     "    except Exception:\n        raise  # BUG: let construction errors escape\n    return ParsedModelOutput(ParsedOutputKind.PROPOSAL, proposal)",
     "capcore/adapters.py"),
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
    # NOTE: the envelope decode moved from OllamaModel._call into the extracted
    # decode_provider_envelope (Review 9 F2), so it is testable without a live
    # provider. The invariant is unchanged; the anchors are dedented to match.
    ("provider_decode_repairs_malformed",
     "        decoded = raw.decode(\"utf-8\")",
     "        decoded = raw.decode(\"utf-8\", errors=\"replace\")  # BUG: repair",
     "capcore/adapters.py"),
    # The provider response field must be an exact str.
    ("provider_response_field_untyped",
     "    if type(text) is not str:\n        raise ProviderProtocolError(\"provider response field must be a string\")",
     "    if False:\n        raise ProviderProtocolError(\"provider response field must be a string\")",
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
    # R9-F3. The two budget modes need DIFFERENT orderings. Applying one to both
    # is precisely the Review 8 regression: the gate moved after authorization to
    # protect the non-counting mode's honest DENIED classification, which silently
    # disabled the ATTEMPT budget in the counting mode.
    #
    # Removing the pre-authorization gate: max_actions no longer bounds attempts
    # when denied attempts count. The run authorizes, classifies, and counts an
    # attempt it had no budget for.
    ("counted_attempt_budget_not_enforced",
     "        if self.budget.count_denied_attempts:\n            if record.steps_taken >= self.budget.max_actions:",
     "        if False:  # BUG: attempt budget never gates\n            if record.steps_taken >= self.budget.max_actions:",
     "capcore/runtime.py",
     ("capcore/tests/test_review9_hardening.py::test_counted_denial_respects_exhausted_attempt_budget",
      "capcore/tests/test_review9_hardening.py::test_counted_approval_respects_exhausted_attempt_budget")),
    # NOT MUTATED, and deliberately so: the MIRROR defect (gating the non-counting
    # mode BEFORE authorization, which is the Review 8 bug) cannot be expressed as a
    # line substitution. Flipping the `if not self.budget.count_denied_attempts:`
    # guard at step 3 to `if True:` is INERT, because by the time control reaches
    # step 3 a denied proposal has already returned DENIED at step 2. Reintroducing
    # that bug requires MOVING the gate, which this harness (a line-substitution
    # mutator) cannot do. The invariant is instead held by the control test
    # test_non_counted_denial_still_survives_execution_budget, and by the existing
    # denied_action_consumes_budget and budget_gate_disabled mutations below.
    ("denied_action_consumes_budget",
     "        # The broker minted an authorization: execution is now being attempted,\n        # which may produce an external effect. Count it exactly once here, for\n        # BOTH budget modes.\n        record.steps_taken += 1",
     "        pass  # BUG: never count executed actions, or count them before mint",
     "capcore/runtime.py"),
    # Re-anchored (Review 9 F3): the single budget gate became two, one per mode,
    # because the modes need different orderings. This one is the NON-COUNTING
    # (execution) budget: an allowed action past it must not run.
    ("budget_not_enforced",
     "        if not self.budget.count_denied_attempts:\n            if record.steps_taken >= self.budget.max_actions:\n                record.state = RunState.ABORTED",
     "        if not self.budget.count_denied_attempts:\n            if False:  # BUG: never enforce the execution budget\n                record.state = RunState.ABORTED",
     "capcore/runtime.py",
     ("capcore/tests/test_review9_hardening.py::test_non_counted_execution_budget_is_enforced",)),
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
     "        if not valid_proposal(action):\n            record.state = RunState.FAILED\n            record.stop_reason = StopReason.MODEL_ERROR",
     "        if False:  # BUG: let a malformed action into history\n            record.state = RunState.FAILED\n            record.stop_reason = StopReason.MODEL_ERROR",
     "capcore/runtime.py"),
    # M1 classification must survive budget exhaustion. Moving the budget gate
    # BEFORE the DENY/APPROVAL returns re-hides denials as BUDGET_EXHAUSTED.
    # Re-anchored (Review 9 F3). The COUNTING (attempt) budget's ABORT: exhausting
    # the attempt budget must abort the run, not merely refuse one step and let the
    # loop keep asking.
    ("budget_gate_disabled",
     "        if self.budget.count_denied_attempts:\n            if record.steps_taken >= self.budget.max_actions:\n                record.state = RunState.ABORTED",
     "        if self.budget.count_denied_attempts:\n            if record.steps_taken >= self.budget.max_actions:\n                record.state = RunState.RUNNING  # BUG: exhaustion does not abort",
     "capcore/runtime.py",
     ("capcore/tests/test_review9_hardening.py::test_counted_budget_exhaustion_aborts_the_run",)),
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
    # grant_tool must be refused after seal_configuration(). Removing the guard
    # lets policy be mutated after sealing.
    # Review 9 note: this guard became REDUNDANT with the policy's own seal (F4),
    # and the redundancy silently disarmed this mutation: with the broker's check
    # removed, ToolPolicy.grant() still refuses, so a type-only assertion cannot
    # tell the difference and the mutation SURVIVED a full harness run. Defense in
    # depth held, but a guard nothing tests is a guard nothing tests. The selector
    # below asserts the broker refuses at ITS OWN boundary (its own message), which
    # makes the two layers separately killable.
    ("grant_after_seal_allowed",
     "        if self._config_sealed:\n            raise CatalogError(\"configuration is sealed; no grants after seal\")",
     "        if False:\n            raise CatalogError(\"configuration is sealed; no grants after seal\")",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_broker_refuses_a_post_seal_grant_at_its_own_boundary",)),
    # issue_credential must be refused after seal.
    ("issue_after_seal_allowed",
     "        if self._config_sealed:\n            raise CatalogError(\"configuration is sealed; no credential issuance after seal\")",
     "        if False:\n            raise CatalogError(\"configuration is sealed; no credential issuance after seal\")",
     "capcore/broker.py"),
    ("mint_allows_unsealed_catalog",
     "        if not self._config_sealed:\n            self._record(\"-\", None, action, False, \"configuration not sealed\")\n            raise MintRefused(MintRefusal.CATALOG_NOT_SEALED, \"configuration is not sealed\")",
     "        if False:\n            self._record(\"-\", None, action, False, \"configuration not sealed\")\n            raise MintRefused(MintRefusal.CATALOG_NOT_SEALED, \"configuration is not sealed\")",
     "capcore/broker.py"),
    # Sealing must actually block registration. If seal() is a no-op, the
    # lifecycle guarantee is void.
    # R9-F4. "Sealed" must mean sealed. The broker retains a caller-supplied policy
    # BY REFERENCE (the supported public constructor arg), so a broker-side flag
    # alone left the policy's own public grant() working after the seal, and the
    # late grant still minted. The object a caller can still hold is the object
    # that has to refuse.
    ("policy_seal_not_propagated",
     "        self._catalog.seal()\n        self._policy.seal()",
     "        self._catalog.seal()\n        pass  # BUG: seal the catalog but not the policy",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_retained_policy_reference_cannot_grant_after_seal",)),
    # And the policy's own refusal must actually refuse. A seal() that sets the
    # flag while grant() ignores it is the same hole with extra ceremony.
    ("sealed_policy_still_grants",
     "            if self._sealed:\n                raise CatalogError(\"tool policy is sealed; no grants after seal\")",
     "            if False:  # BUG: sealed policy accepts grants anyway\n                raise CatalogError(\"tool policy is sealed; no grants after seal\")",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_retained_policy_reference_cannot_grant_after_seal",
      "capcore/tests/test_review9_hardening.py::test_policy_seal_is_idempotent")),
    # The seal must FREEZE the policy, not empty it: grants made before the seal
    # must survive it. A seal that discards them fails closed on everything, which
    # is not a fix, it is a different bug.
    ("policy_seal_discards_grants",
     "    def seal(self) -> None:\n        \"\"\"Freeze the policy. Idempotent: a seal is a STATE, not an event, so\n        sealing an already-sealed policy is not an error.\"\"\"\n        with self._lock:\n            self._sealed = True",
     "    def seal(self) -> None:\n        \"\"\"Freeze the policy. Idempotent: a seal is a STATE, not an event, so\n        sealing an already-sealed policy is not an error.\"\"\"\n        with self._lock:\n            self._grants = []  # BUG: seal empties the policy\n            self._sealed = True",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_grants_made_before_seal_still_work",)),
    # Anchored on the catalog's seal SIGNATURE, not just its body: Review 9 gave
    # ToolPolicy a seal() with an identical body, so a body-only anchor matched
    # twice and check_stale (correctly) flagged it stale. The two seals are
    # different invariants and need different mutations.
    ("catalog_seal_is_noop",
     "    def seal(self) -> None:\n        with self._lock:\n            self._sealed = True",
     "    def seal(self) -> None:\n        with self._lock:\n            self._sealed = self._sealed  # BUG: seal does nothing",
     "capcore/broker.py"),
    ("redemption_ignores_tool_generation",
     "            if reg is None or gen != rec.tool_generation:",
     "            if reg is None:  # BUG: same-version swap inherits authorization",
     "capcore/broker.py"),
    # An injected vault must share the broker clock. Removing the identity check
    # reintroduces the clock-domain split (rewriting or ignoring the mismatch).
    # R9-F5. The clock's OUTPUT is security-load-bearing, not just its identity.
    # Round 6 rejected non-finite TTL VALUES; a non-finite time SOURCE turns a
    # finite TTL into a non-expiring control. NaN and inf fail differently and
    # neither is safe: NaN makes every comparison False (nothing ever expires),
    # while inf makes `now >= expires_at` True (authorization fails closed, by
    # luck) but `inf - inf` NaN (credential TTL never fires). Reject both.
    ("clock_finiteness_unchecked",
     "    if not math.isfinite(value):\n        raise ClockError(\"clock returned non-finite time\")",
     "    if False:  # BUG: a NaN or inf clock disables every expiry\n        raise ClockError(\"clock returned non-finite time\")",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_nan_clock_fails_closed_at_mint",
      "capcore/tests/test_review9_hardening.py::test_infinite_clock_does_not_disable_credential_ttl")),
    # A clock returning a str makes every comparison a TypeError deep inside
    # redemption, with a live credential already in play. Fail at the READ.
    ("clock_type_unchecked",
     "    if type(value) not in (int, float):\n        raise ClockError(\"clock must return a number\")",
     "    if False:  # BUG: trust whatever the clock returned\n        raise ClockError(\"clock must return a number\")",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_non_numeric_clock_is_rejected",)),
    # Clock is DOCUMENTED as monotonic and was never checked. A clock that moves
    # backward extends every authorization and credential lifetime even when all
    # its values are finite.
    ("clock_monotonicity_unchecked",
     "            if self._high_water is not None and value < self._high_water:\n                raise ClockError(\"clock moved backward; time source is not monotonic\")",
     "            if False:  # BUG: time may run backward, extending every lifetime\n                raise ClockError(\"clock moved backward; time source is not monotonic\")",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_backward_clock_is_rejected",)),
    # The wrapper must actually be installed. An unwrapped clock is an unchecked
    # clock, and every read below it bypasses validation.
    ("broker_clock_not_wrapped",
     "        self._clock = MonotonicClock(raw_clock)",
     "        self._clock = raw_clock  # BUG: reads bypass validation entirely",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_nan_clock_fails_closed_at_mint",
      "capcore/tests/test_review9_hardening.py::test_backward_clock_is_rejected")),
    # A clock failure must be an HONEST TERMINAL STATE, not an escaping exception.
    # Nothing executing is necessary but not sufficient: the run must say why.
    ("clock_error_escapes_as_crash",
     "        except ClockError as exc:\n            self._record(\"-\", None, action, False, \"clock unusable\")\n            raise MintRefused(MintRefusal.CLOCK_UNUSABLE, \"clock unusable\") from exc",
     "        except ClockError:\n            raise  # BUG: crash into the engine instead of a typed refusal",
     "capcore/broker.py",
     ("capcore/tests/test_review9_hardening.py::test_clock_failure_is_an_honest_outcome_not_a_crash",)),
    # Re-anchored (Review 9 F5): the broker now wraps its clock in MonotonicClock,
    # so a caller cannot hold the broker's exact clock object and identity is checked
    # against the UNDERLYING source instead. The Review 8 invariant is unchanged
    # (vault and broker must share ONE clock domain); only the comparison moved.
    ("injected_vault_clock_not_checked",
     "            if underlying is not raw_clock:\n                raise ValueError(",
     "            if False:  # BUG: accept a vault from a different clock domain\n                raise ValueError(",
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
    # The credentialed transport must stream and not buffer the body. Reverting to
    # a buffered read reintroduces the unbounded-memory defect.
    ("real_transport_buffers_body",
     "    with requests.request(method, url, headers=headers, timeout=30,\n                          allow_redirects=False, stream=True) as response:\n        return {\"status\": response.status_code}",
     "    response = requests.request(method, url, headers=headers, timeout=30,\n                          allow_redirects=False)\n    return {\"status\": response.status_code, \"body\": response.text}",
     "capcore/httptool.py"),
    # R9-F1. The remote endpoint picks the status code. Treating every status as
    # success lets an UNTRUSTED party choose the runtime's terminal state: a 500,
    # a 403, or an unfollowed 302 all reported EXECUTED, i.e. "the action
    # happened", when it demonstrably did not.
    ("http_non_success_status_reported_as_executed",
     "        if not self._is_success(status):",
     "        if False:  # BUG: any status is a successful execution",
     "capcore/httptool.py",
     ("capcore/tests/test_review9_hardening.py::test_http_500_is_not_reported_as_executed",
      "capcore/tests/test_review9_hardening.py::test_http_302_is_not_reported_as_executed")),
    # 2xx-and-only-2xx is the DEFAULT accepted range. Widening it to "whatever the
    # endpoint says" is the same defect wearing a different hat.
    ("http_accepted_status_range_widened",
     "            return 200 <= status < 300",
     "            return True  # BUG: every status counts as success",
     "capcore/httptool.py",
     ("capcore/tests/test_review9_hardening.py::test_http_500_is_not_reported_as_executed",
      "capcore/tests/test_review9_hardening.py::test_http_2xx_is_reported_as_executed")),
    # A transport that cannot even say what happened has not established that the
    # action occurred. A non-int status must fail closed, not fall through.
    ("http_invalid_status_type_not_rejected",
     "        if type(status) is not int or isinstance(status, bool):",
     "        if False:  # BUG: trust whatever the transport returned",
     "capcore/httptool.py",
     ("capcore/tests/test_review9_hardening.py::test_non_integer_status_is_not_reported_as_executed",)),
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
