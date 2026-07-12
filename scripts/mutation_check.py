#!/usr/bin/env python3
"""Reproducible, crash-safe, reliable mutation check for capcore.

For each known defect, this reintroduces the bug into a FRESH TEMPORARY COPY of
the package (never the live source), runs the test suite against that copy, and
asserts the suite FAILS. If any mutation is not caught, it is a survivor and the
script exits non-zero.

Reliability properties:
  - The live working tree is never modified (crash-safe): all mutation happens
    in throwaway temp dirs that are deleted afterward. Interrupt/timeout/crash
    cannot leave your source mutated.
  - A FRESH temp copy per mutation (no shared bytecode or Hypothesis state
    accumulating across runs, which could wedge the run).
  - PYTHONDONTWRITEBYTECODE and an isolated Hypothesis storage dir per run.
  - A per-mutation subprocess timeout. A timeout is a HARNESS ERROR, not a
    caught mutation, and fails the run.
  - pytest -x stops at the first failing test, so a caught mutation returns fast.

Run:
    python scripts/mutation_check.py
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
# once; otherwise the mutation is reported stale. Covers all 20 documented
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
    ("budget_not_enforced",
     "        if record.steps_taken >= self.budget.max_steps:\n            record.state = RunState.ABORTED\n            res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,",
     "        if False:  # BUG: never enforce budget\n            record.state = RunState.ABORTED\n            res = StepResult(StepOutcome.BUDGET_EXHAUSTED, action,",
     "capcore/runtime.py"),
    # The engine's independent loop ceiling: a hostile model must not be able to
    # produce an unbounded run even if trusted counter state were corrupted.
    ("engine_loop_ceiling_removed",
     "        for _ in range(self.budget.max_steps):",
     "        while True:  # BUG: unbounded loop, no independent ceiling",
     "capcore/runtime.py"),
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
    ("broker_stores_unnormalized_tool_result",
     "    if not isinstance(out, str):\n        return False, None",
     "    if False:\n        return False, None  # BUG: store raw adapter output",
     "capcore/broker.py"),
    # A provider failure must not be reported as a completion. This is the
    # difference between "the work is done" and "nothing happened and we lied".
    ("provider_error_reported_as_completion",
     "            if result.outcome is ModelOutcome.ERROR:\n                record.state = RunState.FAILED",
     "            if result.outcome is ModelOutcome.ERROR:\n                record.state = RunState.COMPLETED  # BUG: failure looks like success",
     "capcore/runtime.py"),
    # An adapter that raises is a failed provider, not a finished one.
    ("model_exception_swallowed_as_completion",
     "                record.state = RunState.FAILED\n                record.stop_reason = StopReason.MODEL_ERROR\n                return record\n\n            if not isinstance(result, ModelResult):",
     "                record.state = RunState.COMPLETED  # BUG: crash looks like success\n                record.stop_reason = StopReason.MODEL_ERROR\n                return record\n\n            if not isinstance(result, ModelResult):",
     "capcore/runtime.py"),
    # OllamaModel must not turn a transport failure into a clean stop.
    ("ollama_error_becomes_finished",
     "            return ModelResult.error()\n\n        proposal = parse_proposal(text)",
     "            return ModelResult.finished()  # BUG: provider failure as completion\n\n        proposal = parse_proposal(text)",
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
    ("broker_ignores_single_use_and_ttl",
     "        if not cred.is_available(now):",
     "        if False:  # BUG: ignore consumed/expired credential",
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


def run_suite(pkg_parent: Path):
    """Run the suite against the copy at pkg_parent. Returns True if it passes.
    Raises HarnessError on timeout (which must not be mistaken for 'caught').
    """
    env = os.environ.copy()
    env["PYTHONPATH"] = str(pkg_parent) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["HYPOTHESIS_STORAGE_DIRECTORY"] = str(pkg_parent / ".hypothesis")
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-m", "pytest", "-x", "-q", "--no-header", "-p", "no:cacheprovider",
             str(pkg_parent / "capcore" / "tests")],
            cwd=pkg_parent, capture_output=True, text=True, env=env,
            timeout=PER_MUTATION_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise HarnessError("pytest exceeded per-mutation timeout")
    return result.returncode == 0


def fresh_copy(dst: Path):
    shutil.copytree(
        ROOT / "capcore", dst / "capcore",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".hypothesis", ".pytest_cache"),
    )


def main() -> int:
    original = (ROOT / CORE_REL).read_text(encoding="utf-8")

    # baseline: a fresh unmutated copy must pass
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

    survivors, stale, errors = [], [], []
    # cache source of each target file we mutate
    src_cache: dict[str, str] = {}
    for mut in MUTATIONS:
        name, find, replace = mut[0], mut[1], mut[2]
        target_rel = Path(mut[3]) if len(mut) > 3 else CORE_REL
        key = str(target_rel)
        if key not in src_cache:
            src_cache[key] = (ROOT / target_rel).read_text(encoding="utf-8")
        target_src = src_cache[key]
        if target_src.count(find) != 1:
            stale.append(name)
            print(f"[stale]   {name}: anchor found {target_src.count(find)} times (expected 1)")
            continue
        # a FRESH copy per mutation: no shared state between mutants
        with tempfile.TemporaryDirectory(prefix=f"capcore-mut-{name}-") as td:
            tmp = Path(td)
            fresh_copy(tmp)
            (tmp / target_rel).write_text(target_src.replace(find, replace, 1), encoding="utf-8")
            try:
                caught = not run_suite(tmp)
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
    if stale:
        print(f"{len(stale)} stale mutation(s): {', '.join(stale)}")
    if errors:
        print(f"FAIL: {len(errors)} mutation(s) errored (timeout/harness): {', '.join(errors)}")
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
