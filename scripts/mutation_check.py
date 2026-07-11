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
# once; otherwise the mutation is reported stale. Covers all 15 documented
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
    for name, find, replace in MUTATIONS:
        if original.count(find) != 1:
            stale.append(name)
            print(f"[stale]   {name}: anchor found {original.count(find)} times (expected 1)")
            continue
        # a FRESH copy per mutation: no shared state between mutants
        with tempfile.TemporaryDirectory(prefix=f"capcore-mut-{name}-") as td:
            tmp = Path(td)
            fresh_copy(tmp)
            (tmp / CORE_REL).write_text(original.replace(find, replace, 1), encoding="utf-8")
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
