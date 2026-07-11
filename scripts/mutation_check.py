#!/usr/bin/env python3
"""Reproducible, crash-safe mutation check for capcore.

For each known defect, this reintroduces the bug into a TEMPORARY COPY of the
package (never the live source), runs the test suite against that copy, and
asserts the suite FAILS. If any mutation is not caught, it is reported as a
survivor and the script exits non-zero.

Crash safety: the live working tree is never modified. All mutation happens
inside a throwaway temp directory that is deleted afterward. An interrupt,
timeout, or crash cannot leave your source mutated. (An earlier version mutated
the live file and relied on a finally block; an interrupt bypassed it and
corrupted the working copy. This version cannot.)

Speed: pytest runs with -x so it stops at the first failing test.

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

# (name, exact source snippet to find, replacement). `find` must occur exactly
# once; otherwise the mutation is reported stale rather than silently skipped.
# Covers all defects claimed in MODEL.md: the original seven plus the four found
# in later hardening review.
MUTATIONS = [
    ("untrusted_identity_from_proposal",
     "        tenant = ctx.tenant                 # TRUSTED. Not from proposal.",
     "        tenant = proposal.resource.split('/')[0]  # BUG"),
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
]


def run_suite(cwd: Path, pkg_parent: Path) -> bool:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(pkg_parent) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-x", "-q", "--no-header",
         str(pkg_parent / "capcore" / "tests")],
        cwd=cwd, capture_output=True, text=True, env=env,
    )
    return result.returncode == 0


def main() -> int:
    original = (ROOT / CORE_REL).read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="capcore-mut-") as td:
        tmp = Path(td)
        shutil.copytree(ROOT / "capcore", tmp / "capcore")
        tmp_core = tmp / CORE_REL

        if not run_suite(tmp, tmp):
            print("ABORT: suite does not pass on the unmutated temp copy", file=sys.stderr)
            return 2

        survivors, stale = [], []
        for name, find, replace in MUTATIONS:
            count = original.count(find)
            if count != 1:
                stale.append((name, count))
                print(f"[stale]   {name}: anchor found {count} times (expected 1)")
                continue
            tmp_core.write_text(original.replace(find, replace, 1), encoding="utf-8")
            caught = not run_suite(tmp, tmp)
            tmp_core.write_text(original, encoding="utf-8")
            if caught:
                print(f"[caught]  {name}")
            else:
                survivors.append(name)
                print(f"[SURVIVED]{name}  <-- not detected by any test")

    print()
    if stale:
        print(f"{len(stale)} stale mutation(s); anchors need updating.")
    if survivors:
        print(f"FAIL: {len(survivors)} mutation(s) survived: {', '.join(survivors)}")
        return 1
    if stale:
        return 3
    print(f"OK: all {len(MUTATIONS)} mutations caught by the test suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
