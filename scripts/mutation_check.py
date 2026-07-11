#!/usr/bin/env python3
"""Reproducible mutation check for capcore.

For each known defect, this reintroduces the bug into a COPY of capcore/__init__.py,
runs the test suite against the mutated copy, and asserts the suite FAILS. Then it
restores the original and confirms the suite passes. If any mutation is NOT caught
(suite still passes with the bug present), that mutation is reported as a survivor
and the script exits non-zero.

This makes the "mutation-tested" claim in MODEL.md reproducible: run
    python scripts/mutation_check.py
and every listed defect must be caught.

Each mutation is a (find, replace) pair applied to the source text. `find` must
be present exactly once; if it is not, the mutation is reported as stale (the
code changed and the mutation needs updating) rather than silently skipped.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORE = ROOT / "capcore" / "__init__.py"

# Each mutation: name, the exact source snippet to remove/replace, replacement.
# Removing or neutralizing each should make at least one test fail.
MUTATIONS = [
    (
        "identity_from_untrusted_resource",
        "        tenant = ctx.tenant                 # TRUSTED. Not from proposal.",
        "        tenant = proposal.resource.split('/')[0]  # BUG: identity from proposal",
    ),
    (
        "attenuation_action_subset_removed",
        "        if not child.actions <= parent.actions:",
        "        if False:  # BUG: skip action-subset check",
    ),
    (
        "revoked_parent_derivation_allowed",
        '        if self.is_revoked(parent_id):\n'
        '            return DeriveResult(ok=False, reason="parent is revoked")\n',
        "",
    ),
    (
        "issue_root_accepts_child_shaped",
        '        if cap.parent is not None:\n'
        '            raise StoreError(\n'
        '                "root capability must not specify a parent; use derive_child()")\n',
        "",
    ),
    (
        "resource_traversal_allowed",
        '        if s in (".", ".."):\n'
        '            raise ResourceError("\'.\' and \'..\' segments not allowed (path traversal)")\n',
        "",
    ),
    (
        "explicit_deny_ignored",
        "        if deny_reason:",
        "        if False:  # BUG: ignore platform deny",
    ),
    (
        "model_deny_reason_leaks",
        "        return Decision(self.verdict, self.public_reason, self.public_reason, ())",
        "        return Decision(self.verdict, self.audit_reason, self.audit_reason, self.trace)  # BUG: leak",
    ),
]


def run_suite() -> bool:
    """Return True if the suite passes."""
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--no-header",
         str(ROOT / "capcore" / "tests")],
        cwd=ROOT, capture_output=True, text=True,
    )
    return result.returncode == 0


def main() -> int:
    original = CORE.read_text(encoding="utf-8")
    backup = CORE.with_suffix(".py.mutbak")
    shutil.copy2(CORE, backup)

    survivors = []
    stale = []
    try:
        # sanity: unmutated suite must pass
        if not run_suite():
            print("ABORT: suite does not pass on unmutated source", file=sys.stderr)
            return 2

        for name, find, replace in MUTATIONS:
            count = original.count(find)
            if count != 1:
                stale.append((name, count))
                print(f"[stale]   {name}: anchor found {count} times (expected 1)")
                continue
            CORE.write_text(original.replace(find, replace, 1), encoding="utf-8")
            caught = not run_suite()
            CORE.write_text(original, encoding="utf-8")  # restore between each
            if caught:
                print(f"[caught]  {name}")
            else:
                survivors.append(name)
                print(f"[SURVIVED]{name}  <-- mutation not detected by any test")
    finally:
        CORE.write_text(original, encoding="utf-8")
        backup.unlink(missing_ok=True)

    print()
    if stale:
        print(f"{len(stale)} stale mutation(s): anchors no longer match the source.")
    if survivors:
        print(f"FAIL: {len(survivors)} mutation(s) survived: {', '.join(survivors)}")
        return 1
    if stale:
        print("All applicable mutations caught, but stale anchors need updating.")
        return 3
    print(f"OK: all {len(MUTATIONS)} mutations caught by the test suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
