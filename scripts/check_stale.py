"""Fast stale-anchor check: no tests run, just verifies each mutation's find-text
matches its target file exactly once. Prints any stale mutation instantly."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check as mc

ROOT = Path(__file__).resolve().parent.parent
CORE_REL = "capcore/__init__.py"

stale = []
for mut in mc.MUTATIONS:
    name, find = mut[0], mut[1]
    target = mut[3] if len(mut) > 3 and mut[3] else CORE_REL
    src = (ROOT / target).read_text(encoding="utf-8")
    n = src.count(find)
    if n != 1:
        stale.append((name, target, n))
        print(f"STALE: {name}  ({target}) -> anchor found {n} times (expected 1)")

if not stale:
    print(f"OK: all {len(mc.MUTATIONS)} mutation anchors match exactly once.")
    sys.exit(0)
print(f"\n{len(stale)} stale mutation(s).")
sys.exit(3)
