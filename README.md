# capcore: M1 capability core

**Status: Partial.** The trusted authorization decision path for a
capability-enforced agent runtime. Given a trusted RunContext (identity) and an
untrusted model Proposal, the ReferenceMonitor returns ALLOW /
REQUIRE_APPROVAL / DENY. Deny is the default.

This is M1 of the milestone plan: the capability core against a hostile-model
attacker, no LLM / tools / execution loop / audit chain yet.

## Install and test

Create a virtual environment, install with the test extra, and run pytest:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    pip install -e ".[test]"
    pytest

Editable install means imports resolve regardless of working directory. 21 tests should pass.

## What is here

- capcore/__init__.py: the core. Capability, CapabilityStore (issue, validated derive_child, revoke), ReferenceMonitor, Decision, policy types.
- capcore/tests/test_properties.py: property-based and enumeration tests for the M1 invariants. See MODEL.md for the proof-vs-evidence split.
- capcore/tests/test_security_regressions.py: pinned fixes for defects found in review (deny-reason leak, derivation-from-revoked-parent).
- capcore/tests/test_scenario.py: the six cases the browser demo runs, asserted against this core so the two cannot drift.
- capcore/MODEL.md: semantics, test regime, mutation results, open decisions.

## Honest scope

MODEL.md records what is implemented and what is designed-but-not-implemented (principal/run binding, cascade revocation, canonical resources). The status stays Partial until the full M1 milestone is complete. A passing suite means the core resists the specific attacks it is tested against, not all attacks.

Pairs with the browser demo (reference-monitor-demo.html), the same semantics rendered for viewing.
