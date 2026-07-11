# capcore - M1 capability core

[![CI](https://github.com/tgandhle/capcore-m1/actions/workflows/ci.yml/badge.svg)](https://github.com/tgandhle/capcore-m1/actions/workflows/ci.yml)

**Status: Partial.** The trusted authorization decision path for a
capability-enforced agent runtime. Given a trusted `RunContext` (identity) and an
untrusted model `Proposal`, the `ReferenceMonitor` returns ALLOW /
REQUIRE_APPROVAL / DENY. Deny is the default.

This is M1 of the milestone plan: the capability core against a hostile-model
attacker (the model emits arbitrary proposed actions, attempting tenant escape,
over-attenuation, prefix confusion, and use of revoked or forged capabilities).
No LLM, tools, execution loop, or audit chain yet.

## Install and test

```
python -m venv .venv
# Windows:      .\.venv\Scripts\Activate.ps1
# macOS/Linux:  source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[test]"
pytest
```

Editable install means imports resolve regardless of working directory. 27 tests
should pass. Run `python scripts/mutation_check.py` to confirm the suite catches
the known defects (it mutates a temporary copy, never your working tree).

## What's here

- `capcore/__init__.py` - the core: `Capability`, `CapabilityStore` (issue,
  validated `derive_child`, revoke), `ReferenceMonitor`, `Decision`, policy types.
- `capcore/tests/test_properties.py` - property-based + enumeration tests for the
  M1 invariants. See MODEL.md for the proof-vs-evidence split.
- `capcore/tests/test_security_regressions.py` - pinned fixes for defects found
  in review (deny-reason leak, derivation-from-revoked-parent).
- `capcore/tests/test_scenario.py` - the six cases the browser demo represents,
  asserted against the Python core. This executes only Python, so it pins the
  Python outcomes the demo shows; it does not run the demo's JavaScript.
  Preventing true Python/JS drift needs the JS core run under Node in CI against
  shared fixtures (a known next step).
- `scripts/mutation_check.py` - reintroduces each known defect and asserts the
  suite catches it; reproduces the mutation results in MODEL.md.
- `capcore/MODEL.md` - semantics, test regime, mutation results, open decisions.

## Honest scope

MODEL.md records what is implemented and what is designed-but-not-implemented
(principal/run binding, cascade revocation, canonical resources). The status
stays Partial until the full M1 milestone is complete. A passing suite means the
core resists the specific attacks it is tested against, not all attacks.

Pairs with the browser demo (`reference-monitor-demo.html`), a browser
visualization of the same intended authorization scenarios. The demo's
JavaScript core mirrors the Python semantics but is not yet executed by an
automated parity test (a Node-based parity check is a known next step).
