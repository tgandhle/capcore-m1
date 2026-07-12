# capcore

[![CI](https://github.com/tgandhle/capcore-m1/actions/workflows/ci.yml/badge.svg)](https://github.com/tgandhle/capcore-m1/actions/workflows/ci.yml)

A capability-enforced agent runtime. The thesis: **an LLM agent's authority should
be enforced by deterministic runtime policy outside the model, not by the model's
cooperation.** A hostile model is the design assumption, not an edge case.

Three layers, each with its own trust boundary:

- **M1, the capability core** (`capcore/__init__.py`). A reference monitor. Given
  a trusted `RunContext` (identity) and an untrusted `Proposal` (verb + resource),
  it returns ALLOW / REQUIRE_APPROVAL / DENY. Deny is the default.
- **M2, the execution loop** (`capcore/runtime.py`). Drives a run through a
  trusted state machine, enforces budgets, and hands authorized actions to the
  broker. The model sees an immutable, redacted `ModelView`, never trusted state.
- **M3, the trusted execution broker** (`capcore/broker.py`). Owns the tool
  catalog, tool policy, pending authorizations, and credentials. It **executes**
  tools inside its own boundary and returns sanitized results. It does not hand
  secrets to anyone.

## Status

| Component | Status |
|---|---|
| M1 capability core | **Implemented**, within documented scope |
| M2 execution loop | **Implemented**, single-process trust model |
| M3 trusted execution broker | **Implemented**, single-process trust model |
| Approval workflow | **Classification only** |
| Cascade revocation | **Not implemented.** Deliberate deferral |
| Adapter isolation | **Not implemented** |

"Single-process trust model" is load-bearing, not a hedge. See
[Trust model](#trust-model).

163 tests pass. `python scripts/mutation_check.py` reintroduces 30 known defects
one at a time and asserts the suite catches every one (it mutates a temporary
copy, never your working tree). CI runs Python 3.11-3.13 on Ubuntu and Windows.

## Install and test

```
python -m venv .venv
# Windows:      .\.venv\Scripts\Activate.ps1
# macOS/Linux:  source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[test]"
pytest
python scripts/mutation_check.py
```

## Trust model

This is the part worth reading. Everything else follows from it.

**Untrusted**, assumed hostile:

- the model provider and its output
- the `ModelClient` implementation (it wraps an untrusted provider)
- every proposal, including the **executor the model names**
- tool results and remote services

**Trusted** (the TCB):

- the reference monitor and the capability store
- run state (`RunRecord`), which the model never receives
- the trusted execution broker: catalog, policy, authorization state, credentials
- **credentialed adapters**

### Credentialed adapters are inside the TCB

The broker keeps the credential away from the engine, the model, and general
application code. It **cannot** protect the credential from a malicious
credentialed adapter in the same process: the adapter receives the secret in order
to use it, and could log it, retain it, or send it somewhere else.

So every `CredentialedTool` you write is trusted code. That is acceptable for a
single-process runtime, and it is stated here rather than buried. Real isolation
means running credentialed adapters in a separate process behind restricted IPC,
which is not done.

## How authorization actually works

The broker **redeems** authorizations; it does not **inspect** them.

An earlier version took a caller-supplied `Decision` and checked
`decision.verdict == ALLOW`. That cannot work in Python:
`Decision(Verdict.ALLOW, "authorized")` is one constructor call away, so any
caller could mint an ALLOW and obtain a real secret. Enriching the object does not
help. A frozen dataclass carrying a digest, a version, and an expiry is
integrity-preserving after construction but still not *authentic*, because an
attacker who can call the constructor sets whatever fields the checker wants to
see.

The flow instead:

```
model proposes (action + executor, both untrusted)
  -> engine authorizes the ACTION            (control flow and audit)
  -> broker authorizes INDEPENDENTLY at mint (it accepts no caller Decision)
  -> broker checks the tool's verb matches the action
  -> broker checks ToolPolicy authorizes THIS executor for THIS action
  -> broker stores a PendingAuthorization, returns an opaque random action_id
  -> broker re-authorizes at redemption, immediately before the credential
  -> broker injects the credential, runs the adapter inside its boundary
  -> engine receives a SanitizedToolResult, never a Secret
```

The `action_id` is not the authority. It is a lookup key. The authority is the
broker-held record. This closes:

- **Forgery.** A fabricated authorization has no record; lookup fails.
- **Replay.** Redemption atomically claims PENDING -> EXECUTING. Single-use is a
  state machine, not a deletion.
- **Staleness.** The live monitor re-authorizes before the credential is touched.
- **Substitution.** The caller supplies neither tool nor credential at redemption.
  Both are bound at mint. The record pins registration id **and version**, so a
  tool swapped out after authorization is refused.
- **Mis-routing.** Catalog existence is not authorization. `read_customer_record`
  and `read_payroll_database` may both serve `verb=read`; a model that names its
  own executor must not thereby choose which one runs.

### ToolPolicy is deny-by-default

Registering a tool does **not** authorize it. An empty policy authorizes nothing.
A tool must be explicitly granted for a scope:

```python
broker.register_tool(ToolRegistration(...))        # it exists
broker.grant_tool("read-records", "acme/records")  # ...and may now be used
```

### Re-authorization uses current-authority semantics

At redemption the broker asks: *is this action authorized right now, through any
valid capability path?* If the capability that originally authorized the action is
revoked, but a different valid capability would independently authorize the same
action, redemption **succeeds**.

That is deliberate, and it is the question a revocation check is actually asking.
It is **not** original-capability-continuity. Binding to the exact granting
capability would require the monitor to return granting capability ids, which it
does not.

### One catalog, one store

The engine owns **no** tool registry and holds no adapter, so it cannot dispatch
around the broker. `ExecutionEngine` also derives its capability store from the
monitor rather than taking a second one.

Both are the same lesson: two trusted structures that must be kept in sync will
eventually disagree. An earlier version let the monitor authorize against store A
while `engine.store` pointed at store B, so revoking through `engine.store` was a
silent no-op and the action executed anyway.

## Secrets

`Secret` never renders its value in repr/str/format/logging. But that protects the
**wrapper**: once `.reveal()` is called and the value is interpolated into an
`Authorization` header, the result is an ordinary Python string, and any exception
carrying it carries the credential. A transport raising
`RuntimeError(headers["Authorization"])` is a real leak.

So `.reveal()` is called **only inside the broker's execution boundary**, where
every exception from the adapter is caught and **discarded** (never inspected,
formatted, re-raised, chained, or logged). The failure code returned is a constant,
not derived from the exception.

That is the mechanism, and the claim is no stronger than the mechanism: *secrets
are contained by the broker boundary*, not *secrets never appear in exceptions*.

`HttpTool` destinations are validated at construction: https only, no embedded
userinfo, explicit host allowlist, explicit port policy, redirects disabled (a 3xx
would otherwise re-send the header to an attacker-chosen `Location`).

## Terminal state is honest

A run that fails does not report success. `RunRecord.stop_reason` says why a run
ended: `MODEL_FINISHED`, `BUDGET_EXHAUSTED`, `CEILING_REACHED`, `MODEL_ERROR`,
`PROVIDER_UNAVAILABLE`, `TOOL_FAILED`.

Previously `None` from a `ModelClient` meant both "I am done" and "my provider is
down", so a run against a dead Ollama server reported `COMPLETED` with zero actions
taken. `ModelResult` now forces the adapter to say which.

## What's open

- **Approval is classification, not a workflow.** The engine classifies an action
  as requiring approval and does not execute it. It does not pause the run,
  persist the pending action, accept an approval, reauthorize, or resume.
- **Cascade revocation.** Revoking a parent does not revoke its descendants.
  Deliberate deferral, not an oversight.
- **Adapter isolation.** See the TCB note above.
- **JS/Python parity.** The browser demo (`reference-monitor-demo.html`) mirrors
  the Python semantics but is not executed by an automated parity test. A
  Node-based check against shared fixtures is a known next step.

A passing suite means the core resists the attacks it is tested against, not all
attacks.

## Layout

- `capcore/__init__.py` - M1: `Capability`, `CapabilityStore`, `ReferenceMonitor`,
  `Decision`, policy types.
- `capcore/runtime.py` - M2: `ExecutionEngine`, `RunRecord`, `ModelView`,
  `ModelResult`, `Budget`. Owns no tool catalog.
- `capcore/broker.py` - M3: `TrustedExecutionBroker` and its internals
  (`ToolCatalog`, `ToolPolicy`, `PendingAuthorizationStore`, `CredentialVault`),
  plus `ExecutionProposal`, `Secret`, `SanitizedToolResult`.
- `capcore/httptool.py` - M3: `HttpTool`, a credentialed adapter, plus destination
  validation.
- `capcore/adapters.py` - `OllamaModel` (a real local LLM as an untrusted
  `ModelClient`), `ScriptedModel`, proposal parsing.
- `capcore/MODEL.md` - semantics, test regime, mutation results, open decisions.
- `scripts/mutation_check.py` - reintroduces 30 known defects; asserts the suite
  catches each.
- `scripts/demo_live.py` - a real local LLM driven through the full trusted loop.
- `scripts/demo_live_m3.py` - a real secret over real HTTPS, through the broker.

## Tests

- `test_properties.py` - property-based tests for the M1 invariants.
- `test_security_regressions.py` - pinned fixes for M1 review defects.
- `test_m2_m3_trust_boundaries.py` - the ten adversarial reproductions from the
  M2/M3 review, each of which failed against shipped code before the fix.
- `test_integration_m2_m3.py` - the engine-to-broker chain end to end, including
  the mis-routing defence and the "engine has no tool registry" invariant.
- `test_broker.py`, `test_httptool.py`, `test_runtime.py`, `test_adapters.py`,
  `test_scenario.py`.
