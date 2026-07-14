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
| Approval workflow | **Classification implemented**; pause/approve/resume designed, not implemented |
| Cascade revocation | **Not implemented.** Deliberate deferral |
| Adapter isolation | **Not implemented** |

"Single-process trust model" is load-bearing, not a hedge. See
[Trust model](#trust-model).

332 tests pass. `python scripts/mutation_check.py` reintroduces 103 known defects
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

CapCore's current implementation uses a **single-process Python trust model**.

All Python code executed inside the runtime process is part of the trusted
computing base, including `ModelClient` implementations, plain and credentialed
tool adapters, hooks, clocks, policies, catalogs, vaults, and other injected
callbacks. Python objects and immutability controls can prevent accidental misuse
through documented interfaces, but they do not isolate malicious code running in
the same interpreter.

The untrusted boundary applies to **data** crossing into trusted runtime code,
including remote model responses, model-generated proposals, tool results, user
content, and responses from remote services. These values are validated and
authorized before they can influence trusted execution or create external effects.

Running model adapters or tool plugins as genuinely untrusted code requires a
process or stronger isolation boundary with restricted IPC. That isolation is not
implemented in the current release and is a future design objective.

### Why the boundary is drawn at data, not code

There is no in-process Python mechanism that makes arbitrary same-interpreter code
untrusted. A hostile callback can walk the call stack
(`inspect.currentframe().f_back`), traverse the object graph
(`gc.get_referrers`), or monkeypatch, and from there reach the engine, the broker,
the vault, and the live `RunRecord`, regardless of any frozen dataclass or
"immutable" view. So the honest line is: the *code* on the runtime's side of the
boundary is trusted, and the *data* that crosses it is not.

That is a narrower claim than an earlier version of this document made (it
classified `ModelClient` implementations as untrusted, which a single-process
architecture cannot enforce). The narrowing is deliberate: the earlier statement
was technically false, and a defensible boundary is worth more than an impressive
one.

What the architecture *does* enforce, against untrusted data, is the whole point
of the rest of this document: a proposal cannot forge an authorization, name an
executor it may not use, replay a credential, or outrun its budget, because those
are decided by trusted code checking untrusted values, never by trusting the
values themselves.

### Credentialed adapters

A credentialed adapter receives a real secret in order to use it, and could log
it, retain it, or send it elsewhere. Under the single-process model above it is
trusted code, like every other in-process component. The broker keeps the secret
away from the *engine* and the *model*, and contains it against accidental leakage
(exceptions, logs), but it cannot contain a hostile adapter. Real containment is
the same process-isolation objective named above.

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

## Broker hardening

Several properties are enforced at the broker that are easy to get subtly wrong:

- **Tool results are inert.** An adapter's return value is untrusted and crosses
  into trusted run state (`RunRecord.history`, then `ModelView`). Only a bounded
  `str` (or `None`) is stored; a dict, list, or object is rejected
  (`invalid_tool_result`), so the model cannot receive a mutable handle into
  trusted history.
- **Security time is broker-owned.** The broker holds a `Clock` (injected at
  construction; `SystemClock` in production, `FakeClock` in tests). Production
  methods do NOT accept a caller-supplied `now`: an earlier version did, which
  let a caller mint a far-future expiry or make an expired authorization look
  current. Credential issue-time is stamped by the vault from the same clock, so
  a TTL cannot be backdated.
- **Tool binding is by catalog generation, not a version string.** The catalog
  owns a monotonic generation the caller cannot forge. A tool replaced after an
  authorization is minted, even under the same id and the same `version` string,
  gets a new generation, and redemption refuses it.
- **Credentials carry no unenforced binding.** There is deliberately no
  `capability_id` on a credential. Under current-authority semantics the
  credential is constrained by verb, scope, TTL, single-use state, tool binding,
  and live re-authorization; a `capability_id` the broker never checked would be
  a false claim of exact-capability binding, so it was removed.
- **Redemption is synchronized.** The `PENDING -> EXECUTING` transition and
  single-use credential consumption are each lock-guarded, so concurrent
  redemptions cannot both succeed. On stock CPython the GIL masks the race, but
  atomicity is now a property of the code, not the interpreter, and holds under
  free-threaded builds.

## Isolation of trusted state from callers

Several round-4 hardening properties close aliasing and validation gaps:

- **Stored credentials are vault-owned copies.** `issue_credential` copies the
  caller's values (including a fresh copy of the secret value) into an immutable
  `_StoredCredential`; consumption is tracked in a vault-owned set. A caller who
  retains a reference to the original `Credential` and mutates it, widening scope,
  resetting single-use, backdating the TTL, or swapping `secret._value`, changes
  nothing the broker reads.
- **Engine authority derives from the broker.** The engine takes its monitor and
  store from `broker.monitor`, so engine and broker cannot authorize against
  different stores (split authority, which would let a revoke through one be a
  no-op for the other).
- **Malformed model results fail closed.** `run()` validates that a `PROPOSAL`
  result carries an actual `ExecutionProposal` at the boundary, not only in
  `ModelResult.__post_init__` (a hostile adapter can bypass a constructor). A
  malformed result yields `RunState.FAILED`, never an escaped exception.
- **Tool results must be exact built-in `str`.** A `str` subclass could override
  `encode()` to beat the size cap and carry mutable state into trusted history, so
  the check is `type(out) is str`, not `isinstance`.
- **Action budget and loop ceiling are separate.** `Budget(max_actions=...,
  max_iterations=...)`: `max_iterations` is the unconditional liveness bound,
  `max_actions` is the execution budget. `Budget(n)` still sets both to n.
- **Refusals are classified honestly.** The model sees a generic
  `authorization_refused`; trusted history records the specific reason. Only a
  live capability re-authorization failure is a `REVOKED_RACE`; an expired or
  consumed credential, a scope/verb mismatch, or a tool-generation change are
  distinct `StepOutcome`s.
- **Action-id collisions fail closed.** A duplicate pending-authorization id
  cannot overwrite an existing record; minting retries with a fresh id.

## Untrusted input boundaries

Round-5 hardening tightens what crosses the untrusted-data boundary:

- **Untrusted fields are size-bounded.** A remote model can return oversized
  ordinary JSON strings; resource (4 KiB), path segment (255 B), verb (64 B), and
  tool-registration id (128 B) are bounded in bytes before validation, hashing,
  audit, or history. This is the one round-5 defect reachable from the real
  adversary (remote model output), not just in-process code.
- **Proposal fields require exact built-in types.** `type(x) is str`, not
  `isinstance`, at the action boundary. A `str` subclass can override
  `split()`/`__str__()`/`encode()` so authorization validates one value while the
  adapter receives another; exact types close that divergence, matching the rule
  already enforced on tool results.
- **Unknown model outcomes fail closed.** `run()` handles the outcome algebra
  with an explicit `else` that fails to `MODEL_ERROR`; an outcome outside
  ERROR/FINISHED/LIMIT_REACHED/PROPOSAL never falls through to execute.
- **The action budget counts execution, not denial.** With
  `count_denied_attempts=False`, a broker refusal (unknown or unauthorized tool,
  nothing executed) does not consume `max_actions`; the count happens only after
  the broker mints an authorization.
- **Refusals are typed, not string-parsed.** The broker reports a specific
  `BrokerRefusal` code (an expired pending authorization, an unknown id, a
  credential mismatch); the engine maps by code. `REVOKED_RACE` is reserved for a
  genuine live re-authorization failure; every other refusal is a distinct,
  honestly-labeled outcome.

The exact-type and unknown-outcome changes are boundary-consistency and
fail-closed-completeness properties: under the single-process trust model they
require in-process (TCB) code to trigger, but the runtime documents proposal data
as untrusted and enforces the invariant uniformly. The size limits are the one
directly reachable from untrusted remote output.

## Malformed-input and lifecycle hardening

Round-6 hardening closes boundary and correctness gaps:

- **Malformed unicode fails closed.** A lone surrogate is a valid Python str that
  JSON accepts but cannot be utf-8 encoded. Every untrusted-text boundary uses a
  fail-closed `utf8_length` (returns None instead of raising), so a malformed
  resource/verb/tool-id/tool-result DENIES deterministically rather than raising,
  preserving M1's valid|invalid contract. Reachable from remote model output.
- **Invalid proposals never enter trusted history.** An oversized or malformed
  action is rejected at the runtime boundary before it can reach `StepResult`,
  `ModelView`, or the next prompt. It fails as `MODEL_ERROR` (a model error, not a
  policy DENY) and retains no raw field. Reachable from remote model output.
- **Raw provider responses are bounded.** `parse_proposal` caps raw text before
  parsing, and the live transport streams with a `bounded_read` that limits by
  bytes ACTUALLY READ (not a Content-Length header a hostile provider can lie
  about). Two limits: HTTP body and generated text. Reachable from remote output.
- **The tool catalog is read atomically and sealed explicitly.** Mint and redeem
  read the registration and its generation as one locked `snapshot()`, closing a
  split-read race. The catalog must be `seal()`-ed before execution
  (register -> grant -> seal -> execute); the broker refuses to mint against an
  unsealed catalog, so configuration state is visible, not silently defaulted.
- **Mint refusals are typed.** The broker raises a `MintRefused` carrying a
  `MintRefusal` code; the engine maps by code, never by parsing exception text.
  `REVOKED_RACE` is reserved for a genuine authorization loss between propose and
  mint; an unknown tool, unsealed catalog, or id exhaustion each map to their own
  honest outcome.
- **TTLs reject non-finite and non-numeric values.** `nan`/`inf` (which the old
  `<= 0` guard let through as "never expires") and `bool` are rejected; only a
  strictly-positive finite number is a valid TTL.

The last three (catalog, mint refusals, TTLs) are correctness controls that
require in-process TCB behaviour or malformed trusted configuration to trigger;
the first three are reachable from ordinary untrusted provider data.

## Boundary completeness

Round-7 hardening closes three cases where a Round-6 fix was applied at one entry
point but a second path to the same trusted operation was left open:

- **`step()` validates by construction.** `run()` validated the action, but
  `step()` is the public, history-writing boundary. It now validates the proposal
  type and the action (size, unicode, canonical form) BEFORE the budget check, so
  a malformed action never enters trusted history, not even via a
  `BUDGET_EXHAUSTED` result, and only a redacted stand-in is retained.
- **One parse path for model output.** Proposals and the completion signal both
  pass a single `parse_model_output` gate (size + utf-8 first). The separate
  `_signals_done` parser is gone, so an oversized or malformed-unicode
  `{"done": true}` can no longer be accepted as completion after the proposal
  path rejected it.
- **Strict provider decoding and cleanup.** The live transport decodes with
  strict utf-8 (no `errors="replace"` silently repairing malformed bytes), rejects
  a response that is not a JSON object or whose `response` field is not an exact
  string (`ProviderProtocolError`), and reads the response inside a context
  manager so the connection closes on every exit path.

## Untrusted-transport and configuration-integrity hardening

Round-8 hardening closes five issues, only the first reachable from an untrusted
remote service:

- **The credentialed HTTP transport is bounded.** The live transport streams,
  never reads the response body (the tool uses only the status), and closes the
  response via a context manager. A hostile allowed endpoint can no longer force
  unbounded memory allocation in the credentialed path. (High, remote-reachable.)
- **Model-output parsing is total.** `parse_model_output` never raises: a
  non-string, oversized, malformed, or excessively nested input becomes a typed
  INVALID result instead of an escaping exception. Nesting is capped
  (`MAX_JSON_NESTING`, 16) by a string-aware scanner BEFORE decoding, on both the
  model-output candidate and the provider envelope. The cap, not `except
  RecursionError`, is the control: CPython 3.11-3.13 raise RecursionError at depth
  10000 while 3.14 simply PARSES it, so the exception is a property of the
  interpreter, not of the input.
- **A non-success HTTP status is a tool failure, not an execution.** Only an
  accepted status (2xx by default, or an explicit `accepted_statuses`) reports
  EXECUTED. A 500, a 403, or an unfollowed 302 is a sanitized TOOL_ERROR. The
  status is chosen by the remote endpoint, so treating any status as success let an
  untrusted party select the runtime's terminal state. (High, remote-reachable.)
- **What `max_actions` bounds depends on the mode, and the gate is ordered
  accordingly.** With `count_denied_attempts=True` it is an ATTEMPT budget, checked
  BEFORE authorization. With `count_denied_attempts=False` it is an EXECUTION
  budget, checked AFTER, so an out-of-scope proposal is DENIED (its honest M1
  classification), not BUDGET_EXHAUSTED, even when the budget is spent. Applying one
  ordering to both modes silently disabled the attempt budget, which is why they are
  now deliberately different.
- **Sealing seals every object you can still be holding.** `seal_configuration()`
  freezes the catalog, the tool policy, AND the credential vault, each through its
  own `seal()`, never by a broker-side flag. The broker accepts caller-supplied
  catalog, policy, and vault objects and RETAINS those references, so a flag alone
  left the caller's own `policy.grant()` and `vault.issue()` working after the seal,
  and the late grant or credential still reached an adapter. Review 9 established
  this for the policy and missed the vault; Review 10 closed it. The seal also
  VALIDATES the configuration first: every credentialed registration must name a
  credential the vault actually holds, which `register_tool` checks but an injected
  prepopulated catalog bypassed. In-process TCB code can still mutate private state;
  the claim is the narrower, honest one: the SUPPORTED PUBLIC API cannot change the
  configuration after the seal.
- **An injected vault must use the broker's EXACT clock, and be empty.** Not "a clock
  in the same domain", and emphatically not "an object with a `_clock` attribute
  pointing at the same source". Review 9 tried the latter and it was wrong: that is a
  duck-type test, and any wrapper satisfies it while returning entirely different time
  (offset, scale, cache, re-epoch), which fully reopened the clock-domain split it was
  meant to close. Sameness is proven, never inferred. The broker's wrapped clock does
  not exist until the broker does, so a vault holding it cannot have issued anything
  beforehand: a prepopulated injected vault is refused rather than accepted and
  silently rebound.
- **Security time is validated at the read AND at the derivation.** Every read goes
  through `checked_now` (non-numeric and non-finite refused) inside `MonotonicClock`,
  which enforces the monotonic contract the `Clock` protocol has always documented and
  reads under its own lock, so concurrent reads are one linearized sequence rather than
  racing observations. Every derived expiry goes through `checked_expiry`, because
  validating the OPERANDS is not validating the value the comparison actually uses:
  `1e308 + 1e308` is `inf` from two finite operands, and no finite clock reading can
  ever reach `inf`, so the authorization would never expire. A clock or expiry failure
  is a typed refusal (`MintRefusal.CLOCK_UNUSABLE`), not a crash.
- **Configuration types are exact.** `bool` is an `int` subclass, so
  `Budget(max_actions=True)` was silently the budget `1`, and
  `count_denied_attempts="false"` is TRUTHY, so a plausible typo selected the OPPOSITE
  budget mode. Tool ids must match an anchored slug grammar, enforced identically at
  registration (trusted config) and in a proposal (untrusted model output), so the
  catalog's accept-set and the JSON parser's cannot drift apart.

## Terminal state is honest

A run that fails does not report success. `RunRecord.stop_reason` says why a run
ended: `MODEL_FINISHED`, `BUDGET_EXHAUSTED`, `CEILING_REACHED`, `MODEL_ERROR`,
`PROVIDER_UNAVAILABLE`, `TOOL_FAILED`, `ADAPTER_LIMIT_REACHED` (the adapter hit
its own cap; not a task completion),
`PROVIDER_UNAVAILABLE`, `TOOL_FAILED`.

Previously `None` from a `ModelClient` meant both "I am done" and "my provider is
down", so a run against a dead Ollama server reported `COMPLETED` with zero actions
taken. `ModelResult` now forces the adapter to say which.

## What's open

- **Approval is classification, not yet a workflow.** Approval *classification* is
  implemented: the engine classifies an action as requiring approval and does not
  execute it. Persistent pause, authenticated approval, reauthorization, and
  resume are *designed but not implemented*.
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
- `scripts/mutation_check.py` - reintroduces 103 known defects; asserts the suite
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
