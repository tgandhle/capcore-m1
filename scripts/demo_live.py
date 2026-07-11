#!/usr/bin/env python3
"""Live M2 demo: a REAL local LLM (via Ollama) proposes actions, and the trusted
execution engine authorizes, budgets, and contains them.

This is NOT run in CI (it needs a local Ollama server and produces
nondeterministic output). Run it yourself:

    1. Install Ollama from https://ollama.com
    2. ollama pull llama3.2
    3. pip install requests
    4. python scripts/demo_live.py

You will see the local model propose actions and the reference monitor + engine
allow, deny, gate, or budget-abort each one. The model is UNTRUSTED: whatever it
emits is authorized exactly like a scripted proposal. Try prompting it toward
out-of-scope resources and watch them get denied.
"""

import sys
from pathlib import Path

# allow running from repo root without install
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capcore import Capability, CapabilityStore, ReferenceMonitor, RunContext
from capcore.runtime import (
    Budget, ToolRegistry, ExecutionEngine, RunState, StepOutcome,
)
from capcore.adapters import OllamaModel


def build_engine():
    store = CapabilityStore()
    # derivation-only root for the tenant
    store.issue(Capability("root", "acme", "acme/records",
                           frozenset({"read", "send"}),
                           approval_actions=frozenset({"send"}),
                           runtime=False))
    # the live run capability: bound to this principal + run, read + send only,
    # scoped to acme/records/customers
    d = store.derive_child("root", Capability(
        "run-cap", "acme", "acme/records/customers",
        frozenset({"read", "send"}), approval_actions=frozenset({"send"}),
        principal="agent-7", run="run-live"))
    assert d.ok, d.reason

    mon = ReferenceMonitor(store)

    # mock tools (no real network): a read tool that returns canned data
    reg = ToolRegistry()
    reg.register("read", lambda p: f"[data for {p.resource}]")

    engine = ExecutionEngine(mon, store, reg, Budget(max_steps=6))
    ctx = RunContext("acme", "agent-7", "run-live")
    return engine, ctx


def main():
    print("Live M2 demo: local LLM proposing actions into a capability-enforced runtime.")
    print("The run capability grants read+send on acme/records/customers only,")
    print("send is approval-gated, budget is 6 steps.\n")

    engine, ctx = build_engine()
    model = OllamaModel(max_proposals=6)

    try:
        record = engine.run(ctx, model)
    except Exception as e:
        print(f"Run failed to start (is Ollama running? 'ollama pull llama3.2'): {e}")
        return 1

    if not record.history:
        print("The model produced no parseable proposals.")
        print("Check that Ollama is running and the model is pulled.")
        return 1

    for i, step in enumerate(record.history, 1):
        p = step.proposal
        line = f"{i}. {p.verb} {p.resource}  ->  {step.outcome.value}"
        if step.tool_result:
            line += f"   (tool: {step.tool_result})"
        if step.outcome in (StepOutcome.DENIED, StepOutcome.REVOKED_RACE):
            line += f"   [audit: {step.audit_reason}]"
        print(line)

    print(f"\nfinal run state: {record.state.value}, steps taken: {record.steps_taken}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
