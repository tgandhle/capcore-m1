#!/usr/bin/env python3
"""Live M3 demo: a REAL secret and a REAL network call, mediated by the broker.

This is the "real secret + real network" path, kept OUT of the test suite and CI
on purpose: it reads a real token from an environment variable (never committed)
and makes a real HTTPS request. It demonstrates, on real infrastructure, the M3
security property: the broker releases the secret ONLY for the authorized action,
the secret goes ONLY to the allowed endpoint's Authorization header, and it
appears NOWHERE in the model-facing decision or the broker audit.

The endpoint is httpbin.org/bearer, which echoes back the Authorization token it
received, so you can SEE that the secret arrived at the endpoint (and confirm the
runtime, not the model, put it there).

Run:
    pip install -e ".[live]"
    $env:CAPCORE_DEMO_TOKEN = "my-real-or-fake-token"   # PowerShell
    # export CAPCORE_DEMO_TOKEN=my-real-or-fake-token     # bash
    python scripts/demo_live_m3.py

The token you set is sent to httpbin over HTTPS and echoed back, proving
delivery. Use any string; it is a bearer-token demo endpoint, not a real
credential check. The point is to show WHERE the secret goes, not to
authenticate against anything sensitive.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from capcore import Capability, CapabilityStore, ReferenceMonitor, RunContext, Proposal, Verdict
from capcore.broker import (
    Secret, Credential, TrustedExecutionBroker, ToolKind, ToolRegistration,
    ExecutionProposal,
)
from capcore.httptool import HttpTool, real_requests_transport


ALLOWED_URL = "https://httpbin.org/bearer"


def main():
    token = os.environ.get("CAPCORE_DEMO_TOKEN")
    if not token:
        print("Set CAPCORE_DEMO_TOKEN first, e.g. (PowerShell):")
        print('  $env:CAPCORE_DEMO_TOKEN = "demo-token-abc123"')
        print("Then re-run. The token is read from the environment, never from code.")
        return 1

    print("Live M3 demo: real secret (from env) + real HTTPS, mediated by the broker.\n")

    # --- capability + monitor ---
    store = CapabilityStore()
    store.issue(Capability("cap-run", "acme", "acme/api",
                           frozenset({"read"}), principal="agent-7", run="run-m3"))
    mon = ReferenceMonitor(store)
    ctx = RunContext("acme", "agent-7", "run-m3")

    # --- broker holds the real secret AND executes the tool inside its boundary ---
    broker = TrustedExecutionBroker(mon)
    broker.issue_credential(Credential("api-token", "read", "acme/api",
                                       Secret(token), single_use=True))
    broker.register_tool(ToolRegistration(
        registration_id="http-1", verb="read", kind=ToolKind.CREDENTIALED,
        adapter=HttpTool(ALLOWED_URL, real_requests_transport),
        version="1", credential_id="api-token",
    ))
    broker.grant_tool("http-1", "acme/api")   # registration is NOT authorization

    # === 1. authorized action: engine mints, broker executes, secret never returned ===
    print("1) authorized action  ->  broker mints authorization  ->  broker executes")
    prop = Proposal("acme/api/data", "read")
    decision = mon.authorize(ctx, prop)
    print(f"   monitor verdict: {decision.verdict.value}")
    action_id = broker.register_authorized_execution(
        ctx, ExecutionProposal(action=prop, tool_registration_id="http-1"))
    result = broker.redeem_and_execute(action_id)
    print(f"   execution ok: {result.ok}")
    print(f"   sanitized result: {result.body if result.ok else result.code}")

    # prove the secret is absent from everything the model or logs can see
    model_view = decision.for_model()
    print("\n   containment checks:")
    print(f"   - token in model-facing reason?  {token in model_view.public_reason}")
    print(f"   - token in model-facing trace?   {token in str(model_view.trace)}")
    print(f"   - token in any broker audit line? "
          f"{any(token in r.reason for r in broker.audit)}")
    print("   (all three should be False: the secret never reaches model/logs)")

    # === 2. denied action: no secret, no call ===
    print("\n2) denied action  ->  no secret released  ->  no network call")
    prop2 = Proposal("acme/api/data", "write")  # write not granted
    decision2 = mon.authorize(ctx, prop2)
    print(f"   monitor verdict: {decision2.verdict.value}")
    try:
        broker.register_authorized_execution(
            ctx, ExecutionProposal(action=prop2, tool_registration_id="http-1"))
        print("   registered: yes (unexpected)")
    except Exception:
        print("   registered: no (correctly refused at mint)")

    # === 3. single-use exhausted: even an authorized repeat gets nothing ===
    print("\n3) authorized repeat  ->  authorization already redeemed")
    repeat = broker.redeem_and_execute(action_id)
    print(f"   execution ok: {repeat.ok}  (should be False: single-use redeemed)")

    print("\nThe broker released the real secret exactly once, only for the")
    print("authorized in-scope action, sent it only to the allowed URL, and it")
    print("never appeared in anything the model or the audit log could see.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
