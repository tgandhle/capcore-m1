"""Adapters that plug a real model into the M2 ExecutionEngine.

OllamaModel calls a locally-running Ollama server (http://localhost:11434) and
turns its output into Proposals. It implements the same ModelClient interface as
ScriptedModel, so the engine runs it through the identical trusted pipeline: the
local LLM's outputs are UNTRUSTED and every proposal is authorized (and
re-authorized) exactly like a scripted one.

IMPORTANT (honesty about what is tested):
  - The parsing logic (`parse_proposal`) is unit-tested in test_adapters.py with
    fixed strings; it does not need a network.
  - The actual network call to Ollama is NOT exercised in CI (CI has no Ollama
    server and model output is nondeterministic). Verify the live path locally
    with `python scripts/demo_live.py` after `ollama pull llama3.2`.

Requires the `requests` package for the live path (an optional dependency); the
parsing logic has no third-party dependency.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from capcore import Proposal
from capcore.broker import ExecutionProposal
from capcore.runtime import ModelResult, ModelView


OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"

# The model is asked to emit ONE action as a compact JSON object. We keep the
# grammar tiny so a small local model can follow it. The engine treats whatever
# comes back as untrusted regardless.
SYSTEM_PROMPT = """You are an agent proposing ONE action at a time inside a \
capability-enforced runtime. Respond with a single JSON object and nothing else:
{"verb": "<read|send>", "resource": "acme/records/customers/<id>", "tool": "<tool-id>"}

You may only READ or SEND on resources under acme/records/customers.
Resources are slash-separated paths with NO leading slash. Use real ids like
c-1001, c-1002. The "tool" field names the concrete executor, e.g. "read-records"
or "send-records". Example of a VALID action:
{"verb": "read", "resource": "acme/records/customers/c-1001", "tool": "read-records"}

Do not use a leading slash. Do not invent other top-level paths. Do not use
placeholders like <id> literally, pick a concrete id. Do not explain, do not
use markdown, output only the JSON object. If done, output exactly:
{"done": true}"""


def parse_proposal(text: str) -> Optional[ExecutionProposal]:
    """Extract an ExecutionProposal from raw model text. None if the model signals
    done or the text has no usable JSON object.

    The model names BOTH the action (verb + resource) and the executor ("tool").
    All three are UNTRUSTED. Naming a tool does not authorize it: the broker's
    deny-by-default ToolPolicy decides whether this registration may serve this
    action, and an unauthorized executor is refused at mint.

    This is deliberately forgiving on FORMAT (small models wrap things in prose
    or markdown) but strict on CONTENT: it only accepts a non-empty string verb
    and resource. Anything malformed returns None, and a None from the model is
    treated by the engine as "stop", while a malformed-but-present action would
    be turned into a Proposal that the monitor then judges (and likely denies).

    Note: this does NOT validate the resource against capcore's rules; that is
    the monitor's job. Parsing only shapes text into a Proposal or None.
    """
    if not text:
        return None
    # find the first {...} JSON object in the text
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if not match:
        return None
    try:
        obj = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("done") is True:
        return None
    verb = obj.get("verb")
    resource = obj.get("resource")
    tool = obj.get("tool")
    if not isinstance(verb, str) or not verb:
        return None
    if not isinstance(resource, str) or not resource:
        return None
    if not isinstance(tool, str) or not tool:
        return None
    return ExecutionProposal(
        action=Proposal(resource=resource, verb=verb),
        tool_registration_id=tool,
    )


def _signals_done(text: str) -> bool:
    """Did the model explicitly say it was finished, as opposed to emitting junk?

    parse_proposal returns None for BOTH cases, which is fine for parsing but not
    for terminal state: a model that said {"done": true} completed its work, while
    a model that emitted prose completed nothing. The engine must not report those
    identically.
    """
    if not text:
        return False
    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if not match:
        return False
    try:
        obj = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(obj, dict) and obj.get("done") is True


def render_history(view: ModelView, max_items: int = 6) -> str:
    """A compact textual history to give the model context on prior outcomes.

    Takes a ModelView, not a RunRecord. The view is already redacted: it carries
    no audit_reason, so there is no way for this function to accidentally render
    trusted diagnostic detail into a prompt. That redaction happens once, at the
    boundary, rather than being re-litigated by every adapter.
    """
    lines = []
    for s in view.history[-max_items:]:
        lines.append(f"- {s.verb} {s.resource} -> {s.outcome.value}")
    return "\n".join(lines) if lines else "(no actions yet)"


class OllamaModel:
    """ModelClient backed by a local Ollama server.

    max_proposals caps how many times we'll ask the model, independent of the
    engine's own budget, so a chatty model cannot loop forever at the network
    layer. The engine's Budget is still the authoritative runtime limit.
    """

    def __init__(self, model: str = DEFAULT_MODEL, url: str = OLLAMA_URL,
                 max_proposals: int = 8, timeout: float = 60.0):
        self.model = model
        self.url = url
        self.max_proposals = max_proposals
        self.timeout = timeout
        self._asked = 0

    def _call(self, prompt: str) -> str:
        # imported lazily so the parsing logic has no hard dependency on requests
        import requests
        resp = requests.post(
            self.url,
            json={
                "model": self.model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {"temperature": 0},  # pin for reproducibility
            },
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    def next_proposal(self, view: ModelView) -> ModelResult:
        """Return a TYPED result. A provider failure is not a completion.

        This used to catch every exception and return None, and the engine read
        None as "the model is done". So a run against a dead Ollama server
        terminated as COMPLETED, with zero actions taken and no indication that
        anything had gone wrong. Silent, total failure reported as success.

        Now a transport failure is ModelResult.error(), which the engine maps to
        RunState.FAILED / StopReason.PROVIDER_UNAVAILABLE. Still fail-closed (no
        further actions, no crash), but HONEST about why.
        """
        if self._asked >= self.max_proposals:
            # Hitting our OWN proposal cap is NOT task completion: the model never
            # said it was done, we just stopped asking. Report it distinctly so a
            # truncated run is not indistinguishable from a finished one.
            return ModelResult.limit_reached()
        self._asked += 1
        prompt = (
            f"History so far:\n{render_history(view)}\n\n"
            f"Propose your next action as JSON, or {{\"done\": true}} to stop."
        )
        try:
            text = self._call(prompt)
        except Exception:
            # Network, HTTP, timeout, malformed-JSON-from-the-server: the provider
            # failed. NOT a completion.
            return ModelResult.error()

        proposal = parse_proposal(text)
        if proposal is None:
            # The model either signalled {"done": true} or emitted something
            # unusable. parse_proposal cannot distinguish those, so ask it again:
            # a clean done is a FINISH, garbage is an ERROR.
            if _signals_done(text):
                return ModelResult.finished()
            return ModelResult.error()
        return ModelResult.propose(proposal)
