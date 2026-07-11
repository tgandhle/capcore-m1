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
from capcore.runtime import RunRecord


OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"

# The model is asked to emit ONE action as a compact JSON object. We keep the
# grammar tiny so a small local model can follow it. The engine treats whatever
# comes back as untrusted regardless.
SYSTEM_PROMPT = """You are an agent proposing ONE action at a time inside a \
capability-enforced runtime. Respond with a single JSON object and nothing else:
{"verb": "<read|send|write|delete>", "resource": "<path/like/this>"}
Do not explain. Do not wrap in markdown. Just the JSON object.
If you have no further action, respond exactly: {"done": true}"""


def parse_proposal(text: str) -> Optional[Proposal]:
    """Extract a Proposal from raw model text. Returns None if the model
    signals done or the text has no usable JSON object.

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
    if not isinstance(verb, str) or not verb:
        return None
    if not isinstance(resource, str) or not resource:
        return None
    return Proposal(resource=resource, verb=verb)


def render_history(record: RunRecord, max_items: int = 6) -> str:
    """A compact textual history to give the model context on prior outcomes."""
    lines = []
    for s in record.history[-max_items:]:
        r = s.proposal.resource if hasattr(s.proposal, "resource") else "?"
        v = s.proposal.verb if hasattr(s.proposal, "verb") else "?"
        lines.append(f"- {v} {r} -> {s.outcome.value}")
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

    def next_proposal(self, record: RunRecord) -> Optional[Proposal]:
        if self._asked >= self.max_proposals:
            return None
        self._asked += 1
        prompt = (
            f"History so far:\n{render_history(record)}\n\n"
            f"Propose your next action as JSON, or {{\"done\": true}} to stop."
        )
        try:
            text = self._call(prompt)
        except Exception:
            # any network/parse failure => stop the run cleanly (fail closed to
            # "no more actions" rather than crashing the engine)
            return None
        return parse_proposal(text)
