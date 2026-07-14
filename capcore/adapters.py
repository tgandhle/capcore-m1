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
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from capcore import Proposal
from capcore.broker import ExecutionProposal
from capcore.runtime import ModelResult, ModelView


OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"


# --------------------------------------------------------------------------- #
# JSON nesting cap. The control against a decoder blowing its stack on
# provider-controlled input.
# --------------------------------------------------------------------------- #

MAX_JSON_NESTING = 16
"""Maximum container nesting accepted from a provider, checked BEFORE decoding.

Depth convention (increment on `[` and `{`):
    {}            -> 1
    {"a": []}     -> 2
    {"a": [[]]}   -> 3

Both accepted schemas are depth 1 (`{"verb":..,"resource":..,"tool":..}` and
`{"done":true}`), so 16 is pure margin: it leaves room for nested metadata later
without revisiting a security control, while staying far below any depth that
troubles a decoder.

WHY A CAP AND NOT `except RecursionError`.

Widening the except clause is the obvious fix and it is NOT sufficient. Evidence,
from this project's own supported interpreters:

    CPython 3.11-3.13   json.loads() at depth 10000 raises RecursionError
    CPython 3.14.6      json.loads() at depth 10000 PARSES, with the default
                        recursion limit (1000) untouched

RecursionError is therefore a property of the DECODER'S IMPLEMENTATION on a given
interpreter, not a property of the INPUT. Two consequences:

  1. On 3.14 a hostile model can send a complete, well-formed, otherwise-valid
     proposal carrying a 10000-deep field and it parses straight through. There is
     no exception for the engine to catch, so the input is not rejected: it is
     ACCEPTED. "Fail closed" was a 3.11-3.13 property, not a system property.
  2. 3.14 did not remove the bound, it RAISED it. Some greater depth still
     exhausts the C scanner's stack, and a native stack overflow is not a
     catchable RecursionError. `except Exception` cannot save you from a segfault,
     which is why the provider-envelope decode needs the cap too even though
     next_proposal already wraps it broadly.

A cap is a pure function of the input, so it behaves identically on every
interpreter, and it is testable and mutatable on every interpreter. RecursionError
stays in the except tuples below as defense in depth, never as the control.
"""


def json_nesting_within_limit(text: str, *, limit: int = MAX_JSON_NESTING) -> bool:
    """True if `text` nests no deeper than `limit`. STRING-AWARE.

    The string-awareness is not a nicety. A naive bracket counter is WORSE than no
    scanner at all: it would reject legitimate output whose string VALUES contain
    brackets, and a resource path like "acme/api/[x]" or an error message the
    model is quoting back are entirely ordinary. Rejecting those would be a silent
    availability bug introduced by a security control.

    So: characters inside a JSON string are content, not structure. A backslash
    escapes the next character, which means `\\"` does NOT end the string but
    `\\\\` followed by `"` DOES (the backslash is itself escaped). Getting that
    wrong in either direction is exploitable: exit string state too early and you
    count content brackets as structure; stay in string state forever and you stop
    counting real structure after the first quote.

    This does NOT validate JSON. Malformed input (unbalanced, unterminated string)
    may still return True; json.loads rejects it immediately after. The scanner's
    ONE job is to refuse excessive nesting before the decoder ever sees it.
    """
    depth = 0
    in_string = False
    escaped = False

    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "[" or char == "{":
            depth += 1
            if depth > limit:
                return False
        elif char == "]" or char == "}":
            depth -= 1
            if depth < 0:
                return False

    return True


def decode_provider_envelope(raw: bytes) -> str:
    """Decode the provider's HTTP envelope and return its `response` field.

    Extracted from OllamaModel._call so the envelope's own untrusted-input gates
    (utf-8, nesting, shape) are testable WITHOUT a live provider or a network.
    This is the SECOND decoder in the pipeline operating on provider-controlled
    bytes, and it gets the same nesting cap as the first for the same reason.
    """
    from capcore.httptool import ProviderProtocolError

    # STRICT decode: do NOT silently repair malformed bytes with errors="replace".
    # Malformed provider unicode fails closed, consistent with every other
    # untrusted-text boundary.
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProviderProtocolError("provider response is not valid utf-8") from exc

    # Cap BEFORE decode. next_proposal wraps _call in `except Exception`, which
    # catches a RecursionError but NOT a native stack overflow.
    if not json_nesting_within_limit(decoded):
        raise ProviderProtocolError("provider response exceeds JSON nesting limit")

    try:
        obj = json.loads(decoded)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ProviderProtocolError("provider response is not valid JSON") from exc
    if type(obj) is not dict:
        raise ProviderProtocolError("provider response must be a JSON object")
    text = obj.get("response")
    if type(text) is not str:
        raise ProviderProtocolError("provider response field must be a string")
    return text

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


class ParsedOutputKind(Enum):
    PROPOSAL = "proposal"
    FINISHED = "finished"
    INVALID = "invalid"            # unusable text (no JSON, wrong shape)
    TOO_LARGE = "too_large"        # exceeded the generated-text limit
    INVALID_UTF8 = "invalid_utf8"  # not utf-8 encodable


@dataclass(frozen=True)
class ParsedModelOutput:
    kind: ParsedOutputKind
    proposal: Optional[ExecutionProposal] = None


def parse_model_output(text: str) -> ParsedModelOutput:
    """The SINGLE parse path for untrusted model text.

    Every outcome, proposal AND completion, passes the same size and utf-8 gate
    FIRST, so there is no second parser (the old `_signals_done`) that could
    accept an oversized or malformed-unicode completion the proposal path
    rejected. Order: encodability -> size -> JSON shape -> done vs proposal.
    """
    from capcore import utf8_length, MAX_GENERATED_MODEL_TEXT_BYTES
    # TOTAL function: never raise, always a typed outcome. A non-str input (a
    # provider adapter bug, a fixture, a hostile caller) is INVALID, not an
    # AttributeError escaping the parser.
    if type(text) is not str:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    if not text:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    n = utf8_length(text)
    if n is None:
        return ParsedModelOutput(ParsedOutputKind.INVALID_UTF8)
    if n > MAX_GENERATED_MODEL_TEXT_BYTES:
        return ParsedModelOutput(ParsedOutputKind.TOO_LARGE)

    match = re.search(r"\{.*?\}", text, re.DOTALL)
    if not match:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    candidate = match.group(0)

    # Cap the nesting of the JSON CANDIDATE, before json.loads sees it. Applied to
    # the candidate rather than the whole text on purpose: braces in explanatory
    # prose the model wrapped around its JSON are not JSON structure and must not
    # count toward depth.
    if not json_nesting_within_limit(candidate):
        return ParsedModelOutput(ParsedOutputKind.INVALID)

    try:
        obj = json.loads(candidate)
    except (json.JSONDecodeError, ValueError, RecursionError):
        # RecursionError is a BACKSTOP, not the control: see MAX_JSON_NESTING. On
        # 3.11-3.13 the decoder raises it, on 3.14 it does not, so a fix relying on
        # it would hold on some interpreters and not others.
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    if not isinstance(obj, dict):
        return ParsedModelOutput(ParsedOutputKind.INVALID)

    if obj.get("done") is True:
        return ParsedModelOutput(ParsedOutputKind.FINISHED)

    verb = obj.get("verb")
    resource = obj.get("resource")
    tool = obj.get("tool")
    if not isinstance(verb, str) or not verb:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    if not isinstance(resource, str) or not resource:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    if not isinstance(tool, str) or not tool:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    # ExecutionProposal.__post_init__ enforces exact types and size limits and
    # RAISES on violation (e.g. an oversized tool id). In a TOTAL parser that must
    # become a typed INVALID, not an escaping exception.
    try:
        proposal = ExecutionProposal(
            action=Proposal(resource=resource, verb=verb),
            tool_registration_id=tool,
        )
    except Exception:
        return ParsedModelOutput(ParsedOutputKind.INVALID)
    return ParsedModelOutput(ParsedOutputKind.PROPOSAL, proposal)


def parse_proposal(text: str) -> Optional[ExecutionProposal]:
    """Backward-compatible thin wrapper over parse_model_output.

    Returns the ExecutionProposal for a PROPOSAL outcome, else None. Retained so
    existing parsing unit tests keep working; new code should use
    parse_model_output, which distinguishes finished/too-large/invalid-utf8.
    """
    parsed = parse_model_output(text)
    return parsed.proposal if parsed.kind is ParsedOutputKind.PROPOSAL else None


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
        from capcore import MAX_PROVIDER_HTTP_BODY_BYTES
        from capcore.httptool import bounded_read
        # The response is used as a CONTEXT MANAGER so the connection is closed on
        # every exit path (success, size rejection, protocol error, HTTP error),
        # not left awaiting garbage collection.
        with requests.post(
            self.url,
            json={
                "model": self.model,
                "prompt": prompt,
                "system": SYSTEM_PROMPT,
                "stream": False,
                "options": {"temperature": 0},  # pin for reproducibility
            },
            timeout=self.timeout,
            stream=True,   # do NOT let requests buffer an unbounded body
        ) as resp:
            resp.raise_for_status()
            # Bound the HTTP body by bytes ACTUALLY READ (a hostile provider can
            # lie about Content-Length).
            raw = bounded_read(resp, MAX_PROVIDER_HTTP_BODY_BYTES)

        # utf-8, nesting cap, and shape checks all live in the extracted decoder,
        # so they are testable without a live provider.
        return decode_provider_envelope(raw)

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

        # SINGLE parse path: proposal and completion pass the same size/utf-8
        # gate. There is no separate _signals_done parser that could accept an
        # oversized or malformed-unicode completion the proposal path rejected.
        parsed = parse_model_output(text)
        if parsed.kind is ParsedOutputKind.PROPOSAL:
            return ModelResult.propose(parsed.proposal)
        if parsed.kind is ParsedOutputKind.FINISHED:
            return ModelResult.finished()
        # INVALID / TOO_LARGE / INVALID_UTF8: the model produced unusable or
        # out-of-bounds output. Not a completion. Fail closed to error.
        return ModelResult.error()
