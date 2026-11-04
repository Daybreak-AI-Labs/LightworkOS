"""Programming by demonstration -- synthesize a pack from a watched task.

The agent factory's other front door is *intake* ("describe the business").
This is the second: **watch a person do their job, then build the agent that
does it.** A demonstration is an ordered record of what a human did -- the
actions they took, the systems they touched, and (optionally) their narration
of why -- captured by any front-end (a screen/action logger, a narrated
walkthrough, an exported activity log). This module turns that
record into a live, sealed specialist:

    Demonstration --induce--> DomainProfile --(intake clamp)--> human approve
        --> save_profile --> provision (skills + tools) --> agent_from_profile

Induction reuses the intake safety pipeline wholesale: it produces the same
``propose(spec) -> dict`` the conversational onboarding uses, hands it to
``intake.generate_profile``, and therefore inherits ``validate_profile`` -- a
demonstrated pack can NO MORE auto-grant a high-impact tool than a described
one. The demonstration is the *evidence* a human reviews at the approval gate;
nothing activates without that yes (``save_profile`` enforces it).

Posture (kernel rule 1): no capture infrastructure is required or assumed here
-- this is the ingest + induction core. Demonstration text is treated as
untrusted (a human may have pasted a secret mid-task): step summaries are
secret-redacted before they land in the pack, and the generated persona is
shield-scanned by the intake path it flows through.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# Kinds of thing a demonstration step can be.
_KINDS = ("action", "narration", "observation")
_MAX_STEP_CHARS = 400
_MAX_WORKFLOW_STEPS = 8
# Bound the work BEFORE the regex-heavy redaction sweep. Only this many chars of a
# raw field can survive the final cap, so scanning a multi-MB paste is wasted CPU;
# the window leaves generous margin for a secret token starting inside the kept
# region. Plus hard caps on the whole capture so an attacker-supplied log can't
# drive unbounded CPU/RAM through induction.
_REDACT_WINDOW = _MAX_STEP_CHARS * 4
_MAX_DEMO_BYTES = 2_000_000        # cap how much of a demonstration file we read
_MAX_DEMO_STEPS = 2_000            # cap how many steps we parse/retain
_MAX_JSON_LINE = 65_536            # don't hand a giant line to the recursive JSON scanner
# A real job uses a handful of tools; cap the derived envelope so a pathological
# demonstration (thousands of distinct tool hints) can't synthesize a pack with
# an unbounded allow_tools list. validate_profile clamps by RISK, not by COUNT.
_MAX_OBSERVED_TOOLS = 16
# Plain-text line prefixes a capture front-end can emit, mapped to step kinds.
# ``ACTION[tool]: ...`` carries an optional capability hint in the brackets.
_PREFIX_KIND = {
    "ACTION": "action", "DO": "action", "STEP": "action",
    "SAY": "narration", "NOTE": "narration", "NARRATE": "narration",
    "SEE": "observation", "OBSERVE": "observation", "CONTEXT": "observation",
}
_ACTION_RE = re.compile(r"^(?P<prefix>[A-Z]+)(?:\[(?P<tool>[a-z0-9_]+)\])?\s*:\s*(?P<body>.*)$")


def _redact(text: str) -> str:
    """Strip secrets a human may have pasted while being watched."""
    try:
        from .safety.secret_detector import redact
        return redact(str(text or ""))[0]
    except Exception:  # pragma: no cover -- detector must never block induction
        return str(text or "")


def _clean(text: str) -> str:
    """Redact secrets, collapse whitespace to single-line, and length-cap.

    A raw (programmatically built) DemoStep can carry a multi-line credential
    paste; the parser only ever yields single lines, so normalize both paths to
    the same shape -- redacted, one line, bounded -- before anything is persisted
    or sent to a provider. The raw field is truncated to ``_REDACT_WINDOW`` BEFORE
    the (regex-heavy) redaction sweep so a multi-MB paste costs O(window), not
    O(field): only the kept window can survive the final ``_MAX_STEP_CHARS`` cap
    anyway."""
    windowed = " ".join((text or "")[:_REDACT_WINDOW].split())
    return _redact(windowed)[:_MAX_STEP_CHARS]


@dataclass
class DemoStep:
    """One observed beat of a demonstration."""

    kind: str                 # action | narration | observation
    summary: str
    tool: str = ""            # capability hint, when kind == "action"
    target: str = ""          # what it acted on (a file / url / system)

    def normalized(self) -> DemoStep:
        kind = self.kind if self.kind in _KINDS else "observation"
        return DemoStep(
            kind=kind,
            summary=_clean(self.summary),
            tool=(self.tool or "").strip(),
            target=_clean(self.target),
        )


@dataclass
class Demonstration:
    """A watched task: title + ordered steps + provenance."""

    title: str
    steps: list[DemoStep] = field(default_factory=list)
    source: str = "manual"    # screen | narration | log | manual
    industry: str = ""

    def actions(self) -> list[DemoStep]:
        return [s for s in self.steps if s.kind == "action"]

    def observed_tools(self) -> list[str]:
        seen: list[str] = []
        for s in self.steps:
            if s.tool and s.tool not in seen:
                seen.append(s.tool)
                if len(seen) >= _MAX_OBSERVED_TOOLS:
                    break
        return seen

    def narration(self) -> str:
        return " ".join(s.summary for s in self.steps if s.kind == "narration").strip()

    def render(self) -> str:
        """A readable transcript for an LLM proposer (or the approval UI)."""
        lines = [f"Task: {self.title}"]
        if self.industry:
            lines.append(f"Industry: {self.industry}")
        lines.append("")
        for i, s in enumerate(self.steps, 1):
            tag = s.kind.upper()
            tool = f" [{s.tool}]" if s.tool else ""
            tgt = f" -> {s.target}" if s.target else ""
            lines.append(f"{i}. {tag}{tool}: {s.summary}{tgt}")
        return "\n".join(lines)


# --------------------------------------------------------------------------
# parsing / loading
# --------------------------------------------------------------------------
def parse_demonstration(text: str) -> list[DemoStep]:
    """Parse a demonstration body into steps. Forgiving by design.

    Accepts two interchangeable formats, chosen per line:

    * **JSONL** -- a line that is a JSON object ``{"kind","summary","tool",
      "target"}`` (any subset; missing kind defaults to ``action``).
    * **Prefixed text** -- ``ACTION[tool]: did X -> target``, ``NOTE: ...``,
      ``SEE: ...``. A bare line with no recognized prefix is treated as an
      action. The optional ``-> target`` tail names what was acted on.

    Unparseable lines are skipped, not fatal -- a capture log should never
    fail induction outright.
    """
    steps: list[DemoStep] = []
    for raw in (text or "").splitlines():
        if len(steps) >= _MAX_DEMO_STEPS:  # bound count for an attacker-supplied log
            break
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("{") and line.endswith("}") and len(line) <= _MAX_JSON_LINE:
            try:
                d = json.loads(line)
                if isinstance(d, dict) and (d.get("summary") or d.get("text")):
                    steps.append(DemoStep(
                        kind=str(d.get("kind") or "action"),
                        summary=str(d.get("summary") or d.get("text") or ""),
                        tool=str(d.get("tool") or ""),
                        target=str(d.get("target") or ""),
                    ).normalized())
                    continue
            except (json.JSONDecodeError, ValueError, RecursionError):
                # RecursionError: a deeply-nested JSON object exceeds the parser's
                # recursion limit -- treat it as not-our-JSON and fall through to
                # text parsing rather than letting it crash a capture ingest.
                pass
        m = _ACTION_RE.match(line)
        if m:
            kind = _PREFIX_KIND.get(m.group("prefix"), None)
            if kind is not None:
                body, target = _split_target(m.group("body"))
                steps.append(DemoStep(
                    kind=kind, summary=body, tool=m.group("tool") or "", target=target,
                ).normalized())
                continue
        body, target = _split_target(line)
        steps.append(DemoStep(kind="action", summary=body, target=target).normalized())
    return [s for s in steps if s.summary]


def _split_target(body: str) -> tuple[str, str]:
    """Split a trailing ``-> target`` off a step body."""
    if "->" in body:
        head, _, tail = body.rpartition("->")
        return head.strip(), tail.strip()
    return body.strip(), ""


def load_demonstration(
    path: str | Path, *, title: str = "", source: str = "log", industry: str = "",
) -> Demonstration:
    """Read a demonstration file (JSONL or prefixed text) into a Demonstration.

    ``title`` defaults to the file stem. Never raises on a malformed body --
    unparseable lines are dropped by ``parse_demonstration``. At most
    ``_MAX_DEMO_BYTES`` are read so an oversized (or attacker-supplied) capture
    log can't drive unbounded work through induction.
    """
    p = Path(path)
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        text = fh.read(_MAX_DEMO_BYTES)
    return Demonstration(
        title=title or p.stem.replace("_", " "),
        steps=parse_demonstration(text),
        source=source, industry=industry,
    )


# --------------------------------------------------------------------------
# induction (demonstration -> DomainProfile, via the intake clamp)
# --------------------------------------------------------------------------
_DEMO_PROPOSER_SYSTEM = (
    "You are watching a recording of a person doing their job and must "
    "configure the specialist agent that would do this task for them. Given the "
    "transcript of their actions and narration, return ONLY a JSON object with "
    "these keys:\n"
    '  "persona": the agent\'s system instructions (string),\n'
    '  "description": a one-line summary of the job (string),\n'
    '  "allow_tools": array of tool names the task used (e.g. read_file, '
    "web_search, email),\n"
    '  "max_risk": "low" or "medium",\n'
    '  "workflow": array of 3-8 steps mirroring what the person did, each '
    '{"name","instruction","tools","gate"} where gate is null except a final '
    'human-handoff step ("review", or "approval" for anything irreversible),\n'
    '  "output": {"shape","deliverable","consumers","cadence","gate"}.\n'
    "Never include shell, code-execution, or file-writing tools. Output JSON only."
)


def _demo_to_spec(demo: Demonstration):
    """Build the IntakeSpec the intake pipeline consumes from a demonstration."""
    from .intake import IntakeSpec

    desc = _redact(demo.narration()) or f"Performs the task: {demo.title}."
    goals = [s.summary for s in demo.actions()][:10]
    return IntakeSpec(
        name=demo.title or "demonstrated task",
        description=desc[:_MAX_STEP_CHARS],
        industry=demo.industry,
        goals=goals,
    )


def _deterministic_demo_proposer(demo: Demonstration):
    """A no-LLM proposer: derive the pack dict straight from the demonstration.

    Workflow steps mirror the observed actions; ``allow_tools`` is the set of
    tools the person used (clamped later by ``validate_profile``). A final
    human review gate is appended so a demonstrated pack routes its deliverable
    for sign-off by default, matching the built-in roster's discipline.
    """
    def propose(_spec) -> dict:
        workflow: list[dict] = []
        for s in demo.steps:
            if s.kind == "narration":
                continue
            name = s.summary[:60].strip() or "Step"
            instruction = s.summary + (f" (on {s.target})" if s.target else "")
            step: dict = {"name": name, "instruction": instruction}
            if s.tool:
                step["tools"] = [s.tool]
            workflow.append(step)
            if len(workflow) >= _MAX_WORKFLOW_STEPS:
                break
        if not workflow or (workflow[-1].get("gate") != "review"):
            workflow.append({
                "name": "Route for review",
                "instruction": "Hand the result to the accountable human before it is acted on.",
                "gate": "review",
            })
        return {
            "description": _redact(demo.narration()) or f"Performs: {demo.title}.",
            "allow_tools": demo.observed_tools() or ["read_file"],
            "max_risk": "medium",
            "workflow": workflow,
        }

    return propose


def build_demo_proposer(demo: Demonstration, llm, *, model: str | None = None, budget=None):
    """An LLM-backed ``propose(spec)`` that reads the demonstration transcript.

    Mirrors ``intake.build_llm_proposer`` (and reuses its parser/sanitizer), so
    the result flows through the identical clamp. Returns ``{}`` on any failure;
    ``generate_profile`` then falls back to its safe default and clamps anyway.
    """
    from .intake import _parse_proposal, _slug

    def propose(_spec) -> dict:
        system = _DEMO_PROPOSER_SYSTEM
        try:  # fold in promoted factory guidance (no-op while self-improvement off)
            from .domain import suite_for
            from .factory_learning import augment_system_prompt
            system = augment_system_prompt(_DEMO_PROPOSER_SYSTEM, suite=suite_for(_slug(demo.title)))
        except Exception:  # pragma: no cover -- guidance must never break generation
            pass
        resp = llm.complete(
            system=system,
            messages=[{"role": "user", "content": demo.render()}],
            model=model, budget=budget, max_tokens=1500,
        )
        return _parse_proposal(getattr(resp, "text", "") or "")

    return propose


def induce_profile(demo: Demonstration, *, llm=None, model: str | None = None, budget=None):
    """Synthesize a validated (UNSAVED) DomainProfile from a demonstration.

    Pass ``llm`` for the generative path (the model proposes the pack from the
    transcript); omit it for the deterministic derivation. Either way the result
    is run through ``intake.generate_profile`` -> ``validate_profile``, so the
    envelope is clamped and the persona shield-scanned before a human ever sees
    it. Persisting is the separate, approved ``intake.save_profile`` step.
    """
    from .intake import generate_profile

    # Defensive normalization at the chokepoint. Only ``parse_demonstration``
    # normalizes; a Demonstration built programmatically (a capture front-end,
    # a test, a future API) may carry RAW DemoSteps whose summaries/targets --
    # and whose title -- still hold pasted secrets. Re-normalize every step and
    # redact the title here so no downstream path (the deterministic proposer's
    # workflow instructions, the LLM transcript, the provenance note) can leak a
    # secret into the persisted pack. Idempotent on already-normalized steps.
    demo = Demonstration(
        title=_redact(demo.title).strip()[:_MAX_STEP_CHARS],
        steps=[s.normalized() for s in demo.steps],
        source=demo.source, industry=demo.industry,
    )
    spec = _demo_to_spec(demo)
    propose = (
        build_demo_proposer(demo, llm, model=model, budget=budget)
        if llm is not None else _deterministic_demo_proposer(demo)
    )
    profile = generate_profile(spec, propose=propose)
    # Provenance: make it obvious in the draft that this pack came from a watch.
    note = f"[synthesized from a recorded demonstration: {demo.title}]"
    if note not in profile.description:
        profile.description = (profile.description + f" {note}").strip()
    return profile


__all__ = [
    "DemoStep", "Demonstration", "parse_demonstration", "load_demonstration",
    "build_demo_proposer", "induce_profile",
]
