"""Plain-language run explanations.

The trajectory page shows engineers raw events; a non-technical reviewer
needs the same story in sentences: what was asked, what the team planned,
what it found, what went wrong, how it ended. This renders that narrative
**deterministically from the recorded events** — template prose, no LLM call,
so the explanation is free, instant, and never hallucinates beyond the log.

Resilient by design: known event kinds (plan / finding / observation / error /
skill) get tailored phrasing; unknown kinds fall into a generic "worked on"
bucket rather than breaking the story.
"""
from __future__ import annotations

import re
from typing import Any

_MAX_QUOTE = 140
_MAX_ITEMS = 5

_CODE_FENCE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_MD = re.compile(r"[*_`#>\[\]()]+")
_WS = re.compile(r"\s+")


def _plain(text: str, limit: int = _MAX_QUOTE) -> str:
    """Strip markdown/code noise and clamp for quoting inside prose."""
    t = _CODE_FENCE.sub(" (code) ", str(text or ""))
    t = _INLINE_MD.sub(" ", t)
    t = _WS.sub(" ", t).strip()
    if len(t) > limit:
        t = t[: limit - 1].rstrip() + "…"
    return t


def _status_phrase(status: str) -> str:
    s = (status or "").lower()
    return {
        "done": "finished successfully",
        "completed": "finished successfully",
        "failed": "stopped after hitting a problem it couldn't get past",
        "error": "stopped after hitting a problem it couldn't get past",
        "running": "is still in progress",
        "pending": "hasn't started yet",
        "cancelled": "was cancelled before it finished",
    }.get(s, f"is currently marked '{status}'" if status else "has no recorded status")


def explain(goal: Any, events: list[Any]) -> str:
    """Render the plain-language narrative for one run.

    ``goal`` and ``events`` are duck-typed (title/description/status; agent/
    kind/content) so the world model's dataclasses or plain dicts both work.
    """
    def _get(obj: Any, name: str, default: str = "") -> str:
        if isinstance(obj, dict):
            return str(obj.get(name) or default)
        return str(getattr(obj, name, default) or default)

    title = _plain(_get(goal, "title"), 100)
    status = _status_phrase(_get(goal, "status"))

    plans: list[str] = []
    findings: list[str] = []
    errors: list[str] = []
    skills: list[str] = []
    other_agents: set[str] = set()
    for e in events or []:
        kind = _get(e, "kind").lower()
        content = _plain(_get(e, "content"))
        agent = _get(e, "agent")
        if not content:
            continue
        if kind == "plan":
            plans.append(content)
        elif kind in ("finding", "observation"):
            findings.append(content)
        elif kind == "error":
            errors.append(content)
        elif kind == "skill":
            skills.append(content)
        elif agent:
            other_agents.add(agent)

    parts: list[str] = []
    opener = f"This run was asked to: {title}." if title else "This run had no recorded title."
    parts.append(f"{opener} It {status}.")

    if plans:
        parts.append(f"The team started with a plan: {plans[0]}")
    if findings:
        shown = findings[:_MAX_ITEMS]
        lines = "; ".join(shown)
        more = f" (and {len(findings) - len(shown)} more)" if len(findings) > len(shown) else ""
        parts.append(f"Along the way it noted: {lines}{more}.")
    if skills:
        parts.append(f"It reused learned know-how: {skills[0]}.")
    if errors:
        shown = errors[:_MAX_ITEMS]
        plural = "problem" if len(errors) == 1 else f"{len(errors)} problems"
        parts.append(
            f"It ran into {plural}, for example: {shown[0]}"
            + (" It recovered and kept going." if "finished" in status else "")
        )
    if other_agents and not (plans or findings):
        names = ", ".join(sorted(other_agents)[:4])
        parts.append(f"Work was carried out by: {names}.")

    if not (plans or findings or errors or skills):
        parts.append("No detailed activity was recorded for this run.")

    result = _plain(_get(goal, "result"), 200)
    if result:
        parts.append(f"The recorded outcome: {result}")

    return "\n\n".join(parts)


__all__ = ["explain"]
