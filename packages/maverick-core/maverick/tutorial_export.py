"""Run-as-tutorial export.

A successful run *is* a worked example: the goal, the plan, the steps that
mattered, the dead ends, the outcome. This renders a run's recorded events
into a step-by-step tutorial markdown a teammate can follow by hand — the
"how we did it" doc nobody writes after the fact, generated from the trace
that already exists.

Deterministic templates over the event log (same discipline as
``plain_language``): no LLM call, never invents beyond the record. Secrets
are scrubbed through the existing detector before anything is written.

Surfaced as ``GET /api/v1/goals/{id}/tutorial.md`` on the dashboard and via
``tutorial_markdown(world, goal_id)``.
"""
from __future__ import annotations

import re
import time
from typing import Any

_MAX_STEP_CHARS = 600
_CODE_FENCE = re.compile(r"```(.*?)```", re.DOTALL)


def _get(obj: Any, name: str, default: str = "") -> str:
    if isinstance(obj, dict):
        return str(obj.get(name) or default)
    return str(getattr(obj, name, default) or default)


def _scrub(text: str) -> str:
    try:
        from .secrets import scrub

        return scrub(text)
    except Exception:  # scrubber must never block an export
        return text


def _clamp(text: str, limit: int = _MAX_STEP_CHARS) -> str:
    t = text.strip()
    if len(t) <= limit:
        return t
    return t[: limit - 1].rstrip() + "…"


def tutorial_markdown(goal: Any, events: list[Any], *, now: float | None = None) -> str:
    """Render the tutorial for one run from its goal row + event list."""
    title = _scrub(_get(goal, "title")) or "(untitled run)"
    description = _scrub(_get(goal, "description"))
    status = _get(goal, "status")
    result = _scrub(_get(goal, "result"))

    plans: list[str] = []
    steps: list[tuple[str, str, str]] = []   # (agent, kind, content)
    errors: list[str] = []
    for e in events or []:
        kind = _get(e, "kind").lower()
        content = _scrub(_get(e, "content"))
        agent = _get(e, "agent") or "agent"
        if not content or kind == "trace_meta":
            continue
        if kind == "plan":
            plans.append(content)
        elif kind == "error":
            errors.append(content)
        elif kind in ("finding", "observation", "skill", "audit"):
            steps.append((agent, kind, content))

    stamp = time.strftime("%Y-%m-%d", time.gmtime(now if now is not None else time.time()))
    lines = [
        f"# Tutorial: {title}",
        "",
        f"*Generated {stamp} from run events — a worked example, not hand-written docs.*",
        "",
        "## What this accomplishes",
        "",
        description or "_(no description was recorded)_",
        "",
    ]
    if plans:
        lines += ["## The approach", ""]
        plan = plans[0]
        # Render an enumerated plan when the plan text already enumerates.
        parts = re.split(r"\s*(?:\d+[.)]\s+)", plan)
        items = [p.strip() for p in parts if p.strip()]
        if len(items) > 1:
            lines += [f"{i}. {_clamp(p, 200)}" for i, p in enumerate(items, 1)]
        else:
            lines.append(_clamp(plan))
        lines.append("")
    if steps:
        lines += ["## Steps", ""]
        for i, (agent, kind, content) in enumerate(steps, 1):
            fenced = _CODE_FENCE.search(content)
            lines.append(f"### Step {i} — {kind} ({agent})")
            lines.append("")
            if fenced:
                before = _clamp(content[: fenced.start()], 300)
                if before:
                    lines += [before, ""]
                lines += ["```", _clamp(fenced.group(1), 1200), "```"]
            else:
                lines.append(_clamp(content))
            lines.append("")
    if errors:
        lines += ["## Dead ends (so you can skip them)", ""]
        for err in errors[:5]:
            lines.append(f"- {_clamp(err, 300)}")
        if len(errors) > 5:
            lines.append(f"- …and {len(errors) - 5} more recorded errors")
        lines.append("")
    lines += ["## Outcome", ""]
    if result:
        lines.append(_clamp(result, 1500))
    else:
        lines.append(f"_The run ended with status: {status or 'unknown'}._")
    lines.append("")
    return "\n".join(lines)


__all__ = ["tutorial_markdown"]
