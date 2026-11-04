"""Skill distillation tool.

Turn a successful execution trace into a reusable skill spec: it keeps only the
steps that actually succeeded (``ok``), drops no-op/noise actions, de-duplicates
the tools needed, and records ordered steps plus the goal as a trigger. The result is a
compact ``{name, triggers, tools_needed, steps}`` the planner can reuse.

ops:
  - distill(trace, goal)  — trace: [{action, tool, ok}] -> a skill spec.
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import Tool

# Actions that carry no reusable behavior — distilled out as noise.
_NOISE = {"", "noop", "no-op", "think", "wait", "retry", "observe"}


def _slug(goal: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", goal.strip().lower()).strip("_")
    return (s or "skill")[:48]


def _distill(trace: list[dict], goal: str) -> str:
    steps: list[dict] = []
    tools_needed: list[str] = []
    seen_tools: set[str] = set()
    for entry in trace:
        if not isinstance(entry, dict):
            continue
        # Drop failed steps: a reusable skill must encode the path that worked.
        if entry.get("ok") is not True:
            continue
        action = str(entry.get("action", "")).strip()
        if action.lower() in _NOISE:
            continue
        tool = str(entry.get("tool", "")).strip()
        step: dict[str, str] = {"action": action}
        if tool:
            step["tool"] = tool
            if tool not in seen_tools:
                seen_tools.add(tool)
                tools_needed.append(tool)
        steps.append(step)

    if not steps:
        return "ERROR: no successful, non-noise actions in trace to distill"

    spec = {
        "name": _slug(goal),
        "triggers": [goal.strip()],
        "tools_needed": tools_needed,
        "steps": steps,
    }
    return (
        f"DISTILLED skill {spec['name']!r}: {len(steps)} step(s), "
        f"{len(tools_needed)} tool(s)\n" + json.dumps(spec, sort_keys=True)
    )


def _run(args: dict[str, Any]) -> str:
    if args.get("op") not in (None, "distill"):
        return f"ERROR: unknown op {args.get('op')!r}"
    trace = args.get("trace")
    goal = args.get("goal")
    if not isinstance(trace, list) or not trace:
        return "ERROR: trace (list of {action, tool, ok}) is required"
    if not isinstance(goal, str) or not goal.strip():
        return "ERROR: goal is required"
    return _distill(trace, goal)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["distill"]},
        "trace": {
            "type": "array",
            "description": "Execution trace: {action, tool, ok}",
            "items": {"type": "object"},
        },
        "goal": {"type": "string", "description": "The goal the trace achieved"},
    },
    "required": ["trace", "goal"],
}


def skill_distill_v2() -> Tool:
    return Tool(
        name="skill_distill_v2",
        description=(
            "Distill a successful trace into a reusable skill spec. "
            "op=distill with 'trace' ([{action, tool, ok}]) and 'goal' -> "
            "{name, triggers, tools_needed, steps}. Drops failed (!ok) and "
            "noise steps and de-duplicates tools. "
            "Deterministic, offline."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
