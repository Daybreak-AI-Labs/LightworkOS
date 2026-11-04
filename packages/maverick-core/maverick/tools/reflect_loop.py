"""Plan-execute-reflect loop tool.

A deterministic control-flow helper (no model) for an agent's outer loop. It
scaffolds a plan and, given the outcome of a step, recommends the next control
action by simple rules.

ops:
  - plan(goal[, max_steps])  — an ordered, numbered step scaffold for the goal.
  - reflect(step, observation, succeeded[, attempts][, max_attempts]) —
    a structured next-action recommendation: ADVANCE (succeeded), RETRY (failed
    with attempts left), or REPLAN (failed and out of retries).
"""
from __future__ import annotations

from typing import Any

from . import Tool

# Fixed plan-execute-reflect phases the scaffold draws from, in order.
_PHASES = [
    "Clarify the goal and success criteria",
    "Gather context and required inputs",
    "Draft an approach",
    "Execute the approach",
    "Verify the result against the success criteria",
    "Reflect and refine",
    "Finalize and report",
]


def _plan(goal: str, max_steps: int) -> str:
    n = min(max_steps, len(_PHASES))
    lines = [f"Plan for: {goal} ({n} step(s))"]
    for i in range(n):
        lines.append(f"{i + 1}. {_PHASES[i]}")
    if max_steps > len(_PHASES):
        lines.append(
            f"note: capped at {len(_PHASES)} phase(s) "
            f"(requested {max_steps})"
        )
    return "\n".join(lines)


def _reflect(step: Any, observation: str, succeeded: bool,
             attempts: int, max_attempts: int) -> str:
    if succeeded:
        action = "ADVANCE"
        rec = "step succeeded; proceed to the next step"
    elif attempts < max_attempts:
        action = "RETRY"
        rec = (
            f"step failed; retry (attempt {attempts + 1}/{max_attempts})"
        )
    else:
        action = "REPLAN"
        rec = (
            f"step failed after {attempts}/{max_attempts} attempt(s); "
            f"revise the plan"
        )
    return (
        f"{action}: step={step} -> {rec}\n"
        f"observation: {observation}"
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "plan":
        goal = " ".join(str(args.get("goal") or "").split()).strip()
        if not goal:
            return "ERROR: goal is required for op=plan"
        try:
            max_steps = int(args.get("max_steps", 5))
        except (TypeError, ValueError):
            return "ERROR: max_steps must be an integer"
        if max_steps < 1:
            return "ERROR: max_steps must be >= 1"
        return _plan(goal, max_steps)
    if op == "reflect":
        if "succeeded" not in args:
            return "ERROR: succeeded (boolean) is required for op=reflect"
        succeeded = args.get("succeeded")
        if not isinstance(succeeded, bool):
            return "ERROR: succeeded must be a boolean"
        step = args.get("step")
        if step is None or str(step).strip() == "":
            return "ERROR: step is required for op=reflect"
        observation = " ".join(str(args.get("observation") or "").split()).strip()
        if not observation:
            return "ERROR: observation is required for op=reflect"
        try:
            attempts = int(args.get("attempts", 1))
        except (TypeError, ValueError):
            return "ERROR: attempts must be an integer"
        try:
            max_attempts = int(args.get("max_attempts", 3))
        except (TypeError, ValueError):
            return "ERROR: max_attempts must be an integer"
        if attempts < 1 or max_attempts < 1:
            return "ERROR: attempts and max_attempts must be >= 1"
        return _reflect(step, observation, succeeded, attempts, max_attempts)
    return f"ERROR: unknown op {op!r} (expected plan|reflect)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["plan", "reflect"]},
        "goal": {"type": "string", "description": "objective for op=plan"},
        "max_steps": {"type": "integer", "description": "max plan steps (default 5)"},
        "step": {"type": ["string", "integer"], "description": "step id for op=reflect"},
        "observation": {"type": "string", "description": "what was observed (op=reflect)"},
        "succeeded": {"type": "boolean", "description": "did the step succeed (op=reflect)"},
        "attempts": {"type": "integer", "description": "attempts so far (default 1)"},
        "max_attempts": {"type": "integer", "description": "retry budget (default 3)"},
    },
    "required": ["op"],
}


def reflect_loop() -> Tool:
    return Tool(
        name="reflect_loop",
        description=(
            "Plan-execute-reflect control-flow helper (deterministic, no model). "
            "op=plan with 'goal' [+'max_steps', default 5] -> an ordered step "
            "scaffold. op=reflect with 'step', 'observation', 'succeeded' "
            "[+'attempts', 'max_attempts'] -> a next-action recommendation: "
            "ADVANCE (succeeded), RETRY (failed, retries left), or REPLAN "
            "(failed, out of retries)."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
