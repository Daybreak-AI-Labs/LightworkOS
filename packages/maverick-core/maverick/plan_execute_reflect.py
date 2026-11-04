"""Plan-execute-reflect loop topology.

A classic long-horizon control loop as a standalone topology helper, in the
same shape as :mod:`maverick.debate`: a **planner** breaks the goal into steps,
an **executor** runs each step, and a **reflector** reads the results and
decides whether the work is DONE, needs another pass with a REVISEd plan, or
should CONTINUE the current plan. The loop repeats until the reflector says
DONE, the iteration cap is hit, or the budget runs out.

Like the other topology helpers this works against any ``complete``-style
callable (``system, messages, ..., budget=, max_tokens=, model=``) returning an
object with ``.text``, so plain LLM instances or full Agents both fit. Wiring
into real sub-agents is the orchestrator's / CLI's call.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .budget import Budget, BudgetExceeded

log = logging.getLogger(__name__)

_PLANNER_SYSTEM = (
    "You are a planner. Break the goal into a short ordered list of concrete "
    "steps. Reply with STRICT JSON: {\"steps\": [\"<step>\", ...]}."
)
_REFLECTOR_SYSTEM = (
    "You are a reflector reviewing executed work against the goal. Decide if "
    "the goal is met. Reply with STRICT JSON: {\"status\": \"done|revise|continue\", "
    "\"notes\": \"<short>\", \"revised_plan\": [\"<step>\", ...]}. Include "
    "revised_plan only when status is 'revise'."
)


@dataclass
class StepResult:
    step: str
    output: str


@dataclass
class Reflection:
    status: str           # "done" | "revise" | "continue"
    notes: str
    revised_plan: list[str] = field(default_factory=list)


@dataclass
class PlanExecuteReflectResult:
    goal: str
    plan: list[str]
    results: list[StepResult]
    reflections: list[Reflection]
    iterations: int
    status: str           # terminal status: "done" | "max_iterations" | "stalled"
    total_dollars: float


def _strip_fence(raw: str) -> str:
    raw = (raw or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw.removeprefix("json")
        raw = raw.strip()
    return raw


def _complete_text(fn: Callable[..., Any], system: str, prompt: str, *, budget: Budget,
                   max_tokens: int, model: str | None) -> str:
    resp = fn(
        system=system,
        messages=[{"role": "user", "content": prompt}],
        budget=budget, max_tokens=max_tokens, model=model,
    )
    return (getattr(resp, "text", "") or "").strip()


def _plan(planner: Callable[..., Any], goal: str, *, budget: Budget,
          model: str | None) -> list[str]:
    raw = _strip_fence(_complete_text(
        planner, _PLANNER_SYSTEM, f"GOAL:\n{goal}\n\nProduce the plan.",
        budget=budget, max_tokens=400, model=model,
    ))
    try:
        steps = json.loads(raw).get("steps", [])
        return [str(s) for s in steps if str(s).strip()]
    except (ValueError, TypeError, AttributeError) as e:
        log.warning("planner returned malformed JSON: %s", e)
        return []


def _reflect(reflector: Callable[..., Any], goal: str, results: list[StepResult],
             *, budget: Budget, model: str | None) -> Reflection:
    done = "\n\n".join(f"STEP: {r.step}\nOUTPUT: {r.output}" for r in results) or "(nothing executed)"
    raw = _strip_fence(_complete_text(
        reflector, _REFLECTOR_SYSTEM,
        f"GOAL:\n{goal}\n\nEXECUTED:\n{done}\n\nAssess and reply with the JSON object.",
        budget=budget, max_tokens=400, model=model,
    ))
    try:
        data = json.loads(raw)
        status = str(data.get("status") or "continue").lower()
        if status not in ("done", "revise", "continue"):
            status = "continue"
        revised = [str(s) for s in (data.get("revised_plan") or []) if str(s).strip()]
        return Reflection(status=status, notes=str(data.get("notes") or ""), revised_plan=revised)
    except (ValueError, TypeError, AttributeError) as e:
        log.warning("reflector returned malformed JSON: %s", e)
        # Fail SAFE, not SUCCESS: a reflector we can't parse must not be read as
        # "goal met". Return 'continue' with no revised plan so the loop's
        # fail-safe (below) marks the run "stalled" rather than "done".
        return Reflection(status="continue", notes="reflector JSON parse failed")


def run_plan_execute_reflect(
    goal: str,
    *,
    planner_complete: Callable[..., Any],
    executor_complete: Callable[..., Any],
    reflector_complete: Callable[..., Any],
    max_iterations: int = 3,
    budget: Budget | None = None,
    model: str | None = None,
) -> PlanExecuteReflectResult:
    """Run the plan → execute → reflect loop until DONE / cap / budget.

    Each iteration: (re)plan if needed, execute every step, then reflect. A
    'revise' verdict swaps in the reflector's revised plan for the next pass;
    'done' stops; 'continue' with no revision is treated as stalled (stop) so
    the loop can't spin. Returns the full plan/results/reflections trace.
    """
    if not goal or not goal.strip():
        raise ValueError("goal must be non-empty")
    if max_iterations < 1:
        raise ValueError("max_iterations must be >= 1")
    if budget is None:
        from .budget import budget_from_config
        budget = budget_from_config()
    start_dollars = budget.dollars

    plan = _plan(planner_complete, goal, budget=budget, model=model)
    all_results: list[StepResult] = []
    reflections: list[Reflection] = []
    status = "max_iterations"

    for _i in range(max_iterations):
        iter_results: list[StepResult] = []
        for step in plan:
            try:
                out = _complete_text(
                    executor_complete,
                    "You are an executor. Carry out the single step and report the result.",
                    f"GOAL:\n{goal}\n\nSTEP:\n{step}\n\nDo it and report the outcome.",
                    budget=budget, max_tokens=600, model=model,
                )
            except BudgetExceeded:
                raise
            except Exception as e:
                log.warning("execute step failed (%s): %s", step, e)
                out = f"(step failed: {e})"
            iter_results.append(StepResult(step=step, output=out))
        all_results.extend(iter_results)

        reflection = _reflect(reflector_complete, goal, iter_results, budget=budget, model=model)
        reflections.append(reflection)
        if reflection.status == "done":
            status = "done"
            break
        if reflection.status == "revise" and reflection.revised_plan:
            plan = reflection.revised_plan
            continue
        # 'continue' with no revised plan, or 'revise' with an empty plan: stop.
        status = "stalled"
        break

    return PlanExecuteReflectResult(
        goal=goal,
        plan=plan,
        results=all_results,
        reflections=reflections,
        iterations=len(reflections),
        status=status,
        total_dollars=budget.dollars - start_dollars,
    )


__all__ = [
    "StepResult", "Reflection", "PlanExecuteReflectResult",
    "run_plan_execute_reflect",
]
