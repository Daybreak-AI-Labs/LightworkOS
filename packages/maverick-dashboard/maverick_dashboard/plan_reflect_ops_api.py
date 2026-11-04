"""Show planning steps: the plan-execute-reflect loop for one task, read-only.

``maverick plan-reflect`` on the task page. It runs
:func:`maverick.plan_execute_reflect.run_plan_execute_reflect` on the task's
own request and returns the trace (the plan, what each step produced, each
review and the final status). The task itself is never changed or restarted.

The loop calls AI, so it is admitted exactly like "Get two viewpoints": the
task page's access check, ``operate``, emergency stop, the person's quota and
spending limits, the workspace allowance, a budget capped at ``MAX_DOLLARS``,
provider admission inside ``LLM`` and settlement to the usage ledger. The
model comes from the configured ``orchestrator`` role, as in the command. It
runs as a background job the page polls; one audit row is written before any
spend and one when it ends.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from .auth import (
    assert_goal_access,
    caller_principal,
    execution_user_id_from_request,
    require_permission,
)

log = logging.getLogger(__name__)
router = APIRouter(tags=["planning-steps"])
MAX_DOLLARS = 2.0
MAX_TEXT = 4000


class PlanningStepsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    passes: int = Field(default=2, ge=1, le=3)


def _goal_text(goal) -> str:
    text = " ".join(str(getattr(goal, "description", "") or getattr(goal, "title", "") or "").split())
    return text[:MAX_TEXT]


def _trace(goal_text: str, passes: int, principal: str, actor: str, goal_id: int) -> dict:
    from maverick.audit import audit_event
    from maverick.budget import BudgetExceeded
    from maverick.llm import LLM, model_for_role
    from maverick.orchestrator import _QuotaUsageSettlement
    from maverick.plan_execute_reflect import run_plan_execute_reflect
    from maverick.spending_limits import SpendingLimitReached
    from maverick.tenant.provider_admission import run_scope

    from .viewpoints_api import _admit, _Refused

    try:
        budget = _admit(principal, MAX_DOLLARS)
    except _Refused as exc:
        return {"ran": False, "message": str(exc)}
    settlement = _QuotaUsageSettlement(principal=principal, budget=budget, domain=None)
    try:
        audit_event("planning_steps_run", agent="dashboard", goal_id=goal_id, actor=actor, phase="start",
                    passes=passes, max_dollars=budget.max_dollars)
    except Exception:
        settlement.record()
        return {"ran": False, "message": "The activity log couldn't record this request, so nothing was started."}
    llm = LLM(model=model_for_role("orchestrator"))
    outcome = "failed"
    try:
        with run_scope(budget, principal):
            result = run_plan_execute_reflect(goal_text, planner_complete=llm.complete,
                                              executor_complete=llm.complete, reflector_complete=llm.complete,
                                              max_iterations=passes, budget=budget)
        review_unavailable = any(r.notes == "reflector JSON parse failed" for r in result.reflections)
        no_plan = not result.plan and not result.results
        outcome = "incomplete" if no_plan or review_unavailable else str(result.status)
    except SpendingLimitReached as exc:
        outcome = "stopped"
        return {"ran": False, "message": str(exc)}
    except BudgetExceeded:
        outcome = "stopped"
        return {"ran": False, "message": f"This stopped at the limit for one request (at most ${budget.max_dollars:,.2f})."}
    finally:
        settlement.record()
        try:
            audit_event("planning_steps_run", agent="dashboard", goal_id=goal_id, actor=actor, phase="end",
                        outcome=outcome, dollars=round(float(budget.dollars), 4))
        except Exception:  # spend already happened; never hide the result
            log.warning("planning steps: completion audit row not written", exc_info=True)
    return {
        "ran": True,
        "plan": [str(step)[:500] for step in result.plan][:20],
        "steps": [{"step": str(r.step)[:500], "output": str(r.output or "")[:MAX_TEXT]} for r in result.results][:60],
        "reviews": [{
            "verdict": "unavailable" if no_plan or r.notes == "reflector JSON parse failed" else str(r.status),
            "notes": ("The AI review could not be read, so it did not confirm this attempt."
                      if r.notes == "reflector JSON parse failed" else str(r.notes or "")[:1000]),
        } for r in result.reflections][:10],
        "status": "no_plan" if no_plan else "review_unavailable" if review_unavailable else str(result.status),
        "passes": int(result.iterations),
        "cost": round(float(result.total_dollars), 4),
    }


def _goal(request: Request, goal_id: int):
    from .app import _world

    goal = _world().get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "no such goal")
    assert_goal_access(request, goal)
    return goal


@router.post("/api/v1/goals/{goal_id}/planning-steps", status_code=202)
async def start_planning_steps(request: Request, goal_id: int, body: PlanningStepsIn) -> dict:
    from maverick.orchestrator import _execution_principal

    from ._shared import require_provider_or_400
    from .app import _require_same_origin
    from .ops_jobs import JOBS, Busy, identity

    require_permission(request, "operate")
    _require_same_origin(request)
    goal = _goal(request, goal_id)
    text = _goal_text(goal)
    if len(text) < 3:
        raise HTTPException(422, "This task has no request to plan from.")
    try:
        require_provider_or_400(role="orchestrator")
    except HTTPException as exc:
        raise HTTPException(400, "AI isn't connected yet. Finish connecting AI in setup, then try again.") from exc
    principal = _execution_principal(user_id=execution_user_id_from_request(request), capability=None)
    actor = caller_principal(request) or principal
    owner, tenant = identity(request)
    try:
        job = JOBS.start(owner=owner, tenant=tenant, kind=f"planning:{goal_id}",
                         work=lambda: _trace(text, body.passes, principal, actor, goal_id))
    except Busy as exc:
        raise HTTPException(429, "Planning steps are already being prepared. Wait for them to finish.") from exc
    return {"job": job}


@router.get("/api/v1/goals/{goal_id}/planning-steps/{job_id}")
async def planning_steps_status(request: Request, goal_id: int, job_id: str) -> dict:
    from .ops_jobs import JOBS, identity

    require_permission(request, "operate")
    _goal(request, goal_id)
    owner, tenant = identity(request)
    job = JOBS.get(job_id[:64], owner=owner, tenant=tenant, kind=f"planning:{goal_id}")
    if job is None:
        raise HTTPException(404, "no such job")
    return job
