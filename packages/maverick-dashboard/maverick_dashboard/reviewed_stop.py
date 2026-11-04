"""The same current-authority Stop service for dashboard, Copilot and devices."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from maverick import goal_stop
from maverick.authority_effects import authority_effect_fence
from pydantic import BaseModel, ConfigDict, Field

from . import auth

router = APIRouter()


class StopInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_updated_at: float = Field(ge=0, allow_inf_nan=False)
    expected_owner: str = Field(max_length=256)
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def _current(request, goal_id):
    from .app import _world
    auth.require_permission(request, "operate")
    world = _world()
    goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "This task is unavailable.")
    auth.assert_goal_access(request, goal)
    return world, goal, auth.caller_principal(request) or "local administrator"


def apply(request, goal_id, body):
    with authority_effect_fence():
        world, _goal, actor = _current(request, goal_id)
        try:
            return goal_stop.stop(world, goal_id, actor=actor, operation_id=body.operation_id,
                                  expected_updated_at=body.expected_updated_at, expected_owner=body.expected_owner)
        except goal_stop.GoalMutationConflict as exc:
            raise HTTPException(409, str(exc)) from exc


def recover(request, goal_id, body):
    with authority_effect_fence():
        world, _goal, actor = _current(request, goal_id)
        try:
            return goal_stop.receipt(world, goal_id, actor=actor, operation_id=body.operation_id,
                                     expected_updated_at=body.expected_updated_at, expected_owner=body.expected_owner)
        except goal_stop.GoalMutationConflict as exc:
            raise HTTPException(409, str(exc)) from exc


@router.post("/api/v1/goals/{goal_id}/stop-reviewed")
def stop_reviewed(request: Request, goal_id: int, body: StopInput):
    from .app import _require_same_origin
    _require_same_origin(request)
    return apply(request, goal_id, body)


@router.get("/api/v1/goals/{goal_id}/stop-progress")
def stop_progress(request: Request, goal_id: int):
    """Finished and remaining steps of a stopped task, for the halt card."""
    from .app import _world
    from .stop_progress import summarize
    auth.require_permission(request, "view")
    world = _world()
    goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "This task is unavailable.")
    auth.assert_goal_access(request, goal)
    return {"goal_id": goal_id, "status": goal.status, "progress": summarize(world, goal)}
