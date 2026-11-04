"""Branch or rewind a task from the dashboard (also available on the command line).

* ``POST /run-tree/{goal_id}/fork`` records a new branch of a task that starts
  from a chosen step (``maverick run-tree fork``). Nothing is re-executed.
* ``GET /run-tree/{goal_id}/checkpoints`` lists the saved steps a task can go
  back to.
* ``POST /run-tree/{goal_id}/rewind`` goes back to one of those steps, either
  on the task itself or as a new copy (``maverick rewind``).

Each action needs the ``operate`` permission and access to the task, exactly
like the task's other controls.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .auth import assert_goal_access, require_permission

router = APIRouter(prefix="/run-tree", tags=["run-tree"])


class ForkIn(BaseModel):
    at_event: int | None = Field(default=None, ge=1)
    label: str = Field(default="", max_length=200)


class RewindIn(BaseModel):
    to_step: int = Field(ge=0)
    as_copy: bool = True


def _goal(request: Request, goal_id: int):
    from ._shared import _world

    world = _world()
    goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(status_code=404, detail="no such task")
    assert_goal_access(request, goal)
    return world, goal


@router.post("/{goal_id}/fork", status_code=201)
async def fork_task(request: Request, goal_id: int, body: ForkIn) -> dict:
    """Branch a task at one of its steps; returns the new branch's id."""
    require_permission(request, "operate")
    from maverick import session_tree

    from .request_identity import request_actor as _request_actor

    _goal(request, goal_id)
    try:
        child = await run_in_threadpool(
            session_tree.fork, goal_id, at_event=body.at_event,
            label=body.label, forked_by=_request_actor(request),
        )
    except session_tree.SessionTreeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"goal_id": child, "parent_goal_id": goal_id}


@router.get("/{goal_id}/checkpoints")
async def task_checkpoints(request: Request, goal_id: int) -> dict:
    """The saved steps this task can go back to (empty when none were kept)."""
    require_permission(request, "operate")
    from maverick.checkpoint import Checkpointer

    world, _goal_row = _goal(request, goal_id)

    def read() -> list[int]:
        ck = Checkpointer(world)
        found = ck.orchestrator_for(goal_id)
        if found is None:
            return []
        agent_id, episode_id = found
        return ck.list_steps(goal_id, agent_id, episode_id)

    steps = await run_in_threadpool(read)
    return {"goal_id": goal_id, "steps": steps}


_RUNNING = frozenset({"active", "running"})
# Statuses a worker may start from (the queue claims these).
_WAITING = frozenset({"pending", "queued"})


@router.post("/{goal_id}/rewind")
async def rewind_task(request: Request, goal_id: int, body: RewindIn) -> dict:
    """Go back to a saved step, on the task itself or as a new copy.

    A task that is still running is refused: going back under a live run would
    race the worker that is writing its steps. A task waiting to run is refused
    too when going back on the task itself, because a worker may pick it up at
    any moment while its steps are being cut back."""
    require_permission(request, "operate")
    from maverick.checkpoint import rewind

    from .request_identity import request_actor as _request_actor

    world, goal = _goal(request, goal_id)
    status = getattr(goal, "status", "")
    if status in _RUNNING or (not body.as_copy and status in _WAITING):
        raise HTTPException(
            status_code=409,
            detail="This task is running or waiting to run. Stop it before going back to an earlier step.")
    actor = _request_actor(request)
    result = await run_in_threadpool(rewind, world, goal_id, body.to_step, fork=body.as_copy)
    if not result.ok:
        raise HTTPException(status_code=409, detail="that step can't be restored")
    target = result.forked_goal_id or goal_id
    owner = getattr(goal, "owner", "") or ""
    if result.forked_goal_id and owner:
        # The copy belongs to the same person as the original task.
        await run_in_threadpool(world.bind_goal_owner, result.forked_goal_id, owner)
    note = (f"went back to step {result.target_step} as a new copy of task #{goal_id}"
            if result.forked_goal_id else f"went back to step {result.target_step}")
    await run_in_threadpool(world.append_event, target, "dashboard", "status", f"{note} (by {actor})")
    return {"goal_id": target, "to_step": result.target_step, "copied": bool(result.forked_goal_id)}


__all__ = ["router"]
