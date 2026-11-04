"""Reviewed task restart through the native admission and exact receipt."""
from __future__ import annotations

from fastapi import BackgroundTasks
from maverick.governed_operations import digest
from pydantic import Field

from . import reviewed_resume as native
from .api_schemas import GoalResumeIn
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput
from .product_operations_tasks import _task


class RestartInput(StrictInput):
    max_dollars: float | None = Field(default=None, gt=0, allow_inf_nan=False)


def snapshot(request, selection):
    _world, goal = _task(request, selection, write=True)
    value = native.status(request, goal.id)
    return Snapshot(digest(value), "Current task restart admission and workspace spending limit",
        value["consequence"], value,
        [{"name": "max_dollars", "label": "Maximum dollars for this new attempt (blank uses workspace defaults)",
          "kind": "number"}], value["blocked"])


def prepare(request, selection, args):
    state = snapshot(request, selection)
    native.limits(request, state.details["goal_id"], args["max_dollars"])
    return Preview("Explicitly authorize one new attempt. Inspect the previous task's external effects before retrying uncertain work.",
        [{"label": "Task", "after": state.details["title"]},
         {"label": "Unanswered questions", "after": state.details["unanswered_questions"]},
         {"label": "Attempt spending limit", "after": args["max_dollars"] if args["max_dollars"] is not None else "Current workspace defaults"},
         {"label": "Previous external outcomes", "after": "Not certified by this restart. Earlier actions are not undone."}],
        {key: state.details[key] for key in ("goal_id", "expected_updated_at", "expected_owner", "context")})


def _body(args, prepared, operation_id):
    return GoalResumeIn(expected_context=prepared["context"], max_dollars=args["max_dollars"], operation_id=operation_id,
        expected_updated_at=prepared["expected_updated_at"], expected_owner=prepared["expected_owner"])


def recover(request, selection, args, prepared, operation_id):
    _world, goal = _task(request, selection, write=True)
    result = native.recover(request, goal.id, _body(args, prepared, operation_id))
    return Outcome("replayed", "The reviewed restart was already admitted. No second attempt was dispatched.", result) if result else None


def execute(request, selection, args, prepared, operation_id):
    _world, goal = _task(request, selection, write=True)
    background = BackgroundTasks()
    result = native.apply(request, goal.id, background, _body(args, prepared, operation_id))
    return Outcome("replayed" if result["replayed"] else "queued",
        "Restart admission was recorded. Check current task progress to confirm execution; earlier external effects remain separate.",
        {**result, "task": {"label": "Open task progress", "href": f"/chat/goal/{goal.id}"}}, background=background)


def entries():
    return (Adapter("tasks.resume", "Review and restart this task", "tasks", "/chat", ("/chat/goal/*", "/goals/*"),
                    RestartInput, snapshot, prepare, execute, recover, read_recovery=recover),)
