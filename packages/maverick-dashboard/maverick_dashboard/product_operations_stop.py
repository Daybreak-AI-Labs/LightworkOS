"""Reviewed Stop preserves partial results and separates request from cleanup."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import reviewed_stop as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot
from .product_operations_tasks import _task


def snapshot(request, selection):
    _world, goal = _task(request, selection, write=True)
    details = {"goal_id": goal.id, "title": goal.title, "status": goal.status,
               "updated_at": float(goal.updated_at), "owner": goal.owner or ""}
    return Snapshot(digest(details), "Current task owner, execution status and revision",
        "Request cooperative Stop. Previously committed external effects cannot be undone; partial results remain available.",
        details, blocked="This task already stopped or finished." if goal.status in native.goal_stop.TERMINAL else "")


def prepare(request, selection, _arguments):
    state = snapshot(request, selection)
    return Preview(state.summary, [{"label": "Task", "after": state.details["title"]},
        {"label": "Execution", "before": state.details["status"], "after": "Stop requested; cleanup must still finish"}],
        {"expected_updated_at": state.details["updated_at"], "expected_owner": state.details["owner"]})


def _outcome(result):
    return Outcome("replayed" if result["replayed"] else "confirmed",
                   "Stop requested. Check task progress for cleanup; already committed external effects cannot be undone.", result)


def execute(request, selection, _arguments, prepared, operation_id):
    _world, goal = _task(request, selection, write=True)
    return _outcome(native.apply(request, goal.id, native.StopInput(**prepared, operation_id=operation_id)))


def recover(request, selection, _arguments, prepared, operation_id):
    _world, goal = _task(request, selection, write=True)
    result = native.recover(request, goal.id, native.StopInput(**prepared, operation_id=operation_id))
    return _outcome(result) if result else None


def entries():
    return (Adapter("tasks.stop", "Request Stop on this task", "tasks", "/chat", ("/chat/goal/*", "/goals/*"),
                    EmptyInput, snapshot, prepare, execute, recover, read_recovery=recover),)
