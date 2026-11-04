"""Reviewed task-map controls using native authorization, CAS and receipts."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput
from .product_operations_tasks import _task

PAGES = ("/graph-editor", "/chat/goal/*", "/goals/*")


class RenameInput(StrictInput):
    title: str = Field(min_length=1, max_length=200)


class MoveInput(StrictInput):
    parent: str = Field(pattern=r"^(root|[1-9][0-9]*)$")


def _current(request, selection):
    from maverick.goal_mutations import GoalMutationConflict
    from maverick.task_handoffs import require_open

    world, goal = _task(request, selection, write=True)
    try:
        require_open(world, goal.id)
    except GoalMutationConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    return world, goal


def _details(goal):
    return {"goal_id": goal.id, "title": goal.title, "parent_id": goal.parent_id,
            "revision": float(goal.updated_at), "href": "/graph-editor"}


def _blocked(world, goal):
    from maverick.goal_mutations import GoalMutationConflict
    from maverick.task_handoffs import require_open

    try:
        require_open(world, goal.id)
    except GoalMutationConflict as exc:
        return str(exc)
    return ""


def rename_snapshot(request, selection):
    world, goal = _task(request, selection, write=True)
    details = _details(goal)
    return Snapshot(digest(details), "Current task-map title and reviewed version", goal.title, details,
                    [{"name": "title", "label": "Task title", "kind": "text", "required": True,
                      "max_length": 200, "value": goal.title}], blocked=_blocked(world, goal))


def _parents(request, world, goal):
    from maverick.goal_mutations import GoalMutationConflict, assert_move_boundary
    from maverick.task_handoffs import require_open

    # The native map uses the same bounded owner-scoped inventory. Never inspect
    # another owner's source content to populate a convenience control.
    result = []
    for parent in world.list_goals(owner=auth.goal_owner_filter(request), limit=300):
        if parent.id == goal.id or (parent.owner or "") != (goal.owner or ""):
            continue
        current, seen = parent, set()
        allowed = True
        while current is not None:
            if current.id == goal.id or current.id in seen or len(seen) >= 100:
                allowed = False
                break
            seen.add(current.id)
            current = world.get_goal(current.parent_id) if current.parent_id is not None else None
        if not allowed:
            continue
        try:
            require_open(world, parent.id)
            assert_move_boundary(world, goal.id, parent.id)
        except GoalMutationConflict:
            continue
        result.append({"id": parent.id, "title": parent.title, "revision": float(parent.updated_at)})
    return result


def move_snapshot(request, selection):
    from maverick.goal_mutations import GoalMutationConflict, assert_move_boundary

    world, goal = _task(request, selection, write=True)
    blocked = _blocked(world, goal)
    details = {**_details(goal), "parents": [] if blocked else _parents(request, world, goal)}
    choices = []
    try:
        assert_move_boundary(world, goal.id, None)
        choices.append({"value": "root", "label": "Keep as a main task"})
    except GoalMutationConflict:
        pass
    choices.extend({"value": str(parent["id"]), "label": parent["title"]} for parent in details["parents"])
    return Snapshot(digest(details), "Current task and permitted task-map destinations", goal.title, details,
                    [{"name": "parent", "label": "New parent task", "kind": "select", "required": True,
                      "choices": choices, "value": str(goal.parent_id) if goal.parent_id is not None else "root"}], blocked=blocked)


def rename_preview(request, selection, args):
    _world, goal = _current(request, selection)
    title = args["title"].strip()
    if not title:
        raise HTTPException(422, "Enter a task title before reviewing this change.")
    return Preview("Rename this task. Its result, ownership and execution state stay the same.",
                   [{"label": "Task title", "before": goal.title, "after": title}],
                   {"title": title, "expected_updated_at": float(goal.updated_at), "move": False})


def move_preview(request, selection, args):
    state = move_snapshot(request, selection)
    if state.blocked:
        raise HTTPException(409, state.blocked)
    if args["parent"] not in {row["value"] for row in state.fields[0]["choices"]}:
        raise HTTPException(409, "Choose a current permitted destination. A map edit cannot change inherited handoff spending limits.")
    parent_id = None if args["parent"] == "root" else int(args["parent"])
    parent = next((row for row in state.details["parents"] if row["id"] == parent_id), None)
    if parent_id is not None and parent is None:
        raise HTTPException(409, "Choose a currently available parent from the task map.")
    return Preview("Move this task in your map. This does not start work, change ownership or grant access.",
                   [{"label": "Task", "after": state.details["title"]},
                    {"label": "Parent task", "before": state.details["parent_id"],
                     "after": parent["title"] if parent else "Main task"}],
                   {"parent_id": parent_id, "expected_updated_at": state.details["revision"], "move": True})


def recover(request, selection, args, native, operation_id):
    from maverick.goal_mutations import GoalMutationConflict, structure_receipt

    # Original owners can inspect their own receipt after a handoff closes work;
    # recovery reads never reopen execution or reapply a historical mutation.
    world, goal = _task(request, selection, write=True)
    try:
        result = structure_receipt(world, goal.id, **native, operation_id=operation_id,
                                   actor=auth.caller_principal(request) or "local administrator")
    except GoalMutationConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    if result is None:
        return None
    return Outcome("replayed", "This map edit was already saved. The receipt identifies that version; the task may have changed later.", result)


def execute(request, selection, args, native, operation_id):
    from .api import reparent_goal, retitle_goal
    from .api_schemas import ReparentIn, RetitleIn

    prior = recover(request, selection, args, native, operation_id)
    if prior is not None:
        return prior
    _world, goal = _current(request, selection)
    if native["move"]:
        reparent_goal(request, goal.id, ReparentIn(parent_id=native["parent_id"],
                      expected_updated_at=native["expected_updated_at"], operation_id=operation_id))
    else:
        retitle_goal(request, goal.id, RetitleIn(title=native["title"],
                     expected_updated_at=native["expected_updated_at"], operation_id=operation_id))
    result = recover(request, selection, args, native, operation_id)
    if result is None:
        return Outcome("unconfirmed", "The map edit could not be confirmed. Read current task state before retrying.")
    return Outcome("confirmed", "The reviewed task-map change was saved. No task was started.",
                   {**result.details, "replayed": False})


def entries():
    return (
        Adapter("tasks.rename", "Rename the selected task", "tasks", "/graph-editor", PAGES,
                RenameInput, rename_snapshot, rename_preview, execute, recover,
                aliases=("rename this task", "change task title")),
        Adapter("tasks.move", "Move the selected task", "tasks", "/graph-editor", PAGES,
                MoveInput, move_snapshot, move_preview, execute, recover,
                aliases=("move this task", "change parent task")),
    )
