"""The file journal's list and undo, on the task files page.

``maverick journal list`` and ``maverick journal revert`` in the app. Both call
the kernel's own :func:`maverick.workspace_journal.list_entries` and
:func:`maverick.workspace_journal.revert_goal` (which writes its signed audit
row before it changes any file and archives the journal afterwards).

The journal's records are files someone with disk access could edit, and each
record names its own folder. So before an undo is allowed, every record must
name exactly this task's own work folder, a safe relative file name, and a
path with no links on the way (the same checks the read-only "what changed"
view makes). One unsafe record refuses the whole undo: nothing is changed.
Access is the task-files page's: operate permission, a named owner in the
selected workspace, the task's department and the per-task access check.
"""
from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import assert_goal_access

router = APIRouter(tags=["task-file-recovery"])
BASE = "/api/v1/task-files"
MAX_LISTED = 500
_LIVE = frozenset({"running", "active"})


class JournalUndoIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    preview: bool = True
    partial: bool = False
    confirm: bool = False


def _access(request: Request, goal_id: int, payload: JournalUndoIn | None = None):
    from .task_file_recovery_api import _authority

    world, actor, context = _authority(request, goal_id)
    goal = world.get_goal(goal_id)
    assert_goal_access(request, goal)
    if payload is not None:
        from .app import _require_same_origin

        _require_same_origin(request)
        if not hmac.compare_digest(payload.context, context):
            raise HTTPException(409, "Your account or workspace changed. Reload this page.")
    return world, goal, actor, context


def _names(entries: list[dict]) -> list[dict]:
    from maverick.workspace_journal import _safe_rel

    rows = []
    for entry in entries[:MAX_LISTED]:
        name = _safe_rel(entry)
        rows.append({
            "file": name or "",
            "change": "existed" if entry.get("existed") else "created",
            "saved": bool(entry.get("blob")) or not entry.get("existed"),
            "unsafe": name is None,
        })
    return rows


def journal_listing(goal_id: int) -> dict:
    """``maverick journal list`` for one task, bounded and people-readable."""
    from maverick import workspace_journal

    from .task_changes_api import _journal_records

    _journal_records(goal_id)  # refuses a history folder shared between workspaces
    entries = workspace_journal.list_entries(goal_id)
    incomplete = workspace_journal.is_capped(goal_id) or any(e.get("skipped_reason") for e in entries)
    return {
        "recording": workspace_journal.enabled(),
        "count": len(entries),
        "entries": _names(entries),
        "more": max(0, len(entries) - MAX_LISTED),
        "incomplete": bool(incomplete),
    }


def _assert_contained(world, goal_id: int, entries: list[dict]) -> None:
    """Every record must point inside this task's own work folder, safely."""
    from pathlib import Path

    from .task_changes_api import Refused, _Skip, read_inside, safe_parts, work_folder

    root = work_folder(world, goal_id)
    for entry in entries:
        try:
            parts = safe_parts(entry.get("path"))
            recorded = entry.get("workdir")
            if not isinstance(recorded, str) or not Path(recorded).is_absolute():
                raise _Skip("unsafe")
            if Path(recorded).resolve(strict=False) != root:
                raise _Skip("unsafe")
            read_inside(root, parts)
        except _Skip as skip:
            if skip.kind == "too_large":
                continue  # large files are still restored; only unsafe ones refuse
            raise Refused("Some recorded changes point outside this task's work folder or through a "
                          "shortcut link, so nothing was undone. An administrator can check the task's "
                          "file history.") from skip
        except (OSError, RuntimeError, ValueError) as exc:
            raise Refused("This task's recorded changes can't be checked safely, so nothing was undone.") from exc


def journal_undo(world, goal, goal_id: int, payload: JournalUndoIn) -> dict:
    """``maverick journal revert`` (``--dry-run`` when previewing)."""
    from maverick import workspace_journal

    from .task_changes_api import _journal_records

    _journal_records(goal_id)
    entries = workspace_journal.list_entries(goal_id)
    if not entries:
        return {"done": False, "preview": payload.preview, "message":
                "There are no recorded file changes to undo for this task."}
    _assert_contained(world, goal_id, entries)
    if not payload.preview:
        if payload.confirm is not True:
            raise HTTPException(409, "Confirm that you want to undo these file changes.")
        if str(getattr(goal, "status", "")) in _LIVE:
            raise HTTPException(409, "Stop this task before undoing its file changes.")
    try:
        result = workspace_journal.revert_goal(goal_id, partial=payload.partial, dry_run=payload.preview)
    except ValueError as exc:
        raise HTTPException(409, "Some of this task's changes weren't fully recorded, so a complete undo "
                                 "isn't possible. Choose to undo only what was recorded.") from exc
    return {
        "done": not payload.preview,
        "preview": payload.preview,
        "restored": int(result.get("reverted", 0)),
        "removed": int(result.get("deleted", 0)),
        "skipped": int(result.get("skipped", 0)),
        "complete": bool(result.get("complete", False)),
    }


async def _run(request: Request, response: Response, operation):
    from .task_changes_api import Refused

    response.headers["Cache-Control"] = "private, no-store"
    try:
        return await run_in_threadpool(operation)
    except HTTPException:
        raise
    except Refused as exc:
        return {"available": False, "message": str(exc)}
    except PermissionError as exc:
        raise HTTPException(403, "You can't change this task's files right now.") from exc
    except Exception as exc:
        from maverick.audit import AuditRefused

        if isinstance(exc, AuditRefused):
            raise HTTPException(503, "The activity log couldn't record the undo, so nothing was changed.") from exc
        raise HTTPException(503, "The file history couldn't be loaded. Try again in a moment.") from exc


@router.get(BASE + "/{goal_id}/journal")
async def journal_list(request: Request, response: Response, goal_id: int):
    """Read-only: every file write the journal recorded for this task."""
    def operation():
        _, _, _, context = _access(request, goal_id)
        return {"context": context, "available": True, **journal_listing(goal_id)}
    return await _run(request, response, operation)


@router.post(BASE + "/{goal_id}/journal/undo")
async def journal_undo_route(request: Request, response: Response, goal_id: int, body: JournalUndoIn):
    """Preview (nothing changes) or, confirmed, undo this task's recorded file changes."""
    def operation():
        world, goal, _, context = _access(request, goal_id, body)
        return {"context": context, "available": True, **journal_undo(world, goal, goal_id, body)}
    return await _run(request, response, operation)
