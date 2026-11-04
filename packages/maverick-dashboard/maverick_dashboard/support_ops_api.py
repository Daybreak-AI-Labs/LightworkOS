"""Locally reviewed task support drafts for customer-controlled sharing."""
from __future__ import annotations

from datetime import date, datetime, time, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import assert_goal_access, goal_owner_filter, require_permission

router = APIRouter(prefix="/api/v1/support/issue-report")
asset_router = APIRouter()
_STATIC = Path(__file__).parent / "static"
_STOPPED = ("blocked", "failed")


@asset_router.get("/static/lightwork-support-ops.js", include_in_schema=False)
async def support_ops_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-support-ops.js", media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


def _world():
    from ._shared import _world as shared
    return shared()


def _day(value: str, *, end: bool = False) -> float | None:
    if not value:
        return None
    try:
        parsed = date.fromisoformat(value)
        if parsed.isoformat() != value:
            raise ValueError("not an ISO date")
        return datetime.combine(parsed, time.max if end else time.min, timezone.utc).timestamp()
    except ValueError:
        raise HTTPException(422, "Choose a valid date in year-month-day order.") from None


def _page_states(world, owner, offset: int) -> list[tuple[int, str, float | None]]:
    """One page of the newest goals as ``(id, status, updated_at)``, without
    decrypting the goals the picker will not show."""
    states = getattr(world, "goal_states", None)
    if callable(states):
        return states(owner=owner, limit=100, offset=offset, order="desc")
    return [(g.id, g.status, g.updated_at)
            for g in world.list_goals(owner=owner, limit=100, offset=offset, order="desc")]


def _task(request, world, task):
    goal = world.get_goal(task)
    if goal is None:
        raise HTTPException(404, "That task is unavailable. Refresh the list.")
    assert_goal_access(request, goal)
    return goal


@router.get("/tasks")
async def stopped_tasks(
    request: Request, response: Response, query: str = Query(default="", max_length=160),
    offset: int = Query(default=0, ge=0), after: str = "", before: str = "",
    selected: int | None = Query(default=None, ge=1, le=2**53),
) -> dict:
    require_permission(request, "view")
    response.headers["Cache-Control"] = "private, no-store"
    owner = goal_owner_filter(request)
    start, end = _day(after), _day(before, end=True)
    if start is not None and end is not None and start > end:
        raise HTTPException(422, "The start date must be on or before the end date.")

    def read() -> dict:
        from maverick.world_model import goals_by_id

        world = _world()
        rows, cursor, scanned = [], offset, 0
        # Bound work per request, but expose a continuation over the complete
        # authorized history rather than silently discarding older records.
        more = True
        while len(rows) < 25 and scanned < 2000:
            page = _page_states(world, owner, cursor)
            if not page:
                more = False
                break
            # Decrypt only the stopped goals on this page, in one read.
            stopped = goals_by_id(world, [gid for gid, status, _ in page if status in _STOPPED])
            for gid, status, _ in page:
                cursor += 1
                scanned += 1
                if status not in _STOPPED:
                    continue
                goal = stopped.get(gid)
                if goal is None:
                    continue
                try:
                    assert_goal_access(request, goal)
                except HTTPException as exc:
                    if exc.status_code not in (403, 404):
                        raise
                    continue
                when = goal.updated_at or 0
                if (query.casefold() not in (goal.title or "").casefold()
                        or (start is not None and when < start) or (end is not None and when > end)):
                    continue
                rows.append({"id": goal.id, "title": (goal.title or "Untitled task")[:160], "when": when})
                if len(rows) == 25:
                    break
        chosen = None
        if selected is not None:
            goal = _task(request, world, selected)
            if goal.status in _STOPPED:
                chosen = {"id": goal.id, "title": (goal.title or "Untitled task")[:160], "when": goal.updated_at}
        return {"tasks": rows, "next_offset": cursor if more else None, "selected": chosen}

    return await run_in_threadpool(read)


class IssueIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task: int = Field(ge=1, le=2**53)


class ReviewedIssueIn(IssueIn):
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1, max_length=6000)


@router.post("")
async def issue_draft(body: IssueIn, request: Request, response: Response) -> dict:
    require_permission(request, "view")
    response.headers["Cache-Control"] = "private, no-store"
    from maverick.issue_report import build_report_fields

    from . import __version__
    world = _world()
    goal = await run_in_threadpool(_task, request, world, body.task)
    if goal.status not in _STOPPED:
        raise HTTPException(409, "Choose a task that stopped with a problem.")

    def build() -> dict:
        errors = [e for e in world.goal_events(body.task, limit=10_000) if e.kind == "error"]
        return build_report_fields(goal, errors, version=__version__, failure_cause=goal.result)

    draft = await run_in_threadpool(build)
    current = await run_in_threadpool(_task, request, world, body.task)
    if current.status not in _STOPPED:
        raise HTTPException(409, "The task changed while this report was prepared. Refresh and try again.")
    return {**draft, "summary": "Review the draft here. Remove business details you do not want to share. "
            "Copy or download it, then use the support channel your organization gave you. "
            "Nothing is sent automatically."}


@router.post("/review")
async def review_issue(body: ReviewedIssueIn, request: Request, response: Response) -> dict:
    require_permission(request, "view")
    response.headers["Cache-Control"] = "private, no-store"
    from maverick.secrets import scrub
    await run_in_threadpool(_task, request, _world(), body.task)
    title, content = scrub(body.title)[:120], scrub(body.body)[:6000]
    return {"title": title, "body": content}
