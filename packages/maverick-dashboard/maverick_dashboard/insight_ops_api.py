"""Questions about tasks, task health and recorded steps, as buttons
(``maverick analytics``, ``diag health`` and ``diag replay``).

* Task questions: a person builds a question from pickers -- what to measure,
  how to group it, a date range -- that maps onto the kernel's
  ``WorldAnalytics.ask``. Everyone sees only the tasks they may see (the same
  owner filter as the Spending page). Installation administrators may also
  type a read-only question in the analytics language, inside Technical
  details: the kernel accepts only a single SELECT/WITH query, returns a
  bounded number of rows, has no file or network access, and here is also
  stopped after a time limit.
* Task health: the 0-100 score ``diag health`` prints, with its parts.
* Recorded steps: the step-by-step recording a run writes when recordings are
  on, verified by the kernel reader before anything is shown.

Task routes use the task page's own access check (``assert_goal_access``).
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import (
    assert_goal_access,
    goal_owner_filter,
    has_global_permission,
    require_global_permission,
    require_permission,
)
from .tools_ops_api import same_origin, technical

router = APIRouter(prefix="/api/v1")

_METRICS = {"spend": "Money spent", "tasks": "Tasks", "runs": "Agent runs",
            "tokens": "AI usage (tokens)", "spend_per_task": "Average spend per task"}
_GROUPS = {"none": "All together", "day": "Day", "week": "Week", "month": "Month",
           "status": "Task status", "outcome": "Run result", "task": "Task"}
_GOAL_LIMIT = 5000
_ASK_SECONDS = 20.0
_SQL_SECONDS = 15.0


def _world():
    from ._shared import _world as shared
    try:
        return shared()
    except Exception as exc:  # noqa: BLE001 -- plain message, no internals
        raise HTTPException(503, "Lightwork's records are not available right now.") from exc


class _OwnedWorld:
    """The world restricted by the request's content-owner filter.

    Dashboard callers, including administrators, supply their exact owner
    scope. Unidentified installation access supplies the unowned-work scope.
    """

    def __init__(self, world, owner: str | None) -> None:
        self._world, self._owner = world, owner

    def list_goals(self, limit: int | None = None):
        return self._world.list_goals(owner=self._owner, limit=min(int(limit or _GOAL_LIMIT), _GOAL_LIMIT),
                                      order="desc")

    def list_episodes(self, goal_id: int, limit: int | None = None):
        return self._world.list_episodes(goal_id=goal_id, limit=limit)


_NOT_INSTALLED = ("Task questions need the DuckDB add-on, which is not installed on this "
                  "server. Whoever installed Lightwork can add it (the “duckdb” add-on).")
_TURNED_OFF = ("Task questions are turned off. A global administrator can turn them on in "
               "Settings > All settings.")


def _turned_on() -> bool:
    """``[analytics] task_questions`` (on unless set to false)."""
    try:
        from maverick.config import load_config

        section = (load_config() or {}).get("analytics") or {}
    except Exception:  # an unreadable configuration keeps the default
        return True
    return not (isinstance(section, dict) and section.get("task_questions") is False)


def _analytics(owner: str | None):
    if not _turned_on():
        raise HTTPException(403, _TURNED_OFF)
    try:
        from maverick.duckdb_analytics import WorldAnalytics
        return WorldAnalytics(_OwnedWorld(_world(), owner), limit=_GOAL_LIMIT, query_limit=1000)
    except ImportError as exc:
        raise HTTPException(503, _NOT_INSTALLED) from exc


def _available() -> bool:
    import importlib.util
    return importlib.util.find_spec("duckdb") is not None


@router.get("/analytics/choices")
async def analytics_choices(request: Request) -> dict:
    require_permission(request, "view")
    installed, turned_on = _available(), _turned_on()
    return {"available": installed and turned_on, "installed": installed,
            "turned_on": turned_on,
            "reason": "" if installed and turned_on else (_TURNED_OFF if not turned_on
                                                          else _NOT_INSTALLED),
            "metrics": [{"value": k, "label": v} for k, v in _METRICS.items()],
            "groups": [{"value": k, "label": v} for k, v in _GROUPS.items()],
            "can_write_queries": has_global_permission(request, "admin")}


def _day(text: str | None, *, end: bool = False) -> float | None:
    if not text:
        return None
    try:
        day = _dt.date.fromisoformat(text)
    except ValueError as exc:
        raise HTTPException(422, "Choose the dates from the calendar.") from exc
    if end:
        day += _dt.timedelta(days=1)
    return _dt.datetime(day.year, day.month, day.day, tzinfo=_dt.timezone.utc).timestamp()


class AskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    metric: Literal["spend", "tasks", "runs", "tokens", "spend_per_task"]
    group: Literal["none", "day", "week", "month", "status", "outcome", "task"] = "none"
    since: str | None = Field(default=None, max_length=10)
    until: str | None = Field(default=None, max_length=10)


def _number(value: Any) -> float:
    try:
        return round(float(value or 0), 6)
    except (TypeError, ValueError):
        return 0.0


@router.post("/analytics/ask")
async def analytics_ask(body: AskIn, request: Request) -> dict:
    require_permission(request, "view")
    since, until = _day(body.since), _day(body.until, end=True)
    if since is not None and until is not None and since >= until:
        raise HTTPException(422, "The start date must be before the end date.")
    owner = goal_owner_filter(request)

    def _do() -> list[dict]:
        wa = _analytics(owner)
        try:
            return wa.ask(body.metric, body.group, since=since, until=until, timeout=_ASK_SECONDS)
        finally:
            wa.close()
    try:
        rows = await run_in_threadpool(_do)
    except TimeoutError as exc:
        raise HTTPException(503, "That question took too long. Try a shorter date range.") from exc
    return {"question": f"{_METRICS[body.metric]} by {_GROUPS[body.group].lower()}",
            "metric": body.metric, "rows": [{"group": str(r["group"])[:200], "value": _number(r["value"])}
                                            for r in rows]}


class QueryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=4000)


@router.post("/analytics/query")
async def analytics_query(body: QueryIn, request: Request) -> dict:
    """Installation administrators only: one read-only question in the
    analytics language, with the kernel's limits and a time limit."""
    same_origin(request)
    require_global_permission(request, "admin")
    owner = goal_owner_filter(request)

    def _do() -> list[dict]:
        wa = _analytics(owner)
        try:
            return wa.query(body.query, timeout=_SQL_SECONDS)
        finally:
            wa.close()
    try:
        rows = await run_in_threadpool(_do)
    except TimeoutError as exc:
        raise HTTPException(503, "That question took too long and was stopped.") from exc
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 -- the engine's wording goes to technical
        raise HTTPException(422, "Lightwork could not answer that question. Only questions that "
                                 "read (starting with SELECT or WITH) are allowed.") from exc
    columns = list(rows[0].keys())[:30] if rows else []
    return {"columns": columns,
            "rows": [[str(r.get(c, ""))[:300] for c in columns] for r in rows[:200]],
            "more": len(rows) > 200}


# ---- Task health (diag health) ----------------------------------------------

def _goal(request: Request, goal_id: int):
    world = _world()
    goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "That task was not found.")
    assert_goal_access(request, goal)
    return world, goal


@router.get("/goals/{goal_id}/health")
async def goal_health(goal_id: int, request: Request) -> dict:
    require_permission(request, "view")
    world, _goal_row = _goal(request, goal_id)
    from maverick.health_score import goal_health as kernel_health
    found = await run_in_threadpool(kernel_health, world, goal_id)
    if found is None:
        raise HTTPException(404, "That task was not found.")
    goal, health = found
    f = health.factors
    finished = goal.status == "done"
    parts = [{"label": "Starting score" + (" (the task finished)" if finished else " (the task did not finish)"),
              "points": int(f.get("base", 0))}]
    if f.get("tool_penalty"):
        parts.append({"label": "Tool errors and retries", "points": int(f["tool_penalty"])})
    if f.get("efficiency_penalty"):
        parts.append({"label": "Used more AI than expected", "points": int(f["efficiency_penalty"])})
    return {"score": health.score, "grade": health.grade, "finished": finished,
            "status": goal.status, "tokens_used": int(f.get("tokens_used", 0)), "parts": parts}


# ---- Recorded steps (diag replay) ------------------------------------------

def _steps(goal_id: int, kind: str) -> dict[str, Any]:
    from maverick.replay.trace import TraceError, goal_trace_path, read_trace
    path = goal_trace_path(goal_id)
    if path is None:
        return {"recording": False, "steps": [], "kinds": [], "total": 0}
    try:
        events = read_trace(path)
    except (TraceError, OSError, ValueError) as exc:
        return {"recording": True, "damaged": True, "steps": [], "kinds": [], "total": 0,
                "technical": technical([f"{type(exc).__name__}: {exc}"])}
    kinds = sorted({str(e.get("kind") or "") for e in events if e.get("kind")})
    shown = [e for e in events if not kind or e.get("kind") == kind]
    return {"recording": True, "damaged": False, "kinds": kinds[:100], "total": len(events),
            "matching": len(shown),
            "steps": [{"step": e.get("seq"), "kind": str(e.get("kind") or ""),
                       "who": str(e.get("agent") or "")[:80], "time": e.get("t"),
                       "text": str(e.get("content") or "")[:300]} for e in shown[:500]]}


@router.get("/goals/{goal_id}/recorded-steps")
async def goal_recorded_steps(goal_id: int, request: Request, kind: str = "") -> dict:
    require_permission(request, "view")
    _goal(request, goal_id)
    return await run_in_threadpool(_steps, goal_id, kind[:80])


__all__ = ["router"]
