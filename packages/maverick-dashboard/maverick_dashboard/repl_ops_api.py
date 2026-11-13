"""The task page's code sandbox (``maverick repl exec`` / ``transcript`` /
``close``).

Every step runs through the kernel's governed session
(:mod:`maverick.governed_repl`): screened, receipted, audited, and executed by
``sandbox.exec`` under the configured sandbox policy -- this module never
changes that policy, so it cannot grant network or host access the policy does
not already allow. The page adds:

* ownership: a session belongs to the person who opened it and to one task,
  and every route first applies the task page's own access check;
* the task's limits: each step counts as one tool call against the configured
  per-task limits, checked before it runs. The time limit is wall time since
  the session was opened (idle minutes included), not time spent running code;
* bounds: code size, returned output, open sessions per person and task and
  in total; sessions close after 30 idle minutes and when Lightwork stops;
* where statements would run directly on this computer (no isolated
  sandbox), only installation administrators may use the panel.

It needs the ``operate`` permission (starting and running tasks), and the
operator must have turned code sessions on (``[repl] enable``).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import assert_goal_access, caller_principal, has_global_permission, require_permission
from .tools_ops_api import record, same_origin

router = APIRouter(prefix="/api/v1/goals/{goal_id}/code")

MAX_CODE_CHARS = 20_000
MAX_OUTPUT_CHARS = 20_000
MAX_OPEN_PER_TASK = 2
MAX_OPEN_TOTAL = 20
IDLE_SECONDS = 30 * 60


@dataclass
class _Open:
    session: str
    goal_id: int
    person: str
    budget: Any
    last_used: float = field(default_factory=time.time)
    busy: threading.Lock = field(default_factory=threading.Lock)


_lock = threading.Lock()
_open: dict[str, _Open] = {}
_threads: list[threading.Thread] = []  # nothing runs in the background; kept for shutdown checks


def _person(request: Request) -> str:
    return caller_principal(request) or "local"


def _repl():
    from maverick import governed_repl
    return governed_repl


def _task(request: Request, goal_id: int):
    require_permission(request, "operate")
    from ._shared import _world
    goal = _world().get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "That task was not found.")
    assert_goal_access(request, goal)
    return goal


def _usable(request: Request) -> None:
    repl = _repl()
    if not repl.enabled():
        raise HTTPException(409, "Running code is turned off. An administrator can turn it on in Settings.")
    if repl.runs_on_host() and not has_global_permission(request, "admin"):
        raise HTTPException(403, "Code here would run directly on this computer, so only installation "
                                 "administrators may run it.")


def _close(entry: _Open) -> None:
    try:
        _repl().close_session(entry.session)
    except Exception:  # noqa: BLE001 -- closing is best-effort; the ledger stays
        pass


def _sweep() -> None:
    """Close sessions nobody has used for :data:`IDLE_SECONDS`."""
    cutoff = time.time() - IDLE_SECONDS
    with _lock:
        idle = [e for e in _open.values() if e.last_used < cutoff and not e.busy.locked()]
        for e in idle:
            _open.pop(e.session, None)
    for e in idle:
        _close(e)


def _mine(request: Request, goal_id: int, session: str) -> _Open:
    with _lock:
        entry = _open.get(session)
    if entry is None or entry.goal_id != goal_id or entry.person != _person(request):
        raise HTTPException(404, "This code session has ended. Start a new one.")
    return entry


def _task_budget():
    from maverick.budget import Budget, resolve_budget_caps
    try:
        caps = resolve_budget_caps()
    except ValueError as exc:
        raise HTTPException(503, "The task limits could not be read, so no code was run.") from exc
    return Budget(max_tool_calls=caps.get("max_tool_calls"), max_wall_seconds=caps.get("max_wall_seconds"))


def _limits() -> dict[str, Any]:
    from maverick.config import get_repl
    policy = get_repl()
    return {"code_characters": MAX_CODE_CHARS,
            "output_characters": min(MAX_OUTPUT_CHARS, int(policy["max_output_chars"])),
            "steps_per_session": int(policy["max_statements"]),
            "seconds_per_step": float(policy["max_seconds"]),
            "idle_minutes": IDLE_SECONDS // 60, "open_sessions": MAX_OPEN_PER_TASK}


def _log(session: str) -> list[dict[str, Any]]:
    rows = _repl().transcript(session)
    return [{"step": r.get("statement"), "time": r.get("ts"), "ok": bool(r.get("ok")),
             "seconds": r.get("wall_seconds"), "code": str(r.get("excerpt") or ""),
             "not_kept": list(r.get("dropped") or [])[:50], "cut_short": bool(r.get("truncated"))}
            for r in rows[-500:]]


@router.get("")
async def code_sessions(goal_id: int, request: Request) -> dict:
    _task(request, goal_id)
    _sweep()
    repl = _repl()
    if not repl.enabled():
        return {"enabled": False, "sessions": []}
    person = _person(request)
    on_host = await run_in_threadpool(repl.runs_on_host)
    rows = await run_in_threadpool(repl.sessions_for, goal_id, person)
    with _lock:
        live = {s for s, e in _open.items() if e.goal_id == goal_id and e.person == person}
    sessions = [{"id": r["session"], "open": r["session"] in live and not r.get("closed"),
                 "steps": int(r.get("statements") or 0), "started": r.get("created")} for r in rows]
    return {"enabled": True, "allowed": not on_host or has_global_permission(request, "admin"),
            "on_this_computer": on_host, "limits": await run_in_threadpool(_limits), "sessions": sessions}


@router.post("/sessions", status_code=201)
async def open_code_session(goal_id: int, request: Request) -> dict:
    same_origin(request)
    _task(request, goal_id)
    _sweep()
    await run_in_threadpool(_usable, request)
    person = _person(request)
    with _lock:
        mine = sum(1 for e in _open.values() if e.goal_id == goal_id and e.person == person)
        if mine >= MAX_OPEN_PER_TASK:
            raise HTTPException(409, "You already have the most code sessions open for this task. "
                                     "Close one first.")
        if len(_open) >= MAX_OPEN_TOTAL:
            raise HTTPException(409, "Too many code sessions are open right now. Try again later.")
    budget = _task_budget()
    record(request, "code_session_open", installation=False, goal_id=goal_id)
    repl = _repl()
    try:
        session = await run_in_threadpool(lambda: repl.open_session(goal_id, principal=person))
    except repl.ReplError as exc:
        raise HTTPException(409, "Lightwork could not start a code session.") from exc
    with _lock:
        _open[session] = _Open(session, goal_id, person, budget)
    return {"id": session}


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=1, max_length=MAX_CODE_CHARS)


def _run(entry: _Open, code: str) -> dict[str, Any]:
    from maverick.budget import BudgetExceeded
    try:
        entry.budget.record_tool_call()
    except BudgetExceeded as exc:
        raise HTTPException(409, "This session reached the task's limits, so the code was not run. "
                                 "Start a new session to continue.") from exc
    repl = _repl()
    try:
        result = repl.execute(entry.session, code, goal_id=entry.goal_id, principal=entry.person)
    except repl.ReplError as exc:
        raise HTTPException(409, "Lightwork did not run this code: a safety check or a limit "
                                 "refused it.") from exc
    out, err = str(result.get("stdout") or ""), str(result.get("stderr") or "")
    return {"ok": bool(result.get("ok")), "output": out[:MAX_OUTPUT_CHARS],
            "problems": err[:MAX_OUTPUT_CHARS],
            "cut_short": bool(result.get("truncated")) or len(out) > MAX_OUTPUT_CHARS or len(err) > MAX_OUTPUT_CHARS,
            "not_kept": list(result.get("dropped") or [])[:50], "seconds": result.get("wall_seconds")}


@router.post("/sessions/{session}/run")
async def run_code(goal_id: int, session: str, body: RunIn, request: Request) -> dict:
    same_origin(request)
    _task(request, goal_id)
    _sweep()
    await run_in_threadpool(_usable, request)
    entry = _mine(request, goal_id, session)
    if not entry.busy.acquire(blocking=False):
        raise HTTPException(409, "Wait for the previous step to finish.")
    try:
        entry.last_used = time.time()
        return await run_in_threadpool(_run, entry, body.code)
    finally:
        entry.last_used = time.time()
        entry.busy.release()


@router.post("/sessions/{session}/close")
async def close_code_session(goal_id: int, session: str, request: Request) -> dict:
    same_origin(request)
    _task(request, goal_id)
    entry = _mine(request, goal_id, session)
    record(request, "code_session_close", installation=False, goal_id=goal_id)
    with _lock:
        _open.pop(session, None)
    await run_in_threadpool(_close, entry)
    return {"closed": True}


@router.get("/sessions/{session}/log")
async def code_session_log(goal_id: int, session: str, request: Request) -> dict:
    _task(request, goal_id)
    repl = _repl()
    try:
        info = await run_in_threadpool(repl.session_info, session)
    except repl.ReplError as exc:
        raise HTTPException(404, "That code session was not found.") from exc
    if info.get("goal_id") != goal_id or info.get("principal") != _person(request):
        raise HTTPException(404, "That code session was not found.")
    return {"steps": await run_in_threadpool(_log, session), "closed": bool(info.get("closed"))}


def close_all_sessions(*, timeout: float, wait: bool = True) -> None:
    """Shutdown: close every open session (the ledgers stay). The signal phase
    does no I/O; closing happens in the wait phase."""
    del timeout
    if not wait:
        return
    with _lock:
        entries = list(_open.values())
        _open.clear()
    for entry in entries:
        _close(entry)


__all__ = ["close_all_sessions", "router"]
