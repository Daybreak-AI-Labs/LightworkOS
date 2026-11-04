"""ClickUp tool — tasks + lists.

Auth: ``CLICKUP_API_TOKEN`` (personal API token from ClickUp →
Apps → API Token).

ops:
  - teams()
  - spaces(team_id)
  - lists(space_id)
  - tasks(list_id, archived, limit)
  - task_get(task_id)
  - task_create(list_id, name, description, assignees, status, priority, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_CU_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["teams", "spaces", "lists", "tasks",
                     "task_get", "task_create"],
        },
        "team_id": {"type": "string"},
        "space_id": {"type": "string"},
        "list_id": {"type": "string"},
        "task_id": {"type": "string"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "assignees": {"type": "array", "items": {"type": "integer"}},
        "status": {"type": "string"},
        "priority": {"type": "integer", "description": "1 urgent .. 4 low"},
        "archived": {"type": "boolean"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.clickup.com/api/v2"


def _token() -> str:
    t = os.environ.get("CLICKUP_API_TOKEN", "").strip()
    if not t:
        raise RuntimeError("ClickUp requires CLICKUP_API_TOKEN.")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": _token(), "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_teams(_args: dict) -> str:
    code, data = _get("/team")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: teams ({code}): {data}"
    teams = data.get("teams") or []
    return "\n".join(f"  {t.get('id')}  {t.get('name')}" for t in teams) or "(none)"


def _op_spaces(args: dict) -> str:
    tid = (args.get("team_id") or "").strip()
    if not tid:
        return "ERROR: spaces requires team_id"
    seg = safe_path_segment(tid)
    if seg is None:
        return "ERROR: spaces requires a valid team_id"
    code, data = _get(f"/team/{seg}/space")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: spaces ({code}): {data}"
    spaces = data.get("spaces") or []
    return "\n".join(f"  {s.get('id')}  {s.get('name')}" for s in spaces) or "(none)"


def _op_lists(args: dict) -> str:
    sid = (args.get("space_id") or "").strip()
    if not sid:
        return "ERROR: lists requires space_id"
    seg = safe_path_segment(sid)
    if seg is None:
        return "ERROR: lists requires a valid space_id"
    code, data = _get(f"/space/{seg}/list")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: lists ({code}): {data}"
    lists = data.get("lists") or []
    return "\n".join(
        f"  {lst.get('id')}  {lst.get('name')}  ({lst.get('task_count', '?')} tasks)"
        for lst in lists
    ) or "(none)"


def _op_tasks(args: dict) -> str:
    lid = (args.get("list_id") or "").strip()
    if not lid:
        return "ERROR: tasks requires list_id"
    seg = safe_path_segment(lid)
    if seg is None:
        return "ERROR: tasks requires a valid list_id"
    limit = max(1, min(int(args.get("limit") or 25), 100))
    archived = "true" if args.get("archived") else "false"
    # ClickUp paginates ~100 tasks per page with a `last_page` flag. Follow
    # the page counter until we have `limit` tasks or the API says it's the
    # last page; bound the loop so a huge list can't spin unbounded.
    tasks: list[dict] = []
    page = 0
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        code, data = _get(f"/list/{seg}/task", {"archived": archived, "page": page})
        if code >= 400 or not isinstance(data, dict):
            return f"ERROR: tasks ({code}): {data}"
        batch = data.get("tasks") or []
        tasks.extend(batch)
        if len(tasks) >= limit or data.get("last_page") or not batch:
            break
        page += 1
    if not tasks:
        return "no tasks"
    return "\n".join(
        f"  {t.get('id')}  [{(t.get('status') or {}).get('status', '?'):>10}]  "
        f"{(t.get('name') or '')[:60]:<60}  "
        f"priority={(t.get('priority') or {}).get('priority', '?')}"
        for t in tasks[:limit]
    )


def _op_task_get(args: dict) -> str:
    tid = (args.get("task_id") or "").strip()
    if not tid:
        return "ERROR: task_get requires task_id"
    seg = safe_path_segment(tid)
    if seg is None:
        return "ERROR: task_get requires a valid task_id"
    code, data = _get(f"/task/{seg}")
    if code == 404:
        return f"task {tid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: task_get ({code}): {data}"
    return (
        f"{data.get('id')}  status={(data.get('status') or {}).get('status', '?')}\n"
        f"  name:        {data.get('name')}\n"
        f"  description: {(data.get('description') or '')[:400]}\n"
        f"  list:        {(data.get('list') or {}).get('name', '?')}\n"
        f"  assignees:   {', '.join(a.get('username', '?') for a in (data.get('assignees') or []))}\n"
        f"  url:         {data.get('url', '?')}"
    )


def _op_task_create(args: dict) -> str:
    lid = (args.get("list_id") or "").strip()
    name = (args.get("name") or "").strip()
    if not lid or not name:
        return "ERROR: task_create requires list_id and name"
    seg = safe_path_segment(lid)
    if seg is None:
        return "ERROR: task_create requires a valid list_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create task in list {lid}. Re-run with confirm=true."
    body: dict = {"name": name}
    if args.get("description"):
        body["description"] = args["description"]
    if args.get("assignees"):
        body["assignees"] = [int(a) for a in args["assignees"]]
    if args.get("status"):
        body["status"] = args["status"]
    if args.get("priority"):
        body["priority"] = int(args["priority"])
    code, data = _post(f"/list/{seg}/task", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: task_create ({code}): {data}"
    return f"created task {data.get('id')}: {data.get('url', '')}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "teams":       _op_teams,
            "spaces":      _op_spaces,
            "lists":       _op_lists,
            "tasks":       _op_tasks,
            "task_get":    _op_task_get,
            "task_create": _op_task_create,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: ClickUp request failed: {type(e).__name__}: {e}"


def clickup_tool() -> Tool:
    return Tool(
        name="clickup",
        description=(
            "ClickUp PM. ops: teams, spaces (per team), lists "
            "(per space), tasks (per list), task_get, task_create "
            "(name + optional description/assignees/status/priority; "
            "confirm=true required). Auth: CLICKUP_API_TOKEN."
        ),
        input_schema=_CU_SCHEMA,
        fn=_run,
    )
