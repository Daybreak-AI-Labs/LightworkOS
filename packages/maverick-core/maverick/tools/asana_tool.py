"""Asana tool — tasks, projects, sections.

Auth: ``ASANA_TOKEN`` (Personal Access Token).

ops:
  - workspaces()
  - projects(workspace_gid, limit)
  - tasks(project_gid, assignee, completed_since, limit)
  - task_get(task_gid)
  - task_create(project_gid, name, notes, assignee, confirm)
  - task_complete(task_gid, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_AS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["workspaces", "projects", "tasks", "task_get",
                     "task_create", "task_complete"],
        },
        "workspace_gid": {"type": "string"},
        "project_gid": {"type": "string"},
        "task_gid": {"type": "string"},
        "name": {"type": "string"},
        "notes": {"type": "string"},
        "assignee": {"type": "string"},
        "completed_since": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://app.asana.com/api/1.0"


def _token() -> str:
    t = os.environ.get("ASANA_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Asana requires ASANA_TOKEN (PAT).")
    return t


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": "application/json", "Accept": "application/json"}


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


def _put(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.put)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_workspaces(_args: dict) -> str:
    code, data = _get("/workspaces")
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: workspaces ({code}): {data}"
    rows = data.get("data") or []
    return "\n".join(f"  {w.get('gid')}  {w.get('name')}" for w in rows) or "(none)"


def _get_paginated(path: str, params: dict, limit: int) -> tuple[int, Any, list[dict]]:
    """Follow Asana's offset pagination (``next_page.offset``) until ``limit``
    rows are collected. Returns ``(code, error_payload, rows)``.

    Asana caps ``limit`` at 100 per page and returns an opaque ``offset`` token
    in ``next_page`` when more results exist; bounded by a hard page cap.
    """
    rows: list[dict] = []
    offset: str | None = None
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        p = dict(params)
        p["limit"] = min(100, max(1, limit - len(rows)))
        if offset:
            p["offset"] = offset
        code, data = _get(path, p)
        if code >= 400 or not isinstance(data, dict):
            return code, data, rows
        rows.extend(data.get("data") or [])
        offset = (data.get("next_page") or {}).get("offset")
        if len(rows) >= limit or not offset:
            break
    return 200, {}, rows[:limit]


def _op_projects(args: dict) -> str:
    wsg = (args.get("workspace_gid") or "").strip()
    if not wsg:
        return "ERROR: projects requires workspace_gid"
    limit = max(1, min(int(args.get("limit") or 25), 100))
    code, err, rows = _get_paginated("/projects", {"workspace": wsg}, limit)
    if code >= 400:
        return f"ERROR: projects ({code}): {err}"
    return "\n".join(f"  {p.get('gid')}  {p.get('name')}" for p in rows) or "(none)"


def _op_tasks(args: dict) -> str:
    pgid = (args.get("project_gid") or "").strip()
    if not pgid:
        return "ERROR: tasks requires project_gid"
    seg = safe_path_segment(pgid)
    if seg is None:
        return "ERROR: tasks requires a valid project_gid"
    limit = max(1, min(int(args.get("limit") or 25), 100))
    params: dict = {"opt_fields": "name,completed,assignee.name,due_on"}
    if args.get("assignee"):
        params["assignee"] = args["assignee"]
    if args.get("completed_since"):
        params["completed_since"] = args["completed_since"]
    code, err, rows = _get_paginated(f"/projects/{seg}/tasks", params, limit)
    if code >= 400:
        return f"ERROR: tasks ({code}): {err}"
    if not rows:
        return "no tasks"
    return "\n".join(
        f"  {t.get('gid')}  [{'x' if t.get('completed') else ' '}]  "
        f"{(t.get('name') or '')[:60]:<60}  "
        f"due={t.get('due_on', '?')}  by={(t.get('assignee') or {}).get('name', '?')}"
        for t in rows
    )


def _op_task_get(args: dict) -> str:
    tgid = (args.get("task_gid") or "").strip()
    if not tgid:
        return "ERROR: task_get requires task_gid"
    seg = safe_path_segment(tgid)
    if seg is None:
        return "ERROR: task_get requires a valid task_gid"
    code, data = _get(f"/tasks/{seg}")
    if code == 404:
        return f"task {tgid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: task_get ({code}): {data}"
    t = data.get("data") or {}
    return (
        f"{t.get('gid')}  [{'x' if t.get('completed') else ' '}]  "
        f"{t.get('name')}\n"
        f"  assignee: {(t.get('assignee') or {}).get('name', '?')}\n"
        f"  due:      {t.get('due_on', '?')}\n"
        f"  notes:    {(t.get('notes') or '')[:400]}\n"
        f"  url:      {t.get('permalink_url', '?')}"
    )


def _op_task_create(args: dict) -> str:
    pgid = (args.get("project_gid") or "").strip()
    name = (args.get("name") or "").strip()
    if not pgid or not name:
        return "ERROR: task_create requires project_gid and name"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create task in project {pgid}. Re-run with confirm=true."
    body = {"data": {
        "projects": [pgid],
        "name": name,
        "notes": args.get("notes") or "",
    }}
    if args.get("assignee"):
        body["data"]["assignee"] = args["assignee"]
    code, data = _post("/tasks", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: task_create ({code}): {data}"
    t = data.get("data") or {}
    return f"created task {t.get('gid')}: {t.get('permalink_url', '')}"


def _op_task_complete(args: dict) -> str:
    tgid = (args.get("task_gid") or "").strip()
    if not tgid:
        return "ERROR: task_complete requires task_gid"
    seg = safe_path_segment(tgid)
    if seg is None:
        return "ERROR: task_complete requires a valid task_gid"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would mark {tgid} complete. Re-run with confirm=true."
    code, data = _put(f"/tasks/{seg}", {"data": {"completed": True}})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: task_complete ({code}): {data}"
    return f"completed {tgid}"


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
            "workspaces":    _op_workspaces,
            "projects":      _op_projects,
            "tasks":         _op_tasks,
            "task_get":      _op_task_get,
            "task_create":   _op_task_create,
            "task_complete": _op_task_complete,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Asana request failed: {type(e).__name__}: {e}"


def asana_tool() -> Tool:
    return Tool(
        name="asana",
        description=(
            "Asana tasks + projects. ops: workspaces, projects, "
            "tasks (with assignee + completed_since filters), "
            "task_get, task_create + task_complete (mutations "
            "confirm=true). Auth: ASANA_TOKEN."
        ),
        input_schema=_AS_SCHEMA,
        fn=_run,
    )
