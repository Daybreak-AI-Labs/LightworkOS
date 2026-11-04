"""Sentry tool — error tracking + release management.

Read-mostly access to a Sentry project so the agent can answer
"what's blowing up?" without leaving Lightwork.

Auth: ``SENTRY_AUTH_TOKEN`` (internal/integration token with at
least ``event:read`` and ``project:read`` scopes). ``SENTRY_ORG`` +
``SENTRY_PROJECT`` short codes pre-fill the org/project for most
ops. ``SENTRY_HOST`` overrides for self-hosted (default
``https://sentry.io``).

ops:
  - issues(query, limit)
  - issue_get(issue_id)
  - events(issue_id, limit)
  - resolve(issue_id, confirm)
  - releases(limit)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_SENTRY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["issues", "issue_get", "events", "resolve", "releases"],
        },
        "query": {"type": "string", "description": "Sentry search query."},
        "issue_id": {"type": "string"},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str, str, str]:
    host = os.environ.get("SENTRY_HOST", "https://sentry.io").rstrip("/")
    tok = os.environ.get("SENTRY_AUTH_TOKEN", "").strip()
    org = os.environ.get("SENTRY_ORG", "").strip()
    proj = os.environ.get("SENTRY_PROJECT", "").strip()
    if not tok:
        raise RuntimeError("Sentry requires SENTRY_AUTH_TOKEN.")
    return host, tok, org, proj


def _headers() -> dict[str, str]:
    _h, tok, _o, _p = _config()
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    host, _t, _o, _p = _config()
    r = _governed_sender(httpx.get)(f"{host}/api/0{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _put(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    host, _t, _o, _p = _config()
    r = _governed_sender(httpx.put)(f"{host}/api/0{path}", headers=_headers(),
                  json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _require_project() -> tuple[str, str] | str:
    _h, _t, org, proj = _config()
    if not org or not proj:
        return "ERROR: SENTRY_ORG + SENTRY_PROJECT must be set"
    return org, proj


def _op_issues(query: str, limit: int) -> str:
    res = _require_project()
    if isinstance(res, str):
        return res
    org, proj = res
    code, data = _get(
        f"/projects/{org}/{proj}/issues/",
        {"query": query or "is:unresolved", "limit": limit},
    )
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: issues ({code}): {data}"
    if not data:
        return "no issues"
    rows = []
    for it in data:
        rows.append(
            f"  {it.get('shortId', '?'):>10}  "
            f"[{it.get('level', '?'):>7}]  "
            f"count={it.get('count', '?')} users={(it.get('userCount') or 0)}  "
            f"{(it.get('title') or '')[:80]}"
        )
    return "\n".join(rows)


def _op_issue_get(issue_id: str) -> str:
    seg = safe_path_segment(issue_id)
    if seg is None:
        return "ERROR: issue_get requires a valid issue_id"
    code, data = _get(f"/issues/{seg}/")
    if code == 404:
        return f"issue {issue_id!r} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: issue_get ({code}): {data}"
    return (
        f"{data.get('shortId')}  level={data.get('level')}  "
        f"status={data.get('status')}\n"
        f"  title:   {data.get('title')}\n"
        f"  culprit: {data.get('culprit', '')}\n"
        f"  count:   {data.get('count')}  users={data.get('userCount')}\n"
        f"  first:   {data.get('firstSeen')}\n"
        f"  last:    {data.get('lastSeen')}\n"
        f"  url:     {data.get('permalink')}"
    )


def _op_events(issue_id: str, limit: int) -> str:
    seg = safe_path_segment(issue_id)
    if seg is None:
        return "ERROR: events requires a valid issue_id"
    code, data = _get(
        f"/issues/{seg}/events/", {"limit": limit},
    )
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: events ({code}): {data}"
    if not data:
        return "no events"
    rows = []
    for e in data:
        rows.append(
            f"  {e.get('eventID', '?')[:12]}  "
            f"{e.get('dateCreated', '?')}  "
            f"env={e.get('environment', '?')}  "
            f"{(e.get('title') or '')[:80]}"
        )
    return "\n".join(rows)


def _op_resolve(issue_id: str, confirm: bool) -> str:
    seg = safe_path_segment(issue_id)
    if seg is None:
        return "ERROR: resolve requires a valid issue_id"
    if not confirm:
        return f"DRY RUN: would resolve {issue_id}. Re-run with confirm=true."
    code, data = _put(f"/issues/{seg}/", {"status": "resolved"})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: resolve ({code}): {data}"
    return f"resolved {issue_id} (status={data.get('status')})"


def _op_releases(limit: int) -> str:
    res = _require_project()
    if isinstance(res, str):
        return res
    org, proj = res
    code, data = _get(
        f"/projects/{org}/{proj}/releases/", {"per_page": limit},
    )
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: releases ({code}): {data}"
    if not data:
        return "no releases"
    rows = []
    for r in data:
        rows.append(
            f"  {r.get('shortVersion') or r.get('version', '?')}  "
            f"first={r.get('dateCreated', '?')}  "
            f"commits={(r.get('lastCommit') or {}).get('id', '')[:8]}"
        )
    return "\n".join(rows)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    limit = max(1, min(int(args.get("limit") or 25), 100))
    try:
        if op == "issues":
            return _op_issues((args.get("query") or "").strip(), limit)
        if op == "issue_get":
            iid = (args.get("issue_id") or "").strip()
            if not iid:
                return "ERROR: issue_get requires issue_id"
            return _op_issue_get(iid)
        if op == "events":
            iid = (args.get("issue_id") or "").strip()
            if not iid:
                return "ERROR: events requires issue_id"
            return _op_events(iid, limit)
        if op == "resolve":
            iid = (args.get("issue_id") or "").strip()
            if not iid:
                return "ERROR: resolve requires issue_id"
            return _op_resolve(iid, as_bool(args.get("confirm")))
        if op == "releases":
            return _op_releases(limit)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Sentry request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def sentry_tool() -> Tool:
    return Tool(
        name="sentry",
        description=(
            "Sentry error tracking. ops: issues (search), "
            "issue_get, events (per issue), resolve "
            "(confirm=true required), releases. Auth: "
            "SENTRY_AUTH_TOKEN + SENTRY_ORG + SENTRY_PROJECT. "
            "SENTRY_HOST overrides for self-hosted."
        ),
        input_schema=_SENTRY_SCHEMA,
        fn=_run,
    )
