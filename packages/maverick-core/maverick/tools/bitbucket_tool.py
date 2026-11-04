"""Bitbucket Cloud tool — issues + pull requests + pipelines.

Mirrors the GitLab tool shape.

Auth:
  - ``BITBUCKET_USERNAME`` + ``BITBUCKET_APP_PASSWORD`` (Basic auth)
  - OR ``BITBUCKET_ACCESS_TOKEN`` (Bearer)

ops:
  - issues(workspace, repo_slug, state, limit)
  - issue_get(workspace, repo_slug, issue_id)
  - prs(workspace, repo_slug, state, limit)
  - pr_get(workspace, repo_slug, pr_id)
  - pipelines(workspace, repo_slug, limit)
"""
from __future__ import annotations

import base64
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, safe_path_segment

log = logging.getLogger(__name__)


_BB_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["issues", "issue_get", "prs", "pr_get", "pipelines"],
        },
        "workspace": {"type": "string"},
        "repo_slug": {"type": "string"},
        "issue_id": {"type": "integer"},
        "pr_id": {"type": "integer"},
        "state": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


_API = "https://api.bitbucket.org/2.0"


def _headers() -> dict[str, str]:
    tok = os.environ.get("BITBUCKET_ACCESS_TOKEN", "").strip()
    if tok:
        return {"Authorization": f"Bearer {tok}",
                "Accept": "application/json"}
    u = os.environ.get("BITBUCKET_USERNAME", "").strip()
    p = os.environ.get("BITBUCKET_APP_PASSWORD", "").strip()
    if u and p:
        raw = f"{u}:{p}".encode("ascii")
        return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii"),
                "Accept": "application/json"}
    raise RuntimeError(
        "Bitbucket requires BITBUCKET_ACCESS_TOKEN OR "
        "BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD."
    )


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _slug(args: dict) -> tuple[str, str] | str:
    ws = (args.get("workspace") or "").strip()
    repo = (args.get("repo_slug") or "").strip()
    if not ws or not repo:
        return "ERROR: workspace and repo_slug are required"
    ws_seg, repo_seg = safe_path_segment(ws), safe_path_segment(repo)
    if ws_seg is None or repo_seg is None:
        return "ERROR: workspace and repo_slug must be valid path segments"
    return ws_seg, repo_seg


def _op_issues(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    ws, repo = sg
    params: dict = {"pagelen": max(1, min(int(args.get("limit") or 25), 100))}
    if args.get("state"):
        params["q"] = f'state="{args["state"]}"'
    code, data = _get(f"/repositories/{ws}/{repo}/issues", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: issues ({code}): {data}"
    rows = data.get("values") or []
    if not rows:
        return "no issues"
    return "\n".join(
        f"  #{i.get('id'):<4}  [{i.get('state', '?'):>8}]  "
        f"{(i.get('title') or '')[:80]}"
        for i in rows
    )


def _op_issue_get(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    ws, repo = sg
    iid = int(args.get("issue_id") or 0)
    if not iid:
        return "ERROR: issue_get requires issue_id"
    code, data = _get(f"/repositories/{ws}/{repo}/issues/{iid}")
    if code == 404:
        return f"issue {ws}/{repo}#{iid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: issue_get ({code}): {data}"
    return (
        f"#{data.get('id')}  {data.get('title', '')}\n"
        f"  state:    {data.get('state')}\n"
        f"  reporter: {(data.get('reporter') or {}).get('display_name', '?')}\n"
        f"  url:      {(data.get('links') or {}).get('html', {}).get('href', '?')}\n\n"
        f"{((data.get('content') or {}).get('raw') or '')[:2000]}"
    )


def _op_prs(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    ws, repo = sg
    params: dict = {"pagelen": max(1, min(int(args.get("limit") or 25), 50))}
    state = (args.get("state") or "").strip()
    if state:
        params["state"] = state.upper()
    code, data = _get(f"/repositories/{ws}/{repo}/pullrequests", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: prs ({code}): {data}"
    rows = data.get("values") or []
    if not rows:
        return "no pull requests"
    return "\n".join(
        f"  !{p.get('id'):<4}  [{p.get('state', '?'):>8}]  "
        f"{(p.get('title') or '')[:60]:<60}  "
        f"by {(p.get('author') or {}).get('display_name', '?')}"
        for p in rows
    )


def _op_pr_get(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    ws, repo = sg
    pid = int(args.get("pr_id") or 0)
    if not pid:
        return "ERROR: pr_get requires pr_id"
    code, data = _get(f"/repositories/{ws}/{repo}/pullrequests/{pid}")
    if code == 404:
        return f"PR {ws}/{repo}!{pid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: pr_get ({code}): {data}"
    src = (data.get("source") or {}).get("branch", {}).get("name", "?")
    dst = (data.get("destination") or {}).get("branch", {}).get("name", "?")
    return (
        f"!{data.get('id')}  {data.get('title', '')}\n"
        f"  state:   {data.get('state')}\n"
        f"  source:  {src}\n"
        f"  target:  {dst}\n"
        f"  url:     {(data.get('links') or {}).get('html', {}).get('href', '?')}\n\n"
        f"{((data.get('description') or '') or '')[:2000]}"
    )


def _op_pipelines(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    ws, repo = sg
    params = {
        "pagelen": max(1, min(int(args.get("limit") or 20), 50)),
        "sort": "-created_on",
    }
    code, data = _get(f"/repositories/{ws}/{repo}/pipelines/", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: pipelines ({code}): {data}"
    rows = data.get("values") or []
    if not rows:
        return "no pipelines"
    return "\n".join(
        f"  #{p.get('build_number', '?'):<5}  "
        f"[{(p.get('state') or {}).get('name', '?'):>10}]  "
        f"{(p.get('target') or {}).get('ref_name', '?')}"
        for p in rows
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return {
            "issues":    _op_issues,
            "issue_get": _op_issue_get,
            "prs":       _op_prs,
            "pr_get":    _op_pr_get,
            "pipelines": _op_pipelines,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Bitbucket request failed: {type(e).__name__}: {e}"


def bitbucket_tool() -> Tool:
    return Tool(
        name="bitbucket",
        description=(
            "Bitbucket Cloud read-only. ops: issues, issue_get, prs, "
            "pr_get, pipelines. Auth: BITBUCKET_ACCESS_TOKEN OR "
            "BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD."
        ),
        input_schema=_BB_SCHEMA,
        fn=_run,
    )
