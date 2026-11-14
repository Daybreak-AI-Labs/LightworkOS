"""GitLab issue / MR / pipeline tool.

Read + write GitLab issues, merge requests, and pipelines via the
v4 REST API.

Auth: ``GITLAB_TOKEN`` (personal access token; ``api`` scope).
Optional ``GITLAB_URL`` for self-hosted instances (default
https://gitlab.com).

ops:
  - issues(project, state, limit)        — list issues
  - issue_get(project, iid)              — fetch one
  - issue_create(project, title, body)
  - issue_comment(project, iid, body)
  - mr_list(project, state, limit)
  - mr_get(project, iid)
  - mr_comment(project, iid, body)
  - pipelines(project, ref, limit)
  - pipeline_get(project, pipeline_id)

``project`` is the URL-encoded full path (e.g. ``"group/repo"``).
"""
from __future__ import annotations

import logging
import os
import urllib.parse
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_GITLAB_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": [
                "issues", "issue_get", "issue_create", "issue_comment",
                "mr_list", "mr_get", "mr_comment",
                "pipelines", "pipeline_get",
            ],
        },
        "project": {"type": "string", "description": "Full path e.g. 'group/repo'."},
        "iid": {"type": "integer", "description": "Issue / MR internal id."},
        "title": {"type": "string"},
        "body": {"type": "string"},
        "state": {"type": "string", "enum": ["opened", "closed", "merged", "all"]},
        "ref": {"type": "string", "description": "Branch / tag (pipelines)."},
        "pipeline_id": {"type": "integer"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str]:
    base = os.environ.get("GITLAB_URL", "https://gitlab.com").strip().rstrip("/")
    tok = os.environ.get("GITLAB_TOKEN", "").strip()
    if not tok:
        raise RuntimeError("GitLab requires GITLAB_TOKEN (personal access token).")
    return base, tok


def _client():
    import httpx

    from ..governed_http import GuardedClient
    base, tok = _config()
    # follow_redirects=False: PRIVATE-TOKEN is a custom auth header that httpx
    # does NOT strip on a cross-host redirect, so a 30x off a (user-set,
    # possibly self-hosted) GITLAB_URL would leak the PAT to another host.
    return base, GuardedClient(httpx.Client(
        headers={"PRIVATE-TOKEN": tok, "Accept": "application/json"},
        timeout=30.0, follow_redirects=False,
    ))


def _enc(project: str) -> str:
    # quote() leaves a bare '..' alone and httpx collapses it, turning
    # /projects/../merge_requests into the instance-wide /merge_requests.
    if project.strip() in ("", ".", ".."):
        raise RuntimeError(f"invalid project {project!r}")
    return urllib.parse.quote(project, safe="")


def _paginated_get(client, url: str, params: dict, limit: int) -> list[dict]:
    """GET ``url`` following GitLab's ``X-Next-Page`` header pagination until
    ``limit`` items are collected.

    GitLab caps ``per_page`` at 100, so a single page can't satisfy a request
    that legitimately spans pages; this follows the ``X-Next-Page`` header
    (empty when there are no more pages). Bounded by ``limit`` and a hard page
    cap so a huge project can't loop unbounded.
    """
    items: list[dict] = []
    page = 1
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        p = dict(params)
        p["per_page"] = min(100, max(1, limit - len(items)))
        p["page"] = page
        r = client.get(url, params=p)
        r.raise_for_status()
        batch = r.json()
        if not isinstance(batch, list):
            break
        items.extend(batch)
        if len(items) >= limit:
            break
        nxt = str(r.headers.get("X-Next-Page") or "").strip()
        if not nxt.isdigit():
            break
        page = int(nxt)
    return items[:limit]


def _list_issues(project: str, state: str, limit: int) -> str:
    base, client = _client()
    with client:
        items = _paginated_get(
            client, f"{base}/api/v4/projects/{_enc(project)}/issues",
            {"state": state}, limit,
        )
    if not items:
        return "no issues"
    return "\n".join(
        f"  #{i['iid']:>4}  [{i.get('state', '?'):>6}]  {(i.get('title') or '')[:80]}"
        for i in items
    )


def _issue_get(project: str, iid: int) -> str:
    base, client = _client()
    with client:
        r = client.get(
            f"{base}/api/v4/projects/{_enc(project)}/issues/{iid}",
        )
        if r.status_code == 404:
            return f"issue {project}#{iid} not found"
        r.raise_for_status()
        d = r.json()
    return (
        f"#{d.get('iid')}  {d.get('title', '')}\n"
        f"  state:   {d.get('state', '?')}\n"
        f"  author:  {(d.get('author') or {}).get('username', '?')}\n"
        f"  url:     {d.get('web_url')}\n\n"
        f"{(d.get('description') or '')[:5000]}"
    )


def _issue_create(project: str, title: str, body: str) -> str:
    base, client = _client()
    with client:
        r = client.post(
            f"{base}/api/v4/projects/{_enc(project)}/issues",
            json={"title": title, "description": body},
        )
        if r.status_code >= 400:
            return f"ERROR: issue_create ({r.status_code}): {r.text[:300]}"
        d = r.json()
    return f"created #{d.get('iid')}: {d.get('web_url')}"


def _issue_comment(project: str, iid: int, body: str) -> str:
    base, client = _client()
    with client:
        r = client.post(
            f"{base}/api/v4/projects/{_enc(project)}/issues/{iid}/notes",
            json={"body": body},
        )
        if r.status_code >= 400:
            return f"ERROR: issue_comment ({r.status_code}): {r.text[:300]}"
    return f"commented on {project}#{iid}"


def _mr_list(project: str, state: str, limit: int) -> str:
    base, client = _client()
    with client:
        items = _paginated_get(
            client, f"{base}/api/v4/projects/{_enc(project)}/merge_requests",
            {"state": state}, limit,
        )
    if not items:
        return "no merge requests"
    return "\n".join(
        f"  !{m['iid']:>4}  [{m.get('state', '?'):>6}]  {(m.get('title') or '')[:80]}"
        for m in items
    )


def _mr_get(project: str, iid: int) -> str:
    base, client = _client()
    with client:
        r = client.get(
            f"{base}/api/v4/projects/{_enc(project)}/merge_requests/{iid}",
        )
        if r.status_code == 404:
            return f"MR {project}!{iid} not found"
        r.raise_for_status()
        d = r.json()
    return (
        f"!{d.get('iid')}  {d.get('title', '')}\n"
        f"  state:  {d.get('state', '?')}\n"
        f"  source: {d.get('source_branch', '?')}\n"
        f"  target: {d.get('target_branch', '?')}\n"
        f"  url:    {d.get('web_url')}\n\n"
        f"{(d.get('description') or '')[:5000]}"
    )


def _mr_comment(project: str, iid: int, body: str) -> str:
    base, client = _client()
    with client:
        r = client.post(
            f"{base}/api/v4/projects/{_enc(project)}/merge_requests/{iid}/notes",
            json={"body": body},
        )
        if r.status_code >= 400:
            return f"ERROR: mr_comment ({r.status_code}): {r.text[:300]}"
    return f"commented on {project}!{iid}"


def _pipelines(project: str, ref: str, limit: int) -> str:
    base, client = _client()
    params: dict = {}
    if ref:
        params["ref"] = ref
    with client:
        items = _paginated_get(
            client, f"{base}/api/v4/projects/{_enc(project)}/pipelines",
            params, limit,
        )
    if not items:
        return "no pipelines"
    return "\n".join(
        f"  #{p['id']:>8}  [{p.get('status', '?'):>10}]  {p.get('ref', '?')}  {p.get('web_url')}"
        for p in items
    )


def _pipeline_get(project: str, pid: int) -> str:
    base, client = _client()
    with client:
        r = client.get(
            f"{base}/api/v4/projects/{_enc(project)}/pipelines/{pid}",
        )
        if r.status_code == 404:
            return f"pipeline {project}#{pid} not found"
        r.raise_for_status()
        d = r.json()
    return (
        f"pipeline #{d.get('id')}\n"
        f"  status:    {d.get('status', '?')}\n"
        f"  ref:       {d.get('ref', '?')}\n"
        f"  sha:       {(d.get('sha') or '')[:12]}\n"
        f"  created:   {d.get('created_at', '?')}\n"
        f"  finished:  {d.get('finished_at', '?')}\n"
        f"  url:       {d.get('web_url')}"
    )


_PROJECT_OPS = {
    "issues", "issue_get", "issue_create", "issue_comment",
    "mr_list", "mr_get", "mr_comment", "pipelines", "pipeline_get",
}


def _dispatch_issue_op(op: str, project: str, args: dict[str, Any]) -> str | None:
    if op == "issues":
        return _list_issues(
            project, args.get("state", "opened"),
            max(1, min(int(args.get("limit") or 25), 100)),
        )
    if op == "issue_get":
        iid = int(args.get("iid") or 0)
        if not iid:
            return "ERROR: issue_get requires iid"
        return _issue_get(project, iid)
    if op == "issue_create":
        title = (args.get("title") or "").strip()
        if not title:
            return "ERROR: issue_create requires title"
        return _issue_create(project, title, args.get("body") or "")
    if op == "issue_comment":
        iid = int(args.get("iid") or 0)
        body = args.get("body") or ""
        if not iid or not body:
            return "ERROR: issue_comment requires iid and body"
        return _issue_comment(project, iid, body)
    return None


def _dispatch_mr_pipeline_op(op: str, project: str, args: dict[str, Any]) -> str | None:
    if op == "mr_list":
        return _mr_list(
            project, args.get("state", "opened"),
            max(1, min(int(args.get("limit") or 25), 100)),
        )
    if op == "mr_get":
        iid = int(args.get("iid") or 0)
        if not iid:
            return "ERROR: mr_get requires iid"
        return _mr_get(project, iid)
    if op == "mr_comment":
        iid = int(args.get("iid") or 0)
        body = args.get("body") or ""
        if not iid or not body:
            return "ERROR: mr_comment requires iid and body"
        return _mr_comment(project, iid, body)
    if op == "pipelines":
        return _pipelines(
            project, args.get("ref") or "",
            max(1, min(int(args.get("limit") or 20), 100)),
        )
    if op == "pipeline_get":
        pid = int(args.get("pipeline_id") or 0)
        if not pid:
            return "ERROR: pipeline_get requires pipeline_id"
        return _pipeline_get(project, pid)
    return None


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    project = (args.get("project") or "").strip()
    try:
        if op in _PROJECT_OPS and not project:
            return f"ERROR: {op} requires project"
        result = _dispatch_issue_op(op, project, args)
        if result is not None:
            return result
        result = _dispatch_mr_pipeline_op(op, project, args)
        if result is not None:
            return result
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: GitLab request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def gitlab() -> Tool:
    return Tool(
        name="gitlab",
        description=(
            "Read / write GitLab issues, merge requests, and "
            "pipelines via REST v4. ops: issues, issue_get, "
            "issue_create, issue_comment, mr_list, mr_get, "
            "mr_comment, pipelines, pipeline_get. project = "
            "'group/repo'. Auth: GITLAB_TOKEN. Self-hosted: "
            "GITLAB_URL."
        ),
        input_schema=_GITLAB_SCHEMA,
        fn=_run,
    )
