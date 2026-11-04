"""GitLab issues tool — list / get / create.

Mirrors ``github_issues`` but addresses projects by id (or URL-encoded
``group/path``) via the GitLab v4 REST API. Requires ``GITLAB_TOKEN``
(personal access token, ``api`` scope) sent as the ``PRIVATE-TOKEN``
header. Optional ``GITLAB_URL`` for self-hosted instances (default
https://gitlab.com).

ops:
  - list(project_id, state, limit)
  - get(project_id, iid)
  - create(project_id, title, body)

Stdlib only (urllib.request + json). The network layer is isolated in two
small helpers; URL building and JSON parsing are pure helpers tested
without any network access.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from . import Tool


def _base() -> str:
    return os.environ.get("GITLAB_URL", "https://gitlab.com").strip().rstrip("/")


def _enc(project_id: str) -> str:
    return urllib.parse.quote(str(project_id), safe="")


def _list_url(base: str, project_id: str, state: str, limit: int) -> str:
    per_page = max(1, min(limit, 100))
    qs = urllib.parse.urlencode({"state": state, "per_page": per_page})
    return f"{base}/api/v4/projects/{_enc(project_id)}/issues?{qs}"


def _get_url(base: str, project_id: str, iid: int) -> str:
    return f"{base}/api/v4/projects/{_enc(project_id)}/issues/{iid}"


def _create_url(base: str, project_id: str) -> str:
    return f"{base}/api/v4/projects/{_enc(project_id)}/issues"


def _parse_list(items: list) -> str:
    """Parse a GitLab issues list into a compact listing."""
    rows = [i for i in items if isinstance(i, dict)]
    if not rows:
        return "no issues"
    return "\n".join(
        f"  #{i.get('iid'):<5}  [{i.get('state', '?'):>6}]  "
        f"{(i.get('title') or '')[:80]}"
        for i in rows
    )


def _parse_issue(d: dict) -> str:
    """Parse a single GitLab issue JSON dict into a detail block."""
    return (
        f"#{d.get('iid')}  {d.get('title', '')}\n"
        f"  state:  {d.get('state', '?')}\n"
        f"  author: {(d.get('author') or {}).get('username', '?')}\n"
        f"  url:    {d.get('web_url')}\n\n"
        f"{(d.get('description') or '')[:5000]}"
    )


def _headers() -> dict[str, str]:
    tok = os.environ.get("GITLAB_TOKEN", "").strip()
    return {
        "PRIVATE-TOKEN": tok,
        "Accept": "application/json",
        "User-Agent": "maverick-gitlab-issues",
    }


# PRIVATE-TOKEN is a custom auth header; CPython's stock HTTPRedirectHandler
# re-sends ALL original request headers (only content-length/content-type are
# dropped) to a 3xx target with no host re-check. GITLAB_URL is operator/
# self-host configurable, so a 30x off it (or any on-path 302) would leak the
# 'api'-scoped PAT to an arbitrary host. Strip auth headers when the redirect
# crosses to a different host (mirrors gitlab.py's follow_redirects=False).
_AUTH_HEADERS = ("private-token", "authorization", "cookie")


class _AuthStrippingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_host = urllib.parse.urlparse(req.full_url).hostname
            new_host = urllib.parse.urlparse(newurl).hostname
            if old_host != new_host:
                for h in _AUTH_HEADERS:
                    new.remove_header(h.capitalize())
        return new


_OPENER = urllib.request.build_opener(_AuthStrippingRedirectHandler())


def _http_get_json(url: str) -> tuple[int, Any]:
    req = urllib.request.Request(url, headers=_headers(), method="GET")
    return _send(req)


def _http_post_json(url: str, body: dict) -> tuple[int, Any]:
    data = json.dumps(body).encode("utf-8")
    headers = {**_headers(), "Content-Type": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    return _send(req)


def _send(req: urllib.request.Request) -> tuple[int, Any]:
    try:
        with _OPENER.open(req, timeout=30) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body[:300]


def _project(args: dict) -> str:
    return str(args.get("project_id") or "").strip()


def _op_list(args: dict) -> str:
    pid = _project(args)
    if not pid:
        return "ERROR: project_id is required"
    if not os.environ.get("GITLAB_TOKEN", "").strip():
        return "ERROR: set GITLAB_TOKEN (PRIVATE-TOKEN) to use GitLab"
    state = (args.get("state") or "opened").strip()
    limit = max(1, min(int(args.get("limit") or 25), 100))
    code, data = _http_get_json(_list_url(_base(), pid, state, limit))
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: list ({code}): {data}"
    return _parse_list(data)


def _op_get(args: dict) -> str:
    pid = _project(args)
    if not pid:
        return "ERROR: project_id is required"
    iid = int(args.get("iid") or 0)
    if not iid:
        return "ERROR: get requires iid"
    if not os.environ.get("GITLAB_TOKEN", "").strip():
        return "ERROR: set GITLAB_TOKEN (PRIVATE-TOKEN) to use GitLab"
    code, data = _http_get_json(_get_url(_base(), pid, iid))
    if code == 404:
        return f"issue {pid}#{iid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: get ({code}): {data}"
    return _parse_issue(data)


def _op_create(args: dict) -> str:
    pid = _project(args)
    if not pid:
        return "ERROR: project_id is required"
    title = (args.get("title") or "").strip()
    if not title:
        return "ERROR: create requires title"
    if not os.environ.get("GITLAB_TOKEN", "").strip():
        return "ERROR: set GITLAB_TOKEN (PRIVATE-TOKEN) to create issues"
    code, data = _http_post_json(
        _create_url(_base(), pid),
        {"title": title, "description": args.get("body") or ""},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: create ({code}): {data}"
    return f"created #{data.get('iid')}: {data.get('web_url')}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        return {
            "list":   _op_list,
            "get":    _op_get,
            "create": _op_create,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: GitLab issues request failed: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "get", "create"]},
        "project_id": {
            "type": "string",
            "description": "Project id or URL-encoded 'group/path'.",
        },
        "iid": {"type": "integer", "description": "Issue internal id (get)."},
        "title": {"type": "string", "description": "Issue title (create)."},
        "body": {"type": "string", "description": "Issue body (create)."},
        "state": {"type": "string", "enum": ["opened", "closed", "all"]},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def gitlab_issues() -> Tool:
    return Tool(
        name="gitlab_issues",
        description=(
            "GitLab issues via REST v4. ops: list (project_id, state), "
            "get (project_id, iid), create (project_id, title, body). "
            "project_id is a numeric id or URL-encoded 'group/path'. "
            "Auth: GITLAB_TOKEN (PRIVATE-TOKEN). Self-hosted: GITLAB_URL."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=False,
    )
