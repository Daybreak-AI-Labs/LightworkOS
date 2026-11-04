"""GitHub issues tool — list / get / create.

Read and write GitHub issues via the REST API. A ``GITHUB_TOKEN`` (Bearer)
is required for ``create`` (and lifts rate limits for reads); ``list`` /
``get`` work anonymously against public repositories.

ops:
  - list(owner, repo, state, limit)
  - get(owner, repo, number)
  - create(owner, repo, title, body)

Stdlib only (urllib.request + json). The network layer is isolated in two
small helpers (``_http_get_json`` / ``_http_post_json``); URL building and
JSON parsing are pure helpers tested without any network access.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from . import Tool

_API = "https://api.github.com"


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "maverick-github-issues",
    }
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _list_url(owner: str, repo: str, state: str, limit: int) -> str:
    per_page = max(1, min(limit, 100))
    qs = urllib.parse.urlencode({"state": state, "per_page": per_page})
    return f"{_API}/repos/{owner}/{repo}/issues?{qs}"


def _get_url(owner: str, repo: str, number: int) -> str:
    return f"{_API}/repos/{owner}/{repo}/issues/{number}"


def _create_url(owner: str, repo: str) -> str:
    return f"{_API}/repos/{owner}/{repo}/issues"


def _parse_list(items: list) -> str:
    """Parse a GitHub issues list (excluding PRs) into a compact listing."""
    rows = [i for i in items if isinstance(i, dict) and "pull_request" not in i]
    if not rows:
        return "no issues"
    return "\n".join(
        f"  #{i.get('number'):<5}  [{i.get('state', '?'):>6}]  "
        f"{(i.get('title') or '')[:80]}"
        for i in rows
    )


def _parse_issue(d: dict) -> str:
    """Parse a single GitHub issue JSON dict into a detail block."""
    return (
        f"#{d.get('number')}  {d.get('title', '')}\n"
        f"  state:  {d.get('state', '?')}\n"
        f"  author: {(d.get('user') or {}).get('login', '?')}\n"
        f"  url:    {d.get('html_url')}\n\n"
        f"{(d.get('body') or '')[:5000]}"
    )


# CPython's stock HTTPRedirectHandler re-sends the original request headers
# (only content-length/content-type are dropped) to a 3xx target with no host
# re-check, so any redirect would leak 'Authorization: Bearer <GITHUB_TOKEN>'
# to the Location host. Strip auth headers when the redirect crosses to a
# different host (the httpx siblings default to follow_redirects=False).
_AUTH_HEADERS = ("authorization", "cookie")


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


def _slug(args: dict) -> tuple[str, str] | str:
    owner = (args.get("owner") or "").strip()
    repo = (args.get("repo") or "").strip()
    if not owner or not repo:
        return "ERROR: owner and repo are required"
    return owner, repo


def _op_list(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    owner, repo = sg
    state = (args.get("state") or "open").strip()
    limit = max(1, min(int(args.get("limit") or 25), 100))
    code, data = _http_get_json(_list_url(owner, repo, state, limit))
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: list ({code}): {data}"
    return _parse_list(data)


def _op_get(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    owner, repo = sg
    number = int(args.get("number") or 0)
    if not number:
        return "ERROR: get requires number"
    code, data = _http_get_json(_get_url(owner, repo, number))
    if code == 404:
        return f"issue {owner}/{repo}#{number} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: get ({code}): {data}"
    return _parse_issue(data)


def _op_create(args: dict) -> str:
    sg = _slug(args)
    if isinstance(sg, str):
        return sg
    owner, repo = sg
    title = (args.get("title") or "").strip()
    if not title:
        return "ERROR: create requires title"
    if not os.environ.get("GITHUB_TOKEN", "").strip():
        return "ERROR: set GITHUB_TOKEN to create issues"
    code, data = _http_post_json(
        _create_url(owner, repo),
        {"title": title, "body": args.get("body") or ""},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: create ({code}): {data}"
    return f"created #{data.get('number')}: {data.get('html_url')}"


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
        return f"ERROR: GitHub issues request failed: {type(e).__name__}: {e}"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "get", "create"]},
        "owner": {"type": "string"},
        "repo": {"type": "string"},
        "number": {"type": "integer", "description": "Issue number (get)."},
        "title": {"type": "string", "description": "Issue title (create)."},
        "body": {"type": "string", "description": "Issue body (create)."},
        "state": {"type": "string", "enum": ["open", "closed", "all"]},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


def github_issues() -> Tool:
    return Tool(
        name="github_issues",
        description=(
            "GitHub issues via REST. ops: list (owner, repo, state), "
            "get (owner, repo, number), create (owner, repo, title, "
            "body). GITHUB_TOKEN (Bearer) required for create; optional "
            "for reads on public repos."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=False,
    )
