"""GitHub code / repo search tool.

Search GitHub repositories and code via the public Search API. A
``GITHUB_TOKEN`` (Bearer) is used when present — it lifts the strict
unauthenticated rate limit and is *required* for code search — but repo
search works anonymously for public repositories.

ops:
  - repos(query, limit)  — search repositories.
  - code(query, limit)   — search code (requires GITHUB_TOKEN).

Stdlib only (urllib.request + json). The network layer is a single small
helper (``_http_get_json``); URL building and JSON parsing are pure helpers
so they can be tested without any network access.
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
        "User-Agent": "maverick-github-repo-search",
    }
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _build_url(op: str, query: str, limit: int) -> str:
    """Build the api.github.com search URL for ``op`` (repos|code)."""
    kind = "repositories" if op == "repos" else "code"
    per_page = max(1, min(limit, 100))
    qs = urllib.parse.urlencode({"q": query, "per_page": per_page})
    return f"{_API}/search/{kind}?{qs}"


def _parse_repos(data: dict) -> str:
    """Parse a /search/repositories JSON dict into a compact listing."""
    items = data.get("items") or []
    items = [it for it in items if isinstance(it, dict)]
    if not items:
        return "no repositories"
    lines = []
    for it in items:
        full = it.get("full_name") or it.get("name") or "?"
        stars = it.get("stargazers_count", 0)
        desc = (it.get("description") or "")[:80]
        lines.append(f"  {full}  ★{stars}  {desc}")
    return "\n".join(lines)


def _parse_code(data: dict) -> str:
    """Parse a /search/code JSON dict into a compact listing."""
    items = data.get("items") or []
    items = [it for it in items if isinstance(it, dict)]
    if not items:
        return "no code matches"
    lines = []
    for it in items:
        path = it.get("path") or "?"
        repository = it.get("repository")
        repo = repository.get("full_name", "?") if isinstance(repository, dict) else "?"
        lines.append(f"  {repo}  {path}")
    return "\n".join(lines)


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
    try:
        with _OPENER.open(req, timeout=30) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:  # type: ignore[attr-defined]
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, body[:300]


def _run(args: dict[str, Any]) -> str:
    op = args.get("op") or "repos"
    if op not in ("repos", "code"):
        return f"ERROR: unknown op {op!r}"
    query = str(args.get("query") or "").strip()
    if not query:
        return "ERROR: query is required"
    if op == "code" and not os.environ.get("GITHUB_TOKEN", "").strip():
        return "ERROR: set GITHUB_TOKEN to search code (code search requires auth)"
    try:
        limit = max(1, min(int(float(args.get("limit") or 20)), 100))
    except (TypeError, ValueError, OverflowError):
        limit = 20
    url = _build_url(op, query, limit)
    try:
        code, data = _http_get_json(url)
    except Exception as e:
        return f"ERROR: GitHub search failed: {type(e).__name__}: {e}"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    return _parse_repos(data) if op == "repos" else _parse_code(data)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["repos", "code"]},
        "query": {"type": "string", "description": "GitHub search query."},
        "limit": {"type": "integer", "description": "Max results (1-100)."},
    },
    "required": ["query"],
}


def github_repo_search() -> Tool:
    return Tool(
        name="github_repo_search",
        description=(
            "Search GitHub via the public Search API. ops: repos "
            "(repositories) and code (requires GITHUB_TOKEN). 'query' "
            "is a GitHub search expression. GITHUB_TOKEN (Bearer) lifts "
            "rate limits; optional for public repo search."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
