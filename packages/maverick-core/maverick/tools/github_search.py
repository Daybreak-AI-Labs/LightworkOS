"""GitHub search tool — repositories / code / issues via the REST search API
.

Auth is explicit, never ambient: a token is read from ``GITHUB_TOKEN`` (or
``GH_TOKEN``), falling back to ``[github] token`` in ``~/.maverick/config.toml``
— the same explicit-token connector pattern as the other REST tools, no
``gh``-CLI credential reuse. Repository and issue search work unauthenticated
(at GitHub's anonymous rate limits); **code search requires auth** — without a
token the tool returns a clear ERROR explaining what to set instead of a
confusing upstream 401.

ops:
  - repos(query[, limit])               — name / stars / description / url
  - code(query[, repo, limit])          — repo:path + url (+ match fragment)
  - issues(query[, repo, state, limit]) — #number [state] title + url

``limit`` is clamped to 1..20 (one ``per_page``-sized request per call — a
search tool must not be a scraping primitive). A 403/429 (primary or
secondary rate limit) is shaped into a readable ERROR carrying the
``Retry-After`` hint when GitHub sends one. Read-only: no mutations, so no
confirm gate. The endpoint host is fixed (``api.github.com``), so no SSRF
surface. ``httpx`` is imported lazily inside the executor.

NOTE: the REST code-search response carries file paths + html urls (and
optional text-match fragments), but no line numbers — so results are
``repo:path`` lines, with the first match fragment shown when present.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)

_API = "https://api.github.com"
MAX_LIMIT = 20
DEFAULT_LIMIT = 10
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")

_GHS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["repos", "code", "issues"]},
        "query": {"type": "string", "description": "Search query (GitHub syntax)."},
        "repo": {
            "type": "string",
            "description": "Scope code/issues search to one 'owner/name' repo.",
        },
        "state": {
            "type": "string",
            "enum": ["open", "closed"],
            "description": "Issue state filter (issues).",
        },
        "limit": {"type": "integer", "description": "Max results, clamped to 20."},
    },
    "required": ["op"],
}


def _token() -> str:
    """Explicit token: env first, then ``[github] token`` in config. May be
    empty — repos/issues then run unauthenticated; code refuses with a clear
    error before any request."""
    t = (os.environ.get("GITHUB_TOKEN", "") or os.environ.get("GH_TOKEN", "")).strip()
    if t:
        return t
    try:
        from ..config import load_config
        return str((load_config() or {}).get("github", {}).get("token") or "").strip()
    except Exception:  # pragma: no cover -- config never blocks the tool
        return ""


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _clamp(limit: Any) -> int:
    try:
        n = int(limit if limit is not None else DEFAULT_LIMIT)
    except (TypeError, ValueError):
        n = DEFAULT_LIMIT
    return max(1, min(n, MAX_LIMIT))


def _get(path: str, params: dict, *, accept: str | None = None) -> tuple[int, Any, Any]:
    import httpx
    headers = _headers()
    if accept:
        headers["Accept"] = accept
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=headers, params=params, timeout=30.0)
    try:
        data = r.json()
    except ValueError:
        data = (r.text or "")[:300]
    return r.status_code, data, r.headers


def _shape_error(op: str, code: int, data: Any, headers: Any) -> str:
    """Readable upstream failure; rate limits get the Retry-After hint."""
    msg = data.get("message") if isinstance(data, dict) else data
    if code in (403, 429):
        retry = None
        try:
            retry = headers.get("retry-after") or headers.get("Retry-After")
        except Exception:
            retry = None
        hint = f" Retry after {retry}s." if retry else " Slow down and retry later."
        kind = ("rate limit" if isinstance(msg, str) and (
            "rate limit" in msg.lower() or "abuse" in msg.lower()) else "forbidden")
        return f"ERROR: {op}: GitHub {kind} ({code}): {msg}.{hint}"
    return f"ERROR: {op} ({code}): {msg}"


def _scoped_query(args: dict, base_query: str) -> str | None:
    """Append a validated ``repo:owner/name`` qualifier; None on a bad repo."""
    repo = (args.get("repo") or "").strip()
    if not repo:
        return base_query
    if not _REPO_RE.fullmatch(repo):
        return None
    return f"{base_query} repo:{repo}"


def _op_repos(args: dict) -> str:
    q = (args.get("query") or "").strip()
    if not q:
        return "ERROR: repos requires query"
    limit = _clamp(args.get("limit"))
    code, data, headers = _get("/search/repositories",
                               {"q": q, "per_page": limit})
    if code >= 400 or not isinstance(data, dict):
        return _shape_error("repos", code, data, headers)
    items = (data.get("items") or [])[:limit]
    if not items:
        return "no matches"
    return "\n".join(
        f"  {i.get('full_name')}  [{i.get('stargazers_count', 0)} stars]  "
        f"{(i.get('description') or '')[:70]}  {i.get('html_url')}"
        for i in items
    )


def _op_code(args: dict) -> str:
    q = (args.get("query") or "").strip()
    if not q:
        return "ERROR: code requires query"
    if not _token():
        return (
            "ERROR: GitHub code search requires authentication (the /search/code "
            "API rejects anonymous calls). Set GITHUB_TOKEN or GH_TOKEN, or "
            "[github] token in ~/.maverick/config.toml, to a token with the "
            "repo (private) or public_repo scope."
        )
    scoped = _scoped_query(args, q)
    if scoped is None:
        return f"ERROR: repo must look like 'owner/name' (got {args.get('repo')!r})"
    limit = _clamp(args.get("limit"))
    # GitHub only populates each item's text_matches (used for the fragment
    # preview below) when the request opts in via the text-match media type;
    # the default vnd.github+json Accept never returns fragments.
    code, data, headers = _get(
        "/search/code", {"q": scoped, "per_page": limit},
        accept="application/vnd.github.text-match+json",
    )
    if code >= 400 or not isinstance(data, dict):
        return _shape_error("code", code, data, headers)
    items = (data.get("items") or [])[:limit]
    if not items:
        return "no matches"
    lines = []
    for it in items:
        repo_full = (it.get("repository") or {}).get("full_name") or "?"
        frag = ""
        text_matches = it.get("text_matches") or []
        if text_matches:
            first = (text_matches[0].get("fragment") or "").strip().splitlines()
            if first:
                frag = f"\n      | {first[0][:100]}"
        lines.append(f"  {repo_full}:{it.get('path')}  {it.get('html_url')}{frag}")
    return "\n".join(lines)


def _op_issues(args: dict) -> str:
    q = (args.get("query") or "").strip()
    if not q:
        return "ERROR: issues requires query"
    scoped = _scoped_query(args, q)
    if scoped is None:
        return f"ERROR: repo must look like 'owner/name' (got {args.get('repo')!r})"
    state = (args.get("state") or "").strip().lower()
    if state:
        if state not in ("open", "closed"):
            return f"ERROR: state must be 'open' or 'closed' (got {state!r})"
        scoped = f"{scoped} state:{state}"
    limit = _clamp(args.get("limit"))
    code, data, headers = _get("/search/issues", {"q": scoped, "per_page": limit})
    if code >= 400 or not isinstance(data, dict):
        return _shape_error("issues", code, data, headers)
    items = (data.get("items") or [])[:limit]
    if not items:
        return "no matches"
    return "\n".join(
        f"  #{i.get('number')}  [{i.get('state', '?'):>6}]  "
        f"{(i.get('title') or '')[:70]}  {i.get('html_url')}"
        for i in items
    )


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
            "repos":  _op_repos,
            "code":   _op_code,
            "issues": _op_issues,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: GitHub search failed: {type(e).__name__}: {e}"


def github_search() -> Tool:
    return Tool(
        name="github_search",
        description=(
            "Search GitHub via the REST API. ops: repos (query -> name/stars/"
            "description/url), code (query + optional repo 'owner/name'; "
            "REQUIRES a token), issues (query + optional repo and state "
            "open/closed). limit clamped to 20. Auth: GITHUB_TOKEN / GH_TOKEN "
            "env or [github] token in config.toml; repos/issues also work "
            "unauthenticated at lower rate limits."
        ),
        input_schema=_GHS_SCHEMA,
        fn=_run,
    )


__all__ = ["github_search"]
