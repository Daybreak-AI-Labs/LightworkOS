"""Hacker News tool.

Read-only access to the HN Firebase API. Good for: monitoring a
specific submission's comments, fetching the top stories for a
research goal, looking up a user's profile / submissions.

No auth required.

ops:
  - top(limit)                  — top story ids + titles
  - new(limit)                  — new story ids + titles
  - best(limit)                 — best story ids + titles
  - get(item_id)                — single item (story or comment)
  - user(username)              — user profile
  - search(query, limit)        — via Algolia HN Search (third-party)
"""
from __future__ import annotations

import logging
from typing import Any

from ..governed_http import guarded_redirect_get
from . import Tool

log = logging.getLogger(__name__)


_HN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["top", "new", "best", "get", "user", "search"]},
        "limit": {"type": "integer"},
        "item_id": {"type": "integer"},
        "username": {"type": "string"},
        "query": {"type": "string"},
    },
    "required": ["op"],
}


_FIREBASE = "https://hacker-news.firebaseio.com/v0"
_ALGOLIA = "https://hn.algolia.com/api/v1"


def _get(url: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = guarded_redirect_get(httpx.get)(url, params=params or {}, timeout=20.0,
                                       follow_redirects=True)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {}


def _fetch_item(item_id: int) -> dict | None:
    code, data = _get(f"{_FIREBASE}/item/{item_id}.json")
    if code != 200 or not isinstance(data, dict):
        return None
    return data


def _format_stories(ids: list[int], limit: int) -> str:
    rows: list[str] = []
    for i in ids[:limit]:
        item = _fetch_item(int(i)) or {}
        title = (item.get("title") or "").strip()
        score = item.get("score", "?")
        comments = item.get("descendants", "?")
        url = item.get("url") or f"https://news.ycombinator.com/item?id={i}"
        rows.append(f"  [{score:>4} | {comments:>3}c]  {title[:80]}\n      {url}")
    return "\n".join(rows) if rows else "no stories"


def _op_list(kind: str, limit: int) -> str:
    code, data = _get(f"{_FIREBASE}/{kind}stories.json")
    if code != 200 or not isinstance(data, list):
        return f"ERROR: {kind}stories ({code}): {data}"
    return _format_stories(data, max(1, min(limit, 30)))


def _op_get(item_id: int) -> str:
    item = _fetch_item(item_id)
    if item is None:
        return f"item {item_id} not found"
    t = item.get("type", "?")
    if t == "story":
        return (
            f"[story #{item.get('id')}] {item.get('title', '')}\n"
            f"  by {item.get('by', '?')}  score={item.get('score', '?')}  "
            f"comments={item.get('descendants', '?')}\n"
            f"  url:  {item.get('url', '(self post)')}\n\n"
            f"{(item.get('text') or '')[:3000]}"
        )
    if t == "comment":
        return (
            f"[comment #{item.get('id')}] by {item.get('by', '?')}\n"
            f"  parent: {item.get('parent', '?')}\n\n"
            f"{(item.get('text') or '')[:3000]}"
        )
    return str(item)[:3000]


def _op_user(username: str) -> str:
    code, data = _get(f"{_FIREBASE}/user/{username}.json")
    if code != 200 or not isinstance(data, dict):
        return f"user {username!r} not found"
    return (
        f"{data.get('id')}  karma={data.get('karma', '?')}\n"
        f"  created: {data.get('created')}\n"
        f"  about:   {(data.get('about') or '')[:300]}\n"
        f"  submitted: {len(data.get('submitted') or [])}"
    )


def _op_search(query: str, limit: int) -> str:
    code, data = _get(f"{_ALGOLIA}/search", {"query": query, "hitsPerPage": limit})
    if code != 200 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    hits = data.get("hits") or []
    if not hits:
        return "no matches"
    rows = []
    for h in hits:
        title = h.get("title") or h.get("story_title") or (h.get("comment_text") or "")[:60]
        url = h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}"
        rows.append(
            f"  [{h.get('points') or '?'!s:>4}]  {title[:80]}\n      {url}"
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
    limit = int(args.get("limit") or 10)
    try:
        if op in ("top", "new", "best"):
            return _op_list(op, limit)
        if op == "get":
            iid = int(args.get("item_id") or 0)
            if not iid:
                return "ERROR: get requires item_id"
            return _op_get(iid)
        if op == "user":
            u = (args.get("username") or "").strip()
            if not u:
                return "ERROR: user requires username"
            return _op_user(u)
        if op == "search":
            q = (args.get("query") or "").strip()
            if not q:
                return "ERROR: search requires query"
            return _op_search(q, max(1, min(limit, 50)))
    except Exception as e:
        return f"ERROR: hackernews failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def hackernews() -> Tool:
    return Tool(
        name="hackernews",
        description=(
            "Hacker News read-only API. ops: top / new / best "
            "(story lists), get (single item by id), user "
            "(profile by username), search (via Algolia HN). No "
            "auth required."
        ),
        input_schema=_HN_SCHEMA,
        fn=_run,
    )
