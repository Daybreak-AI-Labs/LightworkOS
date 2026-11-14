"""Reddit tool — read-only via the public JSON API.

No auth required for the public read endpoints we use; respects
Reddit's User-Agent + rate-limit rules.

ops:
  - subreddit(name, sort, limit)        — sort = hot | new | top | rising
  - post(post_id)                       — t3_id or full permalink shortcode
  - search(q, subreddit, limit)
  - user(username, sort, limit)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_redirect_get
from . import Tool, safe_path_segment

log = logging.getLogger(__name__)


_RD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["subreddit", "post", "search", "user"]},
        "name": {"type": "string"},
        "sort": {"type": "string"},
        "limit": {"type": "integer"},
        "post_id": {"type": "string"},
        "q": {"type": "string"},
        "subreddit": {"type": "string"},
        "username": {"type": "string"},
    },
    "required": ["op"],
}


def _ua() -> str:
    return os.environ.get("REDDIT_USER_AGENT",
                          "maverick-agent/0.1 (https://github.com/Daybreak-AI-Labs/LightworkOS)")


def _get(url: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = guarded_redirect_get(httpx.get)(url, headers={"User-Agent": _ua()},
                                       params=params or {}, timeout=20.0,
                                       follow_redirects=True)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _render_posts(rows: list[dict]) -> str:
    out = []
    for ch in rows:
        d = (ch.get("data") if isinstance(ch, dict) else None) or {}
        out.append(
            f"  r/{d.get('subreddit', '?'):<20}  "
            f"score={d.get('score', '?')!s:>6}  "
            f"c={d.get('num_comments', '?')!s:>4}  "
            f"{(d.get('title') or '')[:80]}"
        )
    return "\n".join(out) or "no posts"


def _op_subreddit(args: dict) -> str:
    name = (args.get("name") or "").strip().removeprefix("r/")
    if not name:
        return "ERROR: subreddit requires name"
    sort = (args.get("sort") or "hot").strip()
    limit = max(1, min(int(args.get("limit") or 25), 100))
    name, sort = safe_path_segment(name), safe_path_segment(sort)
    if name is None or sort is None:
        return "ERROR: name and sort must each be a single path segment"
    code, data = _get(
        f"https://www.reddit.com/r/{name}/{sort}.json",
        {"limit": limit},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: subreddit ({code}): {data}"
    rows = ((data.get("data") or {}).get("children")) or []
    return _render_posts(rows)


def _op_post(args: dict) -> str:
    pid = (args.get("post_id") or "").strip().removeprefix("t3_")
    if not pid:
        return "ERROR: post requires post_id"
    pid = safe_path_segment(pid)
    if pid is None:
        return "ERROR: post_id must be a single path segment"
    code, data = _get(f"https://www.reddit.com/comments/{pid}.json")
    if code >= 400 or not isinstance(data, list):
        return f"ERROR: post ({code}): {data}"
    if not data:
        return "no data"
    post = ((data[0].get("data") or {}).get("children") or [{}])[0]
    pd = post.get("data") or {}
    return (
        f"{pd.get('title')}\n"
        f"  r/{pd.get('subreddit')}  score={pd.get('score')}  "
        f"by u/{pd.get('author')}\n"
        f"  url:  https://reddit.com{pd.get('permalink', '')}\n\n"
        f"{(pd.get('selftext') or '')[:3000]}"
    )


def _op_search(args: dict) -> str:
    q = (args.get("q") or "").strip()
    if not q:
        return "ERROR: search requires q"
    sub = (args.get("subreddit") or "").strip().removeprefix("r/")
    limit = max(1, min(int(args.get("limit") or 25), 100))
    if sub:
        sub = safe_path_segment(sub)
        if sub is None:
            return "ERROR: subreddit must be a single path segment"
    url = (
        f"https://www.reddit.com/r/{sub}/search.json"
        if sub else "https://www.reddit.com/search.json"
    )
    code, data = _get(url, {"q": q, "limit": limit, "restrict_sr": "1" if sub else "0"})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    return _render_posts(((data.get("data") or {}).get("children")) or [])


def _op_user(args: dict) -> str:
    u = (args.get("username") or "").strip().removeprefix("u/")
    if not u:
        return "ERROR: user requires username"
    sort = (args.get("sort") or "new").strip()
    limit = max(1, min(int(args.get("limit") or 25), 100))
    u, sort = safe_path_segment(u), safe_path_segment(sort)
    if u is None or sort is None:
        return "ERROR: username and sort must each be a single path segment"
    code, data = _get(
        f"https://www.reddit.com/user/{u}/submitted/{sort}.json",
        {"limit": limit},
    )
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: user ({code}): {data}"
    return _render_posts(((data.get("data") or {}).get("children")) or [])


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
            "subreddit": _op_subreddit,
            "post":      _op_post,
            "search":    _op_search,
            "user":      _op_user,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: Reddit request failed: {type(e).__name__}: {e}"


def reddit_tool() -> Tool:
    return Tool(
        name="reddit",
        description=(
            "Reddit read-only via public JSON API. ops: subreddit "
            "(name + sort), post (id), search (q + optional "
            "subreddit), user (username + sort). No auth required."
        ),
        input_schema=_RD_SCHEMA,
        fn=_run,
    )
