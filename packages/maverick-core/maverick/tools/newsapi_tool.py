"""NewsAPI tool — headlines + article search.

Auth: ``NEWSAPI_KEY`` (newsapi.org).

ops:
  - top_headlines(country, category, query, limit)
  - search(query, from_date, to_date, sort, limit)
  - sources(category, country)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_NEWS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["top_headlines", "search", "sources"]},
        "country": {"type": "string", "description": "ISO 3166 (e.g. 'us')."},
        "category": {"type": "string"},
        "query": {"type": "string"},
        "from_date": {"type": "string"},
        "to_date": {"type": "string"},
        "sort": {"type": "string", "enum": ["relevancy", "popularity", "publishedAt"]},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


_API = "https://newsapi.org/v2"


def _key() -> str:
    k = os.environ.get("NEWSAPI_KEY", "").strip()
    if not k:
        raise RuntimeError("NewsAPI requires NEWSAPI_KEY.")
    return k


def _get(path: str, params: dict) -> tuple[int, Any]:
    import httpx
    # Key goes in the X-Api-Key header, never the query string: a URL with
    # the key embedded leaks into httpx error reprs and any request log.
    r = _governed_sender(httpx.get)(f"{_API}{path}", params=params,
                  headers={"X-Api-Key": _key()}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _render_articles(arts: list[dict]) -> str:
    if not arts:
        return "no articles"
    out = []
    for a in arts:
        src = (a.get("source") or {}).get("name", "?")
        out.append(
            f"  [{src[:20]:<20}]  {(a.get('title') or '')[:80]}\n"
            f"      {a.get('url', '')}"
        )
    return "\n".join(out)


def _op_top_headlines(args: dict) -> str:
    params: dict = {"pageSize": max(1, min(int(args.get("limit") or 20), 100))}
    if args.get("country"):
        params["country"] = args["country"]
    if args.get("category"):
        params["category"] = args["category"]
    if args.get("query"):
        params["q"] = args["query"]
    if not any(k in params for k in ("country", "category", "q", "sources")):
        params["country"] = "us"
    code, data = _get("/top-headlines", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: top_headlines ({code}): {data}"
    if data.get("status") != "ok":
        return f"ERROR: {data.get('message', data)}"
    return _render_articles(data.get("articles") or [])


def _op_search(args: dict) -> str:
    q = (args.get("query") or "").strip()
    if not q:
        return "ERROR: search requires query"
    params: dict = {
        "q": q, "pageSize": max(1, min(int(args.get("limit") or 20), 100)),
        "sortBy": args.get("sort") or "publishedAt",
    }
    if args.get("from_date"):
        params["from"] = args["from_date"]
    if args.get("to_date"):
        params["to"] = args["to_date"]
    code, data = _get("/everything", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    if data.get("status") != "ok":
        return f"ERROR: {data.get('message', data)}"
    return f"total={data.get('totalResults', '?')}\n" + _render_articles(
        data.get("articles") or [])


def _op_sources(args: dict) -> str:
    params: dict = {}
    if args.get("category"):
        params["category"] = args["category"]
    if args.get("country"):
        params["country"] = args["country"]
    code, data = _get("/top-headlines/sources", params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: sources ({code}): {data}"
    rows = data.get("sources") or []
    if not rows:
        return "no sources"
    return "\n".join(
        f"  {(s.get('id') or '?'):<25}  {(s.get('name') or '')[:40]}  ({s.get('category', '?')})"
        for s in rows[:50]
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
            "top_headlines": _op_top_headlines,
            "search":        _op_search,
            "sources":       _op_sources,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: NewsAPI request failed: {type(e).__name__}: {e}"


def newsapi_tool() -> Tool:
    return Tool(
        name="newsapi",
        description=(
            "NewsAPI.org. ops: top_headlines (country/category/query "
            "filters), search (everything endpoint, date range + "
            "sort), sources (list). Auth: NEWSAPI_KEY."
        ),
        input_schema=_NEWS_SCHEMA,
        fn=_run,
    )
