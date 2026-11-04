"""Wikipedia tool.

Two ops:
  - search(query, limit, lang) — keyword search, returns title + snippet + url
  - fetch(title, lang)         — full article extract (plain text) + url

Uses the Wikipedia Action API (``/w/api.php``). No auth required; the
Wikimedia Foundation just asks for a descriptive User-Agent, which we
send. Falls back gracefully on network errors.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import quote

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_USER_AGENT = "Lightwork/0.1 (https://github.com/Daybreak-AI-Labs/LightworkOS)"

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "fetch"],
            "description": "Operation.",
        },
        "query": {"type": "string", "description": "Search keywords (search op)."},
        "title": {"type": "string", "description": "Article title (fetch op)."},
        "limit": {
            "type": "integer",
            "description": "Search result count (default 10, max 50).",
        },
        "lang": {
            "type": "string",
            "description": "Wikipedia language code (default 'en').",
        },
        "max_chars": {
            "type": "integer",
            "description": "Truncate fetch output to this many chars (default 8000).",
        },
    },
    "required": ["op"],
}


def _strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    return (
        text.replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">")
            .replace("&quot;", '"').replace("&#039;", "'")
    )


def _api_base(lang: str) -> str:
    lang = re.sub(r"[^a-z\-]", "", (lang or "en").lower()) or "en"
    return f"https://{lang}.wikipedia.org/w/api.php"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[session]'"

    lang = args.get("lang") or "en"
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}

    if op == "search":
        query = (args.get("query") or "").strip()
        if not query:
            return "ERROR: search requires query"
        limit = max(1, min(int(args.get("limit") or 10), 50))
        params = {
            "action": "query", "list": "search", "srsearch": query,
            "srlimit": str(limit), "format": "json", "formatversion": "2",
        }
        try:
            resp = _governed_sender(httpx.get)(_api_base(lang), params=params, headers=headers, timeout=15.0)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return f"ERROR: Wikipedia search failed: {type(e).__name__}: {e}"
        hits = (data.get("query") or {}).get("search") or []
        if not hits:
            return "no results"
        lines = []
        for i, h in enumerate(hits, 1):
            title = h.get("title") or ""
            snippet = _strip_html(h.get("snippet") or "")
            url = f"https://{lang}.wikipedia.org/wiki/{quote(title.replace(' ', '_'))}"
            lines.append(f"{i}. {title}\n   {url}\n   {snippet}")
        return "\n\n".join(lines)

    if op == "fetch":
        title = (args.get("title") or "").strip()
        if not title:
            return "ERROR: fetch requires title"
        max_chars = max(100, min(int(args.get("max_chars") or 8000), 50000))
        params = {
            "action": "query", "prop": "extracts", "titles": title,
            "explaintext": "1", "redirects": "1",
            "format": "json", "formatversion": "2",
        }
        try:
            resp = _governed_sender(httpx.get)(_api_base(lang), params=params, headers=headers, timeout=20.0)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return f"ERROR: Wikipedia fetch failed: {type(e).__name__}: {e}"
        pages = (data.get("query") or {}).get("pages") or []
        if not pages:
            return f"no article found for {title!r}"
        page = pages[0]
        if page.get("missing"):
            return f"no article found for {title!r}"
        resolved = page.get("title") or title
        extract = page.get("extract") or ""
        if not extract:
            return f"no extract available for {resolved!r}"
        url = f"https://{lang}.wikipedia.org/wiki/{quote(resolved.replace(' ', '_'))}"
        truncated = extract[:max_chars]
        suffix = f"\n\n[truncated at {max_chars} chars]" if len(extract) > max_chars else ""
        return f"{resolved}\n{url}\n\n{truncated}{suffix}"

    return f"ERROR: unknown op {op!r}"


def wikipedia() -> Tool:
    return Tool(
        name="wikipedia",
        description=(
            "Wikipedia search and article fetch. ops: search (keyword "
            "search, returns titles + snippets + URLs), fetch (full "
            "plain-text article extract by title). Optional 'lang' "
            "(default 'en') selects a language Wikipedia. No API key."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
