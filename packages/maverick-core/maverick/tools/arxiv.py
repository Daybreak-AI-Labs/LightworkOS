"""arXiv tool.

Search arXiv and fetch abstracts. Uses arXiv's free Atom-XML query
API (no auth, no rate-limit beyond 3 req/sec).

Two ops:
  - search(query, max_results)  — returns a ranked list of title +
    arxiv_id + abstract snippet
  - fetch(arxiv_id)             — full abstract + metadata for one paper
"""
from __future__ import annotations

import logging
import re
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_ARXIV_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "fetch"],
            "description": "Operation.",
        },
        "query": {"type": "string", "description": "Search query (search op)."},
        "arxiv_id": {
            "type": "string",
            "description": "arXiv id like '2106.09685' (fetch op).",
        },
        "max_results": {"type": "integer", "description": "Default 10."},
        "category": {
            "type": "string",
            "description": "Optional cat filter (e.g. 'cs.LG').",
        },
    },
    "required": ["op"],
}


_API_URL = "https://export.arxiv.org/api/query"


def _parse_atom(xml: str) -> list[dict[str, str]]:
    """Pull entries out of arXiv's Atom XML response without an XML dep.

    Each entry has fields we extract via regex against the well-known
    arXiv schema. This is brittle if arXiv ever changes their format
    -- but they haven't in 15+ years.
    """
    entries = []
    # Split by <entry>...</entry>.
    for m in re.finditer(r"<entry>(.*?)</entry>", xml, flags=re.DOTALL):
        body = m.group(1)
        def _grab(tag: str, *, body=body) -> str:
            mm = re.search(rf"<{tag}>(.*?)</{tag}>", body, flags=re.DOTALL)
            return (mm.group(1).strip() if mm else "")
        title = re.sub(r"\s+", " ", _grab("title")).strip()
        summary = re.sub(r"\s+", " ", _grab("summary")).strip()
        published = _grab("published")
        id_url = _grab("id")
        # id_url like http://arxiv.org/abs/2106.09685v1; strip version + prefix.
        arxiv_id = re.sub(r"v\d+$", "", id_url.rsplit("/", 1)[-1])
        authors = [
            a.strip()
            for a in re.findall(r"<name>(.*?)</name>", body, flags=re.DOTALL)
        ]
        entries.append({
            "title": title,
            "arxiv_id": arxiv_id,
            "published": published,
            "authors": ", ".join(authors[:5]) + (" et al." if len(authors) > 5 else ""),
            "summary": summary,
            "url": f"https://arxiv.org/abs/{arxiv_id}",
        })
    return entries


def _format_entries(entries: list[dict[str, str]], full: bool = False) -> str:
    if not entries:
        return "no results"
    lines = []
    for i, e in enumerate(entries, 1):
        snippet = e["summary"] if full else (e["summary"][:300] + ("…" if len(e["summary"]) > 300 else ""))
        lines.append(
            f"{i}. {e['title']}\n"
            f"   {e['arxiv_id']}  {e['published'][:10]}  "
            f"{e['authors']}\n"
            f"   {e['url']}\n"
            f"   {snippet}"
        )
    return "\n\n".join(lines)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[session]'"

    if op == "search":
        query = (args.get("query") or "").strip()
        if not query:
            return "ERROR: search requires query"
        cat = args.get("category")
        if cat:
            query = f"cat:{cat} AND ({query})"
        max_results = max(1, min(int(args.get("max_results") or 10), 50))
        params = {
            "search_query": query,
            "max_results": str(max_results),
            "sortBy": "relevance",
            "sortOrder": "descending",
        }
        try:
            resp = _governed_sender(httpx.get)(_API_URL, params=params, timeout=20.0)
            resp.raise_for_status()
        except Exception as e:
            return f"ERROR: arXiv API call failed: {type(e).__name__}: {e}"
        entries = _parse_atom(resp.text)
        return _format_entries(entries)
    if op == "fetch":
        arxiv_id = (args.get("arxiv_id") or "").strip()
        if not arxiv_id:
            return "ERROR: fetch requires arxiv_id"
        # Normalize: strip only the arxiv.org URL prefix and any version
        # suffix. A blind rsplit("/") mangled old-style ids like
        # "math.GT/0309136" (which legitimately contain a slash) down to the
        # bare number, breaking the fetch.
        arxiv_id = re.sub(r"^https?://arxiv\.org/(?:abs|pdf)/", "", arxiv_id)
        arxiv_id = re.sub(r"v\d+$", "", arxiv_id)
        try:
            resp = _governed_sender(httpx.get)(
                _API_URL,
                params={"id_list": arxiv_id, "max_results": "1"},
                timeout=20.0,
            )
            resp.raise_for_status()
        except Exception as e:
            return f"ERROR: arXiv API call failed: {type(e).__name__}: {e}"
        entries = _parse_atom(resp.text)
        if not entries:
            return f"no paper found for arxiv_id={arxiv_id!r}"
        return _format_entries(entries[:1], full=True)
    return f"ERROR: unknown op {op!r}"


def arxiv() -> Tool:
    return Tool(
        name="arxiv",
        description=(
            "Search arXiv or fetch a specific paper. ops: search "
            "(query + optional category filter like 'cs.LG'), fetch "
            "(by arXiv id like '2106.09685'). Returns title, authors, "
            "publication date, URL, and abstract."
        ),
        input_schema=_ARXIV_SCHEMA,
        fn=_run,
    )
