"""SemanticScholar tool.

Search Semantic Scholar's free Graph API. Complements the arXiv
tool with broader coverage (any indexed paper, not just preprints).

Two ops:
  - search(query, limit) — keyword search, returns titles + abstracts
  - paper(paper_id)       — by Semantic Scholar id OR DOI / arXiv id

No auth required for low-volume usage (~100 req/5min). For higher
throughput, set ``SEMANTIC_SCHOLAR_API_KEY``.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_API_BASE = "https://api.semanticscholar.org/graph/v1"

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "paper"],
            "description": "Operation.",
        },
        "query": {"type": "string", "description": "Search keywords (search op)."},
        "paper_id": {
            "type": "string",
            "description": "Semantic Scholar id, DOI (10.x), or arXiv id (paper op).",
        },
        "limit": {"type": "integer", "description": "Default 10, max 100."},
        "year": {
            "type": "string",
            "description": "Year filter (search). e.g. '2024' or '2020-2024'.",
        },
    },
    "required": ["op"],
}


_FIELDS = "title,abstract,year,authors.name,citationCount,openAccessPdf,externalIds,url"


def _format_paper(p: dict, *, full: bool = False) -> str:
    title = p.get("title") or "(no title)"
    year = p.get("year") or ""
    authors = ", ".join(
        a.get("name", "") for a in (p.get("authors") or [])[:5]
    )
    if len(p.get("authors") or []) > 5:
        authors += " et al."
    cites = p.get("citationCount") or 0
    url = p.get("url") or ""
    abstract = p.get("abstract") or "(no abstract)"
    snippet = abstract if full else (abstract[:300] + ("…" if len(abstract) > 300 else ""))
    pdf = (p.get("openAccessPdf") or {}).get("url", "")
    parts = [
        f"{title}",
        f"   {year}  {authors}  ({cites} cite{'s' if cites != 1 else ''})",
        f"   {url}",
    ]
    if pdf:
        parts.append(f"   PDF: {pdf}")
    parts.append(f"   {snippet}")
    return "\n".join(parts)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[session]'"

    headers = {}
    api_key = os.environ.get("SEMANTIC_SCHOLAR_API_KEY")
    if api_key:
        headers["x-api-key"] = api_key

    if op == "search":
        query = (args.get("query") or "").strip()
        if not query:
            return "ERROR: search requires query"
        try:
            limit = max(1, min(int(args.get("limit") or 10), 100))
        except (TypeError, ValueError):
            return "ERROR: limit must be an integer"
        params: dict[str, Any] = {
            "query": query, "limit": str(limit), "fields": _FIELDS,
        }
        year = args.get("year")
        if year:
            params["year"] = str(year)
        try:
            resp = _governed_sender(httpx.get)(
                f"{_API_BASE}/paper/search",
                params=params, headers=headers, timeout=20.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return f"ERROR: SemanticScholar search failed: {type(e).__name__}: {e}"
        papers = data.get("data") or []
        if not papers:
            return "no results"
        return "\n\n".join(
            f"{i}. {_format_paper(p)}"
            for i, p in enumerate(papers, 1)
        )

    if op == "paper":
        pid = (args.get("paper_id") or "").strip()
        if not pid:
            return "ERROR: paper requires paper_id"
        # SemanticScholar accepts:
        #   ssid                   (40-char hex)
        #   DOI:10.1234/abc        (or just 10.1234/abc)
        #   arXiv:2106.09685       (or 2106.09685)
        if pid.lower().startswith(("doi:", "arxiv:", "mag:", "acl:")):
            paper_path = pid
        elif pid.startswith("10."):
            # Bare DOI. Old-style arXiv ids ALSO contain a slash (e.g.
            # "math/0211159"), so gate the DOI branch on the "10." DOI prefix
            # rather than a bare "/" -- otherwise a legacy arXiv id becomes
            # "DOI:math/0211159" and never resolves. Non-DOI slash ids fall
            # through to the arXiv branch below.
            paper_path = f"DOI:{pid}"
        elif len(pid) >= 36 and all(c in "0123456789abcdef" for c in pid.lower()):
            paper_path = pid  # ssid
        else:
            paper_path = f"arXiv:{pid}"  # bare arxiv id fallback
        # DOIs and old arXiv ids keep their "/", but the id must not climb out
        # of /paper/ (httpx resolves dot segments) or add a query/fragment.
        if any(seg in (".", "..") for seg in paper_path.split("/")):
            return "ERROR: paper_id must not contain . or .. path segments"
        from urllib.parse import quote
        paper_path = quote(paper_path, safe="/:")
        try:
            resp = _governed_sender(httpx.get)(
                f"{_API_BASE}/paper/{paper_path}",
                params={"fields": _FIELDS},
                headers=headers, timeout=20.0,
            )
            if resp.status_code == 404:
                return f"no paper found for {pid!r}"
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            return f"ERROR: SemanticScholar fetch failed: {type(e).__name__}: {e}"
        return _format_paper(data, full=True)

    return f"ERROR: unknown op {op!r}"


def semantic_scholar() -> Tool:
    return Tool(
        name="semantic_scholar",
        description=(
            "Search Semantic Scholar's Graph API or fetch a specific "
            "paper. ops: search (keywords + optional year filter), "
            "paper (Semantic Scholar id, DOI, or arXiv id). Returns "
            "title, authors, citation count, abstract, PDF link. "
            "Complements the arxiv tool with broader (non-preprint) "
            "coverage."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
