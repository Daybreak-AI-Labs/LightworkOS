"""Notion tool.

Read / write Notion pages + databases via the v1 REST API.

Auth: ``NOTION_TOKEN`` (integration secret from notion.so/my-integrations).
The integration must be invited to the workspace OR shared on
specific pages.

ops:
  - search(query, limit)               — text search across the workspace
  - page_get(page_id)                  — fetch a page (blocks flattened to text)
  - page_create(parent_id, title, body)
  - page_append(page_id, text)         — append a paragraph to a page
  - db_query(database_id, limit)       — list database rows
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_NOTION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["search", "page_get", "page_create",
                     "page_append", "db_query"],
        },
        "query": {"type": "string"},
        "page_id": {"type": "string"},
        "parent_id": {"type": "string", "description": "Parent page id (page_create)."},
        "title": {"type": "string"},
        "body": {"type": "string"},
        "text": {"type": "string", "description": "Paragraph text (page_append)."},
        "database_id": {"type": "string"},
        "limit": {"type": "integer"},
    },
    "required": ["op"],
}


_API_BASE = "https://api.notion.com/v1"
_API_VERSION = "2022-06-28"

_NOTION_ID_RE = re.compile(r"[0-9a-fA-F]{32}")


def _require_id(value: str, field: str) -> str:
    """Return ``value`` if it is a literal Notion id (32 hex, dashes optional),
    else raise. The id is interpolated straight into the REST path, so without
    this a model-supplied ``../users/me`` or ``<id>?filter=...`` would let httpx
    normalize ``..`` / append a query and reach other authenticated Notion
    endpoints (path traversal / endpoint confusion). Mirrors jira._require_key.
    """
    if not _NOTION_ID_RE.fullmatch(value.replace("-", "")):
        raise ValueError(f"invalid {field} {value!r} (expected a 32-hex Notion id)")
    return value


def _config() -> str:
    tok = os.environ.get("NOTION_TOKEN", "").strip()
    if not tok:
        raise RuntimeError("Notion requires NOTION_TOKEN (integration secret).")
    return tok


def _client():
    import httpx

    from ..governed_http import GuardedClient
    return GuardedClient(httpx.Client(
        headers={
            "Authorization": f"Bearer {_config()}",
            "Notion-Version": _API_VERSION,
            "Content-Type": "application/json",
        },
        # follow_redirects=False: the Bearer token is a client default header,
        # which httpx replays across a cross-origin 30x (it strips only the
        # `auth=` param, not header creds) -- an open-redirect off api.notion.com
        # would exfiltrate the token to another host.
        timeout=30.0, follow_redirects=False,
    ))


def _paginate(c, url: str, body: dict, limit: int) -> tuple[int, str, list[dict]]:
    """POST ``url`` repeatedly, following Notion's ``has_more``/``next_cursor``
    cursor pagination until ``limit`` results are collected.

    Returns ``(status_code, error_text, results)``. ``status_code`` is the
    first failing code (with ``error_text``) or 200. Bounded by ``limit`` and
    a hard page cap so a huge collection can't loop unbounded.
    """
    results: list[dict] = []
    cursor: str | None = None
    # limit <= 100 (caller-capped) and page_size <= 100, so this many pages is
    # always enough to satisfy the request; the cap just bounds pathological loops.
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        page_body = dict(body)
        page_body["page_size"] = min(100, max(1, limit - len(results)))
        if cursor:
            page_body["start_cursor"] = cursor
        r = c.post(url, json=page_body)
        if r.status_code >= 400:
            return r.status_code, r.text[:300], results
        data = r.json()
        results.extend(data.get("results") or [])
        if len(results) >= limit or not data.get("has_more"):
            break
        cursor = data.get("next_cursor")
        if not cursor:
            break
    return 200, "", results[:limit]


def _flatten_rich_text(rich: list[dict] | None) -> str:
    if not rich:
        return ""
    return "".join((r.get("plain_text") or "") for r in rich)


def _flatten_blocks(blocks: list[dict]) -> str:
    out: list[str] = []
    for b in blocks or []:
        btype = b.get("type", "")
        node = b.get(btype) or {}
        text = _flatten_rich_text(node.get("rich_text"))
        if not text:
            continue
        if btype.startswith("heading_"):
            out.append(f"# {text}")
        elif btype == "bulleted_list_item":
            out.append(f"- {text}")
        elif btype == "numbered_list_item":
            out.append(f"1. {text}")
        elif btype == "to_do":
            mark = "[x]" if (node.get("checked")) else "[ ]"
            out.append(f"{mark} {text}")
        else:
            out.append(text)
    return "\n".join(out)


def _op_search(query: str, limit: int) -> str:
    with _client() as c:
        code, err, results = _paginate(
            c, f"{_API_BASE}/search", {"query": query}, limit,
        )
    if code >= 400:
        return f"ERROR: search ({code}): {err}"
    if not results:
        return "no matches"
    rows: list[str] = []
    for it in results[:limit]:
        otype = it.get("object", "?")
        page_id = it.get("id", "?")
        title = ""
        props = it.get("properties") or {}
        # Page title heuristic: first property of type "title".
        for v in props.values():
            if isinstance(v, dict) and v.get("type") == "title":
                title = _flatten_rich_text(v.get("title"))
                break
        if not title:
            title = "(untitled)"
        rows.append(f"  [{otype:>8}]  {page_id[:8]}  {title[:80]}")
    return "\n".join(rows)


def _op_page_get(page_id: str) -> str:
    with _client() as c:
        # Page metadata
        meta = c.get(f"{_API_BASE}/pages/{page_id}")
        if meta.status_code == 404:
            return f"page {page_id!r} not found"
        if meta.status_code >= 400:
            return f"ERROR: page_get meta ({meta.status_code}): {meta.text[:300]}"
        # Block children (one page; agents can paginate via the tool again if needed)
        blocks = c.get(f"{_API_BASE}/blocks/{page_id}/children")
        if blocks.status_code >= 400:
            return f"ERROR: page_get blocks ({blocks.status_code}): {blocks.text[:300]}"
        mdata = meta.json()
        bdata = blocks.json()
    title = ""
    for v in (mdata.get("properties") or {}).values():
        if isinstance(v, dict) and v.get("type") == "title":
            title = _flatten_rich_text(v.get("title"))
            break
    body = _flatten_blocks(bdata.get("results") or [])
    return f"{title or '(untitled)'}\n\n{body[:5000]}"


def _op_page_create(parent_id: str, title: str, body: str) -> str:
    payload = {
        "parent": {"page_id": parent_id},
        "properties": {
            "title": [{"type": "text", "text": {"content": title[:200]}}],
        },
    }
    if body:
        payload["children"] = [{
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{"type": "text", "text": {"content": body[:2000]}}],
            },
        }]
    with _client() as c:
        r = c.post(f"{_API_BASE}/pages", json=payload)
        if r.status_code >= 400:
            return f"ERROR: page_create ({r.status_code}): {r.text[:300]}"
        data = r.json()
    return f"created page {data.get('id')}: {data.get('url', '')}"


def _op_page_append(page_id: str, text: str) -> str:
    payload = {
        "children": [{
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{"type": "text", "text": {"content": text[:2000]}}],
            },
        }],
    }
    with _client() as c:
        r = c.patch(
            f"{_API_BASE}/blocks/{page_id}/children", json=payload,
        )
        if r.status_code >= 400:
            return f"ERROR: page_append ({r.status_code}): {r.text[:300]}"
    return f"appended to {page_id}"


def _op_db_query(database_id: str, limit: int) -> str:
    with _client() as c:
        code, err, rows = _paginate(
            c, f"{_API_BASE}/databases/{database_id}/query", {}, limit,
        )
    if code >= 400:
        return f"ERROR: db_query ({code}): {err}"
    if not rows:
        return "no rows"
    out: list[str] = []
    for row in rows[:limit]:
        title = ""
        for v in (row.get("properties") or {}).values():
            if isinstance(v, dict) and v.get("type") == "title":
                title = _flatten_rich_text(v.get("title"))
                break
        out.append(f"  {row.get('id', '?')[:8]}  {title[:80] or '(untitled)'}")
    return "\n".join(out)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "search":
            return _op_search(
                (args.get("query") or "").strip(),
                max(1, min(int(args.get("limit") or 20), 100)),
            )
        if op == "page_get":
            pid = (args.get("page_id") or "").strip()
            if not pid:
                return "ERROR: page_get requires page_id"
            return _op_page_get(_require_id(pid, "page_id"))
        if op == "page_create":
            parent = (args.get("parent_id") or "").strip()
            title = (args.get("title") or "").strip()
            if not parent or not title:
                return "ERROR: page_create requires parent_id and title"
            return _op_page_create(parent, title, args.get("body") or "")
        if op == "page_append":
            pid = (args.get("page_id") or "").strip()
            text = args.get("text") or ""
            if not pid or not text:
                return "ERROR: page_append requires page_id and text"
            return _op_page_append(_require_id(pid, "page_id"), text)
        if op == "db_query":
            did = (args.get("database_id") or "").strip()
            if not did:
                return "ERROR: db_query requires database_id"
            return _op_db_query(
                _require_id(did, "database_id"),
                max(1, min(int(args.get("limit") or 25), 100)),
            )
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Notion request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def notion() -> Tool:
    return Tool(
        name="notion",
        description=(
            "Read / write Notion pages + databases. ops: search "
            "(query), page_get (id -> flattened markdown), "
            "page_create (parent_id + title + body), page_append "
            "(page_id + text), db_query (database_id). Auth: "
            "NOTION_TOKEN integration secret."
        ),
        input_schema=_NOTION_SCHEMA,
        fn=_run,
    )
