"""Confluence tool — pages + search (Cloud REST v2 + CQL search).

Auth: ``CONFLUENCE_URL`` (e.g. https://your-org.atlassian.net/wiki) +
``CONFLUENCE_USER`` + ``CONFLUENCE_API_TOKEN`` (Basic auth, same token
family as Jira).

ops:
  - search(cql, limit)                 — CQL query
  - page_get(page_id)                  — body flattened to text
  - page_create(space_key, title, body, confirm)
  - page_update(page_id, title, body, version, confirm)
"""
from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_CF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["search", "page_get", "page_create", "page_update"]},
        "cql": {"type": "string"},
        "page_id": {"type": "string"},
        "space_key": {
            "type": "string",
            "description": (
                "Confluence space KEY (e.g. 'ENG'), not the numeric id — the "
                "v1 content API keys space by key. (Legacy 'space_id' alias "
                "accepted.)"
            ),
        },
        "title": {"type": "string"},
        "body": {"type": "string", "description": "Storage-format/HTML body."},
        "version": {"type": "integer", "description": "Current version number (page_update)."},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


def _config() -> tuple[str, str, str]:
    url = os.environ.get("CONFLUENCE_URL", "").strip().rstrip("/")
    user = os.environ.get("CONFLUENCE_USER", "").strip()
    tok = os.environ.get("CONFLUENCE_API_TOKEN", "").strip()
    if not url or not user or not tok:
        raise RuntimeError(
            "Confluence requires CONFLUENCE_URL + CONFLUENCE_USER + "
            "CONFLUENCE_API_TOKEN."
        )
    return url, user, tok


def _headers() -> dict[str, str]:
    _u, user, tok = _config()
    raw = f"{user}:{tok}".encode()
    return {
        "Authorization": "Basic " + base64.b64encode(raw).decode("ascii"),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", text).strip()


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    url, _u, _t = _config()
    # follow_redirects=False: the Basic-auth header isn't stripped by httpx on
    # a cross-host redirect, so a 30x off CONFLUENCE_URL would leak the token.
    r = _governed_sender(httpx.get)(f"{url}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0, follow_redirects=False)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    url, _u, _t = _config()
    r = _governed_sender(httpx.post)(f"{url}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _put(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    url, _u, _t = _config()
    r = _governed_sender(httpx.put)(f"{url}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _op_search(args: dict) -> str:
    cql = (args.get("cql") or "").strip()
    if not cql:
        return "ERROR: search requires cql (e.g. 'text ~ \"roadmap\"')"
    limit = max(1, min(int(args.get("limit") or 25), 100))
    code, data = _get("/rest/api/content/search", {"cql": cql, "limit": limit})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: search ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no matches"
    return "\n".join(
        f"  {r.get('id')}  [{r.get('type', '?'):>5}]  {(r.get('title') or '')[:80]}"
        for r in rows
    )


def _op_page_get(args: dict) -> str:
    pid = (args.get("page_id") or "").strip()
    if not pid:
        return "ERROR: page_get requires page_id"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: page_get requires a valid page_id"
    code, data = _get(f"/rest/api/content/{seg}",
                      {"expand": "body.storage,version,space"})
    if code == 404:
        return f"page {pid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: page_get ({code}): {data}"
    body = ((data.get("body") or {}).get("storage") or {}).get("value", "")
    return (
        f"{data.get('id')}  {data.get('title')}\n"
        f"  space:   {(data.get('space') or {}).get('key', '?')}\n"
        f"  version: {(data.get('version') or {}).get('number', '?')}\n\n"
        f"{_strip_html(body)[:4000]}"
    )


def _op_page_create(args: dict) -> str:
    # The value is the space KEY (the v1 API keys space.key by key, not id).
    # Prefer the renamed `space_key`; accept legacy `space_id` for back-compat.
    space = (args.get("space_key") or args.get("space_id") or "").strip()
    title = (args.get("title") or "").strip()
    body = args.get("body") or ""
    if not space or not title:
        return "ERROR: page_create requires space_key and title"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create page {title!r}. Re-run with confirm=true."
    payload = {
        "type": "page",
        "title": title,
        "space": {"key": space},
        "body": {"storage": {"value": body, "representation": "storage"}},
    }
    code, data = _post("/rest/api/content", payload)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: page_create ({code}): {data}"
    return f"created page {data.get('id')}: {title}"


def _op_page_update(args: dict) -> str:
    pid = (args.get("page_id") or "").strip()
    title = (args.get("title") or "").strip()
    body = args.get("body") or ""
    version = int(args.get("version") or 0)
    if not pid or not title or not version:
        return "ERROR: page_update requires page_id, title, version"
    seg = safe_path_segment(pid)
    if seg is None:
        return "ERROR: page_update requires a valid page_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would update page {pid}. Re-run with confirm=true."
    payload = {
        "id": pid,
        "type": "page",
        "title": title,
        "version": {"number": version + 1},
        "body": {"storage": {"value": body, "representation": "storage"}},
    }
    code, data = _put(f"/rest/api/content/{seg}", payload)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: page_update ({code}): {data}"
    return f"updated page {pid} -> v{version + 1}"


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
            "search":      _op_search,
            "page_get":    _op_page_get,
            "page_create": _op_page_create,
            "page_update": _op_page_update,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Confluence request failed: {type(e).__name__}: {e}"


def confluence_tool() -> Tool:
    return Tool(
        name="confluence",
        description=(
            "Confluence Cloud pages. ops: search (CQL), page_get "
            "(flattened text), page_create / page_update (mutations "
            "confirm=true; update needs current version). Auth: "
            "CONFLUENCE_URL + CONFLUENCE_USER + CONFLUENCE_API_TOKEN."
        ),
        input_schema=_CF_SCHEMA,
        fn=_run,
    )
