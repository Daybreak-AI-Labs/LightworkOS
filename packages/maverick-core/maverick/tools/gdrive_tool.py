"""Google Drive tool — list / get / create / delete files.

Auth: ``GDRIVE_ACCESS_TOKEN`` (OAuth 2 access token; users keep it
fresh via a separate refresh script — we don't bake in OAuth flow
to keep credentials out of the agent's process memory). Optional
``GDRIVE_FOLDER_ID`` as the default parent folder for create.

ops:
  - list(query, page_size)        — Drive query syntax
  - get(file_id)                  — metadata + first 4KB of text
  - create(name, content, mime_type, parent_id, confirm)
  - delete(file_id, confirm)
  - export(file_id, mime_type)    — for Docs / Sheets / Slides
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_GD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["list", "get", "create", "delete", "export"],
        },
        "file_id": {"type": "string"},
        "query": {"type": "string", "description": "Drive query (default: trashed=false)."},
        "page_size": {"type": "integer"},
        "name": {"type": "string"},
        "content": {"type": "string", "description": "utf-8 (create)."},
        "mime_type": {"type": "string"},
        "parent_id": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://www.googleapis.com/drive/v3"
_UPLOAD = "https://www.googleapis.com/upload/drive/v3"


def _token() -> str:
    from .. import connections
    from ..template_connections import active, selected
    if active():
        ref = selected("gdrive", connections.current_principal())
        return connections.resolve_named(ref["name"], expected_revision=ref["revision"],
            connector="gdrive", origin="https://www.googleapis.com")["token"]
    t = os.environ.get("GDRIVE_ACCESS_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Google Drive requires GDRIVE_ACCESS_TOKEN.")
    return t


def _headers(content_type: str = "application/json") -> dict[str, str]:
    return {"Authorization": f"Bearer {_token()}",
            "Content-Type": content_type}


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _get_raw(url: str, params: dict | None = None, max_bytes: int = 4096) -> tuple[int, str]:
    import httpx
    # follow_redirects=False: the OAuth Bearer token is replayed by httpx across
    # a cross-origin 30x (it strips only the `auth=` param, not header creds), so
    # a redirect off the Drive API host would leak the access token. A genuine
    # download/export redirect surfaces as its 3xx code rather than leaking.
    # Ask only for the preview bytes; a server that ignores Range still has
    # its body sliced below.
    r = _governed_sender(httpx.get)(url, headers={"Authorization": f"Bearer {_token()}",
                                                  "Range": f"bytes=0-{max_bytes - 1}"},
                  params=params or {}, timeout=30.0, follow_redirects=False)
    if r.status_code >= 400:
        return r.status_code, r.text[:300]
    return r.status_code, r.content[:max_bytes].decode("utf-8", errors="replace")


def _delete_req(path: str) -> int:
    import httpx
    r = _governed_sender(httpx.delete)(f"{_API}{path}", headers=_headers(), timeout=30.0)
    return r.status_code


def _op_list(args: dict) -> str:
    query = (args.get("query") or "trashed=false").strip()
    limit = max(1, min(int(args.get("page_size") or 25), 100))
    # Drive returns up to `pageSize` files per call plus a `nextPageToken`;
    # follow it until `limit` files are collected (bounded by a hard page cap).
    # `nextPageToken` must be in `fields` for the API to return it.
    rows: list[dict] = []
    token: str | None = None
    max_pages = max(1, (limit // 100) + 2)
    for _ in range(max_pages):
        params: dict = {
            "q": query,
            "pageSize": min(100, max(1, limit - len(rows))),
            "fields": "nextPageToken, files(id, name, mimeType, modifiedTime, size, parents)",
        }
        if token:
            params["pageToken"] = token
        code, data = _get("/files", params)
        if code >= 400 or not isinstance(data, dict):
            return f"ERROR: list ({code}): {data}"
        rows.extend(data.get("files") or [])
        token = data.get("nextPageToken")
        if len(rows) >= limit or not token:
            break
    rows = rows[:limit]
    if not rows:
        return f"no files match {query!r}"
    return "\n".join(
        f"  {(f.get('id') or '?'):<35}  {f.get('mimeType', '?'):<40}  "
        f"{(f.get('name') or '')[:60]}"
        for f in rows
    )


def _op_get(args: dict) -> str:
    fid = (args.get("file_id") or "").strip()
    if not fid:
        return "ERROR: get requires file_id"
    seg = safe_path_segment(fid)
    if seg is None:
        return "ERROR: get requires a valid file_id"
    code, meta = _get(f"/files/{seg}",
                       {"fields": "id,name,mimeType,size,parents,modifiedTime,webViewLink"})
    if code == 404:
        return f"file {fid} not found"
    if code >= 400 or not isinstance(meta, dict):
        return f"ERROR: get meta ({code}): {meta}"
    mt = meta.get("mimeType", "")
    # Binary files: just return metadata.
    text_preview = ""
    if mt.startswith("text/") or mt in {"application/json", "application/xml"}:
        c, text_preview = _get_raw(f"{_API}/files/{seg}", {"alt": "media"})
        if c >= 400:
            text_preview = f"(preview fetch {c})"
    return (
        f"{meta.get('id')}  {meta.get('name')}\n"
        f"  mime:     {mt}\n"
        f"  size:     {meta.get('size', '?')}\n"
        f"  modified: {meta.get('modifiedTime')}\n"
        f"  url:      {meta.get('webViewLink', '?')}\n"
        + (f"\n{text_preview}" if text_preview else "")
    )


def _op_create(args: dict) -> str:
    import httpx
    name = (args.get("name") or "").strip()
    if not name:
        return "ERROR: create requires name"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create {name}. Re-run with confirm=true."
    mime = (args.get("mime_type") or "text/plain").strip()
    parent = (args.get("parent_id") or os.environ.get("GDRIVE_FOLDER_ID", "")).strip()
    metadata: dict = {"name": name, "mimeType": mime}
    if parent:
        metadata["parents"] = [parent]
    content = args.get("content") or ""
    # Multipart upload (simple form). Use a RANDOM per-request boundary: a fixed
    # one could appear inside user content/metadata and split or inject parts,
    # corrupting the upload. 128 bits of randomness makes a collision negligible.
    import uuid
    boundary = f"maverick_{uuid.uuid4().hex}"
    body = (
        f"--{boundary}\r\n"
        "Content-Type: application/json; charset=UTF-8\r\n\r\n"
        f"{json.dumps(metadata)}\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: {mime}\r\n\r\n"
        f"{content}\r\n"
        f"--{boundary}--"
    ).encode()
    r = _governed_sender(httpx.post)(
        f"{_UPLOAD}/files",
        headers={
            "Authorization": f"Bearer {_token()}",
            "Content-Type": f"multipart/related; boundary={boundary}",
        },
        params={"uploadType": "multipart", "fields": "id,name,webViewLink"},
        content=body, timeout=60.0,
    )
    if r.status_code >= 400:
        return f"ERROR: create ({r.status_code}): {r.text[:300]}"
    try:
        data = r.json()
    except ValueError:
        return r.text[:300]
    return f"created {data.get('id')}: {data.get('webViewLink', '')}"


def _op_delete(args: dict) -> str:
    fid = (args.get("file_id") or "").strip()
    if not fid:
        return "ERROR: delete requires file_id"
    seg = safe_path_segment(fid)
    if seg is None:
        return "ERROR: delete requires a valid file_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete {fid}. Re-run with confirm=true."
    code = _delete_req(f"/files/{seg}")
    if code >= 400:
        return f"ERROR: delete ({code})"
    return f"deleted {fid}"


def _op_export(args: dict) -> str:
    fid = (args.get("file_id") or "").strip()
    mime = (args.get("mime_type") or "text/plain").strip()
    if not fid:
        return "ERROR: export requires file_id"
    seg = safe_path_segment(fid)
    if seg is None:
        return "ERROR: export requires a valid file_id"
    code, text = _get_raw(f"{_API}/files/{seg}/export",
                           {"mimeType": mime}, max_bytes=8192)
    if code >= 400:
        return f"ERROR: export ({code}): {text[:300]}"
    return text


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    from ..template_connections import active
    if active() and op in {"create", "delete"}:
        return "REFUSED: selected Google Drive accounts allow read operations only."
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "list":   _op_list,
            "get":    _op_get,
            "create": _op_create,
            "delete": _op_delete,
            "export": _op_export,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Google Drive request failed: {type(e).__name__}: {e}"


def gdrive_tool() -> Tool:
    return Tool(
        name="gdrive",
        description=(
            "Google Drive files. ops: list (Drive query), get "
            "(metadata + text preview), create (multipart upload; "
            "confirm=true), delete (confirm=true), export (Docs/"
            "Sheets/Slides -> mime). Auth: GDRIVE_ACCESS_TOKEN."
        ),
        input_schema=_GD_SCHEMA,
        fn=_run,
    )
