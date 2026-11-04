"""Dropbox tool — files + folders.

Auth: ``DROPBOX_ACCESS_TOKEN`` (OAuth2 access token, refreshed
externally).

ops:
  - list(path, limit)
  - download(path)                 — returns first 4KB of text
  - upload(path, content, confirm)
  - delete(path, confirm)
  - share(path, confirm)           — create/get a shared link
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)


_DBX_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["list", "download", "upload", "delete", "share"]},
        "path": {"type": "string", "description": "Dropbox path, e.g. '/folder/file.txt'."},
        "content": {"type": "string", "description": "utf-8 (upload)."},
        "limit": {"type": "integer"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_RPC = "https://api.dropboxapi.com/2"
_CONTENT = "https://content.dropboxapi.com/2"


def _token() -> str:
    t = os.environ.get("DROPBOX_ACCESS_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Dropbox requires DROPBOX_ACCESS_TOKEN.")
    return t


def _rpc(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_RPC}{path}",
                   headers={"Authorization": f"Bearer {_token()}",
                            "Content-Type": "application/json"},
                   json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _norm(path: str) -> str:
    path = path.strip()
    if path and not path.startswith("/"):
        path = "/" + path
    return path


def _op_list(args: dict) -> str:
    path = _norm(args.get("path") or "")
    code, data = _rpc("/files/list_folder", {
        "path": path,  # "" = root
        "limit": max(1, min(int(args.get("limit") or 100), 2000)),
    })
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: list ({code}): {data}"
    entries = data.get("entries") or []
    if not entries:
        return f"(empty: {path or '/'})"
    return "\n".join(
        f"  {'d' if e.get('.tag') == 'folder' else 'f'}  "
        f"{e.get('size', ''):>10}  {e.get('path_display', e.get('name'))}"
        for e in entries
    )


def _op_download(args: dict) -> str:
    import httpx
    path = _norm(args.get("path") or "")
    if not path:
        return "ERROR: download requires path"
    r = _governed_sender(httpx.post)(
        f"{_CONTENT}/files/download",
        headers={
            "Authorization": f"Bearer {_token()}",
            "Dropbox-API-Arg": json.dumps({"path": path}),
        }, timeout=30.0,
    )
    if r.status_code >= 400:
        return f"ERROR: download ({r.status_code}): {r.text[:300]}"
    body = r.content[:4096].decode("utf-8", errors="replace")
    return f"size={len(r.content)}\n{body}{'... (truncated)' if len(r.content) > 4096 else ''}"


def _op_upload(args: dict) -> str:
    import httpx
    path = _norm(args.get("path") or "")
    content = args.get("content") or ""
    if not path:
        return "ERROR: upload requires path"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would upload to {path} ({len(content)} bytes). Re-run with confirm=true."
    r = _governed_sender(httpx.post)(
        f"{_CONTENT}/files/upload",
        headers={
            "Authorization": f"Bearer {_token()}",
            "Dropbox-API-Arg": json.dumps({"path": path, "mode": "overwrite"}),
            "Content-Type": "application/octet-stream",
        },
        content=content.encode("utf-8"), timeout=60.0,
    )
    if r.status_code >= 400:
        return f"ERROR: upload ({r.status_code}): {r.text[:300]}"
    return f"uploaded to {path} ({len(content)} bytes)"


def _op_delete(args: dict) -> str:
    path = _norm(args.get("path") or "")
    if not path:
        return "ERROR: delete requires path"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete {path}. Re-run with confirm=true."
    code, data = _rpc("/files/delete_v2", {"path": path})
    if code >= 400:
        return f"ERROR: delete ({code}): {data}"
    return f"deleted {path}"


def _op_share(args: dict) -> str:
    path = _norm(args.get("path") or "")
    if not path:
        return "ERROR: share requires path"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create or fetch shared link for {path}. Re-run with confirm=true."
    code, data = _rpc(
        "/sharing/create_shared_link_with_settings", {"path": path},
    )
    if code >= 400 or not isinstance(data, dict):
        # Link may already exist; fetch it.
        c2, d2 = _rpc("/sharing/list_shared_links", {"path": path})
        if c2 < 400 and isinstance(d2, dict) and (d2.get("links") or []):
            return (d2["links"][0]).get("url", "?")
        return f"ERROR: share ({code}): {data}"
    return data.get("url", "?")


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
            "list":     _op_list,
            "download": _op_download,
            "upload":   _op_upload,
            "delete":   _op_delete,
            "share":    _op_share,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Dropbox request failed: {type(e).__name__}: {e}"


def dropbox_tool() -> Tool:
    return Tool(
        name="dropbox",
        description=(
            "Dropbox files. ops: list, download (4KB preview), "
            "upload + delete + share (mutations confirm=true), "
            "(shared link). Auth: DROPBOX_ACCESS_TOKEN."
        ),
        input_schema=_DBX_SCHEMA,
        fn=_run,
    )
