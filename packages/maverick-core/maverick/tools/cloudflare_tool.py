"""Cloudflare tool — DNS records + zone purges.

Manages a zone's DNS records and triggers cache purges via the v4
REST API. The two ops most people actually need.

Auth: ``CLOUDFLARE_API_TOKEN`` (scoped token with Zone:DNS:Edit +
Zone:Cache Purge). ``CLOUDFLARE_ZONE_ID`` selects the default zone
for convenience.

ops:
  - dns_list(zone_id, type)
  - dns_create(zone_id, type, name, content, ttl, confirm)
  - dns_update(zone_id, record_id, content, confirm)
  - dns_delete(zone_id, record_id, confirm)
  - purge(zone_id, urls, confirm)        — when urls empty, purges everything
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool, safe_path_segment

log = logging.getLogger(__name__)


_CF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["dns_list", "dns_create", "dns_update", "dns_delete", "purge"],
        },
        "zone_id": {"type": "string"},
        "record_id": {"type": "string"},
        "type": {"type": "string", "description": "A / AAAA / CNAME / MX / TXT / NS / SRV"},
        "name": {"type": "string"},
        "content": {"type": "string"},
        "ttl": {"type": "integer", "description": "1 = auto."},
        "urls": {"type": "array", "items": {"type": "string"}},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API = "https://api.cloudflare.com/client/v4"


def _token() -> str:
    t = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not t:
        raise RuntimeError("Cloudflare requires CLOUDFLARE_API_TOKEN.")
    return t


def _zone_default() -> str:
    return os.environ.get("CLOUDFLARE_ZONE_ID", "").strip()


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_token()}",
        "Content-Type": "application/json",
    }


def _get(path: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_API}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _patch(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.patch)(f"{_API}{path}", headers=_headers(), json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _delete(path: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.delete)(f"{_API}{path}", headers=_headers(), timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _ok(data: Any) -> bool:
    return bool(isinstance(data, dict) and data.get("success"))


def _zone(args: dict) -> str:
    raw = (args.get("zone_id") or _zone_default()).strip()
    return safe_path_segment(raw) or ""


def _op_dns_list(args: dict) -> str:
    zone = _zone(args)
    if not zone:
        return "ERROR: dns_list requires zone_id or CLOUDFLARE_ZONE_ID"
    params: dict = {"per_page": 100}
    typ = (args.get("type") or "").strip()
    if typ:
        params["type"] = typ
    code, data = _get(f"/zones/{zone}/dns_records", params)
    if not _ok(data):
        return f"ERROR: dns_list ({code}): {data}"
    rows = data.get("result") or []
    if not rows:
        return "no records"
    return "\n".join(
        f"  {r.get('id')}  [{r.get('type', '?'):>5}]  "
        f"{(r.get('name') or '')[:40]:<40}  -> {(r.get('content') or '')[:80]}"
        for r in rows
    )


def _op_dns_create(args: dict) -> str:
    zone = _zone(args)
    typ = (args.get("type") or "").strip()
    name = (args.get("name") or "").strip()
    content = (args.get("content") or "").strip()
    if not (zone and typ and name and content):
        return "ERROR: dns_create requires zone_id, type, name, content"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would create {typ} {name} -> {content}. Re-run with confirm=true."
    code, data = _post(
        f"/zones/{zone}/dns_records",
        {"type": typ, "name": name, "content": content,
         "ttl": int(args.get("ttl") or 1)},
    )
    if not _ok(data):
        return f"ERROR: dns_create ({code}): {data}"
    rec = data.get("result") or {}
    return f"created {rec.get('id')} ({typ} {name} -> {content})"


def _op_dns_update(args: dict) -> str:
    zone = _zone(args)
    rid = (args.get("record_id") or "").strip()
    content = args.get("content")
    if not (zone and rid and content):
        return "ERROR: dns_update requires zone_id, record_id, content"
    rid_seg = safe_path_segment(rid)
    if rid_seg is None:
        return "ERROR: dns_update requires a valid record_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would update {rid} -> {content}. Re-run with confirm=true."
    code, data = _patch(
        f"/zones/{zone}/dns_records/{rid_seg}", {"content": str(content)},
    )
    if not _ok(data):
        return f"ERROR: dns_update ({code}): {data}"
    return f"updated {rid}"


def _op_dns_delete(args: dict) -> str:
    zone = _zone(args)
    rid = (args.get("record_id") or "").strip()
    if not (zone and rid):
        return "ERROR: dns_delete requires zone_id and record_id"
    rid_seg = safe_path_segment(rid)
    if rid_seg is None:
        return "ERROR: dns_delete requires a valid record_id"
    if not as_bool(args.get("confirm")):
        return f"DRY RUN: would delete {rid}. Re-run with confirm=true."
    code, data = _delete(f"/zones/{zone}/dns_records/{rid_seg}")
    if not _ok(data):
        return f"ERROR: dns_delete ({code}): {data}"
    return f"deleted {rid}"


def _op_purge(args: dict) -> str:
    zone = _zone(args)
    urls = args.get("urls") or []
    if not zone:
        return "ERROR: purge requires zone_id"
    if not as_bool(args.get("confirm")):
        target = f"{len(urls)} URL(s)" if urls else "EVERYTHING"
        return f"DRY RUN: would purge {target} for zone {zone}. Re-run with confirm=true."
    body = {"files": urls} if urls else {"purge_everything": True}
    code, data = _post(f"/zones/{zone}/purge_cache", body)
    if not _ok(data):
        return f"ERROR: purge ({code}): {data}"
    return f"purged: {data.get('result', {}).get('id', 'ok')}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        return {
            "dns_list":   _op_dns_list,
            "dns_create": _op_dns_create,
            "dns_update": _op_dns_update,
            "dns_delete": _op_dns_delete,
            "purge":      _op_purge,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Cloudflare request failed: {type(e).__name__}: {e}"


def cloudflare_tool() -> Tool:
    return Tool(
        name="cloudflare",
        description=(
            "Cloudflare DNS + cache. ops: dns_list / dns_create / "
            "dns_update / dns_delete (mutations need confirm=true), "
            "purge (urls=[] purges everything; needs confirm). Auth: "
            "CLOUDFLARE_API_TOKEN + optional CLOUDFLARE_ZONE_ID."
        ),
        input_schema=_CF_SCHEMA,
        fn=_run,
    )
