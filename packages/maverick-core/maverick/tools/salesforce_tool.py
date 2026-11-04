"""Salesforce tool — SOQL + record CRUD.

Lets the agent run SOQL queries and create / update / delete
records on standard or custom objects.

Auth (OAuth 2 username-password flow; simplest for headless agents):
  - ``SALESFORCE_INSTANCE_URL`` (e.g. https://your-domain.my.salesforce.com)
  - ``SALESFORCE_ACCESS_TOKEN`` (pre-acquired Bearer token)

Most users keep tokens current via a separate refresh script; we
deliberately don't bake an OAuth flow here so credentials don't sit
in the agent's process memory longer than necessary.

ops:
  - soql(query)
  - record_get(sobject, id)
  - record_create(sobject, fields, confirm)
  - record_update(sobject, id, fields, confirm)
  - record_delete(sobject, id, confirm)
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

from ..fastjson import dumps_compact
from ..governed_http import guarded_sender as _governed_sender
from . import Tool, as_bool

log = logging.getLogger(__name__)


# Salesforce sobject names and record ids are alphanumeric (with '_' for custom
# objects). Reject anything else — a value containing '?' or '../' would escape
# the intended endpoint into a different API resource (httpx doesn't encode
# f-string path segments). Mirrors spotify_tool's `_safe_id` guard.
_SF_ID_RE = re.compile(r"[A-Za-z0-9_]+")
_SF_VERSION_RE = re.compile(r"v[0-9]{1,3}\.[0-9]{1,2}", re.ASCII)


def _safe_sf(value: str) -> bool:
    return bool(value) and _SF_ID_RE.fullmatch(value) is not None


_SF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["soql", "record_get", "record_create",
                     "record_update", "record_delete"],
        },
        "query": {"type": "string", "description": "SOQL (soql op)."},
        "sobject": {"type": "string", "description": "Account / Contact / Custom__c."},
        "id": {"type": "string"},
        "fields": {"type": "object"},
        "version": {"type": "string", "description": "API version (default v60.0)."},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_DEFAULT_VERSION = "v60.0"


def _config() -> tuple[str, str]:
    url = os.environ.get("SALESFORCE_INSTANCE_URL", "").strip().rstrip("/")
    tok = os.environ.get("SALESFORCE_ACCESS_TOKEN", "").strip()
    if not url or not tok:
        raise RuntimeError(
            "Salesforce requires SALESFORCE_INSTANCE_URL + SALESFORCE_ACCESS_TOKEN."
        )
    return url, tok


def _headers() -> dict[str, str]:
    _u, tok = _config()
    return {
        "Authorization": f"Bearer {tok}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _base(version: str) -> str:
    version = version or _DEFAULT_VERSION
    if not isinstance(version, str) or not _SF_VERSION_RE.fullmatch(version):
        raise ValueError("the Salesforce API version must look like v60.0")
    url, _t = _config()
    return f"{url}/services/data/{version}"


def _get(path: str, version: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(f"{_base(version)}{path}", headers=_headers(),
                  params=params or {}, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _post(path: str, body: dict, version: str) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.post)(f"{_base(version)}{path}", headers=_headers(),
                   json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:500]


def _patch(path: str, body: dict, version: str) -> int:
    import httpx
    r = _governed_sender(httpx.patch)(f"{_base(version)}{path}", headers=_headers(),
                    json=body, timeout=30.0)
    return r.status_code


def _delete(path: str, version: str) -> int:
    import httpx
    r = _governed_sender(httpx.delete)(f"{_base(version)}{path}", headers=_headers(),
                     timeout=30.0)
    return r.status_code


def _op_soql(query: str, version: str) -> str:
    if not query.strip():
        return "ERROR: soql requires query"
    code, data = _get("/query/", version, {"q": query})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: soql ({code}): {data}"
    rows = data.get("records") or []
    total = data.get("totalSize", len(rows))
    if not rows:
        return f"no records (totalSize={total})"
    out = [f"totalSize={total} done={data.get('done')}"]
    # Drop the redundant `attributes` block per record.
    for r in rows[:50]:
        slim = {k: v for k, v in r.items() if k != "attributes"}
        out.append("  " + dumps_compact(slim)[:300])
    if len(rows) > 50:
        out.append(f"  ... (+{len(rows) - 50} more rows in response)")
    return "\n".join(out)


def _op_record_get(sobject: str, rid: str, version: str) -> str:
    if not sobject or not rid:
        return "ERROR: record_get requires sobject and id"
    if not _safe_sf(sobject) or not _safe_sf(rid):
        return "ERROR: record_get requires an alphanumeric sobject and id"
    code, data = _get(f"/sobjects/{sobject}/{rid}", version)
    if code == 404:
        return f"{sobject}/{rid} not found"
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: record_get ({code}): {data}"
    slim = {k: v for k, v in data.items() if k != "attributes"}
    return dumps_compact(slim)[:3000]


def _op_record_create(sobject: str, fields: dict, confirm: bool, version: str) -> str:
    if not sobject or not isinstance(fields, dict) or not fields:
        return "ERROR: record_create requires sobject and fields"
    if not _safe_sf(sobject):
        return "ERROR: record_create requires an alphanumeric sobject"
    if not confirm:
        return f"DRY RUN: would create {sobject}. Re-run with confirm=true."
    code, data = _post(f"/sobjects/{sobject}", fields, version)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: record_create ({code}): {data}"
    return f"created {sobject}/{data.get('id')} (success={data.get('success')})"


def _op_record_update(sobject: str, rid: str, fields: dict, confirm: bool,
                      version: str) -> str:
    if not sobject or not rid or not isinstance(fields, dict) or not fields:
        return "ERROR: record_update requires sobject, id, fields"
    if not _safe_sf(sobject) or not _safe_sf(rid):
        return "ERROR: record_update requires an alphanumeric sobject and id"
    if not confirm:
        return f"DRY RUN: would update {sobject}/{rid}. Re-run with confirm=true."
    code = _patch(f"/sobjects/{sobject}/{rid}", fields, version)
    if code >= 400:
        return f"ERROR: record_update ({code})"
    return f"updated {sobject}/{rid}"


def _op_record_delete(sobject: str, rid: str, confirm: bool, version: str) -> str:
    if not sobject or not rid:
        return "ERROR: record_delete requires sobject and id"
    if not _safe_sf(sobject) or not _safe_sf(rid):
        return "ERROR: record_delete requires an alphanumeric sobject and id"
    if not confirm:
        return f"DRY RUN: would delete {sobject}/{rid}. Re-run with confirm=true."
    code = _delete(f"/sobjects/{sobject}/{rid}", version)
    if code >= 400:
        return f"ERROR: record_delete ({code})"
    return f"deleted {sobject}/{rid}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    raw_version = args.get("version") or _DEFAULT_VERSION
    if not isinstance(raw_version, str) or not _SF_VERSION_RE.fullmatch(raw_version.strip()):
        return "ERROR: the Salesforce API version must look like v60.0"
    version = raw_version.strip()
    fields = args.get("fields") if isinstance(args.get("fields"), dict) else {}
    try:
        if op == "soql":
            return _op_soql((args.get("query") or "").strip(), version)
        if op == "record_get":
            return _op_record_get(
                (args.get("sobject") or "").strip(),
                (args.get("id") or "").strip(),
                version,
            )
        if op == "record_create":
            return _op_record_create(
                (args.get("sobject") or "").strip(),
                fields, as_bool(args.get("confirm")), version,
            )
        if op == "record_update":
            return _op_record_update(
                (args.get("sobject") or "").strip(),
                (args.get("id") or "").strip(),
                fields, as_bool(args.get("confirm")), version,
            )
        if op == "record_delete":
            return _op_record_delete(
                (args.get("sobject") or "").strip(),
                (args.get("id") or "").strip(),
                as_bool(args.get("confirm")), version,
            )
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Salesforce request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def salesforce_tool() -> Tool:
    return Tool(
        name="salesforce",
        description=(
            "Salesforce SOQL + record CRUD via REST. ops: soql, "
            "record_get, record_create / record_update / "
            "record_delete (all mutations need confirm=true). "
            "Auth: SALESFORCE_INSTANCE_URL + SALESFORCE_ACCESS_TOKEN. "
            "API version override via 'version' (default v60.0)."
        ),
        input_schema=_SF_SCHEMA,
        fn=_run,
    )
