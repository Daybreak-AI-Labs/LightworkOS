"""ERP read connector — generic, strictly read-only access to an ERP API.

One suite-agnostic tool (``erp_read``) that the Operations agents (and Finance,
etc.) use to READ from the ERP system of record -- purchase orders, receipts,
invoices, items/inventory, GL accounts -- through the ERP's own API layer
(NetSuite REST, SAP OData, Oracle Fusion REST). It is **read-only (HTTP GET
only)**: it never creates, updates, or deletes. That matches the agents'
"analyze and draft, never act on the world" posture, and it deliberately uses the
ERP's API rather than the underlying database (direct DB access to a SOX system of
record is itself an ITGC finding).

Config (operator-trusted; never model-supplied)::

    [erp]
    base_url = "https://<account>.suitetalk.api.netsuite.com/services/rest/record/v1"
    token = "${ERP_TOKEN}"      # bearer; keep the secret in .env
    system = "NetSuite"          # optional label

or via env: ``ERP_BASE_URL`` + ``ERP_TOKEN`` (+ optional ``ERP_SYSTEM``).

The model supplies only a **relative** resource path + query params; absolute
URLs / host overrides are rejected so the path can't be used for SSRF.
"""
from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import unquote, urlparse

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)

_MAX_BYTES = 16_000

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "path": {
            "type": "string",
            "description": (
                "Relative resource path under the configured ERP base_url, e.g. "
                "'/purchaseOrder/123' or '/inventoryItem'. Must be relative -- no "
                "scheme or host."
            ),
        },
        "params": {
            "type": "object",
            "description": "Optional query parameters (filters, $select, q=...).",
            "additionalProperties": {"type": "string"},
        },
    },
    "required": ["path"],
}


def _config() -> tuple[str, str, str]:
    """Resolve (base_url, token, system) from env, then ``[erp]`` config."""
    base = os.environ.get("ERP_BASE_URL", "").strip()
    tok = os.environ.get("ERP_TOKEN", "").strip()
    system = os.environ.get("ERP_SYSTEM", "").strip()
    if not base or not tok:
        try:
            from ..config import load_config
            cfg = (load_config() or {}).get("erp") or {}
            base = base or str(cfg.get("base_url", "")).strip()
            tok = tok or str(cfg.get("token", "")).strip()
            system = system or str(cfg.get("system", "")).strip()
        except Exception:  # pragma: no cover -- config never blocks the tool
            pass
    if not base or not tok:
        raise RuntimeError(
            "ERP connector needs [erp] base_url + token "
            "(or ERP_BASE_URL + ERP_TOKEN)."
        )
    p = urlparse(base)
    if p.scheme not in ("http", "https") or not p.netloc:
        raise RuntimeError(f"ERP base_url must be an absolute http(s) URL, got {base!r}.")
    return base.rstrip("/"), tok, (system or "ERP")


def _contains_dot_segment(path: str) -> bool:
    """Return true when a path contains dot segments, including encoded variants."""
    decoded = path
    for _ in range(8):
        if any(segment in (".", "..") for segment in decoded.replace("\\", "/").split("/")):
            return True
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            return False
        decoded = next_decoded
    return any(segment in (".", "..") for segment in decoded.replace("\\", "/").split("/"))


def _safe_path(raw: Any) -> str:
    """A model-supplied path must be relative and stay under the ERP base path."""
    path = str(raw or "").strip()
    if not path:
        raise ValueError("path is required.")
    if "://" in path or path.startswith("//"):
        raise ValueError("path must be relative (no scheme or host).")
    parsed = urlparse(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("path must be relative (no scheme or host).")
    if _contains_dot_segment(parsed.path):
        raise ValueError("path must not contain dot-segment traversal.")
    return path if path.startswith("/") else "/" + path


def erp_tool() -> Tool:
    def _run(args: dict) -> str:
        try:
            base, tok, system = _config()
        except RuntimeError as e:
            return f"ERROR: {e}"
        try:
            path = _safe_path(args.get("path"))
        except ValueError as e:
            return f"ERROR: {e}"
        params = args.get("params") or {}
        if not isinstance(params, dict):
            return "ERROR: params must be an object."

        import httpx
        url = f"{base}{path}"
        try:
            r = _governed_sender(httpx.get)(
                url,
                params={str(k): str(v) for k, v in params.items()},
                headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"},
                timeout=30.0,
                follow_redirects=False,
            )
        except Exception as e:  # network / TLS / timeout
            return f"ERROR: ERP request failed: {e}"
        body = r.text[:_MAX_BYTES]
        truncated = "\n...(truncated)" if len(r.text) > _MAX_BYTES else ""
        return f"{system} GET {path} -> {r.status_code}\n{body}{truncated}"

    return Tool(
        name="erp_read",
        description=(
            "Read-only access to the ERP system of record (HTTP GET only): fetch "
            "records or collections -- purchase orders, receipts, invoices, "
            "items/inventory, GL accounts -- by relative path. Never creates, "
            "updates, or deletes. Configure via [erp] base_url + token."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,  # idempotent read
    )


__all__ = ["erp_tool"]
