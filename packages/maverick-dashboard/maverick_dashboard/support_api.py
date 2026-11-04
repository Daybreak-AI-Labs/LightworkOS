"""Reviewed, redacted support downloads bound to the current administrator."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from maverick import config, support_bundle
from maverick.crypto_at_rest import is_sealed, seal, unseal
from maverick.file_lock import (
    _windows_extended_path,
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
)
from maverick.paths import data_dir
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import (
    constant_time_equals,
    has_global_permission,
    require_global_permission,
    require_permission,
)
from .draft_api import context_for

router = APIRouter()
_LOCK = threading.RLock()
MAX_BYTES = 2 * 1024 * 1024
LIFETIME = 600


class PreviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    failure_reference: str | None = Field(default=None, pattern=r"^lw-failure-[0-9a-f]{32}$")


class DownloadIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    confirm: bool = Field(strict=True)


def _admit(request: Request) -> str:
    require_global_permission(request, "admin")
    if not _enabled():
        raise HTTPException(403, "Support report collection is disabled in Settings or its configuration is unavailable.")
    context = context_for(request)
    if not constant_time_equals(request.headers.get("X-Lightwork-Support-Context", ""), context):
        raise HTTPException(409, "The workspace or signed-in account changed. Reload Help before preparing a report.")
    return context


def _enabled() -> bool:
    try:
        return not config.config_source_errors(include_tenant=True) and config.get_features().get("support_center") is True
    except Exception:
        return False


def _directory(context):
    return ensure_private_directory(_io_path(data_dir("support-previews", context)))


def _io_path(path) -> Path:
    """Return a Win32-safe spelling for a private preview path."""

    value = Path(path)
    return Path(_windows_extended_path(value)) if os.name == "nt" else value


def _prepare(context, failure_reference=None):
    # Scrub every section, including recent errors and client status, before
    # either display or encrypted publication. Nothing is sent externally.
    bundle = json.loads(json.dumps(support_bundle._redact(support_bundle.collect()), default=str, allow_nan=False))
    if failure_reference:
        # An incident lookup hint supplied by the failure page, never evidence
        # of permission or a replacement for the report's own identity.
        bundle["reported_failure_reference"] = failure_reference
    payload = json.dumps(bundle, indent=2, ensure_ascii=False, allow_nan=False).encode()
    if len(payload) > MAX_BYTES:
        raise ValueError("The support report exceeds its supported size. No download was created.")
    digest = hashlib.sha256(payload).hexdigest()
    directory = _directory(context)
    with _LOCK, cross_process_lock(directory / "index", strict=True):
        # Ephemeral previews are bounded per identity/context. A replaced
        # preview yields an explicit refresh requirement, never another report.
        previews = sorted(
            _io_path(directory).glob("*.preview"),
            key=lambda path: path.stat().st_mtime,
        )
        for path in previews[:-15]:
            path.unlink()
        identifier = secrets.token_hex(16)
        envelope = {"schema": "lightwork.support-preview.v1", "context": context,
                    "created_at": time.time(), "payload": payload.decode(), "sha256": digest}
        atomic_write_bytes(directory / (identifier + ".preview"), seal(json.dumps(envelope).encode()))
    return {"context": context, "preview_id": identifier, "sha256": digest, "bundle": bundle}


def _download(context, body):
    directory = _directory(context)
    with _LOCK, cross_process_lock(directory / "index", strict=True):
        path = _io_path(directory / (body.preview_id + ".preview"))
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            raise ValueError(
                "This preview is no longer available. Prepare and review a new report."
            ) from None
        if size > MAX_BYTES * 3:
            raise ValueError("The saved preview could not be verified.")
        raw = atomic_read_bytes(path)
        if not is_sealed(raw):
            raise ValueError("The saved preview encryption could not be verified.")
        envelope = json.loads(unseal(raw))
        if (not isinstance(envelope, dict) or envelope.get("schema") != "lightwork.support-preview.v1"
                or envelope.get("context") != context or not isinstance(envelope.get("created_at"), (int, float))
                or not 0 <= time.time() - envelope["created_at"] <= LIFETIME
                or not isinstance(envelope.get("payload"), str)):
            raise ValueError("The preview expired or its account binding changed. Prepare a new report.")
        payload = envelope["payload"].encode()
        digest = hashlib.sha256(payload).hexdigest()
        if len(payload) > MAX_BYTES or not hmac.compare_digest(digest, body.sha256) or digest != envelope.get("sha256"):
            raise ValueError("The download does not match the reviewed preview.")
        from maverick.audit import record
        record("support_bundle_exported", agent="dashboard", context=context,
               preview_id=body.preview_id, sha256=digest)
        return payload


async def _call(function, *args):
    try:
        return await run_in_threadpool(function, *args)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "The support report is unavailable. Current workspace data has been kept.") from exc


@router.get("/help", response_class=HTMLResponse)
async def support_page(request: Request):
    require_permission(request, "view")
    from .app import templates
    from .help_menu import help_request
    from .help_topics import TOPICS
    response = templates.TemplateResponse(request, "support.html", {"support_context": context_for(request),
        "can_check_installation": has_global_permission(request, "admin"),
        "can_prepare_support": has_global_permission(request, "admin") and _enabled(),
        "support_enabled": _enabled(), "help_request": await run_in_threadpool(help_request, request),
        "help_topics": TOPICS})
    response.headers["Cache-Control"] = "private, no-store"
    return response


@router.post("/api/v1/support/preview")
async def preview_support(request: Request, body: PreviewIn):
    context = _admit(request)
    result = await _call(_prepare, context, body.failure_reference) if body.failure_reference else await _call(_prepare, context)
    return Response(json.dumps(result), media_type="application/json", headers={"Cache-Control": "private, no-store"})


@router.post("/api/v1/support/download")
async def download_support(request: Request, body: DownloadIn):
    context = _admit(request)
    if body.confirm is not True:
        raise HTTPException(422, "Review the support report before downloading it.")
    payload = await _call(_download, context, body)
    return Response(payload, media_type="application/json", headers={"Cache-Control": "private, no-store",
        "Content-Disposition": 'attachment; filename="Lightwork-support-' + body.preview_id + '.json"'})
