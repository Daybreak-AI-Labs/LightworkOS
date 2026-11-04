"""Legal matters for eDiscovery: create, review, edit, release and export.

Every route answers 404 while ``[ediscovery] enable`` is off, so the feature is
absent.  Matter details are readable and changeable only with the audit
permission; the admin role holds it too.  Refusals to erase name no matter.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, has_global_permission, require_global_permission

router = APIRouter(prefix="/ediscovery", tags=["ediscovery"])
_ID_RE = re.compile(r"mtr-[0-9a-f]{16}\Z")
RecordKind = Literal["goals", "chats", "attachments", "approvals"]
MAX_LISTED = 500
STALE_EXPORT_SECONDS = 3600


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MatterIn(_Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    custodians: list[str] = Field(min_length=1, max_length=500)
    date_from: str | None = Field(default=None, max_length=10)
    date_to: str | None = Field(default=None, max_length=10)
    record_kinds: list[RecordKind] = Field(min_length=1, max_length=4)


class MatterEdit(_Strict):
    expected_revision: int = Field(ge=1, le=1_000_000)
    name: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    custodians: list[str] | None = Field(default=None, min_length=1, max_length=500)
    date_from: str | None = Field(default=None, max_length=10)
    date_to: str | None = Field(default=None, max_length=10)
    record_kinds: list[RecordKind] | None = Field(default=None, min_length=1, max_length=4)


class ReleaseIn(_Strict):
    expected_revision: int = Field(ge=1, le=1_000_000)


def page_context(request: Request) -> dict[str, bool]:
    """Feature flags for the compliance page.  The section appears only for audit access."""
    from maverick import ediscovery

    switched_on = ediscovery.enabled()
    return {"ediscovery_enabled": switched_on,
            "ediscovery_can_audit": switched_on and has_global_permission(request, "audit")}


def _gate(request: Request) -> str:
    from maverick import ediscovery
    from maverick.paths import current_tenant_id_strict

    if not ediscovery.enabled():
        raise HTTPException(status_code=404, detail="Not Found")
    require_global_permission(request, "audit")
    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(status_code=409, detail="Choose a workspace before managing legal holds.")
    return tenant


def _store(tenant: str):
    from maverick import ediscovery

    return ediscovery.MatterStore(ediscovery.store_path(tenant))


def _actor(request: Request) -> str:
    return caller_principal(request) or "local"


def _matter_id(value: str) -> str:
    if not _ID_RE.fullmatch(value):
        raise HTTPException(status_code=404, detail="That matter was not found.")
    return value


def _translate(exc: Exception) -> HTTPException:
    from maverick import ediscovery

    if isinstance(exc, ediscovery.MatterNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ediscovery.MatterConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, ediscovery.MatterValidationError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ediscovery.MatterExportTooLarge):
        return HTTPException(status_code=413, detail=str(exc))
    if isinstance(exc, ediscovery.EdiscoveryDisabled):
        return HTTPException(status_code=404, detail="Not Found")
    if isinstance(exc, ediscovery.EdiscoveryError):
        return HTTPException(status_code=503, detail=str(exc))
    raise exc


def _public(matter: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in matter.items() if key not in {"schema", "tenant_id"}}


async def _record_read(request: Request, store, **detail: Any) -> None:
    """Audit a reading of matter details before they are returned (fails closed)."""
    actor = _actor(request)
    try:
        await run_in_threadpool(lambda: store.record_read(actor=actor, **detail))
    except Exception as exc:  # noqa: BLE001 -- translated below; unknown errors re-raise
        raise _translate(exc) from exc


@router.get("/matters")
async def list_matters(request: Request) -> dict[str, Any]:
    tenant = _gate(request)
    store = _store(tenant)
    # One row beyond the cap tells the page that more matters exist. Holds still apply to all of them.
    rows = await run_in_threadpool(store.list, tenant, limit=MAX_LISTED + 1)
    await _record_read(request, store, verb="ediscovery_matters_listed", shown=min(len(rows), MAX_LISTED))
    return {"matters": [_public(row) for row in rows[:MAX_LISTED]], "truncated": len(rows) > MAX_LISTED}


@router.post("/matters", status_code=201)
async def create_matter(request: Request, body: MatterIn) -> dict[str, Any]:
    tenant = _gate(request)
    actor = _actor(request)
    try:
        return _public(await run_in_threadpool(
            lambda: _store(tenant).create(tenant, actor=actor, values=body.model_dump())))
    except Exception as exc:  # noqa: BLE001 -- translated below; unknown errors re-raise
        raise _translate(exc) from exc


@router.get("/matters/{matter_id}")
async def get_matter(request: Request, matter_id: str) -> dict[str, Any]:
    tenant = _gate(request)
    matter_id = _matter_id(matter_id)
    store = _store(tenant)
    try:
        matter = await run_in_threadpool(store.get, tenant, matter_id)
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc
    await _record_read(request, store, verb="ediscovery_matter_viewed", matter_id=matter_id,
                       revision=matter["revision"])
    return _public(matter)


@router.patch("/matters/{matter_id}")
async def edit_matter(request: Request, matter_id: str, body: MatterEdit) -> dict[str, Any]:
    tenant = _gate(request)
    matter_id = _matter_id(matter_id)
    actor = _actor(request)
    # Only fields the reviewer actually sent change; an explicit null clears an optional date.
    values = body.model_dump(exclude_unset=True, exclude={"expected_revision"})
    try:
        return _public(await run_in_threadpool(
            lambda: _store(tenant).update(tenant, matter_id, actor=actor,
                                          expected_revision=body.expected_revision, values=values)))
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


@router.post("/matters/{matter_id}/release")
async def release_matter(request: Request, matter_id: str, body: ReleaseIn) -> dict[str, Any]:
    tenant = _gate(request)
    matter_id = _matter_id(matter_id)
    actor = _actor(request)
    try:
        return _public(await run_in_threadpool(
            lambda: _store(tenant).release(tenant, matter_id, actor=actor,
                                           expected_revision=body.expected_revision)))
    except Exception as exc:  # noqa: BLE001
        raise _translate(exc) from exc


def _discard(path) -> None:
    from contextlib import suppress

    with suppress(OSError):
        Path(path).unlink()


def _sweep_stale_exports(directory: Path) -> None:
    """Remove archives left by an export that never finished, such as a stopped process."""
    cutoff = time.time() - STALE_EXPORT_SECONDS
    for path in Path(directory).glob("*.zip"):
        if path.stat().st_mtime < cutoff:
            _discard(path)


class _ArchiveResponse(FileResponse):
    """Streams one export and removes its file however the transfer ends.

    Starlette runs a background task only after a complete send, so a download
    cut off by the client would otherwise leave personal data on disk.
    """

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            _discard(self.path)


@router.get("/matters/{matter_id}/export")
async def export_matter(request: Request, matter_id: str) -> FileResponse:
    from maverick import ediscovery, ediscovery_export

    from ._shared import _world

    tenant = _gate(request)
    matter_id = _matter_id(matter_id)
    actor = _actor(request)
    store = _store(tenant)

    def build():
        _sweep_stale_exports(store.path.parent / "exports")
        matter = store.get(tenant, matter_id)
        return ediscovery_export.export_matter(_world(), matter, actor=actor, out_dir=store.path.parent / "exports")

    try:
        result = await run_in_threadpool(build)
    except ediscovery.EdiscoveryError as exc:
        raise _translate(exc) from exc
    return _ArchiveResponse(
        result["path"],
        media_type="application/zip",
        filename=f"legal-matter-{matter_id}.zip",
        headers={"Cache-Control": "no-store"},
    )


__all__ = ["MatterEdit", "MatterIn", "ReleaseIn", "page_context", "router"]
