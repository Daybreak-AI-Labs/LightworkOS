"""Privacy operations that were only reachable from a terminal.

* ``GET  /api/v1/privacy-ops/dpia`` -- download the data protection impact
  assessment draft (``maverick dpia``), as a readable document or for other
  tools (``operate``, like the Privacy page).
* ``POST /api/v1/data-map/assets/{id}/scan-files`` -- sample the files of a
  SharePoint site or storage bucket place in the data map and record what
  kinds of personal data were found (``maverick data-map scan-sharepoint-files``
  / ``scan-s3-objects``; ``operate``, like the other data map buttons). The
  SharePoint site is looked up on the server from the place's address; the
  bucket defaults to the place's name.
* ``POST /api/v1/vendors/questionnaire-links/prepare`` -- prepare the
  existing questionnaire links before hosted forms are shared
  (``maverick vendor questionnaire-index``; workspace ``admin``).
* ``POST /api/v1/compliance/people/documents/check`` -- count the pieces of
  uploaded documents still held about one person (``maverick knowledge
  residual``; workspace ``admin``, like the other person-data buttons).
* ``POST /api/v1/compliance/people/documents/erase`` -- delete only those
  document pieces (``maverick knowledge erase-subject``; workspace ``admin``).
  Irreversible: the server requires ``confirm`` and the person's name typed
  exactly as the list shows it, and records who asked before anything is
  deleted (never whose data it was).

Every change is recorded in the activity log first; a refused record changes
nothing.
"""
from __future__ import annotations

import re
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

router = APIRouter(tags=["privacy-operations"])

_ASSET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,253}[a-z0-9]$")
_PREPARE_BATCHES = 50


def _record(request: Request, action: str, **detail: Any) -> None:
    from maverick.audit import AuditRefused, audit_event

    try:
        audit_event("control_plane_action", agent="dashboard", action=action,
                    actor=caller_principal(request) or "local administrator", **detail)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was changed.")) from exc


def _actor(request: Request) -> str:
    from .request_identity import request_actor as _request_actor

    return _request_actor(request)


# ---- DPIA draft (maverick dpia) ---------------------------------------------

@router.get("/api/v1/privacy-ops/dpia")
async def dpia(request: Request, format: Literal["text", "json"] = "text") -> Response:  # noqa: A002
    require_permission(request, "operate")
    from maverick.dpia import generate_dpia, render_dpia_json, render_dpia_text

    def build() -> str:
        document = generate_dpia()
        return render_dpia_json(document) if format == "json" else render_dpia_text(document)

    try:
        body = await run_in_threadpool(build)
    except Exception as exc:  # noqa: BLE001 -- reported plainly
        raise HTTPException(status_code=503, detail="The assessment draft could not be prepared.") from exc
    day = time.strftime("%Y-%m-%d", time.gmtime())
    if format == "json":
        media, name = "application/json", f"lightwork-dpia-{day}.json"
    else:
        media, name = "text/plain; charset=utf-8", f"lightwork-dpia-{day}.txt"
    return Response(content=body + "\n", media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


# ---- data map: sample the files of a site or bucket ---------------------------

class ScanFilesIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1)
    #: Storage buckets only: the bucket (defaults to the place's name) and an
    #: optional folder inside it.
    bucket: str | None = Field(default=None, max_length=255)
    folder: str = Field(default="", max_length=512)


def _scan_files(asset_id: str, body: ScanFilesIn, actor: str) -> dict[str, Any]:
    from maverick import data_map as dm

    asset = dm.get_data_asset(asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="That place is no longer in the data map.")
    kind = asset.get("kind")
    if kind == "site":
        site = dm.find_sharepoint_site_id(str(asset.get("location") or ""),
                                          search=str(asset.get("name") or ""))
        if not site:
            raise HTTPException(status_code=409, detail=(
                "SharePoint did not list this site any more. List your SharePoint sites again, then retry."))
        saved = dm.scan_sharepoint_site_files(asset_id, site_id=site, actor=actor,
                                              expected_revision=body.revision)
    elif kind == "bucket":
        bucket = (body.bucket or str(asset.get("name") or "")).strip().lower()
        if not _BUCKET.fullmatch(bucket):
            raise HTTPException(status_code=422, detail="Enter the storage bucket's name.")
        saved = dm.scan_s3_bucket_objects(asset_id, bucket=bucket, prefix=body.folder.strip(),
                                          actor=actor, expected_revision=body.revision)
    else:
        raise HTTPException(status_code=409, detail="Only SharePoint sites and storage buckets can be scanned.")
    scan = saved.get("file_scan") or {}
    categories = [str(c).replace("_", " ") for c in saved.get("content_categories") or []]
    sampled = int(scan.get("files_sampled") or 0)
    skipped = int(scan.get("files_skipped") or 0)
    found = (f"Found: {', '.join(categories)}." if categories else "No personal data was found in the files read.")
    return {"sampled": sampled, "skipped": skipped, "categories": categories,
            "revision": saved.get("revision"),
            "message": f"Read {sampled} file{'s' if sampled != 1 else ''}"
                       + (f" and skipped {skipped}" if skipped else "") + f". {found}"}


@router.post("/api/v1/data-map/assets/{asset_id}/scan-files")
async def scan_files(request: Request, asset_id: str, body: ScanFilesIn) -> dict:
    require_permission(request, "operate")
    if not _ASSET_ID.fullmatch(asset_id):
        raise HTTPException(status_code=404, detail="That place is no longer in the data map.")
    from maverick import data_map as dm
    from maverick.privacy_ops import RecordConflict

    if not dm.enabled():
        from .feature_gate import feature_off

        raise feature_off("data_map", detail="The data map is turned off.")
    await run_in_threadpool(_record, request, "data_map_scan_files", asset=asset_id)
    try:
        return await run_in_threadpool(_scan_files, asset_id, body, _actor(request))
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(status_code=409, detail=(
            "This place changed since the page loaded. Refresh the page and try again.")) from exc
    except dm.DataMapConfigError as exc:
        raise HTTPException(status_code=503, detail=(
            "Lightwork is not connected to this storage yet. Whoever installed Lightwork can connect it.")) from exc
    except dm.DataMapError as exc:
        raise HTTPException(status_code=502, detail="The storage service did not answer as expected. Try again later.") from exc
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Check the bucket name and folder, then try again.") from exc


# ---- vendor questionnaire links (maverick vendor questionnaire-index) ---------

class PrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start_over: bool = False


@router.post("/api/v1/vendors/questionnaire-links/prepare")
async def prepare_questionnaire_links(request: Request, body: PrepareIn) -> dict:
    require_permission(request, "admin")
    from maverick import vendor_management as vm

    if not vm.enabled():
        from .feature_gate import feature_off

        raise feature_off("vendor_management", detail="The vendor register is turned off.")
    await run_in_threadpool(_record, request, "vendor_questionnaire_links_prepare", start_over=body.start_over)
    try:
        result = await run_in_threadpool(
            lambda: vm.prepare_questionnaire_index(batches=_PREPARE_BATCHES, rebuild=body.start_over))
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail="The questionnaire links could not be prepared right now.") from exc
    ready = bool(result and result.get("ready"))
    checked = int((result or {}).get("scanned") or 0)
    return {"ready": ready, "checked": checked,
            "message": ("Questionnaire links are ready to share." if ready else
                        f"Checked {checked} vendor record{'s' if checked != 1 else ''}. More remain; press the "
                        "button again to continue. Shared forms stay unavailable until this finishes.")}


# ---- a person's uploaded documents (maverick knowledge residual / erase-subject)

class PersonDocumentsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: str = Field(min_length=1, max_length=64)
    user: str = Field(min_length=1, max_length=256)


class EraseDocumentsIn(PersonDocumentsIn):
    confirm: bool = False
    #: The person's name typed exactly as the list shows it.
    confirm_name: str = Field(default="", max_length=300)


def _person_label(channel: str, user: str) -> str:
    from .compliance_controls_api import _list_people

    for row in _list_people():
        if row["channel"] == channel and row["user"] == user:
            return str(row["person"])
    raise HTTPException(status_code=404, detail="That person is no longer in the list. Refresh the page.")


def _validated(body: PersonDocumentsIn) -> tuple[str, str]:
    from .compliance_controls_api import PersonIn
    from .compliance_controls_api import _validated as validated_person

    return validated_person(PersonIn(channel=body.channel, user=body.user))


def _count(channel: str, user: str) -> int:
    from maverick.knowledge_admin import count_subject

    return int(count_subject(channel, user))


@router.post("/api/v1/compliance/people/documents/check")
async def check_documents(request: Request, body: PersonDocumentsIn) -> dict:
    require_permission(request, "admin")
    channel, user = _validated(body)
    from maverick.knowledge_admin import KnowledgeUnavailable

    try:
        remaining = await run_in_threadpool(_count, channel, user)
    except KnowledgeUnavailable as exc:
        raise HTTPException(status_code=503, detail="Uploaded documents could not be checked right now.") from exc
    if remaining == 0:
        message = "No pieces of uploaded documents about this person are left."
    elif remaining == 1:
        message = "1 piece of an uploaded document about this person is still held."
    else:
        message = f"{remaining} pieces of uploaded documents about this person are still held."
    return {"remaining": remaining, "clean": remaining == 0, "message": message}


@router.post("/api/v1/compliance/people/documents/erase")
async def erase_documents(request: Request, body: EraseDocumentsIn) -> dict:
    require_permission(request, "admin")
    channel, user = _validated(body)
    if body.confirm is not True:
        raise HTTPException(status_code=409, detail="Confirm the erase to continue. Nothing was erased.")
    label = await run_in_threadpool(_person_label, channel, user)
    if " ".join(body.confirm_name.split()).casefold() != " ".join(label.split()).casefold():
        raise HTTPException(status_code=409, detail="The name typed does not match this person. Nothing was erased.")
    from maverick.knowledge_admin import KnowledgeUnavailable, erase_subject

    # Who asked, never whose data (the subject is exactly what is erased).
    await run_in_threadpool(_record, request, "person_documents_erase", channel=channel)
    try:
        removed = await run_in_threadpool(erase_subject, channel, user)
        remaining = await run_in_threadpool(_count, channel, user)
    except KnowledgeUnavailable as exc:
        raise HTTPException(status_code=503, detail=(
            "Uploaded documents could not be erased right now. Nothing more was removed.")) from exc
    total = sum(int(v) for v in removed.values())
    return {"erased": total, "remaining": remaining, "clean": remaining == 0,
            "message": (f"Erased {total} piece{'s' if total != 1 else ''} of uploaded documents. "
                        + ("None are left." if remaining == 0 else
                           f"{remaining} could not be removed; try again or ask your administrator."))}


__all__ = ["router"]
