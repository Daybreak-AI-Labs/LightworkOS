"""Settings > Maintenance: copy consent records into the shared consent database.

Choosing the shared PostgreSQL database for consent records (All settings,
``[consent_preferences.storage]``) takes effect at the next restart and does
not move anything. This page part is the guided move that follows, in the same
shape as the other moves into the shared database: a preview of what each
workspace's consent stores hold and what the shared database already has, an
explicit confirmation, then a background job
(:func:`maverick.consent_storage.move_local_records`) the page follows to the
end. Each store is copied all or nothing, only into an empty store (or one
holding exactly the same records), and compared row by row afterwards; the
files on this computer are never changed. Global administrators only; the
request and the outcome each add one activity-record row.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import ops_admin_jobs as ops_jobs
from .auth import require_global_permission

router = APIRouter(prefix="/api/v1/admin/installation/consent-records")

_STATES = {
    "ready": "Will be copied",
    "moved": "Already copied",
    "has_records": "Not copied: the shared database already has other records here",
    "unavailable": "The shared database could not be checked",
    "unreadable": "This computer's file could not be read",
}
_STORES = {
    "consent-preferences": "Consent choices and receipts",
    "consent-delivery": "Consent delivery",
    "consent-destination-operations": "Delivery to connected services",
    "consent-publishing": "Published banners",
    "consent-web-publish-settings": "Website publishing settings",
    "consent-experiments": "Banner experiments",
    "consent-profile-data": "Preference profile data",
    "consent-profile-data-assignments": "Preference prompts",
    "consent-native-sdk": "App consent devices",
    "consent-scan-inventory": "Website scans",
    "consent-scan-notice-proposals": "Scan notice proposals",
    "consent-scan-review-requests": "Scan review requests",
    "consumer-trust-center-authority": "Privacy center requests",
    "trust-center-branding": "Privacy center branding",
    "bulk-jobs": "Bulk consent changes",
    "public-consent-credentials": "Website and app keys",
    "native-consent-application-directory": "App directory",
}


class ConfirmIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: bool = Field(default=False, strict=True)


def _store_label(name: str) -> str:
    return _STORES.get(name) or name.replace("-", " ").replace("_", " ").capitalize()


def _preview() -> dict[str, Any]:
    from maverick import consent_storage

    try:
        data = consent_storage.preview_move()
    except consent_storage.ConsentStorageError:
        return {"shared": False, "ready": False, "stores": [], "records": 0,
                "summary": "The consent records settings could not be read. Check them in All "
                           "settings."}
    rows = [{"workspace": item["workspace"] or "Whole installation",
             "store": _store_label(item["store"]), "records": int(item["records"]),
             "state": item["state"], "result": _STATES.get(item["state"], item["state"])}
            for item in data["stores"]]
    waiting = sum(r["records"] for r in rows if r["state"] == "ready")
    if not data["shared"]:
        summary = ("Consent records are kept in files on this computer. To copy them into a shared "
                   "database, first choose the shared database for consent records in All settings "
                   "and restart Lightwork.")
    elif not rows:
        summary = "There are no consent records on this computer to copy."
    elif waiting:
        summary = (f"{waiting:,} consent record{'s' if waiting != 1 else ''} on this computer can be "
                   "copied into the shared database.")
    else:
        summary = "Nothing on this computer is waiting to be copied."
    return {"shared": data["shared"], "ready": bool(data["shared"] and waiting), "stores": rows,
            "records": int(data["records"]), "summary": summary}


@router.get("")
async def consent_records_preview(request: Request) -> dict:
    require_global_permission(request, "admin")
    return await run_in_threadpool(_preview)


def _failure(exc: BaseException) -> str:
    from maverick import consent_storage

    if isinstance(exc, consent_storage.MoveRefused):
        return str(exc)
    return ("The consent records could not be copied. The files on this computer were kept as they "
            "were; ask your IT team to check the shared database.")


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    copied = int(result.get("copied") or 0)
    refused = result.get("refused") or []
    text = f"Copied {copied:,} consent record{'s' if copied != 1 else ''} into the shared database."
    if refused:
        text += (f" {len(refused)} store{'s were' if len(refused) != 1 else ' was'} not copied; see "
                 "below.")
    text += " The files on this computer were kept."
    return {"copied": copied, "summary": text,
            "refused": [{"workspace": r["workspace"] or "Whole installation",
                         "store": _store_label(r["store"]), "reason": r["reason"]}
                        for r in refused],
            "moved": [{"workspace": m["workspace"] or "Whole installation",
                       "store": _store_label(m["store"]), "copied": int(m["copied"])}
                      for m in result.get("moved") or []]}


@router.post("/move")
async def consent_records_move(body: ConfirmIn, request: Request) -> dict:
    from maverick import consent_storage

    from .app import _require_same_origin
    from .system_checks_api import _record

    _require_same_origin(request)
    require_global_permission(request, "admin")
    if body.confirm is not True:
        raise HTTPException(409, "Confirm to copy the consent records. Nothing was changed.")
    try:
        shared = await run_in_threadpool(consent_storage.shared)
    except consent_storage.ConsentStorageError:
        shared = False
    if not shared:
        raise HTTPException(409, "Consent records are kept in files on this computer. Choose the "
                                 "shared database for consent records in All settings and restart "
                                 "Lightwork first. Nothing was copied.")
    await run_in_threadpool(_record, request, "consent_records_move_requested")

    def work() -> dict[str, Any]:
        return _summary(consent_storage.move_local_records())

    def finished(job: dict) -> None:
        result = job.get("result") or {}
        _record(request, "consent_records_moved", succeeded=job["state"] == "done",
                copied=int(result.get("copied") or 0),
                stores_not_copied=len(result.get("refused") or []))

    try:
        job = ops_jobs.start("consent-records", work, failure=_failure, on_finish=finished)
    except ops_jobs.JobBusy as exc:
        raise HTTPException(409, "Consent records are already being copied. Wait for that to "
                                 "finish.") from exc
    return {"job": ops_jobs.public(job)}


__all__ = ["router"]
