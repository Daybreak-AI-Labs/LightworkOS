"""Reviewed practice challenges, exact export consent and isolated native checks."""
from __future__ import annotations

import base64
import binascii
import hmac
import re
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from maverick import approval_challenges as source
from maverick.governed_records import (
    GovernedRecordBackendError,
    GovernedRecordCapacityError,
    GovernedRecordStore,
)
from maverick.paths import current_tenant_id_strict, data_dir
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/learning/approval-challenges", tags=["approval-challenges"])
page_router = APIRouter()
_ID = re.compile(r"ACP-[a-f0-9]{32}\Z")
_STEPS = {"read_review": "Reviewer reads the fictional request", "change_claim": "Another reviewer takes the request",
          "change_card": "The fictional request changes", "expire": "The fictional review expires",
          "vote_reviewed": "First reviewer attempts the earlier sign-off", "vote_other": "Second reviewer signs off",
          "deliver_audit": "The fictional vote's activity entry is delivered", "undo": "The fictional decision is undone"}


class Confirmed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm: bool


class Generate(Confirmed):
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")
    family: Literal["claim_changed", "card_changed", "round_changed", "expired"]
    quorum: int = Field(ge=1, le=2)


class Upload(Confirmed):
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")
    file: str = Field(min_length=1, max_length=10924)


class Review(Confirmed):
    revision: int = Field(ge=1)


class ActionReview(Review):
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")


class Setup(Confirmed):
    previous: bool
    enabled: bool


def records():
    return GovernedRecordStore("approval-challenges", "ACP", "approval_challenge", required_backend="local",
                               archive_when_full=False)


def removals():
    # Only direct receipt reads, never an unbounded public history scan.
    return GovernedRecordStore("approval-challenge-removals", "ACR", "approval_challenge_removal", required_backend="local")


@contextmanager
def _record_lock(identity):
    from maverick.file_lock import cross_process_lock, prepare_private_directory
    if _ID.fullmatch(identity) is None:
        raise HTTPException(404, "Choose a saved practice record.")
    path = data_dir("approval-challenge-operation-locks", identity + ".lock")
    prepare_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        yield


def removal(request, identity):
    _tenant, owner, _context = _bound(request)
    if _ID.fullmatch(identity) is None:
        return None
    row = removals().get("ACR-" + identity[4:])
    return row if row and row.get("owner") == owner else None


def _bound(request, body=None):
    auth.require_permission(request, "operate")
    tenant, actor, context = current_tenant_id_strict(), auth.caller_principal(request), context_for(request)
    if not tenant or not actor or not actor.startswith("user:"):
        raise HTTPException(403, "Sign in with a named account and select your workspace.")
    if body is not None:
        from .app import _require_same_origin
        _require_same_origin(request)
        if not hmac.compare_digest(body.context, context):
            raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
        if body.confirm is not True:
            raise HTTPException(422, "Review and confirm this local challenge action.")
    return tenant, actor, context


def _call(function):
    try:
        return function()
    except HTTPException:
        raise
    except GovernedRecordCapacityError as exc:
        raise HTTPException(409, "This workspace has 256 saved practice records. Review and remove one of your inactive records here to make space. Its decision receipt stays in the activity history; an in-progress check cannot be removed.") from exc
    except GovernedRecordBackendError as exc:
        raise HTTPException(409, "Approval challenges currently support a single local installation. This installation's storage setup is not supported; no live requests were changed.") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "The local challenge record could not be checked. Refresh and read its saved state before starting another check.") from exc


def _allowed():
    from maverick.learning_guard import check_learning_halt
    check_learning_halt("approval_challenges", "check")
    if not source.enabled():
        raise HTTPException(409, "Turn on local approval challenges here before creating or checking one.")


def visible(request, identity):
    _tenant, owner, _context = _bound(request)
    if _ID.fullmatch(identity) is None:
        raise HTTPException(404, "Choose a saved approval challenge.")
    row = records().get(identity)
    if row is None or row.get("owner") != owner:
        raise HTTPException(404, "This approval challenge is not available to your current account.")
    return row


def _plain(row, version=None):
    artifact = source.artifact(row["artifact"])
    result = row.get("result") or {}
    current = row["state"] == "checked" and result.get("adapter_version") == (version or source.adapter_version())
    protected = current and result.get("fault_variant_reproduced") is True and result.get("native_guard_blocked") is True and result.get("native_vote_recorded") is False
    status = {"prepared": "Challenge prepared; local check not started", "checking": "Original local check needs its saved result", "checked": "Outdated sign-off blocked in this practice" if protected else "Local result needs review",
              "unknown": "Local check outcome unavailable", "removing": "Removal saved; finish its original review"}.get(row["state"], "Needs review")
    if row["state"] == "checked" and not current:
        status = "Installed approval safeguards changed; earlier result is historical"
    return {"id": row["id"], "revision": row["revision"], "title": source.FAMILIES[artifact["family"]], "quorum": artifact["quorum"],
            "when": datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%b %d, %Y at %H:%M UTC"),
            "state": row["state"], "status": status, "can_check": row["state"] == "prepared" and source.enabled(),
            "can_resolve": row["state"] == "checking" and time.time() - row.get("started_at", time.time()) > 30,
            "can_export": protected, "download_ready": protected and row.get("exported_revision") is not None,
            "can_remove": row["state"] in {"prepared", "checked", "unknown", "removing"},
            "source": "Practice scenario · fictional requests, no customer incident", "origin": "Imported practice challenge" if row["origin"] == "import" else "Locally generated practice challenge",
            "steps": [_STEPS[action] for action in artifact["schedule"]], "model_states": artifact["corrected_model_states"],
            "bounds": "One fictional request, two reviewers, at most 12 steps and 50,000 possible situations; one local check with a 10-second deadline.",
            "result": {"current": current, "fault_reproduced": result.get("fault_variant_reproduced"), "blocked": result.get("native_guard_blocked"), "vote_recorded": result.get("native_vote_recorded")},
            "explanation": row.get("reason", ""),
            "receipts": {"check": row.get("check_operation"), "export": row.get("export_operation"), "resolve": row.get("resolve_operation"), "remove": row.get("remove_operation")},
            "limitations": "This checks a selected fictional sequence against this installation’s approval safeguards. It does not prove every outdated sign-off is prevented, validate other software, or show that a customer experienced this failure. No live safeguard is installed or enabled."}


def choices(request, offset=0):
    _tenant, owner, context = _bound(request)
    if type(offset) is not int or not 0 <= offset <= 240 or offset % 40:
        raise HTTPException(422, "Choose a current page of saved challenges.")
    own = sorted((row for row in records().list(limit=256) if row.get("owner") == owner), key=lambda row: row["created_at"], reverse=True)
    version = source.adapter_version()
    return {"context": context, "enabled": source.enabled(), "can_configure": auth.has_global_permission(request, "admin"),
            "patterns": [{"value": key, "label": label} for key, label in source.FAMILIES.items()], "total": len(own),
            "offset": offset, "next": offset + 40 if len(own) > offset + 40 else None, "previous": max(0, offset - 40) if offset else None,
            "records": [{key: value for key, value in _plain(row, version).items() if key in {"id", "revision", "title", "quorum", "when", "status", "can_check", "can_resolve", "can_export", "can_remove", "download_ready"}} for row in own[offset:offset + 40]],
            "detail": "Build a reusable fictional approval challenge, check it in an isolated local copy, then review exactly what a shared file contains."}


def _create(request, body, artifact, origin):
    _bound(request, body)
    with _record_lock("ACP-" + body.operation):
        return _create_locked(request, body, artifact, origin)


def _create_locked(request, body, artifact, origin):
    _tenant, owner, _context = _bound(request, body)
    _allowed()
    identity, store = "ACP-" + body.operation, records()
    if removals().get("ACR-" + body.operation):
        raise HTTPException(409, "This original practice record was removed. Its decision receipt remains; start a separately reviewed new challenge instead.")
    row = store.get(identity)
    if row:
        if row.get("owner") != owner or row.get("artifact") != artifact or row.get("origin") != origin:
            raise HTTPException(409, "This original operation belongs to a different review. No check was repeated.")
        return row
    return store.create({"id": identity, "owner": owner, "artifact": artifact, "origin": origin, "state": "prepared", "reason": "", "result": None,
                         "exported_revision": None}, action="approval.challenge.prepare", actor=owner, max_records=256)


def _check(request, row, operation):
    _tenant, owner, _context = _bound(request)
    _allowed()
    if row["state"] != "prepared":
        return row
    store = records()
    row = store.update(row["id"], lambda value: value.update(state="checking", started_at=time.time(), check_operation=operation, check_review_revision=row["revision"]),
                       expected_revision=row["revision"], action="approval.challenge.check", actor=owner)
    try:
        result = source.check_native(row["artifact"])
        _bound(request)  # Current account/role is checked again before retaining the result.
        reason = "The fictional failure happened only in the deliberately weakened disposable copy. This installation’s safeguards blocked that same outdated sign-off." if result["fault_variant_reproduced"] and result["native_guard_blocked"] and not result["native_vote_recorded"] else "This check did not establish protection for the selected sequence. Review its limits before relying on it."
        return store.update(row["id"], lambda value: value.update(state="checked", result=result, reason=reason),
                            expected_revision=row["revision"], action="approval.challenge.result", actor=owner)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "The original local check could not retain a verified result. Its outcome is unknown. No live approval was changed."
        return store.update(row["id"], lambda value: value.update(state="unknown", reason=reason),
                            expected_revision=row["revision"], action="approval.challenge.unknown", actor=owner)


def generate(request, body):
    _bound(request, body)
    _allowed()
    artifact = source.compile_challenge(body.family, body.quorum)
    row = _create(request, body, artifact, "generated")
    # A repeated original operation is readback, including an interrupted check.
    if row["state"] == "prepared":
        row = _check(request, row, body.operation)
    return {"record": _plain(row), "detail": "The original practice challenge and its saved local outcome are shown. No live request, model call or live approval rule was changed."}


def upload(request, body):
    _bound(request, body)
    _allowed()
    try:
        data = base64.b64decode(body.file, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(422, "Choose a supported Lightwork approval challenge file.") from exc
    artifact = source.parse(data)
    row = _create(request, body, artifact, "import")
    return {"record": _plain(row), "detail": "The file's supported practice file has been reviewed. It has not been run; confirm its local check separately."}


def check(request, identity, body):
    _bound(request, body)
    row = visible(request, identity)
    if row.get("check_operation") == body.operation and row.get("check_review_revision") == body.revision:
        return {"record": _plain(row), "detail": "The original local check's saved state was read. No check was repeated."}
    if row["revision"] != body.revision or row["state"] != "prepared":
        raise HTTPException(409, "This challenge changed. Refresh and review its current state.")
    return {"record": _plain(_check(request, row, body.operation)), "detail": "The original local check's saved result is shown. No live request or live approval rule was changed."}


def resolve(request, identity, body):
    _tenant, owner, _context = _bound(request, body)
    row = visible(request, identity)
    if row.get("resolve_operation") == body.operation and row.get("resolve_review_revision") == body.revision:
        return {"record": _plain(row), "detail": "The original resolution was read. No check was repeated."}
    if row["revision"] != body.revision or row["state"] != "checking" or time.time() - row["started_at"] <= 30:
        raise HTTPException(409, "The original check may still be finishing. Refresh its saved state before resolving it.")
    row = records().update(identity, lambda value: value.update(state="unknown", reason="The original check's verified result is unavailable. It was not repeated, and no live request was changed.", resolve_operation=body.operation, resolve_review_revision=row["revision"]),
        expected_revision=row["revision"], action="approval.challenge.resolve", actor=owner)
    return {"record": _plain(row), "detail": "The interrupted check is recorded as unknown. No check was repeated."}


def export(request, identity, body):
    _tenant, owner, _context = _bound(request, body)
    row = visible(request, identity)
    if row.get("export_operation") == body.operation and row.get("export_review_revision") == body.revision:
        return {"record": _plain(row), "detail": "The original exact export consent was read. No consent was repeated."}
    if row["revision"] != body.revision or not _plain(row)["can_export"]:
        raise HTTPException(409, "This exact challenge or installed code changed. Review a current local result before sharing.")
    row = records().update(identity, lambda value: value.update(exported_revision=row["revision"], permitted_release="selected_structural_pattern_and_quorum_only", export_operation=body.operation, export_review_revision=row["revision"]),
        expected_revision=row["revision"], action="approval.challenge.export_consent", actor=owner)
    return {"record": _plain(row), "detail": "You authorized this exact practice scenario and required sign-off count for export. The file contains no customer incident, account, workspace, request identity, private values, runtime timings or installation’s software details."}


def remove(request, identity, body):
    _bound(request, body)
    with _record_lock(identity):
        return _remove_locked(request, identity, body)


def _remove_locked(request, identity, body):
    _tenant, owner, _context = _bound(request, body)
    store, receipts = records(), removals()
    retired = removal(request, identity)
    row = store.get(identity) if _ID.fullmatch(identity) else None
    if retired and (retired["operation"] != body.operation or body.revision not in {retired["reviewed_revision"], retired["source_revision"]}):
        raise HTTPException(409, "This original removal belongs to a different review. Nothing else was removed.")
    if row is None:
        if retired and not retired.get("_audit_pending"):
            return {"removed": True, "detail": "This saved practice record was removed. Its decision receipt is retained; no removal was repeated."}
        raise HTTPException(404, "Choose an available saved practice record.")
    if row.get("owner") != owner:
        raise HTTPException(404, "This practice record is not available to your current account.")
    if row["state"] == "removing":
        if row.get("remove_operation") != body.operation or body.revision not in {row["revision"], row["remove_reviewed_revision"]}:
            raise HTTPException(409, "Another removal owns this original record. Read its saved state.")
    else:
        if row["revision"] != body.revision or row["state"] not in {"prepared", "checked", "unknown"}:
            raise HTTPException(409, "This practice record changed or its check is in progress. Nothing was removed.")
        if row.get("_audit_pending"):
            row = store._flush(row)
            if row.get("_audit_pending"):
                raise HTTPException(409, "The earlier activity receipt is pending. Nothing was removed; refresh and retry after its receipt is available.")
        row = store.update(identity, lambda value: value.update(state="removing", remove_operation=body.operation, remove_reviewed_revision=body.revision),
                           expected_revision=row["revision"], action="approval.challenge.remove_review", actor=owner)
    row = store._flush(row)
    if row.get("_audit_pending"):
        raise HTTPException(409, "The removal review is saved, but its activity receipt is pending. Finish this same removal after refreshing; the practice record is still retained.")
    material = {key: value for key, value in row.items() if key != "_audit_pending"}
    commitment = source._sha(material)
    if retired is None:
        retired = receipts.create({"id": "ACR-" + identity[4:], "owner": owner, "operation": body.operation,
                                   "reviewed_revision": row["remove_reviewed_revision"], "source_revision": row["revision"], "source_sha256": commitment},
                                  action="approval.challenge.remove_receipt", actor=owner)
    retired = receipts._flush(retired)
    if retired.get("_audit_pending") or retired["source_sha256"] != commitment or retired["source_revision"] != row["revision"]:
        raise HTTPException(409, "The retained removal receipt could not be confirmed. The practice record remains; refresh and finish this same removal.")
    _bound(request, body)
    try:
        removed = store.delete(identity, expected_revision=row["revision"])
    except Exception:
        if store.get(identity) is not None:
            raise
        removed = True
    if not removed and store.get(identity) is not None:
        raise HTTPException(409, "The practice record changed during removal. Refresh before continuing.")
    return {"removed": True, "detail": "This saved practice record and local result were removed, making space for another practice. Its decision receipt remains in the activity history. Previously downloaded files are not recalled."}


def setup(request, body):
    _bound(request, body)
    auth.require_global_permission(request, "admin")
    from . import settings_store
    from .learning_ops_api import _record
    with settings_store._locked(strict=True):
        if source.enabled() != body.previous:
            raise HTTPException(409, "This setting changed. Refresh before reviewing it again.")
        _record(request, "approval_challenges_setting", enabled=body.enabled)
        settings_store.set_catalog_values({("approval_challenges", "enable"): body.enabled})
        if source.enabled() != body.enabled:
            raise HTTPException(409, "The setting was not accepted. Refresh to check the effective setting.")
    return {"enabled": source.enabled(), "detail": "Local approval challenges are on. Each check and export still needs its own review." if body.enabled else "Local approval challenges are off. Earlier records remain available for review; no new check can start."}


@router.get("")
def options(request: Request, offset: int = 0):
    return JSONResponse(_call(lambda: choices(request, offset)), headers={"Cache-Control": "private, no-store"})


async def _body(request, model):
    data = bytearray()
    async for chunk in request.stream():
        data.extend(chunk)
        if len(data) > 16384:
            raise HTTPException(413, "Choose a challenge file within 8 KB; this review is too large.")
    try:
        return model.model_validate_json(data)
    except ValueError as exc:
        raise HTTPException(422, "Review the required fields and choose a supported challenge file.") from exc


@router.post("")
async def create_challenge(request: Request):
    body = await _body(request, Generate)
    return await run_in_threadpool(lambda: _call(lambda: generate(request, body)))


@router.post("/import")
async def import_challenge(request: Request):
    body = await _body(request, Upload)
    return await run_in_threadpool(lambda: _call(lambda: upload(request, body)))


@router.post("/setup")
def set_setup(request: Request, body: Setup):
    return _call(lambda: setup(request, body))


@router.get("/{identity}")
def read_challenge(request: Request, identity: str):
    _tenant, _owner, context = _bound(request)
    retired = _call(lambda: removal(request, identity))
    if retired and records().get(identity) is None:
        return JSONResponse({"removed": True, "context": context, "receipt": retired["operation"],
                             "detail": "This practice record was removed. Its decision receipt remains; its saved local result is no longer available."}, headers={"Cache-Control": "private, no-store"})
    return JSONResponse(_call(lambda: {**_plain(visible(request, identity)), "context": context}), headers={"Cache-Control": "private, no-store"})


@router.post("/{identity}/check")
def check_challenge(request: Request, identity: str, body: ActionReview):
    return _call(lambda: check(request, identity, body))


@router.post("/{identity}/resolve")
def resolve_challenge(request: Request, identity: str, body: ActionReview):
    return _call(lambda: resolve(request, identity, body))


@router.post("/{identity}/export")
def export_challenge(request: Request, identity: str, body: ActionReview):
    return _call(lambda: export(request, identity, body))


@router.post("/{identity}/remove")
def remove_challenge(request: Request, identity: str, body: ActionReview):
    return _call(lambda: remove(request, identity, body))


@router.get("/{identity}/download")
def download_challenge(request: Request, identity: str):
    def read():
        row = visible(request, identity)
        if not _plain(row)["download_ready"]:
            raise HTTPException(409, "Review the current local result and separately authorize this exact export first.")
        from .learning_ops_api import _record
        _record(request, "approval_challenge_download", installation=False, challenge=identity)
        return Response(source._bytes(source.artifact(row["artifact"])), media_type="application/json",
            headers={"Cache-Control": "private, no-store", "X-Content-Type-Options": "nosniff", "Content-Disposition": 'attachment; filename="lightwork-approval-challenge.lwchallenge"'})
    return _call(read)


@page_router.get("/learning/approval-challenges")
def challenge_page(request: Request):
    _bound(request)
    from .app import templates
    return templates.TemplateResponse(request, "approval_challenges.html", {"request": request})


@page_router.get("/static/lightwork-approval-challenges.js")
def challenge_asset():
    from .app import _STATIC_DIR
    return FileResponse(_STATIC_DIR / "lightwork-approval-challenges.js", media_type="application/javascript",
                        headers={"Cache-Control": "public, max-age=300"})
