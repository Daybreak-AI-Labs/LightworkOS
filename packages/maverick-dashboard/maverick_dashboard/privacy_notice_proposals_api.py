"""Ordinary protected notice proposals; tenant and actor stay native."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from maverick import privacy_notice_governance as notice
from pydantic import Field

from . import privacy_notice_proposals as service
from .product_operations import StrictInput

router = APIRouter(prefix="/privacy/notice-proposals", route_class=service.native._GenericValidationRoute)


class Review(service.Choices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class Token(StrictInput):
    token: str = Field(min_length=1, max_length=250_000)


class Apply(Token):
    confirmed: bool


class VersionReceipt(service.native.ReleaseCreateIn):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    notice_id: service.native.OpaqueId


def response(function):
    try:
        return JSONResponse(function(), headers={"Cache-Control": "no-store"})
    except HTTPException:
        raise
    except notice.PrivacyNoticeNotFound as exc:
        raise HTTPException(404, "The selected saved record is unavailable.") from exc
    except notice.PrivacyNoticePermissionDenied as exc:
        raise HTTPException(403, "This action is not permitted for your current account.") from exc
    except notice.PrivacyNoticeConflict as exc:
        raise HTTPException(409, "The original request or selected records changed. Nothing was repeated; keep your draft and review current records.") from exc
    except notice.PrivacyNoticeValidationError as exc:
        raise HTTPException(422, "Check the selected records and dates; proposal retention must be between one minute and ten years.") from exc
    except Exception as exc:
        raise HTTPException(503, "The result could not be confirmed. Check the original request or saved records before saving again.") from exc


def same_origin(request):
    from .app import _require_same_origin
    _require_same_origin(request)


@router.get("")
def catalog(request: Request):
    return response(lambda: service.catalog(request))


@router.get("/version-context")
def version_context(request: Request):
    service.authority(request)
    return JSONResponse({"context": service.context_for(request)}, headers={"Cache-Control": "no-store"})


@router.get("/proposal")
def proposal(request: Request, identity: str = Query(min_length=1, max_length=128, pattern=service.native._ID_PATTERN)):
    return response(lambda: service.proposal_view(request, identity))


@router.post("/review")
def review(request: Request, body: Review):
    same_origin(request)
    if body.context != service.context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Your draft is kept; return to the original workspace.")
    return response(lambda: service.review(request, service.Choices.model_validate(body.model_dump(exclude={"context", "revision"})), body.revision))


@router.post("/apply")
def apply(request: Request, body: Apply):
    same_origin(request)
    return response(lambda: service.apply(request, body.token, confirmed=body.confirmed))


@router.post("/readback")
def readback(request: Request, body: Token):
    same_origin(request)
    return response(lambda: service.receipt(request, body.token))


@router.post("/version-readback")
def version_readback(request: Request, body: VersionReceipt):
    same_origin(request)
    if body.context != service.context_for(request):
        raise HTTPException(409, "Return to the original account and workspace to check the original version save.")
    return response(lambda: service.version_receipt(request, body.notice_id, body))
