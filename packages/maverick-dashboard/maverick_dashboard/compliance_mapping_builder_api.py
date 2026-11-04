"""Protected ordinary mapping authoring; native action catalogs stay authoritative."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import Field

from . import compliance_mapping_builder as service
from .product_operations import StrictInput

router = APIRouter(prefix="/api/v1/compliance/mapping-builder", tags=["compliance-mapping-builder"])
page_router = APIRouter()


class Review(service.GuidedChoices):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class Token(StrictInput):
    token: str = Field(min_length=1, max_length=3_000_000)


class Apply(Token):
    confirmed: bool


class Approval(StrictInput):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    mapping: str = Field(min_length=3, max_length=140)


def mutation(request):
    from .app import _require_same_origin
    _require_same_origin(request)
    service.authority(request, write=True)


def response(function):
    try:
        result = function()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "The result could not be checked. Read the original request or saved mapping before retrying.") from exc
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.get("")
def state(request: Request):
    return response(lambda: service.state(request))


@router.get("/controls")
def controls(request: Request, scope: str = Query(min_length=1, max_length=128, pattern=service.native._ID_PATTERN),
             offset: int = Query(default=0, ge=0, le=2000)):
    return response(lambda: service.controls(request, scope, offset=offset))


@router.get("/editor")
def editor(request: Request, scope: str = Query(min_length=1, max_length=128, pattern=service.native._ID_PATTERN),
           mapping: str = Query(default="", max_length=140), offset: int = Query(default=0, ge=0, le=2000)):
    return response(lambda: service.editor(request, scope, mapping, offset=offset))


class ReviewPage(Token):
    offset: int = Field(default=0, ge=0, le=2000)


@router.post("/read-review")
def read_review(request: Request, body: ReviewPage):
    from .app import _require_same_origin
    _require_same_origin(request)
    return response(lambda: service.read_review(request, body.token, offset=body.offset))


@router.get("/mapping")
def mapping(request: Request, mapping: str = Query(min_length=3, max_length=140), offset: int = Query(default=0, ge=0, le=2000)):
    return response(lambda: service.inspect_mapping(request, mapping, offset=offset))


@router.post("/review")
def review(request: Request, body: Review):
    mutation(request)
    if body.context != service.context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Refresh before reviewing.")
    return response(lambda: service.review(request, service.GuidedChoices.model_validate(body.model_dump(exclude={"context", "revision"})), body.revision))


@router.post("/review-approval")
def approval(request: Request, body: Approval):
    mutation(request)
    if body.context != service.context_for(request):
        raise HTTPException(409, "Your account or workspace changed. Refresh before reviewing.")
    return response(lambda: service.review_approval(request, body.mapping))


@router.post("/apply")
def apply(request: Request, body: Apply):
    mutation(request)
    return response(lambda: service.apply(request, body.token, confirmed=body.confirmed))


@router.post("/readback")
def readback(request: Request, body: Token):
    from .app import _require_same_origin
    _require_same_origin(request)
    return response(lambda: service.readback(request, body.token))


@page_router.get(service.PAGE)
def page(request: Request):
    service.authority(request)
    from .app import templates
    result = templates.TemplateResponse(request, "compliance_mapping_builder.html", {"request": request})
    result.headers["Cache-Control"] = "no-store"
    return result


@page_router.get("/static/lightwork-compliance-mapping-builder.js", include_in_schema=False)
def script():
    return FileResponse(Path(__file__).parent / "static" / "lightwork-compliance-mapping-builder.js",
                        media_type="application/javascript", headers={"Cache-Control": "public, max-age=300"})
