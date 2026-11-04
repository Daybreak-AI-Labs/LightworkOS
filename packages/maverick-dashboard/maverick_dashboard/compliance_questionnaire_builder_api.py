"""Same-origin questionnaire builder and original accepted-receipt reads."""
from fastapi import APIRouter, Request, Response
from pydantic import Field
from starlette.concurrency import run_in_threadpool

from . import compliance_questionnaire_builder as native
from .product_operations import StrictInput

router = APIRouter(prefix="/compliance/questionnaire-builder", tags=["compliance-scoping"])


class TokenInput(StrictInput):
    token: str = Field(min_length=1, max_length=4_000_000)


class ApplyInput(TokenInput):
    confirmed: bool


@router.get("/catalog")
async def catalog(request: Request):
    return await run_in_threadpool(native.catalog, request)


@router.get("/source")
async def source(request: Request, identity: str = ""):
    return await run_in_threadpool(native.source, request, identity)


@router.get("/studio-sources")
async def studio_sources(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return await run_in_threadpool(native.studio_sources, request)


@router.get("/studio-form")
async def studio_form(request: Request, response: Response, studio: str, form: str):
    response.headers["Cache-Control"] = "no-store"
    return await run_in_threadpool(native.studio_form, request, studio, form)


@router.post("/review")
async def review(request: Request, body: native.ReviewInput):
    return await run_in_threadpool(native.review, request, body)


@router.post("/apply")
async def apply(request: Request, body: ApplyInput):
    from fastapi import HTTPException
    if body.confirmed is not True:
        raise HTTPException(422, "Review the whole questionnaire before saving it for independent approval.")
    return await run_in_threadpool(native.apply, request, body.token)


@router.post("/receipt")
async def receipt(request: Request, body: TokenInput):
    return await run_in_threadpool(native.receipt, request, body.token)
