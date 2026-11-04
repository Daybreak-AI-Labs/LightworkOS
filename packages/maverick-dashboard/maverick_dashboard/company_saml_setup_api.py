"""Protected ordinary uploads, native sign-in test and exact setup originals."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import company_saml_setup as native
from . import local_owner_second_factor as second
from .company_signin_migration_api import CredentialsIn, RecoveryApplyIn, RecoveryReviewIn
from .local_owner_mfa_routes import cancel_flow, passphrase_step

router = APIRouter(prefix="/api/v1/settings/single-sign-on", tags=["settings"])
recovery_router = APIRouter(prefix="/auth/company-saml-recovery", tags=["auth"])
PRIVATE = {"Cache-Control": "private, no-store"}


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirmed: bool = Field(strict=True)


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check: str = Field(min_length=1, max_length=64)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    password: str = Field(min_length=14, max_length=1024, repr=False)
    # The owner's authenticator code or an unused recovery code; empty when the owner has none.
    code: str = Field(default="", max_length=32, repr=False)


class ActivateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=32768, repr=False)
    confirmed: bool = Field(strict=True)


@router.get("")
def catalog(request: Request):
    return JSONResponse(native.catalog(request), headers=PRIVATE)


@router.post("/review")
async def upload_review(request: Request):
    from starlette.datastructures import UploadFile
    # Bound multipart before parsing; private file bytes never enter a model prompt.
    native.authority(request)
    if not await native.saml._cache_limited_body(request, limit=384 * 1024):
        raise HTTPException(413, "Choose single-sign-on files totalling no more than 256 KB.")
    form = await request.form(max_files=3, max_fields=6)
    if set(form) != {"context", "name", "entity", "metadata", "certificate", "key", "password"}:
        raise HTTPException(422, "Use the complete native single-sign-on file form.")
    fields = {name: str(form[name]) for name in ("context", "name", "entity", "password")}
    if len(fields["password"]) > 1024 or len(fields["name"]) > 120 or len(fields["entity"]) > 300:
        raise HTTPException(422, "The entered provider details exceed the supported bounds.")
    files = {}
    for name in ("metadata", "certificate", "key"):
        item = form[name]
        if not isinstance(item, UploadFile):
            raise HTTPException(422, "Choose the provider document and any optional certificate files.")
        files[name] = await item.read(native.company_saml_materials.MAX_BYTES + 1)
    result = native.upload_review(request, fields, files["metadata"], files["certificate"], files["key"],
                                  fields["password"].encode(), fields["context"])
    return JSONResponse(result, headers=PRIVATE)


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Read and confirm the complete inactive setup before saving.")
    return JSONResponse(native.apply(request, body.operation, body.context), headers=PRIVATE)


@router.get("/original/{operation}")
def original(request: Request, operation: str, context: str):
    return JSONResponse(native.original(request, operation, context), headers=PRIVATE)


@router.post("/try")
def start(request: Request):
    target, cookie, context = native.start(request)
    response = JSONResponse({"authorization_url": target, "context": context}, headers=PRIVATE)
    response.set_cookie(native.COOKIE, cookie, path="/saml", httponly=True, samesite="none", secure=True,
                        max_age=native.migration.TTL)
    return response


@router.post("/activation-review")
def activation_review(request: Request, body: ReviewIn):
    return passphrase_step(request, lambda: native.activation_review(
        request, body.check, body.context, body.password, body.code), headers=PRIVATE)


@router.post("/cancel")
def activation_cancel(request: Request):
    return cancel_flow(request, native.ACTIVATION_FLOW)


@router.post("/activate")
def activate(request: Request, body: ActivateIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Read and confirm the complete single-sign-on activation first.")
    result = native.activate(request, body.token)
    response = JSONResponse(result, headers=PRIVATE)
    second.close_flow(response, flow=native.ACTIVATION_FLOW)
    if result["confirmed"]:
        response.delete_cookie("mvk_session", path="/")
    return response


@router.get("/activation-original/{operation}")
def activation_original(request: Request, operation: str, context: str):
    return JSONResponse(native.migration_original(request, operation, context), headers=PRIVATE)


@recovery_router.post("/lookup")
def recovery_catalog(request: Request, body: CredentialsIn):
    return passphrase_step(request, lambda: native.recovery_catalog(
        request, body.email, body.password, body.code), headers=PRIVATE)


@recovery_router.post("/original")
def recovery_original(request: Request, body: RecoveryReviewIn):
    return passphrase_step(request, lambda: native.recovery_original(
        request, body.operation, body.email, body.password, body.code), headers=PRIVATE)


@recovery_router.post("/review")
def recovery_review(request: Request, body: RecoveryReviewIn):
    return passphrase_step(request, lambda: native.recovery_review(
        request, body.operation, body.email, body.password, body.code), headers=PRIVATE)


@recovery_router.post("/apply")
def recover(request: Request, body: RecoveryApplyIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Read and confirm this separate restoration review first.")
    return passphrase_step(request, lambda: native.recover(
        request, body.token, body.email, body.password, body.code), headers=PRIVATE,
        completes=native.RECOVERY_FLOW)


@recovery_router.post("/cancel")
def recovery_cancel(request: Request):
    return cancel_flow(request, native.RECOVERY_FLOW)
