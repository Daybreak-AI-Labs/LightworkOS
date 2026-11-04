"""Ordinary owner-only company sign-in controls and restricted recovery."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import company_signin_migration as native
from . import local_owner_second_factor as second
from .local_owner_mfa_routes import cancel_flow, passphrase_step

router = APIRouter(tags=["settings"])
PRIVATE = {"Cache-Control": "private, no-store"}


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check: str = Field(min_length=1, max_length=64)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    password: str = Field(min_length=14, max_length=1024, repr=False)
    # The owner's authenticator code or an unused recovery code; empty when the owner has none.
    code: str = Field(default="", max_length=32, repr=False)


class PresetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["microsoft", "google", "okta"]
    directory: str = Field(default="", max_length=300)
    application: str = Field(min_length=1, max_length=128)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=32768, repr=False)
    confirmed: bool


class CredentialsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=14, max_length=1024, repr=False)
    code: str = Field(default="", max_length=32, repr=False)


class RecoveryReviewIn(CredentialsIn):
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")


class RecoveryApplyIn(CredentialsIn):
    token: str = Field(min_length=1, max_length=32768, repr=False)
    confirmed: bool


def _confirm(confirmed):
    from fastapi import HTTPException
    if confirmed is not True:
        raise HTTPException(422, "Read and confirm the complete sign-in change first.")


@router.get("/api/v1/settings/sign-in-migration")
def catalog(request: Request):
    return JSONResponse(native.catalog(request), headers=PRIVATE)


@router.get("/api/v1/settings/sign-in-migration/context")
def context(request: Request):
    current, _owner = native.authority(request)
    return JSONResponse({"context": current}, headers=PRIVATE)


@router.post("/api/v1/settings/sign-in-migration/review")
def review(request: Request, body: ReviewIn):
    return passphrase_step(request, lambda: native.review(
        request, body.check, body.context, body.password, body.code), headers=PRIVATE)


@router.post("/api/v1/settings/sign-in-migration/cancel")
def cancel(request: Request):
    return cancel_flow(request, native.ACTIVATION_FLOW)


@router.post("/api/v1/settings/sign-in-migration/preset")
def preset(request: Request, body: PresetIn):
    return JSONResponse(native.preset(request, body.provider, body.directory, body.application, body.context), headers=PRIVATE)


@router.post("/api/v1/settings/sign-in-migration/activate")
def activate(request: Request, body: ApplyIn):
    _confirm(body.confirmed)
    result = native.activate(request, body.token)
    response = JSONResponse(result, headers=PRIVATE)
    second.close_flow(response, flow=native.ACTIVATION_FLOW)
    if result["confirmed"]:
        response.delete_cookie("mvk_session", path="/")
    return response


@router.get("/api/v1/settings/sign-in-migration/original/{operation}")
def original(request: Request, operation: str, context: str):
    return JSONResponse(native.original(request, operation, context), headers=PRIVATE)


@router.post("/auth/company-signin-recovery/lookup")
def recovery_catalog(request: Request, body: CredentialsIn):
    return passphrase_step(request, lambda: native.recovery_catalog(
        request, body.email, body.password, body.code), headers=PRIVATE)


@router.post("/auth/company-signin-recovery/original")
def recovery_original(request: Request, body: RecoveryReviewIn):
    return passphrase_step(request, lambda: native.recovery_original(
        request, body.operation, body.email, body.password, body.code), headers=PRIVATE)


@router.post("/auth/company-signin-recovery/review")
def recovery_review(request: Request, body: RecoveryReviewIn):
    return passphrase_step(request, lambda: native.recovery_review(
        request, body.operation, body.email, body.password, body.code), headers=PRIVATE)


@router.post("/auth/company-signin-recovery/apply")
def recover(request: Request, body: RecoveryApplyIn):
    _confirm(body.confirmed)
    return passphrase_step(request, lambda: native.recover(
        request, body.token, body.email, body.password, body.code), headers=PRIVATE,
        completes=native.RECOVERY_FLOW)


@router.post("/auth/company-signin-recovery/cancel")
def recovery_cancel(request: Request):
    return cancel_flow(request, native.RECOVERY_FLOW)
