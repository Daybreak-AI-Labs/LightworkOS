"""Protected reviewed withdrawal and read-only original results."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import consent_publication_withdrawal as native

router = APIRouter(prefix="/consent/withdrawal-requests", tags=["consent-publishing"])
HEADERS = {"Cache-Control": "private, no-store"}


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    website: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=1048576)
    operation: str = Field(pattern=r"^[a-f0-9]{32}$")
    confirmed: Literal[True]


@router.get("")
def catalog(request: Request):
    return JSONResponse(native.catalog(request), headers=HEADERS)


@router.get("/{operation}")
def original(request: Request, operation: str, context: str):
    native.authority(request, context)
    return JSONResponse(native.original(request, operation), headers=HEADERS)


@router.post("/review")
def review(request: Request, body: ReviewIn):
    return JSONResponse(native.review(request, body.website, body.context), headers=HEADERS)


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    return JSONResponse(native.apply(request, native.opened(body.token), body.operation), headers=HEADERS)
