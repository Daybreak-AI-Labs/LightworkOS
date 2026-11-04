"""Protected full setting review and pure original-request reads."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from . import settings_all_page as page
from . import settings_catalog_requests as native

router = APIRouter(prefix="/settings/catalog-requests", tags=["settings"])
HEADERS = {"Cache-Control": "private, no-store"}


class ReviewIn(page.CatalogUpdate):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=1048576)
    confirmed: Literal[True]


@router.get("")
def catalog(request: Request, context: str, offset: int = Query(0, ge=0, le=10000)):
    return JSONResponse(native.catalog(request, context, offset=offset), headers=HEADERS)


@router.get("/{operation}")
def original(request: Request, operation: str, context: str):
    return JSONResponse(native.original(request, operation, context), headers=HEADERS)


@router.post("/review")
def review(request: Request, body: ReviewIn):
    value = native.prepare(request, page.CatalogUpdate.model_validate(body.model_dump(exclude={"context"})), body.context)
    return value if isinstance(value, Response) else JSONResponse(value, headers=HEADERS)


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    value, status = native.apply(request, body.token)
    return JSONResponse(value, status_code=status, headers=HEADERS)
