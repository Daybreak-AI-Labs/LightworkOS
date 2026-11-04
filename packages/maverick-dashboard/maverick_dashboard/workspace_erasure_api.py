"""Ordinary full-review controls for native removed-workspace erasure."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import workspace_erasure as service

router = APIRouter(prefix="/api/v1/workspace-erasure", tags=["workspace-erasure"])


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    workspace: str = Field(min_length=1, max_length=200)
    acknowledge_previous: bool = False


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=45000)


class ApplyIn(TokenIn):
    confirmed: bool


class OriginalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    workspace: str = Field(min_length=1, max_length=200)
    operation: str = Field(pattern=r"^[a-f0-9]{48}$")


def _same_origin(request):
    from .app import _require_same_origin
    _require_same_origin(request)


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def status(request: Request):
    return response(service.inventory(request))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    _same_origin(request)
    return response(service.prepare(request, body.workspace, body.acknowledge_previous))


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    _same_origin(request)
    return response(service.apply(request, body.token, body.confirmed))


@router.post("/original")
def original(request: Request, body: TokenIn):
    _same_origin(request)
    return response(service.original(request, body.token))


@router.get("/workspaces/{workspace}/history")
def history(request: Request, workspace: str):
    return response(service.history(request, workspace))


@router.post("/original-by-id")
def original_by_id(request: Request, body: OriginalIn):
    _same_origin(request)
    return response(service.original_by_id(request, body.workspace, body.operation))
