"""Protected native review, one-message admission and pure original read."""
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import channel_test_requests as native

router = APIRouter(prefix="/api/v1/channels/message-test", tags=["channels"])
PRIVATE = {"Cache-Control": "private, no-store"}


class CurrentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ListIn(CurrentIn):
    channel: str = Field(min_length=2, max_length=30)
    cursor: str = Field(default="", max_length=8192)


class HistoryIn(CurrentIn):
    cursor: str = Field(default="", max_length=8192)


class ReviewIn(CurrentIn):
    choice: str = Field(min_length=1, max_length=8192)


class OriginalIn(CurrentIn):
    operation: str = Field(pattern=r"^CHT-[a-f0-9]{32}$")


class ApplyIn(OriginalIn):
    confirmed: bool


@router.get("/context")
def context(request: Request):
    current, _actor = native.authority(request)
    return JSONResponse({"context": current}, headers=PRIVATE)


@router.post("/conversations")
def conversations(request: Request, body: ListIn):
    return JSONResponse(native.catalog(request, body.channel, body.context, body.cursor), headers=PRIVATE)


@router.post("/review")
def review(request: Request, body: ReviewIn):
    return JSONResponse(native.review(request, body.choice, body.context), headers=PRIVATE)


@router.post("/send")
def send(request: Request, body: ApplyIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Review the exact destination and fixed message before sending.")
    return JSONResponse(native.apply(request, body.operation, body.context), headers=PRIVATE)


@router.post("/original")
def original(request: Request, body: OriginalIn):
    return JSONResponse(native.original(request, body.operation, body.context), headers=PRIVATE)


@router.post("/history")
def history(request: Request, body: HistoryIn):
    return JSONResponse(native.history(request, body.context, body.cursor), headers=PRIVATE)
