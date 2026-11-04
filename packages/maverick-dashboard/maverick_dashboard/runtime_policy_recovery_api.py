"""Complete native deployment safety-settings recovery controls."""
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from maverick.runtime_policy_recovery import PolicyRecoveryUnavailable
from pydantic import BaseModel, ConfigDict, Field

from . import runtime_policy_recovery_ops as native

router = APIRouter(prefix="/runtime-policy-recovery", tags=["runtime-policy-recovery"])


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    snapshot: str = Field(pattern=r"^RPC-[a-f0-9]{32}$")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=24000)
    confirmed: Literal[True]


def _call(function, *args):
    from fastapi import HTTPException
    try:
        return JSONResponse(function(*args), headers={"Cache-Control": "private, no-store"})
    except PolicyRecoveryUnavailable as exc:
        raise HTTPException(409, str(exc)) from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "This step could not confirm its outcome. Keep your choices and read the original restoration before a separate new decision; nothing was retried.") from exc


@router.get("/catalog")
def catalog(request: Request, offset: int = 0):
    if not 0 <= offset <= 10000:
        from fastapi import HTTPException
        raise HTTPException(422, "Choose a supported original-request page.")
    return _call(native.catalog, request, offset, request.headers.get("X-Lightwork-Policy-Context"))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    return _call(native.review, request, body.snapshot, body.context)


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    return _call(native.apply, request, body.token)


@router.get("/original/{operation}")
def original(request: Request, operation: str):
    return _call(native.original, request, operation, request.headers.get("X-Lightwork-Policy-Context"))
