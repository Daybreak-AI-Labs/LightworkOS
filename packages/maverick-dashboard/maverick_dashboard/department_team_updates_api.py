"""Ordinary team reviews use the same native save and receipt as Copilot."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from . import department_team_updates as native

router = APIRouter(prefix="/api/v1/department-team-updates", tags=["department-team-updates"])


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    department: str = Field(min_length=1, max_length=80)
    expected_context: str = Field(pattern=r"^[a-f0-9]{64}$")


class TokenInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=8000)
    confirmed: bool = False


def public_receipt(value, *, replayed=False):
    message = ("Team set up." if value["created"] else "Existing team choices saved; future newly offered specialists can be added." if value["baseline_created"]
               else "Added " + str(value["added_count"]) + " new specialist" + ("s" if value["added_count"] != 1 else "") + "; existing changes kept." if value["added_count"]
               else "Team unchanged; existing changes kept.")
    if not value["current_team_matches"]:
        message += " The saved roster has changed since this original save."
    return {"status": "replayed" if replayed else "confirmed", "message": message,
            "details": {"Team size at this save": value["deployed_count"], "New specialists at this save": value["added_count"],
                        "Recorded at": datetime.fromtimestamp(value["recorded_at"], timezone.utc).strftime("%b %d, %Y at %H:%M UTC"),
                        "Current saved roster": "Matches this save" if value["current_team_matches"] else "Changed after this save",
                        "Next step": {"label": "Open the saved team", "href": value["team_href"]},
                        "Recovery history": "The latest 32 saves are retained with this team; an older missing receipt cannot confirm a save.",
                        "Meaning": "Original team save recorded. No tasks, provider calls or outside business actions were started."}}


def _response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def _origin(request):
    from .app import _require_same_origin
    _require_same_origin(request)


@router.get("/context")
def current_context(request: Request):
    from . import auth
    auth.require_permission(request, "operate")
    return _response({"context": native.context(request)})


@router.post("/review")
def review(request: Request, body: ReviewInput):
    _origin(request)
    if native.context(request) != body.expected_context:
        raise HTTPException(409, "Your account, workspace or access changed. Reload before reviewing this team.")
    return _response(native.token_review(request, body.department))


@router.post("/save")
def save(request: Request, body: TokenInput):
    _origin(request)
    if body.confirmed is not True:
        raise HTTPException(422, "Review the before and after, then confirm this team save.")
    material = native.open_token(body.token)
    accepted, replayed = native.apply(request, material, material["operation_id"])
    return _response(public_receipt(accepted, replayed=replayed))


@router.post("/original")
def original(request: Request, body: TokenInput):
    _origin(request)
    material = native.open_token(body.token, recovery=True)
    accepted = native.receipt(request, material, material["operation_id"])
    return _response(public_receipt(accepted, replayed=True) if accepted is not None else
                     {"status": "unconfirmed", "message": "The original save is not confirmed. No save was repeated. This team retains its latest 32 save receipts; older receipts may no longer be available. Open the current team before preparing another change."})
