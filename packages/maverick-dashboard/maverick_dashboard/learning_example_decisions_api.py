"""Native complete learning-example review, write and original-result reads."""
from __future__ import annotations

import json
import secrets
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import learning_example_decisions as native

router = APIRouter(prefix="/learning-example-decisions", tags=["learning-example-decisions"])
PURPOSE = "lightwork.complete-learning-example-decision.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: Literal["accept", "reject", "grant"]
    reason: str = Field(min_length=1, max_length=2000)
    use_until: float | None = Field(default=None, allow_inf_nan=False)
    retain_copies: bool = False


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=24000)
    confirmed: Literal[True]


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("/{flow}/{run}")
def current(request: Request, flow: str, run: str):
    scope, row = native.current(request, flow[:256], run[:256], context=request.headers.get("X-Lightwork-Example-Context"))
    changes = native.evidence_changes(row) if row["status"] in {"awaiting_review", "accepted"} else []
    native.authority(request, flow, scope)
    return response({"context": scope, "record": {key: value for key, value in row.items() if key != "evidence"},
                     "changes": changes, "notice": native.NOTICE})


@router.get("/{flow}/{run}/history")
def history(request: Request, flow: str, run: str):
    scope, service, ctx = native.authority(request, flow[:256], request.headers.get("X-Lightwork-Example-Context"), receipt=True)
    value = native._call(lambda: service.original_decision(ctx, flow, run, operation="", context=scope))
    native.authority(request, flow, scope, receipt=True)
    from datetime import datetime, timezone
    return response({"context": scope, "choices": [{"value": item["operation"],
        "label": ("Learning permission" if item["action"] == "flow.episode.grant" else "Example acceptance" if item["accepted"] else "Example rejection") + " · " + datetime.fromtimestamp(item["recorded_at"], timezone.utc).strftime("%b %d at %H:%M UTC")} for item in value["decisions"]]})


@router.get("/{flow}/{run}/requests/{operation}")
def original(request: Request, flow: str, run: str, operation: str):
    return response(native.original(request, flow[:256], run[:256], operation, context=request.headers.get("X-Lightwork-Example-Context")))


@router.post("/{flow}/{run}/review")
def review(request: Request, flow: str, run: str, body: ReviewIn):
    prepared, changes = native.prepare(request, flow[:256], run[:256], body.kind, body.reason,
        use_until=body.use_until, retain_copies=body.retain_copies, context=body.context)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16)}
    token = crypto_at_rest.seal_to_str(json.dumps(material, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 24000:
        raise HTTPException(503, "This complete review could not be retained securely. No decision was saved.")
    return response({"context": prepared["context"], "operation": material["operation"], "token": token, "changes": changes})


@router.post("/{flow}/{run}/apply")
def apply(request: Request, flow: str, run: str, body: ApplyIn):
    native.authority(request, flow[:256], write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (set(material) != {"purpose", "prepared", "operation"} or material["purpose"] != PURPOSE
                or material["prepared"]["flow"] != flow or material["prepared"]["run"] != run):
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This complete review could not be verified. Review the current example or read the original result.") from exc
    return response(native.apply(request, material["prepared"], material["operation"]))
