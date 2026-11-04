"""Native, account-bound controls for the bounded commitment review pilot."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from maverick import config
from maverick.governed_records import GovernedRecordCapacityError
from maverick.privacy_ops import RecordConflict
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from . import commitment_viability_store as reviews
from .auth import caller_principal, constant_time_equals, has_global_permission, require_permission
from .draft_api import context_for

router = APIRouter(tags=["commitment-reviews"])


class StrictIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True,
                              allow_inf_nan=False)


def _when(value: str) -> float:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Enter a complete date, time and time zone.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Enter a date and time with a time zone.")
    return parsed.timestamp()


class NewReviewIn(StrictIn):
    operation_id: str = Field(min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    title: str = Field(min_length=1, max_length=200)
    order_a_name: str = Field(min_length=1, max_length=160)
    order_a_due_at: str = Field(min_length=20, max_length=40)
    order_a_material_units: int = Field(ge=1, le=1_000_000)
    order_a_uses_capacity: bool
    order_b_name: str = Field(min_length=1, max_length=160)
    order_b_due_at: str = Field(min_length=20, max_length=40)
    order_b_material_units: int = Field(ge=1, le=1_000_000)
    order_b_uses_capacity: bool
    capacity_name: str = Field(min_length=1, max_length=160)
    capacity_units: int = Field(ge=1, le=1_000_000)
    material_name: str = Field(min_length=1, max_length=160)
    stock_units: int = Field(ge=0, le=1_000_000)
    stock_certainty: Literal["confirmed", "unknown", "unavailable"]
    option_name: str = Field(min_length=1, max_length=160)
    option_kind: Literal["capacity", "material"]
    option_units: int = Field(ge=1, le=1_000_000)
    option_ready_at: str = Field(min_length=20, max_length=40)
    option_expires_at: str = Field(min_length=20, max_length=40)
    option_lead_seconds: int = Field(ge=0, le=1_000_000_000)
    option_cost_note: str = Field(default="", max_length=240)
    basis: str = Field(min_length=10, max_length=2000)
    review_by: str = Field(min_length=20, max_length=40)

    @model_validator(mode="after")
    def dates(self):
        for key in ("order_a_due_at", "order_b_due_at", "option_ready_at",
                    "option_expires_at", "review_by"):
            _when(getattr(self, key))
        return self

    def service_body(self) -> dict:
        body = self.model_dump()
        for key in ("order_a_due_at", "order_b_due_at", "option_ready_at",
                    "option_expires_at", "review_by"):
            body[key] = _when(body[key])
        return body


class TraceIn(StrictIn):
    expected_revision: int = Field(ge=1)
    operation_id: str = Field(min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    running_order: Literal["order-a", "order-b"]
    blocked_order: Literal["order-a", "order-b"]
    started_at: str = Field(min_length=20, max_length=40)
    ended_at: str = Field(min_length=20, max_length=40)
    observed_at: str = Field(min_length=20, max_length=40)
    review_by: str = Field(min_length=20, max_length=40)
    basis: str = Field(min_length=10, max_length=2000)

    @model_validator(mode="after")
    def dates(self):
        for key in ("started_at", "ended_at", "observed_at", "review_by"):
            _when(getattr(self, key))
        return self

    def service_body(self) -> dict:
        body = self.model_dump()
        for key in ("started_at", "ended_at", "observed_at", "review_by"):
            body[key] = _when(body[key])
        return body


class ConfirmIn(StrictIn):
    expected_revision: int = Field(ge=1)
    operation_id: str = Field(min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    kind: Literal["dependency", "option"]
    proposal_id: str = Field(default="", max_length=120)
    option_id: Literal["conditional-option"] = "conditional-option"

    @model_validator(mode="after")
    def decision(self):
        if self.kind == "dependency" and not self.proposal_id:
            raise ValueError("Choose a current shared-work suggestion.")
        if self.kind == "option" and self.proposal_id:
            raise ValueError("Review one choice at a time.")
        return self


class RetireIn(StrictIn):
    expected_revision: int = Field(ge=1)
    operation_id: str = Field(min_length=16, max_length=100, pattern=r"^[A-Za-z0-9_-]+$")
    confirm_finished: Literal[True]


def _same_origin(request: Request) -> None:
    from .app import _require_same_origin
    _require_same_origin(request)


def _context(request: Request, *, mutation: bool = False) -> str:
    require_permission(request, "operate")
    if (config.config_source_errors(include_tenant=True)
            or config.get_features().get("commitment_viability") is not True):
        raise HTTPException(403, "Promise reviews are off. An administrator can enable them in Settings.")
    context = context_for(request)
    supplied = request.headers.get("X-Lightwork-Commitment-Context")
    if (mutation or supplied is not None) and not constant_time_equals(supplied or "", context):
        raise HTTPException(409, "The account or workspace changed. Reload this review before continuing.")
    return context


def _actor(request: Request) -> str:
    return caller_principal(request) or "local:dashboard"


async def _call(function, *args, **kwargs):
    try:
        return await run_in_threadpool(function, *args, **kwargs)
    except HTTPException:
        raise
    except reviews.CommitmentAuditPending as exc:
        raise HTTPException(503, str(exc)) from exc
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except GovernedRecordCapacityError as exc:
        raise HTTPException(409, "Your organization has reached the 1,000-active-review pilot limit across its workspaces. Finish and archive a completed review to make room for another.") from exc
    except LookupError as exc:
        raise HTTPException(404, "This review is unavailable in your account and workspace.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "The saved result is uncertain. Refresh this review before trying again.") from exc


def _saved_response(record: dict, context: str):
    if record.get("_audit_pending"):
        return JSONResponse(
            {"status": "audit_pending", "id": record["id"], "revision": record["revision"],
             "context": context,
             "detail": "The change was saved, but its activity receipt is still pending. Refresh saved reviews before deciding what to do next."},
            status_code=503, headers={"Cache-Control": "private, no-store"},
        )
    return {"id": record["id"], "revision": record["revision"], "context": context}


@router.get("/commitment-reviews")
async def page(request: Request):
    from .app import templates

    require_permission(request, "operate")
    enabled = (not config.config_source_errors(include_tenant=True)
               and config.get_features().get("commitment_viability") is True)
    return templates.TemplateResponse(request, "commitment_viability.html",
        {"review_context": context_for(request) if enabled else "",
         "review_enabled": enabled,
         "capability_enabled": enabled and config.get_features().get("commitment_capability_learning") is True,
         "economic_alternatives_enabled": enabled and config.get_features().get("commitment_economic_alternatives") is True,
         "review_admin": has_global_permission(request, "admin")},
        headers={"Cache-Control": "private, no-store"})


@router.get("/api/v1/commitment-reviews")
async def list_reviews(request: Request, response: Response,
                       cursor: str = Query("", max_length=256),
                       limit: int = Query(50, ge=1, le=100),
                       archived: bool = Query(False)):
    context = _context(request)
    response.headers["Cache-Control"] = "private, no-store"
    return {**await _call(reviews.listing, context, cursor=cursor, limit=limit, archived=archived),
            "context": context}


@router.post("/api/v1/commitment-reviews")
async def create_review(request: Request, response: Response, body: NewReviewIn):
    _same_origin(request)
    context = _context(request, mutation=True)
    record = await _call(reviews.create, context, _actor(request), body.service_body())
    response.headers["Cache-Control"] = "private, no-store"
    return _saved_response(record, context)


@router.get("/api/v1/commitment-reviews/{review_id}")
async def read_review(request: Request, response: Response, review_id: str):
    context = _context(request)
    record, archive = await _call(reviews.read, review_id, context)
    projection = await _call(reviews.project, record, archive=archive)
    response.headers["Cache-Control"] = "private, no-store"
    return {**projection, "context": context,
            "owner_can_confirm": archive is None and not record.get("retirement")
                                 and record["owner"] == _actor(request),
            "owner_can_archive": archive is None and record["owner"] == _actor(request)}


@router.post("/api/v1/commitment-reviews/{review_id}/observations")
async def add_observation(request: Request, response: Response, review_id: str, body: TraceIn):
    _same_origin(request)
    context = _context(request, mutation=True)
    record = await _call(reviews.record_trace, review_id, context, _actor(request), body.service_body())
    response.headers["Cache-Control"] = "private, no-store"
    return _saved_response(record, context)


@router.post("/api/v1/commitment-reviews/{review_id}/confirm")
async def confirm_review(request: Request, response: Response, review_id: str, body: ConfirmIn):
    _same_origin(request)
    context = _context(request, mutation=True)
    record = await _call(reviews.confirm, review_id, context, _actor(request), body.model_dump())
    response.headers["Cache-Control"] = "private, no-store"
    return _saved_response(record, context)


@router.post("/api/v1/commitment-reviews/{review_id}/archive")
async def archive_review(request: Request, response: Response, review_id: str, body: RetireIn):
    _same_origin(request)
    context = _context(request, mutation=True)
    archive = await _call(reviews.retire, review_id, context, _actor(request), body.model_dump())
    response.headers["Cache-Control"] = "private, no-store"
    return {"id": review_id, "revision": archive["source"]["revision"],
            "context": context, "archived": True}


__all__ = ["router", "NewReviewIn", "TraceIn", "ConfirmIn", "RetireIn", "_context"]
