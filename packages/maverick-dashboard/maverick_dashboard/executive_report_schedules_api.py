"""Protected complete review, native admission and pure recurring-report originals."""
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from . import executive_report_schedules as native
from .schedule_ops_api import TimetableIn

router = APIRouter(prefix="/api/v1/third-party/executive-reports/schedules", tags=["executive-report-schedules"])


class Timetable(TimetableIn):
    repeat: Literal["daily", "weekly", "monthly"] = "daily"
    advanced: None = None


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    report: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    timetable: Timetable


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reference: str = Field(min_length=1, max_length=native.MAX_BYTES*3)


class Confirm(Reference):
    choices: Choices
    confirmed: bool = Field(strict=True)


class Stop(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: int = Field(strict=True, ge=1)
    confirmed: bool = Field(strict=True)


def call(request, response, function, *args):
    from .app import _require_same_origin
    if request.method != "GET":
        _require_same_origin(request)
    response.headers.update({"Cache-Control": "no-store, private", "Pragma": "no-cache"})
    try:
        return function(request, *args)
    except HTTPException:
        raise
    except native.reports.ThirdPartyExecutiveReportPermissionDenied as exc:
        raise HTTPException(403, "Your current access does not allow this report or its selected records.") from exc
    except native.reports.ThirdPartyExecutiveReportNotFound as exc:
        raise HTTPException(404, "The selected report is no longer available.") from exc
    except native.reports.ThirdPartyExecutiveReportConflict as exc:
        raise HTTPException(409, "The selected report changed. Review the current choices again.") from exc
    except (native.reports.ThirdPartyExecutiveReportError, OSError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(503, "This report request could not be confirmed. Your draft is kept; check Original before creating again.") from exc


@router.get("/options")
def options(request: Request, response: Response):
    return call(request, response, native.options)


@router.get("/list")
def listing(request: Request, response: Response):
    return call(request, response, native.listing)


@router.post("/review")
def review(body: Choices, request: Request, response: Response):
    return call(request, response, native.review, body.model_dump(mode="json"))


@router.post("/create")
def create(body: Confirm, request: Request, response: Response):
    if not body.confirmed:
        raise HTTPException(422, "Review the complete schedule and confirm its creation.")
    return call(request, response, native.create, body.reference, body.choices.model_dump(mode="json"))


@router.post("/original")
def original(body: Reference, request: Request, response: Response):
    return call(request, response, native.original, body.reference)


@router.post("/{definition}/stop")
def stop(definition: str, body: Stop, request: Request, response: Response):
    if not body.confirmed:
        raise HTTPException(422, "Confirm that future PDF creation should stop. Existing PDFs remain separate.")
    native.authority(request, body.context)
    return call(request, response, native.stop, definition, body.revision)


@router.get("/occurrences/{identity}/original")
def occurrence_original(identity: int, request: Request, response: Response):
    return call(request, response, native.occurrence_original, identity)
