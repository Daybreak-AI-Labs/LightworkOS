"""The optional ease-of-use survey ([analytics] usability_survey) in the dashboard.

Signed-in people answer or skip it through ``/api/v1/usability-survey``; global
administrators read the per-role and per-task results at
``/users/usability-survey`` (under People, so it follows the People page's
access). Answers are stored by :mod:`maverick.usability_survey` and never leave
the installation.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from . import auth

router = APIRouter()


def _app():
    from . import app
    return app


def _person(request: Request) -> str:
    auth.require_permission(request, "view")
    principal = auth.caller_principal(request)
    if not principal:
        raise HTTPException(403, "Sign in to answer the survey.")
    return principal


def _answer(request: Request, action) -> dict[str, Any]:
    from maverick import usability_survey as survey

    _app()._require_same_origin(request)
    principal = _person(request)
    if not survey.enabled():
        raise HTTPException(403, "The ease-of-use survey is turned off.")
    try:
        return action(principal) or {}
    except survey.SurveyError as exc:
        raise HTTPException(409, str(exc).capitalize() + ".") from exc


class SusAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answers: list[int] = Field(min_length=10, max_length=10)
    role: str = Field(default="", max_length=40)


class SeqAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    task: str = Field(max_length=40)
    rating: int
    role: str = Field(default="", max_length=40)


class Dismissal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    topic: str = Field(default="sus", max_length=48)


@router.get("/api/v1/usability-survey")
def survey_state(request: Request, task: str = "") -> dict[str, Any]:
    """What to offer this person now: the quarterly survey, or one task's question."""
    from maverick import usability_survey as survey

    principal = _person(request)
    on = survey.enabled()
    return {
        "enabled": on,
        "offer_sus": on and survey.offer_sus(principal),
        "offer_seq": bool(task) and on and survey.offer_seq(principal, task),
        "sus_items": list(survey.SUS_ITEMS),
        "seq_question": survey.SEQ_QUESTION,
        "roles": [{"value": key, "label": label} for key, label in survey.ROLES],
        "tasks": [{"value": key, "label": label} for key, label in survey.TOP_TASKS],
    }


@router.post("/api/v1/usability-survey/sus")
def answer_sus(body: SusAnswer, request: Request) -> dict[str, Any]:
    from maverick import usability_survey as survey

    return _answer(request, lambda who: {"saved": True,
                                         "score": survey.record_sus(who, body.answers, role=body.role)})


@router.post("/api/v1/usability-survey/seq")
def answer_seq(body: SeqAnswer, request: Request) -> dict[str, Any]:
    from maverick import usability_survey as survey

    return _answer(request, lambda who: survey.record_seq(who, body.task, body.rating, role=body.role)
                   or {"saved": True})


@router.post("/api/v1/usability-survey/dismiss")
def dismiss_survey(body: Dismissal, request: Request) -> dict[str, Any]:
    from maverick import usability_survey as survey

    return _answer(request, lambda who: survey.dismiss(who, body.topic) or {"saved": True})


@router.get("/users/usability-survey", response_class=HTMLResponse)
def survey_results(request: Request, quarter: str = "") -> HTMLResponse:
    """Per-role SUS and per-task ease results; global administrators only."""
    from maverick import usability_survey as survey

    auth.require_global_permission(request, "admin")
    period = quarter if len(quarter) == 7 and quarter[4:6] == "-Q" and quarter[6] in "1234" \
        and quarter[:4].isdigit() else survey.quarter()
    from maverick import usage_measures

    return _app().templates.TemplateResponse(request, "usability_survey.html", {
        "enabled": survey.enabled(), "report": survey.results(period),
        "measures_on": usage_measures.enabled(), "first_session": usage_measures.first_session_report(),
        "suggestions": usage_measures.suggestion_report(),
        "first_session_hours": usage_measures.FIRST_SESSION_SECONDS // 3600,
    })


def survey_context(request: Request) -> dict[str, Any]:
    """Load the survey script only for signed-in people when the survey is on."""
    try:
        from maverick import usability_survey as survey

        on = survey.enabled() and bool(auth.caller_principal(request))
    except Exception:  # noqa: BLE001 -- the shell never fails over an optional survey
        on = False
    return {"usability_survey_on": on}


__all__ = ["router", "survey_context"]
