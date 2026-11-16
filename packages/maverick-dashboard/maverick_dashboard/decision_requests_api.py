"""Decisions a run is waiting for: the Approvals page section and its API.

A run that called ``request_decision`` waits as ``blocked`` until a person
chooses one of its options (:mod:`maverick.decision_requests`). This module is
the dashboard's one answer path: the Approvals page, its JSON API and the
Copilot all call :func:`answer_for_request`, so they share one authorization
rule. Chat cards use the kernel path with the stricter chat rule.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response
from maverick import decision_requests as dr
from pydantic import BaseModel, ConfigDict, Field

from .auth import caller_principal, has_permission, require_permission

router = APIRouter(tags=["decisions"])


class AnswerIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    option: int = Field(ge=1, le=dr.MAX_OPTIONS)
    note: str = Field(default="", max_length=dr.MAX_NOTE)


def _world():
    from ._shared import _world as shared

    return shared()


def actor(request: Request) -> str:
    return caller_principal(request) or ""


def is_admin(request: Request) -> bool:
    return has_permission(request, "admin")


def _row(decision: dr.Decision, who: str, admin: bool) -> dict[str, Any]:
    reason, sentence = dr.refusal(decision, who, is_admin=admin)
    return {**decision.public(), "can_answer": not reason, "why_not": sentence}


def visible(request: Request, world=None) -> list[dr.Decision]:
    """Open decisions this person may read: their own runs', or every one in
    the workspace for an administrator. Expired ones are settled first."""
    require_permission(request, "operate")
    world = world if world is not None else _world()
    dr.expire_due(world)
    who, admin = actor(request), is_admin(request)
    return [d for d in dr.list_open(world) if admin or d.requested_by == who]


def selected(request: Request, decision_id: int, world=None) -> dr.Decision:
    """One open decision this person may read, or a plain 404."""
    found = next((d for d in visible(request, world) if d.id == int(decision_id)), None)
    if found is None:
        raise HTTPException(404, "This decision is no longer waiting, or it is not yours to read.")
    return found


def answer_for_request(request: Request, decision_id: int, option: int, note: str = "", *,
                       channel: str = "dashboard", world=None) -> dict[str, Any]:
    """Record a choice for the signed-in person. The Approvals page and the
    Copilot both come here. Returns the saved decision and whether the run
    was moved back to waiting-to-start (the caller starts it)."""
    from .app import _require_same_origin

    _require_same_origin(request)
    world = world if world is not None else _world()
    current = selected(request, decision_id, world)
    try:
        outcome = dr.answer(world, current.id, option, actor=actor(request),
                            is_admin=is_admin(request), note=note, channel=channel,
                            recorded_as=actor(request) or "local:dashboard")
    except dr.DecisionRefused as exc:
        raise HTTPException(exc.status_code, exc.message) from exc
    return outcome


def resume(background: BackgroundTasks, world, goal_id: int) -> bool:
    """Start the run again under its own identity, after the response."""
    from maverick.runner import run_goal_in_background_async

    kwargs = dr.resume_kwargs(world.get_goal(int(goal_id)))
    if kwargs is None:
        return False
    background.add_task(run_goal_in_background_async, int(goal_id), channel="api", **kwargs)
    return True


def outcome_message(outcome: dict[str, Any]) -> str:
    decision = outcome["decision"]
    label = (decision.option(decision.chosen) or {}).get("label", "")
    if outcome["resume"]:
        return f"You chose “{label}”. The run continues with your choice."
    return (f"You chose “{label}”. The run continues once nothing else is waiting. "
            "Open the task to check it.")


@router.get("/decisions")
def list_decisions(request: Request, response: Response) -> dict:
    """Open decisions this person can read, each saying whether they can answer."""
    response.headers["Cache-Control"] = "private, no-store"
    world = _world()
    rows = visible(request, world)
    who, admin = actor(request), is_admin(request)
    return {"decisions": [_row(d, who, admin) for d in rows]}


@router.post("/decisions/{decision_id}/answer")
def answer_decision(decision_id: int, body: AnswerIn, request: Request,
                    background: BackgroundTasks) -> dict:
    """Choose one option for a waiting run."""
    world = _world()
    outcome = answer_for_request(request, decision_id, body.option, body.note, world=world)
    started = outcome["resume"] and resume(background, world, outcome["decision"].goal_id)
    return {"decision": outcome["decision"].public(), "resumed": bool(started),
            "message": outcome_message(outcome)}
