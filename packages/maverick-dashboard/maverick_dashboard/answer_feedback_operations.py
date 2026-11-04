"""Ordinary saved-answer feedback with native authority and original readback."""
from __future__ import annotations

import math

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import result_feedback_receipts as store
from maverick.goal_mutations import GoalMutationConflict
from pydantic import BaseModel, ConfigDict, Field

from . import auth, task_signoff_operations
from .draft_api import context_for
from .product_errors import next_action, product_error

router = APIRouter(prefix="/api/v1/goals", tags=["answer-feedback"])


class FeedbackChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    rating: str = Field(pattern=r"^(up|down)$")
    note: str = Field(default="", max_length=500)
    reason: str = Field(default="", pattern=r"^(|wrong|incomplete|not_asked|unclear|too_long|other)$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_context: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def public(value, goal):
    return {"operation_id": value["operation_id"], "rating": value["rating"], "note": value["note"],
            "reason": value.get("reason", ""), "reason_label": store.REASONS.get(value.get("reason", ""), ""),
            "acknowledgement": _acknowledgement(value), "recorded_at": value["recorded_at"], "current_result": value["revision"] == store.version(goal),
            "observation": value["observation"], "replayed": value.get("replayed", False), "legacy": False,
            "signal_note": ("Your feedback is saved. The optional learning signal is unconfirmed and will not be submitted again."
                            if value["observation"] == "started" else "")}


def read(request, goal_id, operation_id=None):
    from . import api
    world, goal = task_signoff_operations.authorized(request, goal_id)
    value = store.receipt(world, goal_id, operation_id, api._supervisor(request)) if operation_id else store.latest(world, goal_id, goal.owner or "")
    _world, goal = task_signoff_operations.authorized(request, goal_id)
    if value is not None and value["owner"] != (goal.owner or ""):
        value = None
    feedback = public(value, goal) if value else None
    if feedback is None and operation_id is None:
        from . import goal_feedback_store
        legacy = goal_feedback_store.latest_for_goal(goal_id, owner=goal.owner or "")
        if (legacy and legacy.get("rating") in {"up", "down"} and isinstance(legacy.get("note", ""), str)
                and type(legacy.get("ts")) in (int, float) and math.isfinite(legacy["ts"]) and legacy["ts"] > 0):
            feedback = {"operation_id": None, "rating": legacy["rating"], "note": legacy.get("note", "")[:500],
                        "reason_label": store.REASONS.get(legacy.get("reason"), "") if isinstance(legacy.get("reason"), str) else "",
                        "recorded_at": legacy["ts"], "current_result": False, "observation": "not_known", "replayed": False,
                        "legacy": True, "message": "Earlier feedback: the answer version was not recorded"}
    _world, current = task_signoff_operations.authorized(request, goal_id)
    if (current.owner or "") != (goal.owner or ""):
        raise HTTPException(404, "This task is unavailable to your account.")
    if value is not None:
        feedback = public(value, current)
    return {"context": context_for(request), "revision": store.version(current), "updated_at": float(current.updated_at),
            "task": current.title, "eligible": current.status in {"done", "blocked", "failed"} and bool(current.result),
            "feedback": feedback,
            "original": operation_id is not None}


def write_authority(request, goal_id):
    from maverick.task_handoffs import closure

    world, goal = task_signoff_operations.authorized(request, goal_id, write=True)
    if (auth.caller_principal(request) or "") != (goal.owner or ""):
        raise HTTPException(403, "Only the current task owner can give feedback on this answer.")
    if closure(world, goal_id):
        raise HTTPException(409, "This original conversation is closed after its handoff. Read its saved feedback instead.")
    return world, goal


def submit(request, goal_id, payload):
    from maverick.authority_effects import authority_effect_fence

    with authority_effect_fence():
        return _submit_reviewed(request, goal_id, payload)


def _submit_reviewed(request, goal_id, payload):
    from . import api
    world, goal = write_authority(request, goal_id)
    if payload.expected_context != context_for(request):
        raise product_error(409, "context_changed", "Your account, workspace or access changed. Reopen the authorized answer before giving feedback.")
    actor = api._supervisor(request)
    if payload.reason and payload.rating != "down":
        raise HTTPException(422, "Choose Needs improvement to include a reason, or remove the reason before saving Useful.")
    previous = store.latest(world, goal_id, goal.owner or "")
    try:
        value = store.record(world, goal_id, rating=payload.rating, note=payload.note, revision=payload.revision,
                             owner=goal.owner or "", context=payload.expected_context, actor=actor, operation_id=payload.operation_id, reason=payload.reason)
    except GoalMutationConflict as exc:
        raise product_error(409, "stale_version", "The reviewed answer or feedback changed. Your note is kept; review the current saved answer before giving feedback.",
                            next_action=next_action("Review the saved answer", f"/chat/goal/{goal_id}#feedback")) from exc
    # Only the caller that admitted the receipt may attempt the optional signal.
    # A crash or a lost response never authorizes another learning attempt.
    if not value.get("replayed"):
        from maverick.consequence import ConsequenceWriteUncertain

        value = store.observed(world, goal_id, payload.operation_id, actor, "started")
        def authorize_signal():
            # No world read here: the native fence rechecks every source field.
            auth.require_permission(request, "operate")
            auth.assert_goal_access(request, goal)
            if context_for(request) != payload.expected_context:
                raise HTTPException(409, "The feedback's account or workspace changed.")
        try:
            recorded = store.observe(world, goal_id, value, authorize=authorize_signal)
        except ConsequenceWriteUncertain:
            # The durable write may exist. Keep the original attempt unconfirmed
            # rather than promising failure or repeating an optional signal.
            pass
        except Exception:
            # Failure of optional learning never changes the accepted feedback.
            value = store.observed(world, goal_id, payload.operation_id, actor, "not_recorded")
        else:
            value = store.observed(world, goal_id, payload.operation_id, actor, "recorded" if recorded else "not_recorded")
    _world, current = task_signoff_operations.authorized(request, goal_id)
    feedback = public(value, current) if value["owner"] == (current.owner or "") else None
    if feedback is None:
        return {"context": context_for(request), "feedback": None}
    from . import goal_feedback_store
    follow_up = (not value.get("replayed") and goal_feedback_store.should_follow_up(
        actor, value.get("agent", ""), previous=previous, rating=payload.rating, world=world))
    hand_off = goal_feedback_store.should_offer_person(
        actor, value.get("agent", ""), rating=payload.rating, world=world)
    return {"context": context_for(request), "feedback": feedback, "saved": True, "training_completed": False,
            "acknowledgement": _acknowledgement(value),
            "follow_up": {"question": "What would make this better?"} if follow_up else None,
            # A person is one step away once the AI's answers keep missing.
            "hand_off": {"label": "Get help from a person",
                         "href": f"/help?from=/chat/goal/{goal_id}&task={goal_id}#get-help"} if hand_off else None}


def _acknowledgement(value):
    """Describe only the accepted receipt's actual optional learning state."""
    from .agent_changelog import agent_kind

    noun = agent_kind(value.get("agent", ""))
    if value["observation"] == "recorded":
        text = ("Thanks. Saved with this task and recorded as a learning signal. Your workspace's "
                f"learning policy decides how it is used to improve this {noun}.")
    elif value["observation"] in {"not_started", "started"}:
        text = "Thanks. Saved with this task. The optional learning signal is unconfirmed and will not be submitted again."
    else:
        text = f"Thanks. Saved with this task. It was not recorded as a learning signal, so it does not change this {noun}."
    if value.get("reason") or value.get("note"):
        text += f" The administrators' summary shows counts and the reasons picked for this {noun}, not what you wrote."
    return text


@router.get("/{goal_id}/answer-feedback")
def feedback_read(request: Request, response: Response, goal_id: int, operation_id: str | None = None):
    response.headers["Cache-Control"] = "no-store"
    if operation_id is not None and (len(operation_id) != 32 or any(c not in "0123456789abcdef" for c in operation_id)):
        raise HTTPException(422, "The original feedback reference is unavailable. Review current saved feedback instead.")
    return read(request, goal_id, operation_id)


@router.post("/{goal_id}/answer-feedback")
def feedback_submit(request: Request, response: Response, goal_id: int, payload: FeedbackChangeIn):
    response.headers["Cache-Control"] = "no-store"
    return submit(request, goal_id, payload)
