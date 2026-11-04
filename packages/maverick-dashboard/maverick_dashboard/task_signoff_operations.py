"""Native finished-result decisions and exact original-actor readback."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from maverick import deliverable_signoff_receipts as store
from maverick.governed_operations import digest

from . import _shared, auth
from .draft_api import context_for
from .product_errors import next_action, product_error


def selected(selection):
    identifier = selection.get("goal_id", selection.get("id"))
    if selection.get("kind") != "goal" or type(identifier) is not int or identifier < 1:
        raise HTTPException(404, "Open the task result you want to review.")
    return identifier


def authorized(request, goal_id, *, write=False):

    auth.require_permission(request, "operate" if write else "view")
    world = _shared._world()
    goal = world.get_goal(goal_id)
    if goal is None:
        raise HTTPException(404, "no such goal")
    auth.assert_goal_access(request, goal)
    return world, goal


def read(request, goal_id, operation_id=None):
    from . import api

    world, goal = authorized(request, goal_id)
    result = {"gate": api._goal_gate(goal.domain), "deliverable_updated_at": goal.updated_at,
              "signoff": world.signoff_for(goal_id)}
    if operation_id is not None:
        receipt = store.receipt(world, goal_id, operation_id, api._supervisor(request))
        # A current matching row is never a substitute for this actor's exact
        # durable operation receipt (including another person's no-op verdict).
        result["receipt"] = public_receipt(receipt, goal) if receipt is not None else None
        result["message"] = result["receipt"]["message"] if receipt is not None else (
            "No accepted receipt for this attempt was found. Its outcome is unconfirmed. Check the current review before preparing another decision; nothing was submitted again.")
    return result


def public_receipt(value, goal):
    current = goal.status == "done" and float(goal.updated_at) == value["deliverable_updated_at"] and (goal.owner or "") == value["owner"]
    signoff = value["signoff"]
    if value["changed"]:
        message = "Your original " + ("approval" if value["decision"] == "approved" else "rejection") + " was recorded for the result you reviewed."
    else:
        message = "This result was already " + signoff["decision"] + " by " + reviewer(signoff["decided_by"]) + ". This attempt did not add a decision or repeat learning or handoff."
    if not current:
        message += " This is a historical receipt; the task or result has changed since that review."
    message += " A recorded review is not proof of training, delivery or recipient acceptance."
    return {"operation_id": value["operation_id"], "changed": value["changed"],
            "own_decision": value["own_decision"], "current_result": current,
            "decision": signoff["decision"], "reviewer": reviewer(signoff["decided_by"]),
            "recorded_at": datetime.fromtimestamp(signoff["created_at"], timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
            "review_note": signoff["note"], "follow_through": value["effects"], "message": message}


def reviewer(actor):
    from .identity_format import humanize_principal

    return humanize_principal(actor).name if actor else "a reviewer"


def snapshot(request, goal_id, *, write=False):
    from maverick.deliverable import render_deliverable

    from . import api

    world, goal = authorized(request, goal_id, write=write)
    gate, signoff = api._goal_gate(goal.domain), world.signoff_for(goal_id)
    rendered = render_deliverable(api._goal_shape(goal.domain), goal.result)
    details = {"Task": goal.title, "Status": goal.status, "Review requirement": gate or "No sign-off required",
               "Current decision": signoff["decision"] if signoff else "Awaiting review",
               "Reviewer": reviewer(signoff["decided_by"]) if signoff else "Not yet reviewed",
               "Reviewed result": {"headers": rendered.table.headers, "rows": rendered.table.rows} if rendered.table else rendered.prose,
               "Next step": f"/chat/goal/{goal.id}#signoff"}
    binding = {"id": goal.id, "owner": goal.owner or "", "updated_at": float(goal.updated_at),
               "result": goal.result, "domain": goal.domain, "status": goal.status, "gate": gate, "signoff": signoff}
    return digest(binding), details, {"expected_updated_at": float(goal.updated_at), "owner": goal.owner or "", "context": context_for(request)}, gate, goal.status


def decide(request, goal_id, payload, *, expected_owner=None):
    from . import api

    world, goal = authorized(request, goal_id, write=True)
    gate = api._goal_gate(goal.domain)
    if gate is None:
        raise HTTPException(400, "this deliverable has no sign-off gate")
    if goal.status != "done":
        raise product_error(409, "task_unfinished", "This task must finish before its result can be signed off.",
                            next_action=next_action("Review task progress", f"/chat/goal/{goal_id}"))
    actor = api._supervisor(request)
    operation_id = payload.operation_id
    if payload.expected_context is not None and payload.expected_context != context_for(request):
        raise HTTPException(409, "Your account, workspace or access changed. Review this result again.")
    try:
        if operation_id is None:
            changed = world.record_signoff(goal_id, payload.decision, decided_by=actor, note=payload.note,
                                          expected_updated_at=payload.expected_updated_at)
            value = None
        else:
            value = store.decide(world, goal_id, decision=payload.decision, expected_updated_at=payload.expected_updated_at,
                                 note=payload.note, operation_id=operation_id, actor=actor,
                                 owner=(goal.owner or "") if expected_owner is None else expected_owner,
                                 context=payload.expected_context or context_for(request))
            changed = value["changed"] and not value["replayed"]
    except ValueError as exc:
        raise product_error(409, "stale_version", "The result or review changed after you reviewed it. Review the current result before deciding.",
                            next_action=next_action("Review the current result", f"/chat/goal/{goal_id}")) from exc
    if changed:
        if value is not None:
            store.effects(world, goal_id, operation_id, actor, "started")
        api._record_signoff_outcome(world, goal_id, payload.decision)
        if payload.decision == "approved":
            api._handoff_approved_deliverable(goal, actor)
        if value is not None:
            value = store.effects(world, goal_id, operation_id, actor, "attempted")
    result = {"gate": gate, "deliverable_updated_at": goal.updated_at, "changed": changed,
              "signoff": world.signoff_for(goal_id)}
    if value is not None:
        _world, current = authorized(request, goal_id)
        result["receipt"] = public_receipt(value, current)
        result["replayed"] = value["replayed"]
    return result


def recover(request, goal_id, operation_id, review):
    from . import api

    world, goal = authorized(request, goal_id, write=True)
    value = store.receipt(world, goal_id, operation_id, api._supervisor(request))
    if value is None:
        return None
    if any(value[key] != review[original] for key, original in (("owner", "owner"), ("context", "context"), ("deliverable_updated_at", "expected_updated_at"))):
        raise HTTPException(409, "This receipt belongs to a different result review. Nothing was submitted again.")
    return public_receipt(value, goal)
