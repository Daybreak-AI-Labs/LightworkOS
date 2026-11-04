"""Explicit selection and exact task linkage for existing capability reuse."""
from __future__ import annotations

import time
from urllib.parse import urlencode

from fastapi import HTTPException
from maverick.intent_value import opportunities, workflow_evidence

from . import auth


def select(request, identifier, revision):
    from .intent_value_api import capabilities, recommendation, records

    row = recommendation(request, identifier, write=True)
    if row["status"] in {"declined", "deferred"}:
        raise HTTPException(409, "Reopen the suggestion before using it.")
    fresh = opportunities.evaluate(records(request), owner=auth.goal_owner_filter(request), capabilities=capabilities(request))
    candidate = next((item for item in fresh if item["id"] == identifier), None)
    if candidate is None:
        raise HTTPException(409, "The supporting source is no longer available.")
    capability = candidate["current_evidence"]["capability"]
    if capability and capability["kind"] == "process":
        capability = {**capability, "workflow_binding": workflow_evidence.bind(capability["id"],
            version=capability["version"], revision=capability["revision"])}
    def guard():
        validate(request, identifier)
        if capability and capability["kind"] == "process":
            workflow_evidence.current(capability["workflow_binding"])
    def update(current):
        if current.get("adopted_capability"):
            current.setdefault("adoption_history", []).append({"capability": current["adopted_capability"],
                "at": current.get("adopted_at"), "outcome": current.get("outcome_feedback")})
        current.update(adopted_capability=capability, adopted_at=time.time())
        current["decision_history"].append({"at": time.time(), "decision": "use_existing", "actor": auth.caller_principal(request) or "local"})
    with workflow_evidence.selection_guard(capability.get("workflow_binding") if capability else None):
        row = opportunities.RECOMMENDATIONS.update(identifier, update, expected_revision=revision,
            action="intent_value.capability_selected", actor=auth.caller_principal(request) or "local",
            effect_guard=guard)
    href = capability["href"] if capability else "/chat"
    if not capability or capability["kind"] == "specialist":
        href = "/chat?" + urlencode({"title": row["label"], "value_opportunity": row["id"],
            **({"specialist": capability["id"]} if capability else {})})
    return {"state": "audit_pending" if row.get("_audit_pending") else "selected", "href": href,
            "message": "Capability selected. Review inputs and start it explicitly using its normal controls. No execution was started."}


def validate(request, identifier):
    if not identifier:
        return None
    from .intent_value_api import recommendation
    row = recommendation(request, identifier, write=True)
    if row["status"] in {"declined", "deferred"}:
        raise HTTPException(409, "This opportunity is deferred or declined. Reopen it before continuing.")
    return row


def bind(request, identifier, world, goal_id):
    row = validate(request, identifier)
    if row is None:
        return
    goal = world.get_goal(goal_id)
    if goal is None or goal.owner != row["owner"]:
        raise HTTPException(404, "The selected work is unavailable.")
    if goal_id in row.get("linked_goal_ids", []):
        return
    def update(current):
        current.setdefault("linked_goal_ids", []).append(goal_id)
    result = opportunities.RECOMMENDATIONS.update(identifier, update, expected_revision=row["revision"],
        action="intent_value.task_linked", actor=auth.caller_principal(request) or "local",
        effect_guard=lambda: validate(request, identifier))
    if result.get("_audit_pending"):
        raise HTTPException(503, "The opportunity link is waiting for its audit receipt. Retry this same task submission.")
