"""Typed Copilot retention controls share Compliance's exact native review."""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import Field

from . import retention_maintenance as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PAGE = "/compliance#cmp-retention"
_PAGES = ("/compliance", "/settings", "/settings/all")
_STATES = {"review": "Not started", "pending": "Not started", "running": "Outcome not confirmed",
           "completed": "Completed", "partial": "Needs attention", "unknown": "Outcome not confirmed", "blocked": "Blocked"}


class ApplyInput(StrictInput):
    review: str = Field(pattern=r"^[a-f0-9]{32}$")
    confirm_no_holds: bool


class ReadInput(StrictInput):
    review: str = Field(default="", pattern=r"^(?:[a-f0-9]{32})?$")


def _details(value):
    return {"Review": value["message"], "Workspaces": [row["name"] for row in value["targets"]],
        "Reviewed records": [{"Workspace": step["workspace"], "Record type": step["label"],
            "Keep for": str(step["days"]) + " days", "Eligible at preview": step["eligible"],
            "Confirmed removed": step.get("removed"), "Outcome": _STATES[step["status"]],
            "Activity unconfirmed": step.get("audit_record") == "unconfirmed", "Note": step.get("note", "")} for step in value["steps"]],
        "open": {"label": "Open retention review", "href": _PAGE}}


def snapshot(request, selection, *, action):
    if selection:
        raise HTTPException(422, "Choose a saved retention review in this form.")
    policy, history = native.policy(request), native.history(request)
    fields = []
    if action in {"read", "apply"}:
        from datetime import datetime, timezone

        fields = [{"name": "review", "label": "Saved retention review", "kind": "select", "required": action == "apply",
            "choices": [{"value": row["id"], "label": datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%b %d, %Y %H:%M:%S UTC") + " · " + row["workspaces"] + " · " + str(row["eligible"]) + " eligible at preview"}
                        for row in history["records"] if action == "read" or row["status"] == "review"]}]
        if action == "apply":
            fields.append({"name": "confirm_no_holds", "label": "I confirmed with the records owner that no preservation hold applies", "kind": "boolean", "required": True})
    return Snapshot(native.catalog_revision([policy, history]), "Current effective periods, recorded preservation holds and your saved local reviews",
        "Check the current policy, preview eligible records, or confirm one exact saved review. Recovery reads the original receipt without deleting again.",
        {"Workspaces": [{"Workspace": row["name"], "Deletion blocked by recorded holds": row["blocked"],
            "Periods": [{"Record type": period["label"], "Keep for": str(period["days"]) + " days" if period["days"] else "Until I choose"}
                        for period in row["periods"]]} for row in policy["workspaces"]], "Saved review count": len(history["records"]),
         "open": {"label": "Open retention", "href": _PAGE}}, fields,
        "Preview old records first. No saved review is awaiting confirmation." if action == "apply" and not fields[0]["choices"] else "")


def prepare(request, selection, arguments, *, action):
    current = snapshot(request, selection, action=action)
    if action == "read":
        return Preview("Read current retention or the selected original review result. No records are deleted.",
                       native=_details(native.read(request, arguments["review"])) if arguments["review"] else current.details)
    if action == "preview":
        policy = native.policy(request)
        return Preview("Save a ten-minute preview of eligible old records under the current effective periods. No records are deleted.",
            [{"label": "Scope", "after": policy["workspaces"]}], {"policy": policy["revision"], "context": policy["context"]})
    if arguments["confirm_no_holds"] is not True:
        raise HTTPException(422, "Confirm external preservation holds with your records owner before reviewing deletion.")
    value = native.read(request, arguments["review"])
    if not value["can_apply"]:
        raise HTTPException(409, value["message"])
    return Preview("Permanently delete the exact unchanged records eligible at this preview cutoff. Recorded holds cannot be overridden. Task-history deletion removes provenance links from retained facts.",
        [{"label": key, "after": item} for key, item in _details(value).items() if key != "open"],
        {"review": value["id"], "revision": value["revision"], "context": value["context"]})


def _outcome(value, operation_id, *, replayed=False):
    own = value.get("execution_id") == operation_id
    message = value["message"]
    if replayed:
        message = "Read the original saved result without repeating any deletion. " + message
        if value.get("execution_id") and not own:
            message = "This review was already consumed by a different confirmation from your account. " + message
    return Outcome("unconfirmed" if value["unresolved"] else "replayed" if replayed else "confirmed", message, _details(value))


def execute(request, _selection, arguments, prepared, operation_id, *, action):
    if action == "preview":
        value = native.preview(request, prepared["context"], prepared["policy"], operation_id)
        return Outcome("confirmed", "Retention preview saved. No records were deleted. Review it in Compliance or choose Confirm a saved retention review.", _details(value))
    value = native.apply(request, prepared["review"], confirm_holds=arguments["confirm_no_holds"],
        expected_context=prepared["context"], expected_revision=prepared["revision"], operation_id=operation_id)
    return _outcome(value, operation_id)


def recover(request, _selection, _arguments, prepared, operation_id, *, action):
    identity = operation_id if action == "preview" else prepared["review"]
    try:
        value = native.read(request, identity)
    except HTTPException as exc:
        if exc.status_code == 404 and action == "preview":
            return None
        raise
    if action == "preview":
        return Outcome("replayed", "Read the original retention preview without making another one. No deletion was requested by this operation.", _details(value))
    if not value.get("execution_id"):
        return None
    return _outcome(value, operation_id, replayed=True)


def entries():
    from functools import partial

    return tuple(Adapter("preferences.retention_" + action, label, "preferences", _PAGE, _PAGES,
        ApplyInput if action == "apply" else ReadInput if action == "read" else EmptyInput,
        partial(snapshot, action=action), partial(prepare, action=action),
        partial(execute, action=action) if action != "read" else None,
        partial(recover, action=action) if action != "read" else None,
        aliases=(label.lower(),)) for action, label in (
            ("read", "Check retention and saved results"), ("preview", "Preview old records"),
            ("apply", "Confirm a saved retention review")))
