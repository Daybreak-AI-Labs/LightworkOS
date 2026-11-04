"""Copilot uses the same expired-review recovery as the flow run page."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.approval_cards import digest

from . import flow_approval_recovery as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


def _run_id(selection):
    if (selection.get("kind") != "flow_run" or set(selection) != {"kind", "id", "flow_id"}
            or not isinstance(selection.get("id"), str) or not 1 <= len(selection["id"]) <= 120
            or not isinstance(selection.get("flow_id"), str)):
        raise HTTPException(422, "Open the paused workflow run first.")
    return selection["id"]


def snapshot(request, selection):
    run_id = _run_id(selection)
    try:
        value = native.state(request, run_id)
    except HTTPException as exc:
        if exc.status_code != 409:
            raise
        run, _actor = native._owned(request, run_id)
        if run.flow_id != selection["flow_id"]:
            raise HTTPException(404, "This run is unavailable in the selected workflow.") from exc
        return Snapshot(digest([run.run_id, run.status, run.updated, (run.human or {}).get("approval_refresh")]),
                        "Current workflow review", "Check this run's current review on its run page.",
                        blocked="Only an expired open-ended review with unchanged work and access can be renewed.")
    if value["flow_id"] != selection["flow_id"]:
        raise HTTPException(404, "This run is unavailable in the selected workflow.")
    return Snapshot(digest(value), "Current paused workflow and approval authority",
                    value["message"], value)


def prepare(request, selection, _arguments):
    value = snapshot(request, selection).details
    return Preview(value["summary"] + ". " + value["message"], native=value)


def execute(request, selection, _arguments, review, _operation_id):
    value = native.refresh(request, _run_id(selection),
                           native.RefreshIn(binding=review["binding"], confirmed=True))
    return Outcome("confirmed", value["message"], {"run_id": selection["id"]})


def recover(request, selection, arguments, review, operation_id):
    # Native recovery checks the persisted receipt and current ownership before
    # answering a repeated request; it never repeats a completed workflow step.
    run, actor = native._owned(request, _run_id(selection))
    receipt = (run.human or {}).get("approval_refresh") or {}
    if receipt.get("previous_binding") != review["binding"] or receipt.get("actor") != actor:
        return None
    return execute(request, selection, arguments, review, operation_id)


def entries():
    return (Adapter("learning.approval_refresh", "Request a fresh workflow review", "learning", "/workflows",
                    ("/flows/*/runs/*",), EmptyInput, snapshot, prepare, execute, recover,
                    aliases=("request a fresh review", "refresh this approval", "renew this workflow review")),)
