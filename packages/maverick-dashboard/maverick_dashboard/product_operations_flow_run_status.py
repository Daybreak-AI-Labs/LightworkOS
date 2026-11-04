"""Copilot reads owned native run status and opens its complete result controls."""
from __future__ import annotations

import re

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import api, auth
from .plain_labels import datetime_text
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

STATES = {
    "queued": "Waiting to start", "claimed": "Starting", "resuming": "Continuing",
    "running": "In progress", "paused_approval": "Waiting for a decision",
    "paused_delay": "Waiting until the scheduled time", "paused_event": "Waiting for another app",
    "completed": "Finished", "failed": "Needs attention", "rejected": "Rejected",
    "cancelled": "Cancelled", "budget_limited": "Paused because the spending limit was reached",
    "indeterminate": "Needs checking in the other app",
}


def _state(request, selection):
    if (set(selection) != {"kind", "id", "flow_id"}
            or selection.get("kind") != "flow_run"
            or not isinstance(selection.get("id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", selection["id"])
            or not isinstance(selection.get("flow_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", selection["flow_id"])):
        raise HTTPException(422, "Open the exact workflow run first.")
    auth.require_permission(request, "operate")
    api._require_flows()
    # An assigned decision does not grant the owner's complete result custody.
    run = api._load_owned_run(request, selection["id"])
    if run.flow_id != selection["flow_id"]:
        raise HTTPException(404, "This workflow run is no longer available.")
    details = {
        "Current state": STATES.get(run.status, "Review this run"),
        "Last updated": datetime_text(run.updated),
        "Scope": "Current saved state of this owned workflow run. A finished run does not "
                 "independently verify that its answer is accurate or an outside action succeeded.",
        "Next step": "Open the complete run to read its answer, explore all permitted information "
                     "and starting information, or handle a waiting decision.",
        "open": {"label": "Open this complete workflow run",
                 "href": f"/flows/{run.flow_id}/runs/{run.run_id}#fr-data-rows"},
    }
    return digest({"run": run.run_id, "flow": run.flow_id, "owner": run.owner,
                   "updated": run.updated, "status": run.status}), details


def snapshot(request, selection):
    revision, details = _state(request, selection)
    return Snapshot(revision, "The selected owned workflow run",
                    "Read current status and open its complete native result controls.", details)


def prepare(request, selection, _arguments):
    _, details = _state(request, selection)
    return Preview("Current workflow run status. Nothing was run or changed.", native=details)


def entries():
    return (Adapter("artifacts.workflow_run_status", "Read this run and open its complete result",
                    "artifacts", "/automations", ("/flows/*/runs/*",), EmptyInput, snapshot, prepare,
                    aliases=("read this workflow run", "show this complete workflow result",
                             "what is the status of this workflow run", "open this workflow result")),)
