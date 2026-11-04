"""Read retained native learning work and request one reviewed safe-point stop."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import learning_ops_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class JobInput(StrictInput):
    job: str = Field(pattern=r"^[a-f0-9]{16}$")


def _label(row):
    job = row["job"]
    return job["label"] + " / " + datetime.fromtimestamp(job["started_at"], timezone.utc).strftime("%d %b at %H:%M UTC") + " / " + row["status"]


def _details(row):
    return {"task": row["job"]["label"], "started": datetime.fromtimestamp(row["job"]["started_at"], timezone.utc).strftime("%d %b %Y at %H:%M UTC"),
            "current_status": row["status"], "problem": row["job"]["problem"],
            "recorded_observations": row["observations"], "scope": row["notice"],
            "open_retained_tasks": {"href": "/learned#learning-job-history", "label": "Open your retained learning tasks"}}


def snapshot(request, selection, *, stop):
    history = native.current_learning_jobs(request)
    rows = [row for row in history["jobs"] if not stop or row["job"]["state"] == "running" and row["job"]["can_stop"]]
    choices = [{"value": row["job"]["id"], "label": _label(row)} for row in rows]
    selected = selection.get("id") if selection.get("kind") == "learning_job" else None
    return Snapshot(digest([[row["context"], row["revision"], row["job"]["id"]] for row in rows]),
        "Your current retained learning tasks in this workspace",
        "Request a stop at the next safe point. Completed work remains; the request does not prove work has stopped." if stop else history["notice"],
        fields=[{"name": "job", "label": "Learning task", "kind": "select", "required": True,
                 "choices": choices, "value": selected if selected in {choice["value"] for choice in choices} else ""}],
        blocked="No retained task is currently available to stop part-way." if stop and not choices else
                "No learning task from your account is currently retained here. A missing record does not mean the work failed." if not choices else "")


def prepare(request, _selection, arguments, *, stop):
    row = native.current_learning_job(request, arguments["job"])
    if stop and (row["job"]["state"] != "running" or not row["job"]["can_stop"]):
        raise HTTPException(409, "This task changed or cannot stop part-way. Read its current progress.")
    if not stop:
        return Preview("Read this task's retained current progress only. No work is started or repeated.", native=_details(row))
    return Preview("Request a stop for this exact retained task at its next safe point. Work already completed remains; this does not undo changes or establish that the task has finished.",
        changes=[{"label": "Task", "before": _label(row), "after": "Stop requested at its next safe point"},
                 {"label": "Completed work", "after": "Kept; no work is repeated or undone"}],
        native={"job": row["job"]["id"], "revision": row["revision"], "context": row["context"]})


def _reviewed(arguments, prepared):
    if prepared.get("job") != arguments["job"]:
        raise HTTPException(409, "The selected task changed. Read its current progress and review again.")


def execute(request, _selection, arguments, prepared, operation):
    _reviewed(arguments, prepared)
    result = native.reviewed_learning_stop(request, arguments["job"], native.JobStopIn(
        context=prepared["context"], revision=prepared["revision"], operation=operation, confirm=True))
    return Outcome("confirmed" if result["receipt"]["confirmed"] else "unconfirmed", result["receipt"]["message"], _details(result["current"]))


def recover(request, _selection, arguments, prepared, operation, *, read_only=False):
    _reviewed(arguments, prepared)
    row = native.original_learning_stop(request, arguments["job"], operation)
    if not row["confirmed"] and not row["intent_recorded"] and not read_only:
        return None
    return Outcome("replayed" if row["confirmed"] else "unconfirmed", row["message"], _details(row["current"]))


def entries():
    common = {"family": "learning", "direct_ui": "/learned#learning-job-history", "pages": ("/learning", "/learned"), "input_model": JobInput}
    return (
        Adapter("learning.retained_job", "Read a retained learning task", snapshot=lambda r, s: snapshot(r, s, stop=False),
                prepare=lambda r, s, a: prepare(r, s, a, stop=False), **common),
        Adapter("learning.stop_retained_job", "Stop a retained learning task", snapshot=lambda r, s: snapshot(r, s, stop=True),
                prepare=lambda r, s, a: prepare(r, s, a, stop=True), execute=execute, recover=recover,
                read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
    )
