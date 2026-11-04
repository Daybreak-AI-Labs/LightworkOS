"""Selected consent jobs use the same authorized native controls in Copilot."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Literal
from urllib.parse import quote

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import auth
from . import consent_bulk_jobs_api as native
from .draft_api import context_for
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_OPERATIONS = {"export_receipts": "Export consent records", "edit_preferences": "Change choices",
    "delete_subject": "Erase stored identifiers", "change_identifier_type": "Change how people are identified",
    "reactivate": "Bring back earlier choices", "clear_expiration": "Remove end dates"}
_STATES = {"queued": "Waiting", "running": "Running", "succeeded": "Finished",
           "failed": "Finished with records needing review", "cancelled": "Cancelled"}
_PAGE = "/consent/bulk-jobs"


def _job_id(selection):
    if (set(selection) != {"kind", "id"} or selection.get("kind") != "consent_bulk_job"
            or not isinstance(selection.get("id"), str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", selection["id"])):
        raise HTTPException(404, "Choose a job in Bulk consent changes first.")
    return selection["id"]


def _state(request, selection, *, write=False):
    if write:
        auth.require_permission(request, "operate")
        auth.require_global_permission(request, "admin")
    return native.job_controls().state(request, _job_id(selection))


def _details(job):
    return {"operation": _OPERATIONS.get(job["operation"], "Consent job"),
            "created": datetime.fromtimestamp(job["created_at"], timezone.utc).strftime("%d %b %Y at %H:%M UTC"),
            "status": "Cancelling" if job["cancel_requested"] and job["state"] != "cancelled" else _STATES[job["state"]],
            "progress": f"{job['processed_items']} of {job['total_items']} processed",
            "records_needing_review": job["failed_items"],
            "remaining_records": job["total_items"]-job["processed_items"],
            "review_job": {"href": _PAGE + "?job=" + quote(job["job_id"], safe=""), "label": "Open this job and its activity"}}


def _snapshot(request, selection, action):
    state = _state(request, selection, write=action in {"run", "cancel"})
    job, blocked = state.job, ""
    if action in {"run", "cancel"} and (job["state"] not in {"queued", "running"} or job["cancel_requested"]):
        blocked = "This job has finished or its future work has already been cancelled. Check saved progress."
    elif action == "run" and job["scheduled_for"] > state.now:
        blocked = "This job is scheduled for later. Its start time must arrive before a part can run."
    elif action == "download" and (job["operation"] != "export_receipts" or job["state"] != "succeeded"):
        blocked = "Downloads are available after an export job finishes. Check the saved progress first."
    return Snapshot(digest([context_for(request), job, state.part_limit, action]),
        "Current selected consent job in this account and workspace",
        "Review this job's saved progress and completed changes.", details=_details(job), blocked=blocked)


def read_snapshot(request, selection):
    return _snapshot(request, selection, "read")


def read_prepare(request, selection, _arguments):
    state = _state(request, selection)
    return Preview("Read saved progress only. This starts no work and changes no consent records.", native=_details(state.job))


def run_snapshot(request, selection):
    return _snapshot(request, selection, "run")


def run_prepare(request, selection, _arguments):
    state = _state(request, selection, write=True)
    job = state.job
    count = min(state.part_limit, job["total_items"]-job["processed_items"])
    amount = f"{count} " + ("record" if count == 1 else "records")
    return Preview(f"Run one part of the existing reviewed job: up to {amount}. This may change or erase consent information. Remaining parts do not start automatically. Completed changes stay applied, and an interrupted response requires a saved-progress check.",
        changes=[{"label": "Job", "after": _OPERATIONS.get(job["operation"], "Consent job")},
                 {"label": "Saved progress", "before": _details(job)["progress"], "after": f"At most {amount} in this part"}],
        native={"job_id": job["job_id"], "revision": job["revision"]})


def _reviewed(selection, prepared):
    job_id = _job_id(selection)
    if prepared.get("job_id") != job_id or type(prepared.get("revision")) is not int:
        raise HTTPException(409, "The selected job changed. Review its current progress again.")
    return job_id


def run_recover(request, selection, _arguments, prepared, _operation_id):
    _reviewed(selection, prepared)
    job = _state(request, selection, write=True).job
    if job["revision"] == prepared["revision"]:
        return None
    return Outcome("unconfirmed", "Saved progress changed since this review. This does not establish whether the original part ran. No additional part was started; review the current job before continuing.", _details(job))


def run_execute(request, selection, _arguments, prepared, _operation_id):
    job_id = _reviewed(selection, prepared)
    try:
        job = native.job_controls().run_part(request, job_id, prepared["revision"])
    except HTTPException as exc:
        if exc.status_code != 503:
            raise
        job = _state(request, selection, write=True).job
        return Outcome("unconfirmed", "The part's result could not be confirmed. Saved progress is shown; no additional part was started. Review the job's activity before continuing.", _details(job))
    message = ("The job finished. Review any records needing attention." if job["state"] in {"succeeded", "failed"}
               else "Future work is cancelled. Completed changes stay applied." if job["state"] == "cancelled"
               else "One part finished. This job still has remaining work; no additional part was started.")
    return Outcome("confirmed", message, _details(job))


def cancel_snapshot(request, selection):
    return _snapshot(request, selection, "cancel")


def cancel_prepare(request, selection, _arguments):
    job = _state(request, selection, write=True).job
    return Preview("Cancel this job's future work. A part already underway stops between records; completed changes are kept and are not undone.",
        changes=[{"label": "Remaining work", "before": f"{job['total_items']-job['processed_items']} records",
                  "after": "Do not continue this job"}], native={"job_id":job["job_id"], "revision":job["revision"]})


def cancel_recover(request, selection, _arguments, prepared, _operation_id):
    _reviewed(selection, prepared)
    job = _state(request, selection, write=True).job
    if not job["cancel_requested"]:
        return None
    return Outcome("unconfirmed", "A cancellation request is saved. The original request remains unconfirmed. Completed changes stay applied; no cancellation was repeated.", _details(job))


def cancel_execute(request, selection, _arguments, prepared, operation_id):
    job_id = _reviewed(selection, prepared)
    try:
        job = native.job_controls().cancel_future(request, job_id,
            native.RevisionIn(expected_revision=prepared["revision"], idempotency_key="copilot-"+operation_id))
    except HTTPException as exc:
        if exc.status_code != 503:
            raise
        job = _state(request, selection, write=True).job
        return Outcome("unconfirmed", "The cancellation response could not be confirmed. Saved progress is shown; check the job's activity before deciding what to do next.", _details(job))
    return Outcome("confirmed", "Future work is cancelled or stopping between records. Completed changes stay applied.", _details(job))


def download_snapshot(request, selection):
    return _snapshot(request, selection, "download")


def download_prepare(request, selection, _arguments):
    job_id = _job_id(selection)
    native.job_controls().download_result(request, job_id)  # Native readiness and artifact-integrity verification.
    return Preview("The finished export is available. Select Download consent records to save the file; private record contents stay out of Copilot.",
        native={"download": {"href":"/api/v1/consent/bulk-jobs/"+quote(job_id, safe="")+"/download",
                             "label":"Download consent records"}})



class AllowanceInput(StrictInput):
    amount: Literal[10, 50, 100, 500]


def create_snapshot(request, _selection):
    state = native.job_controls().creation_state(request)
    available = [label for key, label in _OPERATIONS.items() if state["operations"].get(key)]
    return Snapshot(digest([context_for(request), state]), "Current native consent executors and record allowance",
        "Choose people and their choices in the ordinary request form, review every selected record, then submit once. Private selections stay in the native consent controls and are not sent to the model guide.",
        {"Available requests": available, "Records available": state["allowance"]["available"]},
        blocked="No consent request executor is available yet." if not available else "")


def create_prepare(request, _selection, _arguments):
    native.job_controls().creation_state(request)
    return Preview("Open the current account's consent request form. Choose people, policy and choices there; review and confirm before submission. A submitted request is queued, and processing is confirmed separately.",
        native={"context": context_for(request), "form": "consent_bulk_job"})


def allowance_snapshot(request, _selection):
    auth.require_permission(request, "operate")
    auth.require_global_permission(request, "admin")
    value = native.job_controls().credit_detail(request)
    return Snapshot(digest([context_for(request), value]), "Current native consent record allowance",
        "Allow more records to be processed in this workspace. This changes the processing allowance; it does not purchase anything or run a job.",
        {"Available": value["available"], "Set aside for waiting jobs": value["reserved"], "Already used": value["consumed"]},
        [{"name": "amount", "label": "Additional records allowed", "kind": "select", "required": True,
          "choices": [{"value": amount, "label": str(amount) + " records"} for amount in (10, 50, 100, 500)]}])


def allowance_prepare(request, selection, arguments):
    allowance_snapshot(request, selection)
    current = native.job_controls().credit_detail(request)
    return Preview("Allow " + str(arguments["amount"]) + " more consent records to be processed. No job runs and no payment is made.",
        [{"label": "Available records", "before": current["available"], "after": current["available"] + arguments["amount"]}],
        {"revision": current["revision"]})


def allowance_execute(request, _selection, arguments, prepared, operation_id):
    value = native.job_controls().grant_allowance(request, native.GrantCreditsIn(amount=arguments["amount"],
        expected_revision=prepared["revision"], idempotency_key="copilot-" + operation_id))
    return Outcome("confirmed", "The allowance was increased by " + str(value["added"]) + " records. No job was run.",
        {"Available after this change": value["available"], "Added records": value["added"]})


def allowance_recover(request, _selection, _arguments, _prepared, operation_id):
    value = native.job_controls().check_allowance(request, "copilot-" + operation_id)
    if value is None:
        return None
    return Outcome("replayed", "Read your original accepted allowance change. No records were added again and no job was run.",
        {"Available after the original change": value["available"], "Added records": value["added"]})


def entries():
    return (
        Adapter("consent.jobs.create", "Prepare a consent request", "tasks", _PAGE, (_PAGE,), EmptyInput,
                create_snapshot, create_prepare, aliases=("start a bulk consent change", "export selected consent records")),
        Adapter("consent.jobs.allowance", "Increase the consent record allowance", "tasks", _PAGE, (_PAGE,), AllowanceInput,
                allowance_snapshot, allowance_prepare, allowance_execute, allowance_recover, aliases=("allow more consent records",)),
        Adapter("consent.jobs.read", "Read this consent job", "tasks", _PAGE, (_PAGE,), EmptyInput,
                read_snapshot, read_prepare, aliases=("check this consent job", "show saved consent progress")),
        Adapter("consent.jobs.run_part", "Run one part of this consent job", "tasks", _PAGE, (_PAGE,), EmptyInput,
                run_snapshot, run_prepare, run_execute, run_recover, aliases=("continue this consent job", "run this consent job")),
        Adapter("consent.jobs.cancel", "Cancel this consent job's future work", "tasks", _PAGE, (_PAGE,), EmptyInput,
                cancel_snapshot, cancel_prepare, cancel_execute, cancel_recover, aliases=("cancel this consent job", "stop this consent job")),
        Adapter("consent.jobs.download", "Get this consent job's download", "tasks", _PAGE, (_PAGE,), EmptyInput,
                download_snapshot, download_prepare, aliases=("download this consent job", "get this consent export")),
    )
