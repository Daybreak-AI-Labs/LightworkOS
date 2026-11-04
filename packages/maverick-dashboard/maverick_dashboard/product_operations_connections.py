"""Typed native connection diagnostics and durable schedule controls for Copilot."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from .auth import caller_principal, goal_owner_filter, require_permission
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ConnectionInput(StrictInput):
    name: str = Field(min_length=1, max_length=64)


class TemplateAccountInput(StrictInput):
    account: str = Field(min_length=1, max_length=2048)


def _key_setup_current(request):
    from maverick.tools.enterprise_connectors import connection_setup_catalog

    from .app import require_page_visible
    from .auth import require_page_permission
    from .connection_dependencies import require_connections as _require_connections
    from .draft_api import context_for

    require_permission(request, "admin")
    require_page_permission(request, "/connections")
    require_page_visible(request, "/connections")
    _require_connections()
    return {"context": context_for(request), "connectors": connection_setup_catalog()}


def key_setup_snapshot(request, _selection):
    current = _key_setup_current(request)
    return Snapshot(digest(current), "Current saved-key connection setup",
        "Open the protected connection form to choose a named service and save its key. "
        "Your entered choices stay in the form. Opening it saves nothing and contacts no service.",
        details={"Available services": [row["label"] for row in current["connectors"] if row["key_setup_supported"]]})


def key_setup_prepare(request, selection, _arguments):
    state = key_setup_snapshot(request, selection)
    current = _key_setup_current(request)
    if digest(current) != state.revision:
        raise HTTPException(409, "Your connection setup or access changed. Open the current controls again.")
    return Preview(state.summary, native={"connections_key_review": {
        "scope": "current_page", "context": current["context"],
    }})


def account_snapshot(request, selection):
    from .in_app_routes import template_connection_choices
    current = template_connection_choices(request)
    choices = current["choices"]
    return Snapshot(digest(current), "Your current connected accounts",
        "Review an exact account for a workflow input. Selection grants no additional tools or permissions.",
        fields=[{"name": "account", "label": "Connected account", "kind": "select", "required": True,
                 "choices": [{"value": row["value"], "label": row["name"] + " (" + row["connector"] + ")"} for row in choices]}],
        blocked="No eligible connected accounts. Open Connections to connect your own account." if not choices else "")


def account_prepare(request, selection, arguments):
    from maverick.template_connections import decode, validate
    require_permission(request, "operate")
    try:
        reference = validate(caller_principal(request) or "", [decode(arguments["account"])])[0]
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return Preview("This account selection is current. Choose this account in the template form; task admission checks it again. No provider check or task execution occurred.",
        native={"account": reference["name"], "service": reference["connector"], "next_step": "/templates",
                "scope": "Your own saved account; no additional tools or permissions", "executed": False})


def connection_snapshot(request, selection):
    from .connection_dependencies import owned_connections
    from .connection_dependencies import require_connections as _require_connections

    require_permission(request, "operate")
    _require_connections()
    rows = owned_connections(request)
    return Snapshot(digest(rows), "Connections", "Review readiness and affected work for one owned account.",
        fields=[{"name": "name", "label": "Saved connection", "kind": "select", "required": True,
                 "choices": [{"value": row["name"], "label": row["name"] + " / " + row["connector"]} for row in rows]}],
        blocked="No owned connection is available in this workspace." if not rows else "")


def connection_prepare(request, selection, arguments):
    from .connection_dependencies import impact, owned_connections, require_review

    value = impact(request, arguments["name"])
    value = require_review(request, value["name"], value["revision"], value["impact_version"], expected_context=value["context"])
    record = next((row for row in owned_connections(request) if row["name"] == value["name"]), None)
    if record is None or record["revision"] != value["revision"]:
        raise HTTPException(409, "This connection changed. Refresh its current status before proceeding.")
    work = {}
    labels = {"flow": "Saved workflows", "flow_schedule": "Workflow schedules", "active_flow": "Active workflow runs",
              "active_task": "Active tasks", "schedule": "Saved schedules", "discovery_source": "Privacy scan sources"}
    for item in value["items"]:
        label = labels.get(item["kind"], "Other recorded work")
        work[label] = work.get(label, 0) + 1
    states = {"current": "Checked in the permitted saved records", "partial": "Only part of the permitted records was checked",
              "unavailable": "Could not check these records", "disabled": "Not enabled", "administrator-only": "Installation administrator access needed"}
    areas = {"saved flows": "Saved workflows", "active flows and approvals": "Active workflows and requests",
             "tasks with possible dynamic use": "Tasks that may choose this account", "declared schedule references": "Saved schedules",
             "discovery sources": "Privacy scan sources", "agent-selected tools and unstructured instructions": "Actions chosen while work runs"}
    coverage = [{"Area": areas.get(row["kind"], "Other permitted records"), "Coverage": states.get(row["state"], "Cannot determine from saved setup; review with affected owners")}
                for row in value["coverage"]]
    details = {"Open complete account controls": {"href": "/connections#cx-list", "label": "Open saved connections"},
               "Connection": value["name"], "Credential": "Saved" if record["has_token"] else "Not saved",
               "Recorded access check": _connection_check(record),
               "Related work shown": work or "No related work found in the checked records",
               "Exact saved references": sum(item.get("binding") == "exact reference" for item in value["items"]),
               "Coverage": coverage,
               "Scope": "This summarizes permitted saved records, including possible uses; it is not a complete dependency list or a live service test. A saved credential or earlier authentication check does not prove current task access. Unknown external outcomes remain unknown."}
    if record.get("oauth"):
        oauth = record["oauth"]
        details["Account sign-in"] = oauth.get("recovery_action") or (
            "Renewal is ready; exact task access remains separate" if oauth.get("renewal_state") == "ready" else "Renewal is not confirmed; review this account in Connections")
    return Preview("Current scoped account status. No service was contacted, credential changed or work started.", native=details)


def _connection_check(record):
    check = record.get("last_test")
    if not check:
        return "Access not checked. A saved key does not prove task access."
    if check.get("revision") != record["revision"]:
        return "Earlier credential check; test the current saved credential."
    labels = {"authenticated": "Authentication verified at check time", "access_unverified": "Reachable; access not verified",
              "sign_in_refused": "Sign-in refused", "blocked_by_policy": "Blocked by connection policy",
              "unreachable": "Service unreachable", "address_missing": "Service address needed"}
    try:
        stamp = datetime.fromtimestamp(float(check["tested_at"]), tz=timezone.utc)
        when = stamp.strftime("%b %d, %Y at %H:%M UTC")
        age = (datetime.now(timezone.utc) - stamp).total_seconds()
        previous = "Check time is unconfirmed: " if age < 0 else "Previous check (stale): " if age > 86400 else ""
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        when, previous = "Date not available", "Previous check: "
    return previous + labels.get(check.get("outcome"), "Access not verified") + " · " + when + ". Service address only; exact task permissions remain separate."


class ScheduleInput(StrictInput):
    identity: str = Field(min_length=1, max_length=128)
    state: Literal["active", "paused", "retired"]


def _schedules(request):
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions

    from .schedule_policy import require_scheduling as _require_scheduling

    require_permission(request, "operate")
    _require_scheduling()
    return list_definitions(JobQueue(), owner=goal_owner_filter(request))


def schedule_snapshot(request, selection):
    rows = _schedules(request)
    return Snapshot(digest(rows), "Automations", "Review future schedule admission and durable history.",
        details={"schedules": rows}, fields=[
            {"name": "identity", "label": "Schedule", "kind": "select", "required": True,
             "choices": [{"value": row["definition_id"], "label": row["title"] + " / " + row["state"]} for row in rows]},
            {"name": "state", "label": "Future runs", "kind": "select", "required": True,
             "choices": [{"value": value, "label": label} for value, label in
                         (("active", "Activate future runs"), ("paused", "Pause future runs"), ("retired", "Retire and retain history"))]}],
        blocked="No durable schedule is available in this workspace." if not rows else "")


def schedule_prepare(request, selection, arguments):
    row = next((item for item in _schedules(request) if item["definition_id"] == arguments["identity"]), None)
    if row is None:
        raise HTTPException(404, "Schedule is unavailable.")
    return Preview("Change future schedule admission. Already admitted attempts are not cancelled or replayed.",
        changes=[{"label": row["title"], "before": row["state"], "after": arguments["state"]}],
        native={"identity": row["definition_id"], "revision": row["revision"], "state": arguments["state"]})


def schedule_recover(request, selection, arguments, native, operation):
    from maverick.job_queue import JobQueue

    _schedules(request)
    with JobQueue()._conn() as connection:
        row = connection.execute("SELECT revision FROM schedule_definition_versions WHERE id=? AND rationale=? AND actor=?",
            (native["identity"], "Copilot reviewed schedule change " + operation, caller_principal(request) or "local")).fetchone()
    if row:
        return Outcome("replayed", "This exact reviewed schedule change was already recorded. No work was dispatched again.", {"revision": row["revision"]})
    return None


def schedule_execute(request, selection, arguments, native, operation):
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import change_definition

    from .app import _require_same_origin

    _require_same_origin(request)
    _schedules(request)
    recovered = schedule_recover(request, selection, arguments, native, operation)
    if recovered is not None:
        return recovered
    try:
        result = change_definition(JobQueue(), native["identity"], expected_revision=native["revision"],
            state=native["state"], owner=goal_owner_filter(request), actor=caller_principal(request) or "local",
            rationale="Copilot reviewed schedule change " + operation)
    except (ValueError, KeyError) as exc:
        raise HTTPException(409, "The schedule changed. Refresh native status before reviewing again.") from exc
    return Outcome("confirmed", "Future schedule admission changed. Existing attempts and history were retained.", result)


class RecoveryInput(StrictInput):
    job_id: int = Field(ge=1)


def recovery_snapshot(request, selection):
    import json

    from maverick.job_queue import JobQueue

    require_permission(request, "admin")
    with JobQueue()._conn() as connection:
        rows = [dict(row) for row in connection.execute("SELECT j.id,j.attempts,j.status,j.scheduled_at,j.updated_at,"
            "COALESCE(d.payload,j.recurrence_payload) AS source_payload FROM jobs j LEFT JOIN schedule_definitions d "
            "ON d.id=j.recurrence_id WHERE j.recurrence_reconcile_required=1 ORDER BY j.id DESC LIMIT 101")]
    for row in rows:
        payload = json.loads(row.pop("source_payload") or "{}")
        row["title"] = str(payload.get("title") or payload.get("template") or "Scheduled work")[:200]
    return Snapshot(digest(rows), "Automations recovery", "Review a parked occurrence before repairing future recurrence.",
        details={"Available occurrences": "The newest 100 needing review are shown." if len(rows) > 100 else "All occurrences currently needing review are shown."},
        fields=[{"name": "job_id", "label": "Schedule and occurrence needing review", "kind": "select", "required": True,
                 "choices": [{"value": row["id"], "label": row["title"] + " · " + _occurrence(row)} for row in rows[:100]]}],
        blocked="No parked occurrence needs review." if not rows else "")


def _occurrence(row):
    from datetime import datetime, timezone
    when = (datetime.fromtimestamp(row["scheduled_at"], tz=timezone.utc).strftime("%b %d, %Y %H:%M UTC")
            if row["scheduled_at"] else "Time not recorded")
    status = {"pending": "Waiting", "running": "Running", "failed": "Needs review", "done": "Finished",
              "cancelled": "Cancelled"}.get(row["status"], "Recorded run")
    return when + " · " + status


def _review_details(value):
    return {"Schedule": value["title"], "Occurrence": _occurrence(value),
            "Historical business result": "Unknown; this repair will not repeat it.",
            "Recorded problem": value["problem"],
            "Compatible future occurrences shown": len(value["successors"]),
            "All compatible occurrences shown": value["successors_complete"]}


def recovery_prepare(request, selection, arguments):
    from .schedule_ops_api import recurrence_recovery_review

    value = recurrence_recovery_review(request, arguments["job_id"])
    return Preview("Review the current occurrence and future choices. No work is repeated.", native=_review_details(value))


class RepairInput(StrictInput):
    job_id: int = Field(ge=1)
    action: Literal["rearm", "link_successor"]
    successor_id: int | None = Field(default=None, ge=1)
    old_workers_stopped: bool = False
    rationale: str = Field(min_length=5, max_length=1000)


def repair_snapshot(request, selection):
    from dataclasses import replace

    from .schedule_ops_api import recurrence_recovery_review

    state = recovery_snapshot(request, selection)
    successors = {}
    for choice in state.fields[0]["choices"]:
        try:
            current = recurrence_recovery_review(request, choice["value"])
        except HTTPException as exc:
            if exc.status_code == 409:
                continue
            raise
        successors[choice["value"]] = [{"value": None, "label": "Create one next future occurrence"}] + [
            {"value": row["id"], "label": "Existing occurrence · " + _occurrence(row)} for row in current["successors"][:100]]
    return replace(state, summary="Repair future recurrence only after stopping old workers and reviewing current evidence.",
        fields=state.fields + [
            {"name": "action", "label": "Future recurrence decision", "kind": "select", "required": True,
             "choices": [{"value": "rearm", "label": "Create one next future occurrence"},
                         {"value": "link_successor", "label": "Use an existing compatible occurrence"}]},
            {"name": "successor_id", "label": "Future occurrence", "kind": "select", "depends_on": "job_id",
             "choices_by": successors},
            {"name": "old_workers_stopped", "label": "I confirmed old workers are stopped", "kind": "boolean", "required": True},
            {"name": "rationale", "label": "Reason for this reviewed repair", "kind": "textarea", "required": True, "max_length": 1000}])


def repair_prepare(request, selection, arguments):
    from .schedule_ops_api import recurrence_recovery_review
    if not arguments["old_workers_stopped"]:
        raise HTTPException(422, "Confirm old workers are stopped before reviewing recurrence repair.")
    linking = arguments["action"] == "link_successor"
    if linking != (arguments["successor_id"] is not None):
        raise HTTPException(422, "Choose exactly one existing successor or one new future occurrence.")
    value = recurrence_recovery_review(request, arguments["job_id"])
    selected = next((row for row in value["successors"] if row["id"] == arguments["successor_id"]), None)
    if linking and selected is None:
        raise HTTPException(409, "This successor is not in the current compatible recovery evidence. Refresh native Automations.")
    return Preview("Repair future recurrence only. Historical business work will not be replayed; its external outcome remains unknown.",
        [{"label": "Occurrence needing review", "after": _review_details(value)},
         {"label": "Reviewed decision", "after": _occurrence(selected) if linking else "Create exactly one next future occurrence"},
         {"label": "Stopped old workers", "after": True},
         {"label": "Reason", "after": arguments["rationale"]}],
        {"expected_attempts": value["attempts"], "expected_evidence": value["expected_evidence"], "context": value["context"]})


def repair_recover(request, selection, arguments, native, operation):
    from maverick.job_queue import JobQueue

    from .draft_api import context_for
    require_permission(request, "admin")
    if native["context"] != context_for(request):
        raise HTTPException(409, "Account or workspace changed. Review recurrence recovery again.")
    try:
        successor = JobQueue().recovery_receipt(arguments["job_id"], actor=caller_principal(request) or "local",
            operation_id=operation, expected_attempts=native["expected_attempts"],
            successor_id=arguments["successor_id"], rearm=arguments["action"] == "rearm",
            expected_evidence=native["expected_evidence"], rationale=arguments["rationale"])
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if successor is None:
        return None
    return Outcome("replayed", "This exact future recurrence repair was already recorded. Historical work was not replayed.",
        _repair_details(successor))


def _repair_details(successor):
    from maverick.job_queue import JobQueue
    with JobQueue()._conn() as connection:
        row = connection.execute("SELECT status,scheduled_at FROM jobs WHERE id=?", (successor,)).fetchone()
    return {"Recorded continuation": _occurrence(row) if row else "Its execution record is no longer retained.",
            "Historical work repeated": False, "Historical business result": "Unknown"}


def repair_execute(request, selection, arguments, native, operation):
    from .schedule_ops_api import RecurrenceRecoveryIn, recurrence_recovery_apply
    if not arguments["old_workers_stopped"]:
        raise HTTPException(422, "Confirm old workers are stopped before repairing recurrence.")
    result = recurrence_recovery_apply(request, arguments["job_id"], RecurrenceRecoveryIn(
        **native, successor_id=arguments["successor_id"], rearm=arguments["action"] == "rearm",
        rationale=arguments["rationale"], confirm=True, operation_id=operation))
    return Outcome("confirmed", "Future recurrence was repaired. Historical work was not replayed and its external outcome remains unknown.",
                   _repair_details(result["successor_id"]))


def receipt_snapshot(request, selection):
    require_permission(request, "admin")
    if (selection.get("kind") != "schedule_repair_receipt" or not isinstance(selection.get("reference"), str)
            or len(selection["reference"]) > 8000):
        return Snapshot(digest(selection), "Original schedule repair receipt", "Check the original repair without repeating it.",
            blocked="Choose Check original request with Copilot beside the interrupted repair on Automations.")
    result = _receipt(request, selection)
    return Snapshot(digest([selection["reference"], result]), "Original schedule repair receipt",
                    "Read the exact saved decision. This check cannot repair or repeat any work.", details=result)


def _receipt(request, selection):
    from .schedule_ops_api import RecurrenceReceiptIn, recurrence_recovery_receipt
    value = recurrence_recovery_receipt(request, RecurrenceReceiptIn(reference=selection["reference"]))
    return {"Exact original repair recorded": value["found"], "Result": value["message"],
            "Recorded continuation": _occurrence(value["future_occurrence"]) if value.get("future_occurrence") else "Not currently recorded",
            "Historical business result": "Unknown", "This check repeated work": False}


def receipt_prepare(request, selection, arguments):
    return Preview("The exact original schedule repair was checked. No repair was submitted or repeated.", native=_receipt(request, selection))

def entries():
    return (
        Adapter("connections.key_setup", "Set up a service with its key", "connections", "/connections#cx-form", ("/connections",),
            EmptyInput, key_setup_snapshot, key_setup_prepare, aliases=("connect a reference service", "set up FRED", "save a service key", "connect Census")),
        Adapter("templates.accounts", "Review a workflow account selection", "connections", "/templates", ("/templates", "/workflow-builder", "/connections"), TemplateAccountInput, account_snapshot, account_prepare),
        Adapter("connections.review", "Review connection diagnostics", "connections", "/connections", ("/connections", "/automations"), ConnectionInput, connection_snapshot, connection_prepare, aliases=("check my connection",)),
        Adapter("schedules.change", "Change future schedule runs", "schedules", "/automations", ("/automations",), ScheduleInput, schedule_snapshot, schedule_prepare, schedule_execute, schedule_recover, aliases=("pause my schedule",), read_recovery=schedule_recover),
        Adapter("schedules.recovery", "Review parked schedule recovery", "schedules", "/automations", ("/automations",), RecoveryInput, recovery_snapshot, recovery_prepare),
        Adapter("schedules.repair", "Repair reviewed future recurrence", "schedules", "/automations", ("/automations",), RepairInput, repair_snapshot, repair_prepare, repair_execute, repair_recover, read_recovery=repair_recover),
        Adapter("schedules.repair_receipt", "Check this original schedule repair", "schedules", "/automations", ("/automations",), EmptyInput, receipt_snapshot, receipt_prepare),
    )
