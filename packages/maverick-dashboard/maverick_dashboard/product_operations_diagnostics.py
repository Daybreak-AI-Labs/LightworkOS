"""Owned support reports use the native exact-preview and audited download service."""
from __future__ import annotations

import hashlib

from maverick.governed_operations import digest

from . import task_diagnostics as native
from .draft_api import context_for
from .product_errors import product_error
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


def _goal(request, selection):
    identity = selection.get("goal_id")
    if type(identity) is not int or identity < 1:
        raise product_error(404, "diagnostic_task_missing", "Open one of your tasks to prepare its report.")
    return native._goal(request, identity)[1]


def snapshot(request, selection):
    goal = _goal(request, selection)
    document = native._document(native._app()._world(), goal, "preview")
    document.pop("generated_at_utc")
    return Snapshot(digest(document), "Current owned task and local receipt metadata",
        "Prepare a private report with task state, event times and accounting references. No content or credentials are included.",
        {"task_id": goal.id, "status": document["status"], "failure_class": document["failure_class"],
         "excluded": document["excluded"], "direct_ui": f"/tasks/{goal.id}/diagnostics"})


def prepare(request, selection, arguments):
    _goal(request, selection)
    return Preview("Save an encrypted, metadata-only report for your review. The download link expires in 15 minutes. Nothing is sent to support.",
        [{"field": "Private support report", "before": "No new report", "after": "Exact preview and owner-only audited download"}])


def execute(request, selection, arguments, review, operation_id):
    value = native.prepare_report(request, selection["goal_id"], native.PrepareIn(context=context_for(request)), operation_id=operation_id)
    return Outcome("confirmed", "Private report prepared. Review its exact preview before downloading or manually sharing it.", value)


def recover(request, selection, arguments, review, operation_id):
    _goal(request, selection)
    identity = "OTD-" + hashlib.sha256(operation_id.encode()).hexdigest()[:48]
    row = native.REPORTS.get(identity)
    return Outcome("replayed", "Recovered the original report without creating another copy.", native.report_result(request, row)) if row else None


def entries():
    return [Adapter("tasks.diagnostics.prepare", "Prepare a private task report", "tasks", "/chat",
        ("/chat/goal/*", "/tasks/*/diagnostics"), EmptyInput, snapshot, prepare, execute, recover)]
