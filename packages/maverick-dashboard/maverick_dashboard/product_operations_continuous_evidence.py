"""Read native evidence status and open its existing protected controls."""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import auth
from . import trc_continuous_evidence_api as api
from . import trc_setup_api as setup
from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .trc_continuous_evidence_scheduler import TrcEvidenceSchedulerError

PAGE = "/compliance/continuous-evidence"
INVENTORY_LIMIT = 100
RUN_LIMIT = 50


def _access(request):
    from maverick import trc_continuous_evidence as evidence

    from .app import require_page_visible

    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    try:
        evidence.require_enabled()
    except evidence.ContinuousEvidenceConfigError as exc:
        raise HTTPException(403, "Continuous evidence is turned off.") from exc
    tenant = api._tenant_id()
    return tenant, api._principal(request, tenant), tuple(sorted(api._collector_ids(request)))


def _scheduler(request):
    scheduler = getattr(request.app.state, "trc_continuous_evidence_scheduler", None)
    if not callable(getattr(scheduler, "status", None)):
        return {"state": "Unknown; no current status is available", "needs_attention": None}
    try:
        status = scheduler.status()
    except (TrcEvidenceSchedulerError, OSError, ValueError):
        return {"state": "Unknown; current status could not be read", "needs_attention": None}
    if not isinstance(status, Mapping) or not isinstance(status.get("running"), bool):
        return {"state": "Unknown; current status could not be verified", "needs_attention": None}
    return {"state": "On" if status["running"] else "Off",
            "needs_attention": bool(status.get("last_error_code"))}


def _states(rows, names):
    return dict(Counter(names.get(row.state, "Other retained state") for row in rows))


def _state(request, selection):
    if selection:
        raise HTTPException(422, "Open the current Continuous evidence page to review its controls.")
    authority = _access(request)
    evidence, tenant, store = setup._store(request)
    if store is None or store.tenant_id != tenant:
        raise HTTPException(503, "Current evidence records could not be verified. Your work is kept.")
    try:
        plans = list(setup._manifests(request, tenant).values())
        definitions = store.list_definitions(limit=INVENTORY_LIMIT + 1)
        enrollments = store.list_enrollments(limit=INVENTORY_LIMIT + 1)
        jobs = store.list_jobs(limit=INVENTORY_LIMIT + 1)
        runs = store.list_runs(limit=RUN_LIMIT + 1)
        scheduler = _scheduler(request)
    except (evidence.ContinuousEvidenceError, OSError) as exc:
        raise HTTPException(503, "Current evidence records could not be verified. Your work is kept.") from exc
    if _access(request) != authority:
        raise HTTPException(409, "Your workspace or access changed. Read the current status again.")
    sources = plans[:INVENTORY_LIMIT]
    details = {
        "Configured sources included": len(sources),
        "Sources with a connection key found": sum(plan["credential_ready"] is True for plan in sources),
        "Sources with a missing connection key": sum(plan["credential_ready"] is False for plan in sources),
        "Sources whose connection key status is unknown": sum(plan["credential_ready"] is None for plan in sources),
        "More configured sources": len(plans) > INVENTORY_LIMIT,
        "Collection setups included": min(len(definitions), INVENTORY_LIMIT),
        "Collection setup states": _states(definitions[:INVENTORY_LIMIT], {
            "pending": "Waiting for independent approval", "approved": "Approved", "retired": "Retired"}),
        "More collection setups": len(definitions) > INVENTORY_LIMIT,
        "Collection schedules included": min(len(enrollments), INVENTORY_LIMIT),
        "Collection schedule states": _states(enrollments[:INVENTORY_LIMIT], {
            "active": "Collecting", "paused": "Paused", "revoked": "Removed"}),
        "More collection schedules": len(enrollments) > INVENTORY_LIMIT,
        "Retained collection jobs included": min(len(jobs), INVENTORY_LIMIT),
        "Retained collection job states": _states(jobs[:INVENTORY_LIMIT], {
            "queued": "Waiting", "running": "Being collected", "leased": "Being collected",
            "completed": "Finished", "incomplete": "Incomplete", "cancelled": "Cancelled", "dead_letter": "Needs attention"}),
        "More retained collection jobs": len(jobs) > INVENTORY_LIMIT,
        "Recent collections included": min(len(runs), RUN_LIMIT),
        "Recent complete collections": sum(run.complete for run in runs[:RUN_LIMIT]),
        "Recent incomplete collections": sum(not run.complete for run in runs[:RUN_LIMIT]),
        "More retained collections": len(runs) > RUN_LIMIT,
        "Collection scheduler": scheduler["state"],
        "Scheduler reports a retained error": scheduler["needs_attention"],
        "Scope": "Current workspace only. At most 100 sources in native configuration order, "
                 "100 setups and 100 schedules in native identifier order; "
                 "100 retained jobs ordered by their scheduled time; "
                 "and the newest 50 finished collections. Counts describe these views, not the whole "
                 "portfolio when more records exist. Scheduler status describes the installation process.",
        "Next step": "Review the existing controls. Set up a source, have another administrator approve it, "
                     "then choose Start collecting. A saved setup or complete collection does not prove compliance.",
    }
    # Source plans, credentials, control bindings, customer values and collected
    # evidence stay in native readers. Only count/state metadata reaches Copilot.
    revision = digest({"authority": authority, "plans": digest(plans), "scheduler": scheduler,
                       "records": [[row.integrity_sha256 for row in rows]
                                   for rows in (definitions, enrollments, jobs, runs)]})
    return revision, details


def snapshot(request, selection):
    revision, details = _state(request, selection)
    return Snapshot(revision, "Current workspace evidence records and configured sources",
                    "Read current evidence status and open the existing protected controls.", details)


def prepare(request, selection, _arguments):
    _, details = _state(request, selection)
    return Preview("Current evidence status. No setup, approval or collection was started.", native={
        **details, "continuous_evidence_review": {"scope": "current_page"},
    })


def source_snapshot(request, selection):
    _, tenant, owner, context = setup._source_access(request)
    revision, details = _state(request, selection)
    _, current_tenant, current_owner, current_context = setup._source_access(request)
    if (current_tenant, current_owner, current_context) != (tenant, owner, context):
        raise HTTPException(409, "Your account or workspace changed. Read the source setup again.")
    return Snapshot(digest([revision, context]), "Current authorized evidence source setup",
                    "Open named provider, saved account and security-check controls. Nothing is saved or collected.",
                    {**details, "Next step": "Choose and check a saved account and its source. Review the complete setup "
                     "before saving; independent approval and Start collecting remain separate."})


def source_prepare(request, selection, _arguments):
    current = source_snapshot(request, selection)
    return Preview(current.summary, native={
        **current.details, "continuous_evidence_source_review": {"scope": "current_page"},
    })


def entries():
    return (Adapter("connections.continuous_evidence_status", "Read evidence status and open collection controls",
                    "connections", PAGE + "#trc-refresh", (PAGE,), EmptyInput, snapshot, prepare,
                    aliases=("read current evidence status", "read current evidence collection status",
                             "show continuous evidence status", "open complete evidence controls",
                             "open the complete evidence controls", "review evidence collection controls")),
            Adapter("connections.evidence_source_setup", "Open guided evidence source setup",
                    "connections", PAGE + "#trc-source-form", (PAGE,), EmptyInput, source_snapshot, source_prepare,
                    aliases=("set up an evidence source", "add an evidence source", "configure evidence sources",
                             "open evidence source setup", "repair an evidence source")))
