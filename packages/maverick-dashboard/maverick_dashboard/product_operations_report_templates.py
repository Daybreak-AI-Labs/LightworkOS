"""Reuse an allowed saved report's choices in its existing private editor."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import third_party_executive_reports_api as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput

PAGE = "/third-party/executive-reports"


class ReportIn(StrictInput):
    report: str = Field(..., min_length=1, max_length=128, pattern=native._ID_PATTERN)


def _guard(request):
    from .app import require_page_visible

    with auth.fresh_configuration():
        current = native._report_read_context(request)
        if not (native._report_has_permission(request, "operate") or native._report_has_permission(request, "audit")):
            raise HTTPException(403, "Your current access allows reading reports, but not preparing a new report.")
        auth.require_page_permission(request, PAGE)
        require_page_visible(request, PAGE)
        return current


def _read(request, report=None):
    before = _guard(request)
    factory = getattr(request.app.state, "third_party_executive_reports_runtime_factory", None)
    if not callable(factory):
        raise HTTPException(503, "Executive reports are unavailable. Open the report page to check its setup.")
    try:
        runtime = factory(tenant_id=before[1], request=request)
        records = ([runtime.store.get_report(report, caller_role=runtime.role_view)] if report else
                   runtime.store.list_reports(caller_role=runtime.role_view, limit=500))
        values = [asdict(row) for row in records if getattr(row, "brand", None) is not None and row.state == "active"]
        config_gate = getattr(runtime.store, "_config_gate", None)
        if config_gate is not None:
            config_gate()
    except native._ops().ThirdPartyExecutiveReportPermissionDenied:
        raise HTTPException(403, "This report is not available to your current account.") from None
    except native._ops().ThirdPartyExecutiveReportNotFound:
        raise HTTPException(404, "This saved report is no longer available.") from None
    except (native._ops().ThirdPartyExecutiveReportError, ValueError, OSError):
        raise HTTPException(503, "Current executive reports could not be read. Your entered work is kept.") from None
    if _guard(request) != before:
        raise HTTPException(409, "Your account, workspace or access changed. Open the current report page again.")
    return before[0], values


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Choose the saved report by name in this control.")
    context, rows = _read(request)
    choices = [{"value": row["report_id"], "label": row["brand"]["report_title"] + " — " +
                datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%b %d, %Y at %H:%M:%S UTC")} for row in rows]
    return Snapshot(digest([context, [[row["report_id"], row["integrity_sha256"]] for row in rows]]),
        "Current permitted saved executive reports",
        "Choose from up to 500 recent permitted saved reports. Open a complete private review of its layout and currently available record choices. "
        "Old report findings are not reused. Nothing is created until you separately choose Create report.",
        fields=[{"name": "report", "label": "Saved report", "kind": "select", "required": True, "choices": choices}],
        blocked="Create an executive report first, then use its choices for a later report." if not choices else "")


def prepare(request, selection, arguments):
    snapshot(request, selection)
    context, rows = _read(request, arguments["report"])
    if len(rows) != 1:
        raise HTTPException(409, "This report is no longer an available starting point. Choose a current saved report.")
    row = rows[0]
    return Preview("Review the saved layout and current record choices on the report page. "
                   "Your entered work is kept until you explicitly use those choices; no report is created here.",
        native={"report_starting_point": {"context": context, "report": row["report_id"],
                                           "revision": row["integrity_sha256"]}})


def entries():
    return (Adapter("reports.executive_starting_point", "Start a report from saved choices", "artifacts",
        PAGE + "#tper-editor", (PAGE,), ReportIn, snapshot, prepare,
        aliases=("reuse a report layout", "start from a saved report", "report starting point")),)
