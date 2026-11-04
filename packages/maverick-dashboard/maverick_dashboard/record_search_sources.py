"""Read-only search adapters using the same authority as each review surface."""
from __future__ import annotations

from urllib.parse import quote

from fastapi import HTTPException

from .auth import (
    domain_suites_allowed,
    goal_owner_filter,
    require_permission,
    require_suite,
    suite_allowed,
)
from .record_search import SOURCE_LIMIT, Source, SourceOff, item, link


def _workspace(tenant_id):
    """The selected workspace; a workspace-bound source with none selected is
    off rather than failed (its own check answers 409)."""
    try:
        return tenant_id()
    except HTTPException as exc:
        if exc.status_code == 409:
            raise SourceOff("no workspace selected") from exc
        raise


def _tasks(request):
    from .app import _deliverable_specs, _world

    require_permission(request, "view")
    rows = _world().list_goals(owner=goal_owner_filter(request), limit=SOURCE_LIMIT + 1, order="desc")
    specs = ({spec["domain"] for spec in _deliverable_specs()}
             if any(row.status == "done" and row.domain for row in rows[:SOURCE_LIMIT]) else set())
    out = []
    for row in rows[:SOURCE_LIMIT]:
        if not domain_suites_allowed(request, row.domain):
            continue
        kind = "report" if row.status == "done" and row.domain in specs else "task"
        out.append(item(kind, row.id, row.title, href=f"/chat/goal/{row.id}", state=row.status, source="tasks"))
    return Source(out, len(rows) <= SOURCE_LIMIT)


def _vendors(request):
    from maverick import vendor_management

    require_permission(request, "operate")
    require_suite(request, "privacy")
    try:
        rows = vendor_management.list_vendors()
    except vendor_management.VendorManagementConfigError as exc:
        raise SourceOff("vendor management is off") from exc
    return Source([item("vendor", row["id"], row.get("name"),
                        href="/privacy/vendors/" + quote(row["id"], safe=""),
                        state=row.get("status"), revision=row.get("revision"), source="vendor register")
                   for row in rows[:SOURCE_LIMIT]], len(rows) <= SOURCE_LIMIT)


def _onboarding(request):
    from maverick.paths import current_tenant_id_strict

    from .vendor_onboarding_api import _binding, _call
    from .vendor_onboarding_composition import settings

    if not current_tenant_id_strict() or not settings().enable:
        raise SourceOff("vendor onboarding is off in this workspace")
    rows = _call(_binding(request), "list")
    out = []
    for row in rows[:SOURCE_LIMIT]:
        href = link("/third-party/vendor-onboarding", "case", row["id"])
        out.append(item("vendor", row["id"], row.get("vendor_name"), href=href,
                        state=row.get("stage"), revision=row.get("revision"), source="vendor onboarding"))
        # Only persisted document identities are searched, never extracted text,
        # evidence URLs, answers, notes, tickets, or provider-backed Drive search.
        evidence = row.get("evidence") or {}
        for index, document in enumerate(evidence.get("documents") or ([evidence] if evidence else [])):
            if not isinstance(document, dict):
                continue
            out.append(item("evidence", document.get("document_id", index), row.get("vendor_name"),
                            href=href, state=document.get("status"), revision=row.get("revision"),
                            source="vendor evidence"))
        for review in (row.get("review_history") or [])[-1:]:
            if isinstance(review, dict) and review.get("decision") in {"approved", "rejected"}:
                out.append(item("decision", row["id"], row.get("vendor_name"), href=href,
                                state=review["decision"], revision=review.get("assessment_revision"), source="vendor review"))
    return Source(out, len(rows) <= SOURCE_LIMIT)


def _assessments(request):
    from maverick.assessment import custom_template_records, list_saved_heads

    from .app import FINANCE_ASSESSMENT_TYPES, PRIVACY_ASSESSMENT_TYPES, SECURITY_ASSESSMENT_TYPES

    require_permission(request, "operate")
    mapping = {kind: suite for suite, kinds in (("finance", FINANCE_ASSESSMENT_TYPES),
        ("privacy", PRIVACY_ASSESSMENT_TYPES), ("security", SECURITY_ASSESSMENT_TYPES)) for kind in kinds}
    mapping.update({kind: record.get("department", "privacy") for kind, record in custom_template_records().items()})
    records, scanned_total = list_saved_heads(limit=SOURCE_LIMIT)
    out = []
    for row in records:
        suite = mapping.get(row.get("type"))
        if suite not in {"finance", "privacy", "security"} or not suite_allowed(request, suite):
            continue
        href = link("/" + suite, "assessment", row["id"])
        for kind in ("assessment", "decision") if row.get("status") in {"approved", "rejected"} else ("assessment",):
            out.append(item(kind, row["id"], row.get("subject"), href=href,
                            state=row.get("status"), revision=row.get("revision"), source="questionnaires"))
    return Source(out, scanned_total <= SOURCE_LIMIT)


def _vault(request):
    from .governed_document_vault_api import _tenant_id
    from .governed_document_vault_composition import governed_document_vault_enabled

    require_permission(request, "view")
    tenant = _workspace(_tenant_id)
    probe = getattr(request.app.state, "governed_document_vault_enabled_probe", None)
    if (probe if callable(probe) else governed_document_vault_enabled)(tenant) is not True:
        raise HTTPException(403, "disabled")
    store = request.app.state.governed_document_vault_store_factory(tenant, request)
    rows = store.list_documents(limit=500)
    return Source([item("evidence", row.document_ref, row.safe_display_name,
                        href=link("/administration/document-vault", "document", row.document_ref),
                        state=row.state, revision=row.content_revision, source="document vault") for row in rows],
                  len(rows) < 500)


def _reports(request):
    from maverick.third_party_executive_reports import ThirdPartyExecutiveReportConfigError

    from .third_party_executive_reports_api import _require_report_permission, _tenant_id

    _require_report_permission(request, "view")
    tenant = _workspace(_tenant_id)
    try:
        selected = request.app.state.third_party_executive_reports_runtime_factory(tenant_id=tenant, request=request)
    except ThirdPartyExecutiveReportConfigError as exc:
        if exc.error_code == "executive_report_disabled":
            raise SourceOff("executive reports are off in this workspace") from exc
        raise
    rows = selected.store.list_reports(caller_role=selected.role_view, limit=500)
    return Source([item("report", row.report_id, getattr(getattr(row, "brand", None), "report_title", "Executive report"),
                        href=link("/third-party/executive-reports", "report", row.report_id),
                        state=row.state, revision=row.control_revision, source="executive reports") for row in rows],
                  len(rows) < 500)


def _project_reviews(request):
    from .project_reviews_api import _service

    # Recheck current workspace membership, suite and packet assignment before
    # projecting metadata. The packet's captured result and comments stay out
    # of search, and the destination performs another exact authorized read.
    rows = _service(request).inbox()
    return Source([item("decision", row["id"], row["title"],
                        href="/project-reviews#packet=" + quote(row["id"], safe=""),
                        state="source changed" if row["stale"] else row["status"],
                        revision=row["revision"], source="project reviews")
                   for row in rows[:SOURCE_LIMIT]], len(rows) <= SOURCE_LIMIT)


def _additional(request, source):
    from maverick.metadata_history import HistoryNarrowing

    from .record_history import load_window
    try:
        value = load_window(request, source, offset=0, after=None, before=None, oldest=False)
    except HistoryNarrowing:
        return Source([], False)
    return Source(value.rows, value.next_offset is None)


def sources_for(request, kind):
    sources = {
        "tasks": ({"task", "report"}, _tasks),
        "vendor register": ({"vendor"}, _vendors),
        "vendor onboarding": ({"vendor", "evidence", "decision"}, _onboarding),
        "questionnaires": ({"assessment", "decision"}, _assessments),
        "document vault": ({"evidence"}, _vault),
        "executive reports": ({"report"}, _reports),
        "project reviews": ({"decision"}, _project_reviews),
        **{source: ({kind}, lambda request, source=source: _additional(request, source))
           for source, kind in (("projects", "project"), ("workflows", "workflow"),
                                ("automations", "automation"), ("connections", "connection"), ("facts", "fact"))},
    }
    return {name: (lambda load=load: load(request)) for name, (kinds, load) in sources.items()
            if kind == "all" or kind in kinds}
