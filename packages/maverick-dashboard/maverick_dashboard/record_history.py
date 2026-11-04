"""Current-authority metadata history across native stores, one bounded window.

Titles/IDs/status only. A cursor carries a position and source digest, never
source contents or an authority grant. Every continuation recollects authority.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import date, datetime, timezone
from datetime import time as daytime
from urllib.parse import quote

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.metadata_history import (
    WINDOW,
    HistoryChanged,
    HistoryNarrowing,
    Window,
    check_scan,
    digest,
    world_window,
)

from .auth import caller_principal, require_permission, require_suite, suite_allowed
from .draft_api import context_for
from .plain_labels import fill_placeholders
from .record_search import item, link

SOURCES = {
    "tasks": ("Tasks", "/goals", "Created"),
    "projects": ("Projects", "/projects", "Created"),
    "workflows": ("Workflows", "/workflows", "Last saved"),
    "automations": ("Automations", "/automations", "Last changed"),
    "connections": ("Connections", "/connections", "Created"),
    "facts": ("Shared facts", "/facts", "Last changed"),
    "questionnaires": ("Questionnaires", "/privacy", "Last saved"),
    "vault": ("Document vault", "/administration/document-vault", "Created"),
    "reports": ("Executive reports", "/third-party/executive-reports", "Created"),
    "vendors": ("Vendor register", "/privacy/vendors", "Created, when recorded"),
    "onboarding": ("Vendor onboarding", "/third-party/vendor-onboarding", "Created, when recorded"),
    "reviews": ("Project reviews", "/project-reviews", "Created, when recorded"),
}


def date_bound(value, *, end=False):
    if not value:
        return None
    selected = date.fromisoformat(value)
    if end:
        from datetime import timedelta
        selected += timedelta(days=1)
    return datetime.combine(selected, daytime(), tzinfo=timezone.utc).timestamp()


def dated(row, value):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            value = None
    row["date"] = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    return row


def projected_window(rows, *, offset, after, before, oldest):
    # The native service already owns complete authority-scoped metadata. Filter
    # before slicing; the first-window cap never defines the historical corpus.
    started = time.monotonic()
    rows = [row for row in rows if (after is None or row.get("date") is not None and row["date"] >= after)
            and (before is None or row.get("date") is not None and row["date"] < before)]
    check_scan(len(rows), started)
    rows.sort(key=lambda row: ((row.get("date") or 0) * (1 if oldest else -1), row["id"], row["kind"]))
    return Window(rows[offset:offset + WINDOW], digest(rows), offset + WINDOW if offset + WINDOW < len(rows) else None)


def _world(request, source, **options):
    from maverick.domain import available_domains, suites_for_domain

    from ._shared import _world as world
    require_permission(request, "view")
    profiles = available_domains()
    value = world_window(world(), source=source, owner=caller_principal(request) or "",
                         allowed_domain=lambda domain: not domain or all(
                             suite_allowed(request, suite)
                             for suite in suites_for_domain(domain, profiles.get(domain))
                         ), **options)
    rows = []
    for row in value.rows:
        if source == "tasks":
            out = item("task", row["id"], row["title"], href=f"/chat/goal/{row['id']}", state=row["status"], revision=row["updated_at"], source=source)
        elif source == "projects":
            out = item("project", row["id"], row["name"], href=f"/projects/{row['id']}", state=row["status"], source=source)
        else:
            out = item("fact", row["key"], row["key"], href=link("/facts", "key", row["key"]), state=row["source"], revision=row["updated_at"], source=source)
        rows.append(dated(out, row.get("created_at", row.get("updated_at"))))
    value.rows = rows
    return value


def _vault(request, **options):
    from .governed_document_vault_api import _tenant_id
    from .governed_document_vault_composition import governed_document_vault_enabled
    require_permission(request, "view")
    tenant = _tenant_id()
    probe = getattr(request.app.state, "governed_document_vault_enabled_probe", None)
    if (probe if callable(probe) else governed_document_vault_enabled)(tenant) is not True:
        raise HTTPException(403, "Document vault unavailable")
    store = request.app.state.governed_document_vault_store_factory(tenant, request)
    value = store.history_window(**options)
    value.rows = [dated(item("evidence", row.document_ref, row.safe_display_name,
                        href=link("/administration/document-vault", "document", row.document_ref),
                        state=row.state, revision=row.content_revision, source="document vault"), row.created_at) for row in value.rows]
    return value


def _reports(request, **options):
    from .third_party_executive_reports_api import _require_report_permission, _tenant_id
    _require_report_permission(request, "view")
    runtime = request.app.state.third_party_executive_reports_runtime_factory(tenant_id=_tenant_id(), request=request)
    value = runtime.store.history_window(caller_role=runtime.role_view, **options)
    value.rows = [dated(item("report", row.report_id, getattr(getattr(row, "brand", None), "report_title", "Executive report"),
                        href=link("/third-party/executive-reports", "report", row.report_id), state=row.state,
                        revision=row.control_revision, source="executive reports"), row.created_at) for row in value.rows]
    return value


def _assessments(request, **options):
    from maverick.assessment import custom_template_records, history_heads

    from .app import FINANCE_ASSESSMENT_TYPES, PRIVACY_ASSESSMENT_TYPES, SECURITY_ASSESSMENT_TYPES
    require_permission(request, "operate")
    mapping = {kind: suite for suite, kinds in (("finance", FINANCE_ASSESSMENT_TYPES),
        ("privacy", PRIVACY_ASSESSMENT_TYPES), ("security", SECURITY_ASSESSMENT_TYPES)) for kind in kinds}
    mapping.update({kind: record.get("department", "privacy") for kind, record in custom_template_records().items()})
    allowed = {kind for kind, suite in mapping.items() if suite in {"finance", "privacy", "security"} and suite_allowed(request, suite)}
    value = history_heads(allowed_types=allowed, **options)
    rows = []
    for row in value.rows:
        suite = mapping.get(row.get("type"))
        if suite not in {"finance", "privacy", "security"} or not suite_allowed(request, suite):
            continue
        for kind in ("assessment", "decision") if row.get("status") in {"approved", "rejected"} else ("assessment",):
            rows.append(dated(item(kind, row["id"], row.get("subject"), href=link("/" + suite, "assessment", row["id"]),
                           state=row.get("status"), revision=row.get("revision"), source="questionnaires"), row["date"]))
    value.rows = rows
    return value


def _workflows(request, *, after=None, before=None):
    from maverick import flow
    from maverick.flow.store import list_flow_summaries
    from maverick.templates import can_read_template, list_templates, load_template
    require_permission(request, "view")
    owner = caller_principal(request) or ""
    rows = [dated(item("workflow", row["id"], row["name"], href="/flows/designer/" + quote(row["id"], safe=""),
                 state="Flow definition", revision=row["revision"] or row["version"], source="workflows"), row["updated_at"])
            for row in (list_flow_summaries(owner=owner, after=after, before=before, bounded=True) if flow.enabled() else [])]
    started = time.monotonic()
    for count, name in enumerate(list_templates(), 1):
        check_scan(count, started)
        template = load_template(name)
        if not can_read_template(template, owner):
            continue
        # Show template blanks as the Templates page does ("[Team]"), never raw "{{ team }}".
        rows.append(dated(item("workflow", name, fill_placeholders(template.title), href=link("/workflow-builder", "edit", name),
                         state="Task template", revision=template.generation, source="workflows"), template.path.stat().st_mtime))
    return rows


def _automations(request):
    from maverick.job_queue import JobQueue
    require_permission(request, "operate")
    owner = caller_principal(request) or ""
    with JobQueue()._conn() as connection:
        # Payload bodies never leave this projection. This source remains local
        # queue metadata and cannot run or rearm any schedule.
        rows = connection.execute("SELECT id,payload,state,revision,updated_at FROM schedule_definitions "
                                  "WHERE COALESCE(json_extract(payload,'$.owner'),'')=?", (owner,)).fetchall()
        return [dated(item("automation", row["id"], json.loads(row["payload"]).get("title") or json.loads(row["payload"]).get("template") or "Scheduled work",
                     href="/automations#schedule-" + quote(row["id"], safe=""), state=row["state"], revision=row["revision"], source="automations"), row["updated_at"]) for row in rows]


def _connections(request):
    from maverick import connections

    from .connection_dependencies import owned_connections
    require_permission(request, "operate")
    if not connections.enabled():
        raise HTTPException(403, "Connections unavailable")
    return [dated(item("connection", row["name"], row["name"], href="/connections#connection-" + quote(row["name"], safe=""),
                       state="Authorization recorded; check current access" if row.get("oauth") else "Credential saved; check current access" if row.get("has_token") else "Credential not saved", revision=row["revision"], source="connections"),
                  row.get("created")) for row in owned_connections(request)]


def _vendors(request):
    from maverick import vendor_management
    require_permission(request, "operate")
    require_suite(request, "privacy")
    return [dated(item("vendor", row["id"], row.get("name"), href="/privacy/vendors/" + quote(row["id"], safe=""),
                       state=row.get("status"), revision=row.get("revision"), source="vendor register"), row.get("registered_at"))
            for row in vendor_management.list_vendors()]


def _onboarding(request):
    from .vendor_onboarding_api import _binding, _call
    out = []
    for row in _call(_binding(request), "list"):
        href = link("/third-party/vendor-onboarding", "case", row["id"])
        out.append(dated(item("vendor", row["id"], row.get("vendor_name"), href=href, state=row.get("stage"), revision=row.get("revision"), source="vendor onboarding"), row.get("created_at")))
        evidence = row.get("evidence") or {}
        for index, document in enumerate(evidence.get("documents") or ([evidence] if evidence else [])):
            if isinstance(document, dict):
                out.append(dated(item("evidence", document.get("document_id", index), row.get("vendor_name"), href=href,
                                     state=document.get("status"), revision=row.get("revision"), source="vendor evidence"), row.get("created_at")))
        for review in (row.get("review_history") or [])[-1:]:
            if isinstance(review, dict) and review.get("decision") in {"approved", "rejected"}:
                out.append(dated(item("decision", row["id"], row.get("vendor_name"), href=href,
                                     state=review["decision"], revision=review.get("assessment_revision"), source="vendor review"), row.get("created_at")))
    return out


def _reviews(request):
    from .project_reviews_api import _service
    return [dated(item("decision", row["id"], row["title"], href="/project-reviews#packet=" + quote(row["id"], safe=""),
                       state="source changed" if row["stale"] else row["status"], revision=row["revision"], source="project reviews"), row.get("created_at"))
            for row in _service(request).inbox()]


def load_window(request, source, **options):
    if source in {"tasks", "projects", "facts"}:
        return _world(request, source, **options)
    native = {"vault": _vault, "reports": _reports, "questionnaires": _assessments}
    if source in native:
        return native[source](request, **options)
    projected = {"workflows": _workflows, "automations": _automations, "connections": _connections,
                 "vendors": _vendors, "onboarding": _onboarding, "reviews": _reviews}
    rows = _workflows(request, after=options.get("after"), before=options.get("before")) if source == "workflows" else projected[source](request)
    return projected_window(rows, **options)


def _position(cursor, binding):
    if not cursor:
        return 0, 0, ""
    try:
        sealed = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        decoded = json.loads(crypto_at_rest.unseal_bound(sealed, "record-history/" + binding))
        if decoded["binding"] != binding or set(decoded) != {"binding", "offset", "skip", "snapshot"}:
            raise ValueError
        if type(decoded["offset"]) is not int or not 0 <= decoded["offset"] <= 100_000_000:
            raise ValueError
        if type(decoded["skip"]) is not int or not 0 <= decoded["skip"] <= WINDOW * 2:
            raise ValueError
        return decoded["offset"], decoded["skip"], decoded["snapshot"]
    except Exception:
        raise HistoryChanged("History filters or account changed. Start a fresh search.") from None


def search_history(request, *, source, query="", kind="all", after="", before="", oldest=False, cursor=None, limit=20):
    if source not in SOURCES:
        raise ValueError("Choose a historical source")
    require_permission(request, "view")
    context = context_for(request)
    binding = digest([context, source, query, kind, after, before, oldest])
    offset, skip, snapshot = _position(cursor, binding)
    options = {"offset": offset, "after": date_bound(after), "before": date_bound(before, end=True), "oldest": oldest}
    started = time.monotonic()
    try:
        value = load_window(request, source, **options)
    except HistoryChanged:
        raise
    except HistoryNarrowing:
        label, href, basis = SOURCES[source]
        return {"items": [], "total": 0, "snapshot": binding, "next_offset": None, "next_cursor": None,
                "complete": False, "coverage": [{"source": label, "state": "partial", "href": href}],
                "mode": "history", "context": context, "date_basis": basis,
                "notice": "This source exceeded the metadata scan budget. Choose a narrower UTC date range and search again; no exhaustive result count is available."}
    except Exception as exc:
        # Source error text can contain private identities. The workspace is the
        # recovery surface, and a denied source contributes no counts or snippets.
        if cursor:
            raise HTTPException(409, "This historical source or access changed. Start a fresh search or open its workspace.") from exc
        label, href, basis = SOURCES[source]
        return {"items": [], "total": 0, "snapshot": binding, "next_offset": None, "next_cursor": None,
                "complete": False, "coverage": [{"source": label, "state": "unavailable", "href": href}],
                "mode": "history", "context": context, "date_basis": basis,
                "notice": "This source is unavailable for current access. Open its workspace to resolve access or availability; no source records were counted."}
    current = digest([binding, value.snapshot])
    if snapshot and snapshot != current:
        raise HistoryChanged("Records or access changed while paging. Start a fresh search.")
    terms = query.casefold().split()
    matches = [row for row in value.rows if (kind == "all" or row["kind"] == kind)
               and all(term in " ".join(row[key] for key in ("id", "title", "state", "revision")).casefold() for term in terms)]
    rows = matches[skip:skip + limit]
    position = None
    if skip + limit < len(matches):
        position = {"offset": offset, "skip": skip + limit}
    elif value.next_offset is not None:
        position = {"offset": value.next_offset, "skip": 0}
    try:
        encoded = None if position is None else base64.urlsafe_b64encode(crypto_at_rest.seal_bound(
            json.dumps({**position, "snapshot": current, "binding": binding}).encode(), "record-history/" + binding)).decode().rstrip("=")
    except Exception as exc:
        raise HTTPException(503, "This page could not be continued securely. Open the source workspace or try again after storage recovery.") from exc
    if context != context_for(request):
        raise HistoryChanged("Access changed during search. Reload before searching again.")
    require_permission(request, "view")
    label, href, basis = SOURCES[source]
    return {"items": rows, "total": len(rows), "snapshot": current, "next_offset": None, "next_cursor": encoded,
            "complete": position is None, "coverage": [{"source": label, "state": "current" if position is None else "partial", "href": href}],
            "mode": "history", "context": context, "date_basis": basis, "elapsed_ms": round((time.monotonic() - started) * 1000),
            "notice": "Counts cover returned matches only. Continue through remaining windows; narrow dates to reduce work. Dates are UTC: " + basis.lower() + ". Records without a known date are excluded only when dates are selected."}
