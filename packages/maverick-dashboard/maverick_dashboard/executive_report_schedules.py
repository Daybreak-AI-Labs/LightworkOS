"""Reviewed recurring native PDFs on the existing dashboard automation queue."""
from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass
from uuid import uuid4

from fastapi import HTTPException, Request
from maverick import crypto_at_rest
from maverick import third_party_executive_reports as reports
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.paths import current_tenant_id_strict

from . import auth
from .third_party_executive_reports_composition import _build_runtime

PAGE = "/third-party/executive-reports"
KIND = "executive_report"
PURPOSE = "lightwork.executive-report-schedule.v1"
MAX_BYTES = 262144
KINDS = {"intelligence_vendor": "Vendor", "intelligence_finding": "Screening finding",
         "lifecycle_assessment": "Assessment", "lifecycle_record": "Vendor relationship",
         "contract_record": "Contract or engagement", "collaboration_invitation": "Vendor questionnaire"}


@dataclass(frozen=True)
class _ScheduledReportKeyAuthority:
    owner: str
    tenant: str
    role: str
    key: str
    scopes: frozenset[str]
    permissions: frozenset[str]
    suites: frozenset[str] | None


def refresh_background_key(request):
    """Current native key floor for this server-created request; no retained bearer."""
    from maverick.tenant.registry import assert_tenant_active

    from . import api_keys, workspace_tenants
    from .rbac import permissions_for
    from .session_revocation import is_revoked

    grant = getattr(request.state, "_scheduled_report_key_authority", None)
    try:
        if type(grant) is not _ScheduledReportKeyAuthority:
            raise ValueError
        principal = getattr(request.state, "principal", None)
        if ((getattr(principal, "claims", None) or {}).get("via") != "scheduled_report"
                or principal.principal != grant.owner or current_tenant_id_strict() != grant.tenant):
            raise ValueError
        assert_tenant_active(grant.tenant)
        owner, _user, suites = auth.stored_automation_identity(grant.owner)
        if auth.role_for_principal(owner) != grant.role or suites != grant.suites:
            raise ValueError
        key = api_keys.get_key(grant.key)
        if (key is None or not api_keys.enabled() or key.owner != owner
                or key.status() not in {"active", "expiring", "rotating"}
                or (key.workspace and (key.workspace != grant.tenant
                    or not workspace_tenants.principal_can_select(owner, grant.tenant)))):
            raise ValueError
        if key.is_service_account:
            account = api_keys.get_service_account(owner.removeprefix("user:svc:"))
            if account is None or account.disabled_at is not None:
                raise ValueError
        elif is_revoked(owner.removeprefix("user:"), key.created_at):
            raise ValueError
        scopes = frozenset(key.scopes) & grant.scopes
        if frozenset(key.scopes) != grant.scopes:
            raise ValueError
        permissions = (frozenset(permissions_for(grant.role)) & grant.permissions
                       & api_keys.effective_permissions(scopes, owner))
        if not {"operate", "view"} <= permissions or not scopes & {"tasks:write", "admin"}:
            raise ValueError
        request.state.api_key_id = grant.key
        request.state.api_key_permissions = permissions
        request.state.api_key_scopes = scopes
    except Exception as exc:
        request.state.api_key_permissions = frozenset()
        request.state.api_key_scopes = frozenset()
        raise HTTPException(403, "This report's current access key or owner permissions are unavailable.") from exc


def seal(value):
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(raw.encode()) > MAX_BYTES:
        raise HTTPException(422, "This complete report schedule is too large to review. Choose fewer records.")
    with crypto_at_rest.deployment_key_scope():
        result = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(result):
        raise HTTPException(503, "This request could not be protected. No schedule was created.")
    return result


def unseal(reference):
    try:
        if not isinstance(reference, str) or len(reference) > MAX_BYTES * 3 or not crypto_at_rest.is_sealed_str(reference):
            raise ValueError
        with crypto_at_rest.deployment_key_scope():
            value = json.loads(crypto_at_rest.unseal_from_str(reference))
        if not isinstance(value, dict) or value.get("purpose") != PURPOSE:
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This original request could not be verified. Nothing was repeated.") from exc


def authority(request, expected=None, *, write=False):
    from maverick import config

    from .api_flow_operator_review import _workspace_authority
    from .app import require_page_visible
    from .draft_api import context_for

    with auth.fresh_configuration():
        initial = getattr(request.state, "principal", None)
        claims = getattr(initial, "claims", None) or {}
        via = claims.get("via")
        fresh = initial
        if via == "api_key":
            fresh = auth._authenticate_api_key(request, auth._api_key_bearer(request))
        elif via in {"session", "invite", "proxy"}:
            fresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                     "proxy": auth._proxy_principal}[via](request)
        if initial is not None:
            if fresh is None or fresh.principal != initial.principal:
                raise HTTPException(401, "Sign in again before continuing with report schedules.")
            request.state.principal = fresh
            expiry = fresh.claims.get("exp")
            if expiry is not None and (type(expiry) not in {int, float} or not time.time() < expiry < math.inf):
                raise HTTPException(401, "Sign in again before continuing with report schedules.")
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        auth.require_permission(request, "operate")
        auth.require_page_permission(request, PAGE)
        require_page_visible(request, PAGE)
        context = context_for(request)
        if expected is not None and context != expected:
            raise HTTPException(409, "Your account or workspace changed. Open the current report page again.")
        owner = auth.durable_automation_owner(request)
        tenant = current_tenant_id_strict() or ""
        if not tenant:
            raise HTTPException(409, "Choose a workspace before using report schedules.")
        suites, scopes = auth.caller_suites(request), auth.api_key_scopes(request)
        binding = _workspace_authority(request, owner, tenant)
        from .rbac import permissions_for
        permissions = permissions_for(auth.caller_role(request)) if owner else {"admin", "audit", "operate", "view"}
        if auth.api_key_permissions(request) is not None:
            permissions = set(permissions) & set(auth.api_key_permissions(request))
        from .mfa_policy import principal_mfa
        mfa, _ = principal_mfa(fresh) if fresh is not None else (False, None)
        value = {"context": context, "owner": owner, "tenant": tenant,
                 "role": auth.caller_role(request) or "admin", "permissions": sorted(permissions),
                 "suites": None if suites is None else sorted(suites), "scopes": None if scopes is None else sorted(scopes),
                 "key": (getattr(request.state, "principal", None).claims.get("api_key_id", "") if via == "api_key" else ""),
                 "workspace_source": getattr(request.state, "workspace_tenant_source", "operator_floor"), "workspace_binding": binding,
                 "mfa": mfa, "address": request.client.host if request.client else ""}
        if write:
            from .schedule_policy import require_scheduling as _require_scheduling
            if config.config_source_errors(include_tenant=True):
                raise HTTPException(503, "Current report settings are unavailable. Your entered choices are kept.")
            _require_scheduling()
            _build_runtime(request.app, tenant_id=tenant, request=request)
        return value


def _layout(runtime, identity, revision=None):
    record = runtime.store.get_report(identity, caller_role=runtime.role_view)
    if not isinstance(record, reports.ExecutiveReportRecord) or record.state != "active":
        raise HTTPException(409, "This saved layout is unavailable or withdrawn. Choose a current report.")
    if revision is not None and record.integrity_sha256 != revision:
        raise HTTPException(409, "This saved report changed. Review its current layout again.")
    return record


def _selectors(record):
    return tuple(reports.SourceSelector(row.source_kind, row.source_id) for row in record.snapshot.sources)


def _snapshot(runtime, selectors, when):
    return runtime.source_resolver.resolve(selectors, role_view=runtime.role_view,
        captured_at=when, max_sources=runtime._max_sources)


def _source_names(runtime, snapshot):
    resolver = runtime.source_resolver
    result = []
    for source in snapshot.sources:
        kind, identity = source.source_kind, source.source_id
        label = "Name unavailable in this view"
        if source.state == "available":
            if kind.startswith("intelligence_"):
                store = resolver._intelligence_store()
                row = (store.get_vendor if kind == "intelligence_vendor" else store.get_finding)(snapshot.tenant_id, identity)
            elif kind.startswith("lifecycle_"):
                store = resolver._lifecycle_store()
                row = (store.get_assessment if kind == "lifecycle_assessment" else store.get_lifecycle)(snapshot.tenant_id, identity)
            elif kind == "contract_record":
                row = resolver._contract_store().get_record(snapshot.tenant_id, identity)
            else:
                row = resolver._collaboration_store().get_invitation(snapshot.tenant_id, identity)
            data = dict(row) if isinstance(row, dict) else asdict(row)
            label = next((str(data[key]) for key in ("display_label", "title", "name", "vendor_name", "label")
                          if isinstance(data.get(key), str) and data[key].strip()), label)
        result.append({"kind": KINDS[kind], "name": label, "available": source.state == "available",
                       "reviewed_version": source.revision})
    return result


def options(request):
    before = authority(request)
    available = True
    message = "Choose a saved report and a timetable. Each run reads the selected records again."
    rows = []
    try:
        if auth.require_durable_automation_creator(request) != before["owner"]:
            raise HTTPException(409, "Your account changed. Review sign-in before scheduling.")
        authority(request, before["context"], write=True)
        runtime = _build_runtime(request.app, tenant_id=before["tenant"], request=request)
        rows = [{"value": row.report_id, "revision": row.integrity_sha256,
                 "label": row.brand.report_title + " — " + time.strftime("%b %d, %Y %H:%M UTC", time.gmtime(row.created_at))}
                for row in runtime.store.list_reports(caller_role=runtime.role_view, limit=500)
                if isinstance(row, reports.ExecutiveReportRecord) and row.state == "active"]
    except HTTPException as exc:
        available = False
        if "named account" in str(exc.detail):
            message = "Sign in with a named account to create a report schedule. You can still check or stop existing requests."
        else:
            message = "New report schedules are unavailable or turned off. You can still check an original request and stop future runs."
    except reports.ThirdPartyExecutiveReportError:
        available = False
        message = "New report schedules are unavailable or turned off. You can still check an original request and stop future runs."
    if before != authority(request):
        raise HTTPException(409, "Your access changed. Open the current report page again.")
    from .schedule_ops_api import _zones
    return {"context": before["context"], "enabled": available, "choices": rows, "zones": _zones(), "message": message}


def review(request, body):
    from .schedule_ops_api import TimetableIn, _cron
    with authority_effect_fence():
        current = authority(request, body["context"], write=True)
        if auth.require_durable_automation_creator(request) != current["owner"]:
            raise HTTPException(409, "Your account changed. Review sign-in before scheduling.")
        runtime = _build_runtime(request.app, tenant_id=current["tenant"], request=request)
        layout = _layout(runtime, body["report"], body["revision"])
        cron, zone, runs = _cron(TimetableIn.model_validate(body["timetable"]))
        snapshot = _snapshot(runtime, _selectors(layout), time.time())
        if not snapshot.sources or any(row.state != "available" for row in snapshot.sources):
            raise HTTPException(409, "Every selected record must be available before scheduling. Open the report's records and review current access.")
        names = _source_names(runtime, snapshot)
        operation = uuid4().hex
        recipe = {"purpose": PURPOSE, "operation": operation, "authority": current,
                  "layout": layout.report_id, "layout_revision": layout.integrity_sha256,
                  "brand": asdict(layout.brand), "selectors": [asdict(row) for row in _selectors(layout)],
                  "reviewed_sources": [asdict(row) for row in snapshot.sources]}
        payload = {"tenant": current["tenant"], "owner": current["owner"], "title": layout.brand.report_title,
                   "__cron__": cron, "__tz__": zone, "schedule_id": operation, "report_recipe": seal(recipe)}
        value = {"purpose": PURPOSE, "operation": operation, "authority": current, "expires": time.time()+600,
                 "body": body, "payload": payload, "runs": runs}
        reference = seal(value)
        if current != authority(request, body["context"], write=True) or _layout(runtime, layout.report_id).integrity_sha256 != layout.integrity_sha256:
            raise HTTPException(409, "The layout or your access changed. Review current choices again.")
        if [asdict(row) for row in _snapshot(runtime, _selectors(layout), snapshot.captured_at).sources] != recipe["reviewed_sources"]:
            raise HTTPException(409, "A selected record changed. Review current records again.")
        return {"context": current["context"], "reference": reference, "layout": asdict(layout.brand),
                "sources": names, "timetable": body["timetable"], "next_runs": runs,
                "notice": "These are the current selected records. Future runs use their then-current contents and your current access. "
                          "A missing or inaccessible record stops that run. No AI is used and no report is sent to anyone. "
                          "Stop prevents future PDF creation; it does not withdraw PDFs already created. Check original after an interrupted reply."}


def _owned(request, value):
    current = authority(request, value["authority"]["context"])
    if any(current[key] != value["authority"][key] for key in ("context", "owner", "tenant")):
        raise HTTPException(404, "This original request belongs to another account or workspace.")
    return current


def original(request, reference):
    from .automation_queue import queue
    value = unseal(reference)
    with authority_effect_fence():
        _owned(request, value)
        identity = queue().admission_receipt(KIND, value["payload"], idempotency_key="report-schedule:"+value["operation"])
        result = {"context": value["authority"]["context"], "found": identity is not None,
                  "message": ("The original report schedule was created. Nothing was created or run again." if identity is not None else
                              "This exact creation is not confirmed. It may still be underway; check current schedules before separately reviewing another creation.")}
        if identity is not None:
            row = queue().get(identity)
            result.update(id=identity, definition=row.recurrence_id if row else None)
        _owned(request, value)
        return result


def _access_holds(current, reviewed):
    """Whether the access a person reviewed under still holds on a later request.

    The source address and second-factor flag are not part of what is reviewed:
    ``authority`` re-checks the workspace's allowed addresses and second-factor
    policy on this very request, and each scheduled run checks them again for
    the reviewed address. So a changed network or a stronger sign-in does not
    void the review; a weaker sign-in, or any other change, still does."""
    keys = (set(current) | set(reviewed)) - {"address", "mfa"}
    return (all(current.get(key) == reviewed.get(key) for key in keys)
            and (bool(current.get("mfa")) or not reviewed.get("mfa")))


def create(request, reference, body):
    from .automation_queue import queue, start
    value = unseal(reference)
    if digest(body) != digest(value["body"]):
        raise HTTPException(409, "Your choices changed after review. Your draft is kept; review it again.")
    with authority_effect_fence():
        prior = original(request, reference)
        if prior["found"]:
            return prior
        def current():
            if auth.require_durable_automation_creator(request) != value["authority"]["owner"]:
                raise HTTPException(409, "Your account changed. Review sign-in before scheduling.")
            if not _access_holds(authority(request, value["authority"]["context"], write=True), value["authority"]):
                raise HTTPException(409, "Your access changed. Review the current report schedule again.")
            recipe = unseal(value["payload"]["report_recipe"])
            runtime = _build_runtime(request.app, tenant_id=value["authority"]["tenant"], request=request)
            layout = _layout(runtime, recipe["layout"], recipe["layout_revision"])
            sources = _snapshot(runtime, _selectors(layout), time.time()).sources
            if [asdict(row) for row in sources] != recipe["reviewed_sources"]:
                raise HTTPException(409, "A selected record changed. Review its current contents before scheduling.")
            if time.time() >= min(value["expires"], value["runs"][0]):
                raise HTTPException(409, "This review expired. Review current choices again; no new schedule was created.")
            if not _access_holds(authority(request, value["authority"]["context"], write=True), value["authority"]):
                raise HTTPException(409, "Your access changed. Review current choices again.")
        current()
        queue().enqueue_once(KIND, value["payload"], idempotency_key="report-schedule:"+value["operation"],
                             run_at=value["runs"][0], effect_guard=current)
    # Startup cannot change a confirmed admission into permission to repeat it.
    try:
        start()
    except Exception:
        pass
    return original(request, reference)


def listing(request):
    from maverick.schedule_definitions import list_definitions

    from .automation_queue import queue
    before = authority(request)
    rows = []
    for row in list_definitions(queue(), owner=before["owner"]):
        if row["kind"] == KIND:
            job = queue().get(row["id"])
            if job and job.payload.get("tenant") == before["tenant"]:
                rows.append(row)
    result = []
    for row in rows[:100]:
        # Queue errors never release a traceback or selected-source body.
        history = []
        for item in row["history"]:
            job = queue().get(item["id"])
            phase = (job.payload.get("report_phase") if job else None) or ("scheduled" if item["status"] == "pending" else "stopped")
            history.append({"id": item["id"], "state": phase, "when": item["run_at"],
                            "report": job.payload.get("created_report") if job and phase == "created" else None})
        visible = False
        try:
            job = queue().get(row["id"])
            recipe = unseal(job.payload["report_recipe"])
            runtime = _build_runtime(request.app, tenant_id=before["tenant"], request=request)
            layout = _layout(runtime, recipe["layout"], recipe["layout_revision"])
            visible = all(source.state == "available" for source in _snapshot(runtime, _selectors(layout), time.time()).sources)
        except (HTTPException, reports.ThirdPartyExecutiveReportError, OSError, ValueError, KeyError):
            pass
        result.append({"definition": row["definition_id"], "revision": row["revision"], "state": row["state"],
                       "title": row["title"] if visible else "Saved report schedule — private layout unavailable",
                       "next_run": row["next_run"], "history": history})
    if before != authority(request):
        raise HTTPException(409, "Your access changed. Open the current report page again.")
    return {"context": before["context"], "items": result, "limit": 100, "more": len(rows)>100}


def stop(request, definition, revision):
    from maverick.schedule_definitions import change_definition

    from .automation_queue import queue
    with authority_effect_fence():
        current = authority(request)
        with queue()._conn() as connection:
            row = connection.execute("SELECT kind,payload FROM schedule_definitions WHERE id=?", (definition,)).fetchone()
        if row is None or row["kind"] != KIND or json.loads(row["payload"]).get("tenant") != current["tenant"]:
            raise HTTPException(404, "This report schedule is unavailable in the current workspace.")
        # Existing native CAS cancels only unattempted future occurrences.
        try:
            return change_definition(queue(), definition, expected_revision=revision, state="retired",
                owner=current["owner"], actor=current["owner"] or "local", rationale="Stopped future report creation")
        except KeyError as exc:
            raise HTTPException(404, "This report schedule is unavailable.") from exc
        except ValueError as exc:
            raise HTTPException(409, "This schedule changed. Refresh before stopping future runs.") from exc


def occurrence_original(request, identity):
    from .automation_queue import queue
    before = authority(request)
    job = queue().get(identity)
    if (job is None or job.kind != KIND or job.payload.get("owner") != before["owner"]
            or job.payload.get("tenant") != before["tenant"]):
        raise HTTPException(404, "This report occurrence is unavailable in the current account and workspace.")
    recipe = unseal(job.payload["report_recipe"])
    operation = "scheduled-report:" + digest([job.recurrence_id, job.occurrence, recipe["operation"]])
    report_id = "report_" + digest([operation])[:32]
    runtime = _build_runtime(request.app, tenant_id=before["tenant"], request=request)
    result = runtime.store.creation_original(idempotency_key=operation, report_id=report_id, caller_role=runtime.role_view)
    if before != authority(request):
        raise HTTPException(409, "Your access changed. Open the current report page again.")
    return {"context": before["context"], "found": result is not None,
            "report": report_id if result is not None else None,
            "message": ("The original PDF was created. This check did not collect records or create it again." if result is not None else
                        "This PDF's creation is not confirmed. It may still be underway; no collection or creation was repeated.")}


def background_request(app, recipe):
    """Rebuild a current native owner context, never a stored browser credential."""
    from maverick.oidc import VerifiedPrincipal
    from maverick.tenant.registry import assert_tenant_active

    from . import api_keys, workspace_tenants
    from .app import require_page_visible
    from .rbac import permissions_for
    from .session_revocation import is_revoked

    grant = recipe["authority"]
    if current_tenant_id_strict() != grant["tenant"]:
        raise HTTPException(403, "This report's workspace is unavailable.")
    assert_tenant_active(grant["tenant"])
    owner, _user, suites = auth.stored_automation_identity(grant["owner"])
    if (auth.role_for_principal(owner) or "admin") != grant["role"]:
        raise HTTPException(403, "The report owner's role changed. Review a new schedule with current access.")
    if grant["workspace_source"] == "principal_selection" and not workspace_tenants.principal_can_select(owner, grant["tenant"]):
        raise HTTPException(403, "The report owner's workspace access changed.")
    effective = (set(permissions_for(auth.role_for_principal(owner))) if owner else
                 {"admin", "audit", "operate", "view"}) & set(grant["permissions"])
    if grant["key"]:
        key = api_keys.get_key(grant["key"])
        if (key is None or key.owner != owner or key.status() not in {"active", "expiring", "rotating"}
                or (key.workspace and key.workspace != grant["tenant"]) or not api_keys.enabled()):
            raise HTTPException(403, "The report's access key is no longer available.")
        if key.is_service_account:
            account = api_keys.get_service_account(owner.removeprefix("user:svc:"))
            if account is None or account.disabled_at is not None:
                raise HTTPException(403, "The report's service account is unavailable.")
        elif is_revoked(owner.removeprefix("user:"), key.created_at):
            raise HTTPException(403, "The report's access key is no longer available.")
        scopes = set(key.scopes) & set(grant["scopes"] or [])
        if set(key.scopes) != set(grant["scopes"] or []):
            raise HTTPException(403, "The report's access key permissions changed. Review a new schedule.")
        effective &= set(api_keys.effective_permissions(scopes, owner))
        if not scopes & {"tasks:write", "admin"}:
            raise HTTPException(403, "The report's access key cannot create reports now.")
    if "operate" not in effective or "view" not in effective:
        raise HTTPException(403, "The report owner's current access no longer allows report creation.")
    # Current owner floor plus the captured narrower scope is checked on every
    # execution and physical write; this request contains no credential.
    request = Request({"type": "http", "method": "GET", "path": PAGE, "headers": [], "app": app,
                       "scheme": "http", "server": ("localhost", 80), "client": (grant["address"], 0)})
    if owner:
        request.state.principal = VerifiedPrincipal(owner.removeprefix("user:"), "scheduled-report", "",
                                                    {"via": "scheduled_report", "amr": ["mfa"] if grant["mfa"] else []})
    elif not auth.anonymous_local_access_allowed():
        raise HTTPException(403, "This local report's original authority is unavailable.")
    if grant["key"]:
        request.state._scheduled_report_key_authority = _ScheduledReportKeyAuthority(
            owner, grant["tenant"], grant["role"], grant["key"], frozenset(grant["scopes"]),
            frozenset(grant["permissions"]), None if grant["suites"] is None else frozenset(grant["suites"]))
        refresh_background_key(request)
    elif owner is None and effective != set(grant["permissions"]):
        raise HTTPException(403, "This local report's original permission floor changed.")
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    auth._enforce_workspace_policies(request, getattr(request.state, "principal", None))
    # An execution may not broaden a captured restricted department grant.
    if (None if suites is None else sorted(suites)) != grant["suites"]:
        raise HTTPException(403, "The report owner's department access changed; review a new schedule.")
    return request


def execute(app, job):
    """One occurrence: exact prepared source survives unknown/reclaimed attempts."""
    from maverick.paths import tenant_scope

    recipe = unseal(job.payload["report_recipe"])
    if job.payload.get("tenant") != recipe["authority"]["tenant"] or job.payload.get("owner") != recipe["authority"]["owner"]:
        from maverick.worker import GoalRunStopped
        raise GoalRunStopped("This report occurrence's account or workspace could not be verified.")
    with tenant_scope(tenant=recipe["authority"]["tenant"]):
        _execute(app, job, recipe)


def _execute(app, job, recipe):
    from maverick.worker import GoalRunStopped

    from .automation_queue import queue
    key = "scheduled-report:" + digest([job.recurrence_id, job.occurrence, recipe["operation"]])
    report_id = "report_" + digest([key])[:32]
    def save_phase(phase, **extra):
        job.payload.update(report_phase=phase, **extra)
        if not queue().set_payload(job.id, job.payload, expected_attempts=job.attempts):
            raise GoalRunStopped("This report's worker ownership changed. Check its original outcome.")
    try:
        with auth.fresh_configuration(), authority_effect_fence():
            request = background_request(app, recipe)
            runtime = _build_runtime(app, tenant_id=recipe["authority"]["tenant"], request=request)
            prior = runtime.store.creation_original(idempotency_key=key, report_id=report_id, caller_role=runtime.role_view)
            if prior is not None:
                save_phase("created", created_report=report_id)
                return
            if job.payload.get("report_phase") == "creating":
                save_phase("unconfirmed")
                raise GoalRunStopped("The earlier PDF creation is unconfirmed. No creation was repeated.")
            if job.payload.get("report_phase") in {"unconfirmed", "stopped"}:
                raise GoalRunStopped("This occurrence has stopped or is unconfirmed. No creation was repeated.")
            with queue()._conn() as connection:
                definition = connection.execute("SELECT state,revision FROM schedule_definitions WHERE id=?", (job.recurrence_id,)).fetchone()
            if definition is None or definition["state"] != "active":
                raise HTTPException(409, "Future report creation was stopped.")
            definition_revision = definition["revision"]
            layout = _layout(runtime, recipe["layout"], recipe["layout_revision"])
            prepared = job.payload.get("report_prepared")
            if prepared:
                material = unseal(prepared)
                snapshot = reports.ReportSnapshot(reports.SNAPSHOT_SCHEMA, recipe["authority"]["tenant"], material["role"],
                    tuple(reports.SourceManifestEntry(**row) for row in material["sources"]),
                    tuple(reports.ReportMetric(**row) for row in material["metrics"]), material["captured_at"], False)
            else:
                snapshot = _snapshot(runtime, _selectors(layout), time.time())
                if any(row.state != "available" for row in snapshot.sources):
                    raise HTTPException(409, "A selected record is unavailable. This report was not created.")
                save_phase("prepared", report_prepared=seal({"purpose": PURPOSE, "role": snapshot.role_view,
                    "sources": [asdict(row) for row in snapshot.sources], "metrics": [asdict(row) for row in snapshot.metrics],
                    "captured_at": snapshot.captured_at}))
            def current():
                with auth.fresh_configuration():
                    background_request(app, recipe)
                    with queue()._conn() as connection:
                        row = connection.execute("SELECT state,revision FROM schedule_definitions WHERE id=?", (job.recurrence_id,)).fetchone()
                    if row is None or row["state"] != "active" or row["revision"] != definition_revision:
                        raise HTTPException(409, "Future report creation was stopped. This PDF was not created.")
                    claimed = queue().get(job.id)
                    if claimed is None or claimed.status != "running" or claimed.attempts != job.attempts:
                        raise HTTPException(409, "This report's worker ownership changed. No new PDF was admitted.")
                    _layout(runtime, recipe["layout"], recipe["layout_revision"])
                    if _snapshot(runtime, _selectors(layout), snapshot.captured_at) != snapshot:
                        raise HTTPException(409, "A selected record changed during creation. This PDF was not created.")
                    background_request(app, recipe)
            current()
            save_phase("creating")  # durable claim before the actual PDF transaction
            try:
                runtime.store.create_report(snapshot=snapshot, brand=reports.BrandTokens(**recipe["brand"]),
                    report_id=report_id, idempotency_key=key, effect_guard=current)
            except HTTPException:
                save_phase("stopped")  # guarded native transaction rolled back
                raise
            except Exception as exc:
                save_phase("unconfirmed")
                raise GoalRunStopped("PDF creation could not be confirmed. Check its original outcome; it will not be repeated.") from exc
            save_phase("created", created_report=report_id)
    except GoalRunStopped:
        raise
    except Exception as exc:
        save_phase("stopped")
        raise GoalRunStopped("Current report access, settings or selected records are unavailable. This occurrence stopped without replay.") from exc
