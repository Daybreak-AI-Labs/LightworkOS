"""Current local decisions through each family's existing native authority."""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict

from fastapi import HTTPException

from . import auth
from .draft_api import context_for

LIMIT = 99
_CAPABILITIES = {
    "active_publication": "See the published notice",
    "consent_history": "See consent history",
    "profile_data": "See profile data",
    "rights_cases": "Make privacy requests",
}
_DROP_ACTIONS = {
    "enroll_broker": "Approve a data broker's registration",
    "revoke_broker": "Review removal of a data broker's registration",
    "import_record": "Review a DROP request",
    "revoke_record": "Review removal of a DROP request",
    "approve_outcome": "Review a DROP result",
    "rotate_key": "Review a new signing key",
    "retire_key": "Review retirement of a signing key",
    "revoke_key": "Review removal of a signing key",
    "record_key_migration": "Review a signing key change",
}


def _name(value, fallback):
    text = str(value)
    if re.search(r"[a-f0-9]{24,}", text, re.IGNORECASE):
        return fallback
    return re.sub(r"[-_:]+", " ", text).strip().capitalize() or fallback


def _access(request, path):
    from .app import require_page_visible

    principal = getattr(request.state, "principal", None)
    claims = getattr(principal, "claims", None) or {}
    via = claims.get("via")
    resolver = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                "proxy": auth._proxy_principal}.get(via)
    if resolver is not None:
        fresh = resolver(request)
        if fresh is None or fresh.principal != auth.caller_principal(request):
            raise HTTPException(401, "Sign in again to read current decisions.")
        request.state.principal = fresh
        auth._enforce_scim_active(fresh)
        auth._enforce_workspace_policies(request, fresh)
    auth.require_global_permission(request, "admin")
    auth.require_page_permission(request, path)
    require_page_visible(request, path)
    return context_for(request)


def _entry(identity, title, href, version, updated, reason, *, due=None):
    return {"key": identity, "title": title, "href": href, "version": version,
            "updated_at": updated, "reason": reason, "due_at": due}


def _lifecycle(request):
    from . import third_party_lifecycle_api as native

    native._ops()
    tenant, principal = native._tenant_id(), native._principal(request, native._tenant_id())
    if not (auth.caller_principal(request) or "").startswith("user:"):
        raise HTTPException(403, "Individual sign-in is required for independent review.")
    factory = getattr(request.app.state, "third_party_lifecycle_store_factory", None)
    store = (factory(tenant_id=tenant, principal_ref=principal,
                     principal_resolver=lambda: principal, request=request)
             if callable(factory) else native._default_store_for(tenant, principal))
    templates = store.list_templates(tenant, limit=LIMIT + 1)
    plans = store.list_offboarding_plans(tenant, limit=LIMIT + 1)
    items, now = [], time.time()
    for record in templates[:LIMIT]:
        if (record.state != "pending_approval" or record.authored_by == principal
                or native._unattributed_author(tenant, record.authored_by) or record.retained_until <= now):
            continue
        items.append(_entry("template:" + record.template_id + ":" + str(record.version),
            "Review questionnaire: " + _name(record.title_ref, "Vendor questionnaire") + " · version " + str(record.version),
            "/third-party/lifecycle#tpl-templates", asdict(record), record.updated_at,
            "Another person wrote this questionnaire. Read all questions and rules before approving its use."))
    for plan in plans[:LIMIT]:
        if (plan.state != "in_progress" or plan.initiated_by == principal
                or native._unattributed_author(tenant, plan.initiated_by) or plan.legal_hold
                or plan.blockers or any(task["status"] != "completed" for task in plan.tasks)):
            continue
        lifecycle = store.get_lifecycle(tenant, plan.lifecycle_id)
        if lifecycle.stage != "offboarding" or lifecycle.offboarding_plan_id != plan.plan_id:
            continue
        items.append(_entry("offboarding:" + plan.plan_id,
            "Review completed offboarding: " + _name(lifecycle.vendor_ref, "Vendor"),
            "/third-party/lifecycle#tpl-offboarding", [asdict(plan), asdict(lifecycle)], plan.updated_at,
            "The recorded tasks have been completed. Independently review their evidence before confirming offboarding; recorded callbacks do not prove outside work."))
    return items, any(len(rows) > LIMIT for rows in (templates, plans))


def _drop(request):
    from . import privacy_drop_authority_api as native

    tenant = native._tenant_id()
    principal = native._principal(request, tenant)
    _registry, _keys, store, _factory = native._factories(request, tenant)
    rows = store.list_open_summaries(proposer_ref=principal, limit=LIMIT + 1)
    items = []
    with store._connect() as connection:
        for row in rows[:LIMIT]:
            if row["proposed_by_you"] or row["state"] != "proposed":
                continue
            raw = connection.execute("SELECT * FROM drop_authority_proposals WHERE tenant_id=? AND proposal_id=?",
                (tenant, row["proposal_id"])).fetchone()
            record = store._public(store._body(raw))
            if record.state != "proposed" or record.retained_until <= time.time():
                continue
            if record.kind not in _DROP_ACTIONS:
                raise ValueError("DROP proposal kind is unavailable")
            items.append(_entry(record.proposal_id, _DROP_ACTIONS[record.kind],
                "/privacy/drop#drop-waiting", asdict(record), record.updated_at,
                "Another administrator requested this change. Read its complete authority and evidence before approving. Approval records a local decision; it does not confirm an outside result."))
    return items, len(rows) > LIMIT


def _trust_store(request, native, tenant, principal):
    factory = getattr(request.app.state, "consumer_trust_center_authority_store_factory", None)
    return (factory(tenant_id=tenant, principal_ref=principal,
                    principal_resolver=lambda: principal, request=request)
            if callable(factory) else native._default_store_for(request, tenant, principal))


def _trust(request):
    from . import consumer_trust_center_authority_api as native

    native._ops()
    tenant = native._tenant_id()
    principal = native._principal(request, tenant)
    store = _trust_store(request, native, tenant, principal)
    listed = store.list_authority(tenant, limit=LIMIT + 1)
    contexts = {row.context_ref: row for row in listed["contexts"]}
    actor, now, items = hashlib.sha256(principal.encode()).hexdigest(), time.time(), []
    for kind, records in (("grant", listed["grants"]), ("rights", listed["rights_authorizations"])):
        for record in records[:LIMIT]:
            parent = contexts.get(record.context_ref) or store.get_context_authority(tenant, record.context_ref)
            if (record.status not in {"proposed", "first_approved"} or record.valid_until <= now
                    or parent.status != "active" or parent.valid_until <= now
                    or actor in {record.requested_by_sha256, record.approved_by_sha256,
                                 record.second_approved_by_sha256, parent.actor_sha256}):
                continue
            name = _CAPABILITIES[record.capability] if kind == "grant" else "Follow a privacy request"
            identity = record.grant_ref if kind == "grant" else record.authorization_ref
            items.append(_entry(identity, "Review Trust Center access: " + name,
                "/consent/trust-center-authority#tca-access", [asdict(record), asdict(parent)], record.updated_at,
                "Read the connected person's current access and request. "
                + ("Two independent approvals are needed; this would be the first." if record.status == "proposed"
                   else "One independent approval remains; approving would start this access."), due=record.valid_until))
    return items, any(len(rows) > LIMIT for rows in listed.values())


def _disclosure(request):
    from . import privacy_notice_governance_api as native

    native._fresh_decision_access(request)
    _ops, tenant, store = native.authority(request)
    principal = native._principal(request, tenant)
    rows = store.list_records(tenant, limit=LIMIT + 1)["proposals"]
    items = []
    for record in rows[:LIMIT]:
        if record.status != "pending_review" or record.created_by == principal or record.retained_until <= time.time():
            continue
        base = store.get_release(tenant, record.notice_id, record.base_version)
        items.append(_entry(record.proposal_id,
            "Review privacy notice update: " + _name(record.notice_id, "Privacy notice"),
            "/privacy/notice-governance#png-proposals", [asdict(record), asdict(base)], record.created_at,
            "Another person suggested an update. Read its reasons, references and changed files before accepting or rejecting. Acceptance does not publish a notice."))
    return items, len(rows) > LIMIT


def collect(request):
    from . import consumer_trust_center_authority_api as trust
    from . import privacy_notice_governance_api as disclosure
    from . import third_party_lifecycle_api as lifecycle

    drop_enabled = getattr(request.app.state, "privacy_drop_management_enabled_probe", None)
    from maverick.paths import current_tenant_id_strict

    families = (
        ("lifecycle_review", "/third-party/lifecycle", lifecycle._enabled, _lifecycle),
        ("drop_authority_review", "/privacy/drop",
         lambda: callable(drop_enabled) and drop_enabled(current_tenant_id_strict()) is True, _drop),
        ("trust_center_review", "/consent/trust-center-authority", trust._enabled, _trust),
        ("disclosure_review", "/privacy/notice-governance", disclosure._enabled, _disclosure),
    )
    items, coverage = [], []
    for kind, path, enabled, read in families:
        state = "unavailable"
        try:
            with auth.fresh_configuration():
                context = _access(request, path)
                if enabled() is not True:
                    state = "disabled"
                    rows = []
                else:
                    rows, partial = read(request)
                    state = "partial" if partial else "current"
            with auth.fresh_configuration():
                if _access(request, path) != context:
                    raise HTTPException(409, "Your account or workspace changed during the read.")
            items.extend({**row, "kind": kind} for row in rows)
        except HTTPException as exc:
            state = "denied" if exc.status_code in {401, 403} else "unavailable"
        except Exception:
            state = "unavailable"
        coverage.append({"kind": kind, "status": state, "limit": LIMIT})
    return {"items": items, "coverage": coverage}
