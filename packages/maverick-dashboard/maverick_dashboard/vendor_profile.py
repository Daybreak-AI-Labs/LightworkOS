"""One current registered vendor view over existing lifecycle and risk authorities."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import HTTPException
from maverick import config
from maverick import vendor_management as vm
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict

from . import auth, tools_ops_api
from . import third_party_intelligence_api as intelligence_api
from . import third_party_lifecycle_api as lifecycle_api
from ._shared import authenticated_subject
from .draft_api import context_for

ORIGINALS = GovernedRecordStore("vendor-profile-decisions", "VPD", "vendor_profile_decision")
NOTICE = ("The registered vendor is the master identity. Linking an existing intelligence profile is an administrator's explicit identity decision, "
          "not independently verified identity or fresh screening. Activation uses the latest evaluated assessment and records the complete reviewed consequences. "
          "A questionnaire reply remains the respondent's statement. No vendor or provider is contacted here.")


def authority(request, *, write=False, admin=False):
    auth.require_permission(request, "admin" if admin else "operate" if write else "view")
    tenant = current_tenant_id_strict()
    if not tenant or not vm.enabled():
        raise HTTPException(409, "Choose a workspace and turn on Vendor management in Privacy before opening this profile.")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current vendor settings could not be checked.")
    from maverick.tenant.registry import assert_tenant_active

    from .scim_groups import active_for_principal
    actor = authenticated_subject(request, error_detail="Sign in before changing a registered vendor.")
    assert_tenant_active(tenant)
    if active_for_principal(auth.caller_principal(request)) is False:
        raise HTTPException(403, "Your current account is inactive.")
    if write:
        tools_ops_api.same_origin(request)
    return tenant, actor, context_for(request)


def effect_guard(request, tenant, actor, *, family, admin=False):
    context = context_for(request)
    def guard():
        auth.require_global_permission(request, "admin") if admin else auth.require_permission(request, "operate")
        if current_tenant_id_strict() != tenant or context_for(request) != context:
            raise HTTPException(409, "Your vendor workspace or account changed. Review this decision again.")
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current vendor settings could not be checked.")
        from maverick.tenant.registry import assert_tenant_active

        from .scim_groups import active_for_principal
        assert_tenant_active(tenant)
        if active_for_principal(auth.caller_principal(request)) is False:
            raise HTTPException(403, "Your current account is inactive.")
        module = lifecycle_api if family == "lifecycle" else intelligence_api
        module._ops()
        if module._principal(request, tenant) != actor:
            raise HTTPException(403, "The current vendor owner or account changed.")
        tools_ops_api.same_origin(request)
    return guard


def registered_vendor(tenant, identifier):
    if current_tenant_id_strict() != tenant or not isinstance(identifier, str) or not identifier.startswith("VMR-"):
        raise HTTPException(409, "Select an actual vendor from the Privacy register. Register a new vendor there first.")
    row = vm.get_vendor(identifier)
    if row is None:
        raise HTTPException(404, "This registered vendor is no longer available.")
    return row


def lifecycle_store(request, tenant):
    principal = lifecycle_api._principal(request, tenant)
    factory = getattr(request.app.state, "third_party_lifecycle_store_factory", None)
    key = (tenant, principal, id(factory))
    cached = getattr(request.state, "vendor_profile_lifecycle", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    if callable(factory):
        store = factory(tenant_id=tenant, principal_ref=principal,
                        principal_resolver=lambda: lifecycle_api._principal(request, tenant), request=request)
    else:
        store = lifecycle_api._default_store_for(tenant, principal)
    request.state.vendor_profile_lifecycle = (key, store)
    return store


def intelligence_store(request, tenant):
    factory = getattr(request.app.state, "third_party_intelligence_store_factory", None)
    key = (tenant, id(factory))
    cached = getattr(request.state, "vendor_profile_intelligence", None)
    if cached is not None and cached[0] == key:
        return cached[1]
    store = factory(tenant_id=tenant, request=request) if callable(factory) else intelligence_api._default_store_for(tenant)
    request.state.vendor_profile_intelligence = (key, store)
    return store


def _bounded(rows, label):
    if len(rows) >= 1000:
        raise HTTPException(503, "The current " + label + " collection exceeds this complete profile's admitted window. Narrow its native register before reviewing a decision.")
    return rows


def profile(request, identifier):
    tenant, _, context = authority(request)
    vendor = registered_vendor(tenant, identifier)
    result = {"context": context, "vendor": vendor, "notice": NOTICE, "lifecycle": [], "assessments": [],
              "intelligence": [], "screening": [], "decisions": [], "due_diligence": [], "contracts": [], "modules": {}, "unbound_profiles": []}
    if lifecycle_api.third_party_lifecycle_enabled_for_page():
        store = lifecycle_store(request, tenant)
        result["lifecycle"] = [asdict(row) for row in _bounded(store.list_lifecycles(tenant, limit=1000), "lifecycle") if row.vendor_ref == identifier]
        result["assessments"] = [asdict(row) for row in _bounded(store.list_assessments(tenant, limit=1000), "assessment") if row.vendor_ref == identifier]
        result["modules"]["lifecycle"] = "Available"
        try:
            result["activation"] = store.activation_assessment(tenant, identifier)
            result["activation_blocked"] = ""
        except lifecycle_api._ops().ThirdPartyLifecycleConflict as exc:
            result["activation"] = None
            result["activation_blocked"] = str(exc)
    else:
        result["activation"] = None
        result["activation_blocked"] = "Turn on Third-party lifecycle in Settings, then complete and evaluate this vendor's assessment."
        result["modules"]["lifecycle"] = "Turn on Third-party lifecycle in Settings"
    if intelligence_api.third_party_intelligence_enabled_for_page():
        store = intelligence_store(request, tenant)
        profiles = _bounded(store.list_vendors(tenant, limit=1000), "intelligence vendor")
        result["intelligence"] = [asdict(row) for row in profiles if row.register_vendor_id == identifier]
        ids = {row["vendor_id"] for row in result["intelligence"]}
        result["unbound_profiles"] = [{"value": row.vendor_id, "label": row.display_label, "revision": row.revision}
                                     for row in profiles if row.register_vendor_id is None]
        for key, method in (("screening", "list_screening_runs"), ("decisions", "list_risk_decisions"), ("due_diligence", "list_edd_cases")):
            result[key] = [asdict(row) for row in _bounded(getattr(store, method)(tenant, limit=1000), key) if row.vendor_id in ids]
        result["modules"]["intelligence"] = "Available"
        from maverick.third_party_contracts import enabled as contracts_enabled
        from maverick.third_party_contracts import redacted_record
        if contracts_enabled():
            factory = getattr(request.app.state, "third_party_contracts_store_factory", None)
            if not callable(factory):
                raise HTTPException(503, "Contract authority is unavailable. This profile cannot claim there are no contracts.")
            from .third_party_contracts_api import _principal
            contract_store = factory(tenant_id=tenant, principal_ref=_principal(request, tenant), request=request)
            for linked in ids:
                records = _bounded(contract_store.list_records(tenant, vendor_id=linked, limit=1000), "contract")
                result["contracts"].extend([redacted_record(row, include_sensitive=False) for row in records])
            result["modules"]["contracts"] = "Available"
        else:
            result["modules"]["contracts"] = "Turn on Contracts in Settings"
    else:
        result["modules"]["intelligence"] = "Turn on Third-party intelligence in Settings"
        result["modules"]["contracts"] = "Contracts keep their existing Intelligence vendor identities"
    result["binding"] = digest({key: value for key, value in result.items() if key not in {"notice", "context", "binding"}})
    return result


def prepare(request, identifier, action, *, intelligence=None, lifecycle=None, reason="", context=None):
    tenant, actor, current = authority(request, write=True, admin=action == "bind")
    if context is not None and context != current:
        raise HTTPException(409, "Your vendor workspace or account changed. Reload this profile.")
    view = profile(request, identifier)
    if len(reason.strip()) < 8 or len(reason) > 500:
        raise HTTPException(422, "Explain this vendor identity or activation decision in at least eight characters.")
    prepared = {"vendor": identifier, "action": action, "tenant": tenant, "actor": actor, "context": current,
                "source": view["binding"], "reason": reason.strip(), "before": view}
    if action == "bind":
        if view["intelligence"]:
            raise HTTPException(409, "This registered vendor already has an intelligence profile. Open that existing record.")
        row = next((row for row in view["unbound_profiles"] if row["value"] == intelligence), None)
        if row is None:
            raise HTTPException(409, "Select an existing unbound intelligence profile from this workspace.")
        prepared["intelligence"] = asdict(intelligence_store(request, tenant).get_vendor(tenant, intelligence))
    elif action == "activate":
        if not view["activation"]:
            raise HTTPException(409, view["activation_blocked"])
        tracked = next((row for row in view["lifecycle"] if row["lifecycle_id"] == lifecycle), None) if lifecycle else None
        if lifecycle and tracked is None:
            raise HTTPException(409, "Select this registered vendor's actual lifecycle record.")
        if tracked and tracked["owner_ref"] != lifecycle_api._principal(request, tenant):
            raise HTTPException(403, "Only the current lifecycle owner can activate its record.")
        if tracked and tracked["stage"] not in {"onboarding", "suspended", "active"}:
            raise HTTPException(409, "Offboarding remains governed by its dedicated workflow.")
        prepared["lifecycle"] = tracked
        prepared["assessment"] = view["activation"]
    else:
        raise HTTPException(422, "Select a vendor identity or activation decision.")
    return prepared


def changes(prepared):
    view = prepared["before"]
    rows = [{"label": "Decision", "after": "Link the selected existing intelligence identity" if prepared["action"] == "bind" else "Activate this registered vendor and the selected tracked lifecycle"},
            {"label": "Registered vendor", "after": view["vendor"]},
            {"label": "Current tracked lifecycle and assessments", "after": {"Lifecycle": view["lifecycle"], "Assessments": view["assessments"]}},
            {"label": "Current screening and risk decisions", "after": {"Profiles": view["intelligence"], "Screening": view["screening"], "Decisions": view["decisions"], "Due diligence": view["due_diligence"]}},
            {"label": "Current contracts", "after": view["contracts"]},
            {"label": "Complete selected existing identity" if prepared["action"] == "bind" else "Exact evaluated assessment and selected lifecycle", "after": prepared.get("intelligence") or {"Assessment": prepared.get("assessment"), "Lifecycle": prepared.get("lifecycle")}},
            {"label": "Your decision reason", "after": prepared["reason"]},
            {"label": "Consequences and evidence boundary", "after": NOTICE}]
    return rows


def original(request, prepared, operation):
    tenant, actor, context = authority(request)
    if (tenant, actor, context) != (prepared["tenant"], prepared["actor"], prepared["context"]):
        raise HTTPException(403, "This vendor decision belongs to another account or workspace.")
    row = ORIGINALS.get("VPD-" + operation)
    if row is None:
        return {"confirmed": False, "state": "absent", "message": "No admitted original was found. Nothing was repeated."}
    if row["binding"] != digest(prepared):
        raise HTTPException(409, "This original does not match the complete reviewed vendor decision.")
    return {"confirmed": row["state"] == "confirmed", "state": row["state"], "message": row["message"],
            "results": row.get("results", []), "open": "/privacy/vendors/" + prepared["vendor"] + "#vendor-profile"}


def apply(request, prepared, operation):
    tenant, actor, context = authority(request, write=True, admin=prepared["action"] == "bind")
    if (tenant, actor, context) != (prepared["tenant"], prepared["actor"], prepared["context"]):
        raise HTTPException(403, "This vendor decision belongs to another account or workspace.")
    previous = original(request, prepared, operation)
    if previous["state"] != "absent":
        return previous
    identifier = "VPD-" + operation
    row = ORIGINALS.create({"id": identifier, "binding": digest(prepared), "prepared": prepared,
        "state": "admitted", "message": "The native vendor decision was admitted; its effect remains unconfirmed.", "results": []},
        action="admit_vendor_profile_decision", actor=actor)
    if row["binding"] != digest(prepared):
        raise HTTPException(409, "The original vendor decision changed.")
    def guard():
        authority(request, write=True, admin=prepared["action"] == "bind")
        if profile(request, prepared["vendor"])["binding"] != prepared["source"]:
            raise HTTPException(409, "The current vendor, assessment or linked risk record changed. Read the original before reviewing a new decision.")
    def claim(value):
        guard()
        if value["state"] != "admitted":
            raise HTTPException(409, "This vendor intent has already started. Read its original; nothing will be repeated.")
        value["state"] = "running"
    ORIGINALS.update(identifier, claim, expected_revision=row["revision"], action="start_vendor_profile_decision", actor=actor)
    results = []
    try:
        if prepared["action"] == "bind":
            selected = prepared["intelligence"]
            kwargs = {key: selected[key] for key in ("vendor_id", "display_label", "entity_identity_sha256", "encrypted_profile_ref", "profile_key_ref", "territories", "service_categories", "inherent_risk_level", "criticality", "data_access_level", "owner_ref")}
            changed = intelligence_store(request, tenant).upsert_vendor(tenant, **kwargs,
                actor_ref=intelligence_api._principal(request, tenant), expected_revision=selected["revision"],
                register_vendor_id=prepared["vendor"], idempotency_key="vendor-profile-" + operation, effect_guard=guard)
            results.append({"kind": "intelligence_identity_link", "record": asdict(changed)})
        else:
            assessment = prepared["assessment"]
            tracked = prepared["lifecycle"]
            if tracked and tracked["stage"] != "active":
                changed = lifecycle_store(request, tenant).transition_lifecycle(tenant, tracked["lifecycle_id"], "active",
                    reason_code="reviewed-vendor-activation", expected_revision=tracked["revision"],
                    idempotency_key="vendor-profile-" + operation, assessment_id=assessment["assessment_id"],
                    assessment_revision=assessment["revision"], effect_guard=guard)
                results.append({"kind": "tracked_lifecycle_activation", "record": asdict(changed)})
            def master_guard():
                authority(request, write=True)
            changed = vm.set_vendor_status(prepared["vendor"], "active", actor=auth.caller_principal(request) or actor,
                expected_revision=prepared["before"]["vendor"]["revision"], effect_guard=master_guard,
                assessment_id=assessment["assessment_id"], assessment_revision=assessment["revision"])
            results.append({"kind": "registered_vendor_activation", "record": changed})
        def finish(value):
            value.update(state="confirmed", results=results, message="The original vendor decision is confirmed. Nothing was repeated.")
        live = ORIGINALS.get(identifier)
        ORIGINALS.update(identifier, finish, expected_revision=live["revision"], action="confirm_vendor_profile_decision", actor=actor)
    except Exception:
        live = ORIGINALS.get(identifier)
        def uncertain(value):
            value.update(state="unknown", results=results, message="The original vendor effect is unconfirmed. A recorded step may already have completed; nothing will be repeated automatically.")
        ORIGINALS.update(identifier, uncertain, expected_revision=live["revision"], action="retain_vendor_profile_unknown", actor=actor)
        raise
    return original(request, prepared, operation)

