"""Current native authorities projected into retained, digest-only loop pins."""
from __future__ import annotations

import json
from dataclasses import asdict

from maverick import ai_governance_loop as loop
from maverick import crypto_at_rest
from maverick import runtime_enforcement_records as enforcement
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict

from .auth import fresh_configuration

STORE = GovernedRecordStore("ai-governance-source-pins", "AGP", "ai_governance_source_pins")
NAMES = ("inventory", "declaration", "risk", "policy", "enforcement", "evidence")
MAX_ASSETS = 5_000


def _tenant(expected):
    if current_tenant_id_strict() != expected:
        raise loop.AIGovernanceLoopAuthorityDrift("The current governance workspace changed.")
    return expected


def _context(observation, declaration):
    from maverick import ai_runtime_guardrails as runtime

    facts = declaration.get("risk_context") or {}
    return runtime.RuntimePolicyContext(risk_tier=declaration.get("risk_tier", "unclassified"),
        asset_types=(observation["identity"]["asset_type"],),
        **{name: tuple(facts.get(name, [])) for name in
            ("jurisdictions", "data_classes", "deployment_types", "tags", "use_case_tags")}
        ).as_mapping(observation["asset_id"])


def _material(tenant, asset):
    """Read actual native currentness; no record here invents an approval."""
    from maverick import ai_dynamic_risk as risk
    from maverick import ai_policy_management as policy
    from maverick import model_risk_assurance as assurance

    _tenant(tenant)
    with fresh_configuration():
        loop.require_enabled()
        observation = assurance.get_observation(asset)
        if observation is None:
            absent = {name: enforcement.digest({"state": "absent", "asset": asset}) for name in NAMES}
            return absent, {"declaration_approved": False, "risk_current": False, "policy_current": False,
                "policy_decision": "review", "enforcement_decision": "unknown", "evidence_complete": False}
        declaration = assurance.get_declaration(asset)
        declared = (declaration is not None and not observation.get("_audit_pending")
            and not declaration.get("_audit_pending")
            and assurance._DEFAULT._declaration_is_current(declaration, observation))
        score = risk.default_service.current_score(asset)
        score_record = None if score is None else risk.default_service._snapshots.get(score["snapshot_id"])
        manager = policy.configured_policy_management()
        policies, exceptions = manager.list_policies(), manager.list_exceptions()
        policy_pending = any(row.get("_audit_pending") for row in
            [*manager._policies.list(limit=policy._MAX_POLICIES + 1),
             *manager._exceptions.list(limit=policy._MAX_EXCEPTIONS + 1)])
        preview = manager.preview(_context(observation, declaration)) if declaration else None
        receipts = sorted((row for row in enforcement.records()
            if row["receipt"]["asset_binding"]["asset_id"] == asset), key=lambda row: row["id"])
        newest = max(receipts, key=lambda row: (row["created_at"], row["id"]), default=None)
        evidence = assurance.list_evidence(asset_id=asset)
        usable = {row.get("evidence_kind") for row in evidence
            if not row.get("_audit_pending") and row.get("status") == "approved" and row.get("freshness") == "current"
            and row.get("result") == "passed" and row.get("artifact_digest") == observation["version_digest"]
            and assurance._DEFAULT._evidence_evaluator_is_current(row)
            and (row.get("evidence_kind") != "red_team" or assurance._red_team_review_is_independent(row))}
        required = {"evaluation", "red_team"}
        if ((declaration or {}).get("assurance_profile") or {}).get("screening_reasons", {}).get("third_party") is True:
            required.add("vendor_assessment")
        policy_digest = enforcement.digest(preview)
        decision = {"prohibit": "block"}.get((preview or {}).get("final_effect"), (preview or {}).get("final_effect", "review"))
        facts = {"declaration_approved": bool(declared), "risk_current": bool(score is not None
                and score_record is not None and not score_record.get("_audit_pending") and score.get("snapshot_fresh") is True),
            "policy_current": bool(declared and not policy_pending and preview is not None and preview.get("policy_authority")),
            "policy_decision": decision,
            "enforcement_decision": "unknown" if newest is None else enforcement.observed_decision(newest,
                asset=observation, policy_sha256=policy_digest), "evidence_complete": required <= usable}
        sources = {"inventory": observation, "declaration": {"record": declaration, "current": facts["declaration_approved"]},
            "risk": {"score": score, "confirmed": score_record is not None and not score_record.get("_audit_pending")},
            "policy": {"policies": policies, "exceptions": exceptions, "decision": preview, "unconfirmed": policy_pending},
            "enforcement": receipts, "evidence": {"records": evidence, "complete": facts["evidence_complete"]}}
        commitments = {name: enforcement.digest(value) for name, value in sources.items()}
    _tenant(tenant)
    return commitments, facts


def _id(tenant, asset):
    return "AGP-" + enforcement.digest([tenant, asset])[:32]


def _decode(row, tenant, asset):
    try:
        if not crypto_at_rest.is_sealed_str(row.get("body")):
            raise ValueError("encryption")
        value = json.loads(crypto_at_rest.unseal_from_str(row["body"]))
        if (value["tenant"] != tenant or value["asset"] != asset or enforcement.digest(value) != row["body_sha256"]
                or set(value["pins"]) != set(NAMES)):
            raise ValueError("binding")
        for pin in value["pins"].values():
            loop.AuthorityPin(**pin).normalized()
        return value
    except Exception as exc:
        raise loop.AIGovernanceLoopIntegrityError("Retained governance source commitments could not be verified.") from exc


def capture(tenant, asset):
    """Advance explicit projection generations under an exact current-source guard."""
    from maverick.authority_effects import authority_effect_fence

    with authority_effect_fence():
        return _capture(tenant, asset)


def _capture(tenant, asset):
    commitments, facts = _material(tenant, asset)
    identifier = _id(tenant, asset)
    old = STORE.get(identifier)
    previous = None if old is None else _decode(old, tenant, asset)
    if previous and previous["commitments"] == commitments and previous["facts"] == facts:
        if old.get("_audit_pending"):
            raise loop.AIGovernanceLoopIntegrityError("Governance source activity is unconfirmed.")
        return old, previous
    pins = {}
    for name in NAMES:
        before = (previous or {}).get("pins", {}).get(name)
        changed = before is None or before["sha256"] != commitments[name]
        pins[name] = asdict(loop.AuthorityPin(tenant, asset, f"native-{name}-{identifier}",
            (0 if before is None else before["revision"]) + int(changed), commitments[name]))
    value = {"schema": "lightwork.native-governance-source-pins.v1", "tenant": tenant, "asset": asset,
        "commitments": commitments, "facts": facts, "pins": pins}
    sealed = crypto_at_rest.seal_to_str(json.dumps(value, sort_keys=True, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(sealed):
        raise loop.AIGovernanceLoopIntegrityError("Protected governance source commitments are unavailable.")

    def guard():
        current = _material(tenant, asset)
        if current != (commitments, facts):
            raise loop.AIGovernanceLoopAuthorityDrift("Governance sources changed before their commitments were saved.")

    fields = {"body": sealed, "body_sha256": enforcement.digest(value)}
    if old is None:
        saved = STORE.create({"id": identifier, **fields}, action="source_capture", actor="system:governance-sources",
            max_records=MAX_ASSETS, effect_guard=guard)
    else:
        saved = STORE.update(identifier, lambda row: row.update(fields), expected_revision=old["revision"],
            action="source_capture", actor="system:governance-sources", effect_guard=guard)
    if saved is None or saved.get("_audit_pending"):
        raise loop.AIGovernanceLoopIntegrityError("Governance source activity is retained but unconfirmed.")
    return saved, value


class NativeAuthorityReader:
    def __init__(self, tenant):
        self.tenant = tenant

    def read_snapshot(self, *, tenant_id, asset_id):
        _tenant(tenant_id)
        if self.tenant != tenant_id:
            raise loop.AIGovernanceLoopAuthorityDrift("Governance source workspace mismatch.")
        row = STORE.get(_id(tenant_id, asset_id))
        if row is None or row.get("_audit_pending"):
            raise loop.AIGovernanceLoopValidationError("Current governance sources have not been completely captured yet.")
        value = _decode(row, tenant_id, asset_id)
        if _material(tenant_id, asset_id) != (value["commitments"], value["facts"]):
            raise loop.AIGovernanceLoopAuthorityDrift("The governance sources changed. Wait for the current check.")
        return loop.AuthoritySnapshot(tenant_id=tenant_id, asset_id=asset_id,
            **{name: loop.AuthorityPin(**pin) for name, pin in value["pins"].items()},
            **value["facts"], limitations=(), captured_at=row["updated_at"]).normalized()


def factory(*, tenant_id, principal_ref, request):
    _tenant(tenant_id)
    return NativeAuthorityReader(tenant_id)


def produce(runtime, *, limit, after=""):
    """Bounded rotating native source discovery; existing queue supplies custody."""
    from maverick import model_risk_assurance as assurance

    _tenant(runtime.tenant_id)
    inventory = assurance.list_inventory()
    if len(inventory) > MAX_ASSETS:
        raise loop.AIGovernanceLoopValidationError("AI inventory exceeds the supported governance-source limit.")
    retained = STORE.list(limit=MAX_ASSETS + 1)
    if len(retained) > MAX_ASSETS:
        raise loop.AIGovernanceLoopValidationError("Retained governance source inventory exceeds its limit.")
    old_assets = []
    for row in retained:
        if not crypto_at_rest.is_sealed_str(row.get("body")):
            raise loop.AIGovernanceLoopIntegrityError("Protected governance source inventory is unavailable.")
        body = json.loads(crypto_at_rest.unseal_from_str(row["body"]))
        _decode(row, runtime.tenant_id, body["asset"])
        old_assets.append(body["asset"])
    assets = sorted(set(row["asset_id"] for row in inventory) | set(old_assets))
    if len(assets) > MAX_ASSETS:
        raise loop.AIGovernanceLoopValidationError("Current and retained governance sources exceed their supported limit.")
    ordered = [asset for asset in assets if asset > after] + [asset for asset in assets if asset <= after]
    selected = ordered[:limit]
    for asset in selected:
        row, _value = capture(runtime.tenant_id, asset)
        trigger = loop.GovernanceTrigger(tenant_id=runtime.tenant_id, asset_id=asset, code="manual_reconcile",
            source_revision=row["revision"], source_sha256=row["body_sha256"], occurred_at=row["updated_at"])
        runtime.ingest_server_trigger(trigger, operation_id=f"native-source-{row['id']}-{row['revision']}")
    return selected[-1] if selected else ""
