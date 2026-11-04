from __future__ import annotations

from copy import deepcopy

import pytest
from maverick.ai_identity_governance_controls import (
    CHANGE_EVENT_SCHEMA,
    AgentPrincipalAuthority,
    AgentPrincipalFederationBinding,
    AgentPrincipalFederationObservation,
    CapabilityRule,
    GovernedIdentityChangeRequestSink,
    IdentityCapabilityMapper,
    IdentityGovernanceAuthorityRegistry,
    IdentityGovernanceBindingError,
    IdentityGovernanceStaleBinding,
    PurviewAssetBinding,
)
from maverick.privacy_ops import RecordConflict


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    def authoritative_time(self) -> float:
        return 1_000.0

    def get(self, record_id: str):
        row = self.rows.get(record_id)
        return deepcopy(row) if row is not None else None

    def list(self, *, limit=None):
        rows = [deepcopy(value) for _, value in sorted(self.rows.items())]
        return rows if limit is None else rows[:limit]

    def create(self, record, *, action, actor, max_records=None):
        del action, actor
        if record["id"] in self.rows:
            raise RecordConflict("duplicate")
        if max_records is not None and len(self.rows) >= max_records:
            raise RuntimeError("capacity")
        saved = deepcopy(record)
        saved["revision"] = 1
        saved["created_at"] = 1_000.0
        saved["updated_at"] = 1_000.0
        self.rows[saved["id"]] = saved
        return deepcopy(saved)

    def update(
        self,
        record_id,
        mutate,
        *,
        expected_revision,
        action,
        actor,
    ):
        del action, actor
        current = self.rows.get(record_id)
        if current is None:
            return None
        if current["revision"] != expected_revision:
            raise RecordConflict("stale")
        saved = deepcopy(current)
        mutate(saved)
        saved["revision"] += 1
        self.rows[record_id] = saved
        return deepcopy(saved)


def _authorities():
    tenant = "a" * 64
    authority = AgentPrincipalAuthority(
        tenant_sha256=tenant,
        principal_ref="prn_" + ("b" * 32),
        authority_binding_sha256="c" * 64,
        revision=1,
    )
    binding = AgentPrincipalFederationBinding.bind(
        authority,
        provider="entra",
        provider_subject_id="sub_" + ("d" * 32),
    )
    rule = CapabilityRule(
        tenant_sha256=tenant,
        provider="entra",
        permission_id="prm_" + ("e" * 32),
        capabilities=(
            "purview.classification.rollback",
            "purview.classification.write",
        ),
        revision=1,
    )
    asset = PurviewAssetBinding(
        tenant_sha256=tenant,
        asset_id="ast_" + ("f" * 32),
        binding_sha256="1" * 64,
        revision=1,
        classification_codes=("confidential",),
    )
    return tenant, authority, binding, rule, asset


def test_authority_registry_is_exact_cas_bound_and_integrity_checked():
    tenant, authority, binding, rule, asset = _authorities()
    store = MemoryStore()
    registry = IdentityGovernanceAuthorityRegistry(
        tenant_sha256=tenant,
        store=store,
        clock=lambda: 1_000.0,
    )

    enrolled = registry.enroll_authority(authority, actor="system:provisioner")
    registry.enroll_federation_binding(binding, actor="system:provisioner")
    registry.enroll_capability_rule(rule, actor="system:provisioner")
    registry.enroll_purview_asset(asset, actor="system:provisioner")

    assert registry.resolve_authority(tenant, authority.principal_ref) == authority
    assert (
        registry.resolve_federation_binding(
            tenant,
            authority.principal_ref,
            "entra",
        )
        == binding
    )
    assert registry.resolve_purview_asset(tenant, asset.asset_id) == asset
    assert registry.capability_rules() == (rule,)
    status = registry.status()
    assert status["purview_authority_ready"] is True
    assert status["browser_enrollment_supported"] is False
    assert registry.verify_integrity()["verified"] is True

    replacement = AgentPrincipalAuthority(
        tenant_sha256=tenant,
        principal_ref=authority.principal_ref,
        authority_binding_sha256="2" * 64,
        revision=2,
    )
    with pytest.raises(IdentityGovernanceStaleBinding, match="revision_stale"):
        registry.enroll_authority(replacement, actor="system:provisioner")
    registry.enroll_authority(
        replacement,
        actor="system:provisioner",
        expected_record_revision=enrolled["revision"],
    )
    assert registry.resolve_authority(tenant, authority.principal_ref) == replacement
    with pytest.raises(IdentityGovernanceBindingError, match="tenant_mismatch"):
        registry.resolve_authority("9" * 64, authority.principal_ref)


def test_authority_registry_lists_only_active_enrolled_records_of_one_kind():
    tenant, authority, binding, rule, asset = _authorities()
    registry = IdentityGovernanceAuthorityRegistry(
        tenant_sha256=tenant,
        store=MemoryStore(),
        clock=lambda: 1_000.0,
    )
    registry.enroll_authority(authority, actor="system:provisioner")
    registry.enroll_federation_binding(binding, actor="system:provisioner")
    registry.enroll_capability_rule(rule, actor="system:provisioner")
    registry.enroll_purview_asset(asset, actor="system:provisioner")

    bindings = registry.active_payloads("federation_binding")
    assert [row["binding_sha256"] for row in bindings] == [binding.binding_sha256]
    assert bindings[0]["authority_revision"] == authority.revision
    assert [row["asset_id"] for row in registry.active_payloads("purview_asset_binding")] == [
        asset.asset_id
    ]
    assert registry.active_payloads("capability_rule")[0]["capabilities"] == list(
        rule.capabilities
    )
    # Short-lived capability mappings are never offered as choices.
    with pytest.raises(ValueError, match="kind is invalid"):
        registry.active_payloads("capability_mapping")


def test_capability_mapping_registry_retains_then_purges_after_bound():
    tenant, authority, binding, rule, _asset = _authorities()
    now = {"value": 1_000.0}
    registry = IdentityGovernanceAuthorityRegistry(
        tenant_sha256=tenant,
        store=MemoryStore(),
        mapping_retention_seconds=300,
        clock=lambda: now["value"],
    )
    observation = AgentPrincipalFederationObservation(
        schema="lightwork.identity_governance.agent-principal-observation.v1",
        tenant_sha256=tenant,
        provider="entra",
        principal_ref=authority.principal_ref,
        provider_subject_id=binding.provider_subject_id,
        binding_sha256=binding.binding_sha256,
        binding_revision=authority.revision,
        active=True,
        permission_ids=(rule.permission_id,),
        source_sha256="3" * 64,
        observed_at=1_000.0,
    )
    mapping = IdentityCapabilityMapper(
        (rule,),
        revision=1,
        clock=lambda: now["value"],
    ).map(
        authority,
        binding,
        observation,
        expected_binding_sha256=binding.binding_sha256,
        expected_authority_revision=authority.revision,
    )

    assert registry.store(mapping) is True
    assert registry.store(mapping) is True
    assert (
        registry.get(tenant, authority.principal_ref, mapping.mapping_sha256)
        == mapping
    )
    now["value"] = mapping.expires_at + 301
    assert registry.purge_expired_mappings(actor="system:retention") == 1
    assert registry.get(tenant, authority.principal_ref, mapping.mapping_sha256) is None


def test_governed_change_request_sink_is_tenant_bound_and_idempotent():
    tenant = "a" * 64
    store = MemoryStore()
    sink = GovernedIdentityChangeRequestSink(
        tenant_sha256=tenant,
        sink="dynamic_risk",
        store=store,
    )
    event = {
        "schema": CHANGE_EVENT_SCHEMA,
        "event_id": "IGCE-" + ("b" * 32),
        "tenant_sha256": tenant,
        "provider": "entra",
        "change_sha256": "c" * 64,
        "slot": 1,
        "observed_at": 1_000.0,
        "change_kind": "comparison",
        "previous_snapshot_sha256": "d" * 64,
        "current_snapshot_sha256": "e" * 64,
        "counts": {"added": 1, "removed": 0},
        "configuration_changed": False,
        "provider_tenant_changed": False,
        "digests_truncated": False,
        "risk_assessment_required": True,
        "alert_candidate": True,
        "source_complete": False,
        "live_acceptance_verified": False,
    }

    first = sink(event)
    replay = sink(event)
    assert replay == first
    assert len(store.rows) == 1
    assert first.sink == "dynamic_risk"
    assert sink.status()["risk_score_generated"] is False
    with pytest.raises(IdentityGovernanceBindingError, match="tenant_mismatch"):
        sink({**event, "tenant_sha256": "f" * 64})
