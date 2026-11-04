from __future__ import annotations

from copy import deepcopy

from maverick.ai_identity_governance_controls import (
    AgentPrincipalAuthority,
    AgentPrincipalFederationBinding,
    AgentPrincipalFederationObservation,
    CapabilityRule,
    ConditionalAccessDecisionEngine,
    ConditionalAccessObservation,
    IdentityCapabilityMapper,
)
from maverick.ai_identity_governance_outcomes import (
    GovernedConditionalAccessDecisionLedger,
    IdentityChangeAssetRegistry,
    IdentityChangeOutcomeConsumer,
    asset_event_from_change_event,
    make_identity_change_asset_binding,
)
from maverick.privacy_ops import RecordConflict

TENANT = "a" * 64
ASSET = "MAA-" + ("b" * 32)
VERSION = "c" * 64
SELECTOR = "d" * 64


class MemoryStore:
    backend_kind = "memory"

    def __init__(self) -> None:
        self.rows: dict[str, dict] = {}

    def authoritative_time(self) -> float:
        return 1_000.0

    def get(self, record_id):
        row = self.rows.get(record_id)
        return deepcopy(row) if row is not None else None

    def list(self, *, limit=None):
        rows = [deepcopy(row) for _, row in sorted(self.rows.items())]
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
        saved["updated_at"] += 1
        self.rows[record_id] = saved
        return deepcopy(saved)


def _binding(*, revision=1, version=VERSION, selector_kind="identities"):
    return make_identity_change_asset_binding(
        tenant_sha256=TENANT,
        provider="entra",
        selector_kind=selector_kind,
        selector_sha256=SELECTOR,
        asset_id=ASSET,
        asset_revision=revision,
        asset_version_digest=version,
        binding_revision=1,
        asset_criticality="high",
        eu_risk_tier="high",
        sensitive_data="personal",
        external_exposure="partner",
    )


def _normalized_change(*, selector=SELECTOR, added=1):
    category = {
        "added_count": added,
        "removed_count": 0,
        "added_sha256": [selector] if added else [],
        "removed_sha256": [],
        "digests_truncated": False,
    }
    empty = {
        "added_count": 0,
        "removed_count": 0,
        "added_sha256": [],
        "removed_sha256": [],
        "digests_truncated": False,
    }
    return {
        "tenant_sha256": TENANT,
        "provider": "entra",
        "slot": 1,
        "collected_at": 1_000.0,
        "change_sha256": "e" * 64,
        "change_kind": "comparison",
        "previous_snapshot_sha256": "f" * 64,
        "current_snapshot_sha256": "1" * 64,
        "configuration_changed": False,
        "provider_tenant_changed": False,
        "categories": {
            "identities": category,
            "grants": deepcopy(empty),
            "data_classifications": deepcopy(empty),
        },
    }


def _event(manifest, *, added=1):
    return asset_event_from_change_event(
        {
            "schema": "lightwork.identity_governance.change-event.v1",
            "event_id": "IGCE-" + ("2" * 32),
            "tenant_sha256": TENANT,
            "provider": "entra",
            "change_sha256": "e" * 64,
            "slot": 1,
            "observed_at": 1_000.0,
            "change_kind": "comparison",
            "previous_snapshot_sha256": "f" * 64,
            "current_snapshot_sha256": "1" * 64,
            "counts": {"added": added, "removed": 0},
            "configuration_changed": False,
            "provider_tenant_changed": False,
            "digests_truncated": False,
            "risk_assessment_required": True,
            "alert_candidate": True,
            "source_complete": False,
            "live_acceptance_verified": False,
        },
        manifest,
    )


class FakeRisk:
    def __init__(self) -> None:
        self.signal = None
        self.current = None
        self.ingests = 0
        self.scores = 0

    def ingest_signal(self, signal, *, actor):
        assert actor.principal == "system:identity-governance-outcome-consumer"
        self.signal = signal
        self.ingests += 1
        return {"signal_id": "DRS-" + ("3" * 32)}

    def current_score(self, asset_id):
        assert asset_id == ASSET
        return deepcopy(self.current)

    def score_asset(self, asset_id, *, context, expected_revision, actor):
        assert asset_id == ASSET
        assert context.asset_criticality == "high"
        assert expected_revision == 0
        assert actor.principal == "system:identity-governance-outcome-consumer"
        self.scores += 1
        self.current = {
            "asset_revision": 1,
            "asset_version_digest": VERSION,
            "snapshot_id": "DRP-" + ("4" * 32),
            "snapshot_revision": 1,
            "score": 70.0,
            "risk_tier": "high",
            "contributions": [
                {
                    "signal_id": "DRS-" + ("3" * 32),
                    "source_id": self.signal.source_id,
                    "source_digest": self.signal.source_digest,
                }
            ],
        }
        return deepcopy(self.current)


def test_asset_registry_is_cas_bound_and_reports_unmapped_coverage():
    store = MemoryStore()
    registry = IdentityChangeAssetRegistry(
        tenant_sha256=TENANT,
        store=store,
        clock=lambda: 1_000.0,
    )
    enrolled = registry.enroll(_binding(), actor="system:provisioner")
    manifest = registry.resolve_change(_normalized_change())

    assert manifest["coverage_complete"] is True
    assert manifest["unmapped_item_count"] == 0
    assert manifest["bindings"][0]["binding"]["asset_id"] == ASSET
    assert manifest["bindings"][0]["binding_record_revision"] == 1
    assert registry.status()["active_binding_count"] == 1

    unknown = registry.resolve_change(_normalized_change(selector="9" * 64))
    assert unknown["coverage_complete"] is False
    assert unknown["unmapped_item_count"] == 1

    revoked = registry.revoke(
        enrolled["binding_id"],
        expected_revision=enrolled["revision"],
        evidence_sha256="8" * 64,
        actor="user:security-admin",
    )
    assert revoked["status"] == "revoked"
    assert registry.status()["revoked_binding_count"] == 1


def test_dynamic_risk_consumer_produces_idempotent_signal_and_score():
    registry = IdentityChangeAssetRegistry(
        tenant_sha256=TENANT,
        store=MemoryStore(),
    )
    registry.enroll(_binding(), actor="system:provisioner")
    event = _event(registry.resolve_change(_normalized_change()))
    risk = FakeRisk()
    consumer = IdentityChangeOutcomeConsumer(
        tenant_sha256=TENANT,
        sink="dynamic_risk",
        asset_lookup=lambda _asset: {
            "asset_id": ASSET,
            "revision": 1,
            "version_digest": VERSION,
        },
        risk_service=risk,
        store=MemoryStore(),
        clock=lambda: 1_000.0,
    )

    first = consumer(event)
    replay = consumer(event)
    record = consumer.list()[0]

    assert replay == first
    assert risk.ingests == 1
    assert risk.scores == 1
    assert record["status"] == "completed"
    assert record["items"][0]["outcome"]["score"] == 70.0
    assert record["items"][0]["outcome"]["asset_revision"] == 1
    assert consumer.status()["downstream_consumer_attached"] is True


def test_stale_asset_dead_letters_then_exact_replacement_can_replay():
    registry = IdentityChangeAssetRegistry(
        tenant_sha256=TENANT,
        store=MemoryStore(),
    )
    registry.enroll(_binding(), actor="system:provisioner")
    event = _event(registry.resolve_change(_normalized_change()))
    current = {"revision": 2, "version": "7" * 64}
    store = MemoryStore()
    consumer = IdentityChangeOutcomeConsumer(
        tenant_sha256=TENANT,
        sink="alert",
        asset_lookup=lambda _asset: {
            "asset_id": ASSET,
            "revision": current["revision"],
            "version_digest": current["version"],
        },
        store=store,
        max_attempts=1,
        clock=lambda: 1_000.0,
    )

    acknowledgement = consumer(event)
    dead = consumer.list()[0]
    assert acknowledgement.receipt_sha256 == dead["receipt_sha256"]
    assert dead["status"] == "dead_letter"
    assert dead["last_error_type"] == "IdentityGovernanceStaleBinding"

    replacement_registry = IdentityChangeAssetRegistry(
        tenant_sha256=TENANT,
        store=MemoryStore(),
    )
    replacement_registry.enroll(
        _binding(revision=2, version="7" * 64),
        actor="system:provisioner",
    )
    replacement = _event(
        replacement_registry.resolve_change(_normalized_change())
    )
    replayed = consumer.replay(
        dead["outcome_id"],
        expected_revision=dead["revision"],
        replacement_event=replacement,
        evidence_sha256="6" * 64,
        actor="user:security-admin",
    )
    assert replayed["status"] == "pending"
    worker = consumer.run_due()
    assert worker["completed"] == 1
    assert consumer.list()[0]["items"][0]["outcome"]["alert_state"] == "open"


def test_unmapped_and_empty_baseline_have_distinct_terminal_receipts():
    registry = IdentityChangeAssetRegistry(
        tenant_sha256=TENANT,
        store=MemoryStore(),
    )
    unmapped = _event(registry.resolve_change(_normalized_change()))
    consumer = IdentityChangeOutcomeConsumer(
        tenant_sha256=TENANT,
        sink="alert",
        asset_lookup=lambda _asset: None,
        store=MemoryStore(),
    )
    consumer(unmapped)
    assert consumer.list()[0]["status"] == "dead_letter"

    empty_manifest = registry.resolve_change(_normalized_change(added=0))
    no_change = _event(empty_manifest, added=0)
    no_change_consumer = IdentityChangeOutcomeConsumer(
        tenant_sha256=TENANT,
        sink="alert",
        asset_lookup=lambda _asset: None,
        store=MemoryStore(),
    )
    no_change_consumer(no_change)
    assert no_change_consumer.list()[0]["status"] == "no_change"


def test_conditional_access_decision_is_durable_evidence_bound_and_revocable():
    authority = AgentPrincipalAuthority(
        tenant_sha256=TENANT,
        principal_ref="prn_" + ("1" * 32),
        authority_binding_sha256="2" * 64,
        revision=1,
    )
    federation = AgentPrincipalFederationBinding.bind(
        authority,
        provider="entra",
        provider_subject_id="sub_" + ("3" * 32),
    )
    rule = CapabilityRule(
        tenant_sha256=TENANT,
        provider="entra",
        permission_id="prm_" + ("4" * 32),
        capabilities=("agent.execute",),
        revision=1,
    )
    federation_observation = AgentPrincipalFederationObservation(
        schema="lightwork.identity_governance.agent-principal-observation.v1",
        tenant_sha256=TENANT,
        provider="entra",
        principal_ref=authority.principal_ref,
        provider_subject_id=federation.provider_subject_id,
        binding_sha256=federation.binding_sha256,
        binding_revision=1,
        active=True,
        permission_ids=(rule.permission_id,),
        source_sha256="5" * 64,
        observed_at=1_000.0,
    )
    mapping = IdentityCapabilityMapper(
        (rule,),
        revision=1,
        clock=lambda: 1_000.0,
    ).map(
        authority,
        federation,
        federation_observation,
        expected_binding_sha256=federation.binding_sha256,
        expected_authority_revision=1,
    )
    observation = ConditionalAccessObservation(
        schema="lightwork.identity_governance.conditional-access-observation.v1",
        tenant_sha256=TENANT,
        provider="entra",
        principal_ref=authority.principal_ref,
        provider_subject_id=federation.provider_subject_id,
        binding_sha256=federation.binding_sha256,
        binding_revision=1,
        outcome="allow",
        policy_sha256="6" * 64,
        reason_codes=("policy_allow",),
        source_sha256="7" * 64,
        observed_at=1_000.0,
    )
    decision = ConditionalAccessDecisionEngine(clock=lambda: 1_000.0).decide(
        authority,
        mapping,
        observation,
        required_capability="agent.execute",
        expected_binding_sha256=federation.binding_sha256,
        expected_revision=1,
        idempotency_key="decision-1",
    )
    ledger = GovernedConditionalAccessDecisionLedger(
        tenant_sha256=TENANT,
        store=MemoryStore(),
        clock=lambda: 1_000.0,
    )

    first = ledger.record(
        decision,
        observation,
        mapping,
        actor="user:security-admin",
    )
    replay = ledger.record(
        decision,
        observation,
        mapping,
        actor="user:security-admin",
    )
    assert replay == first
    assert first["action"] == "permit"
    assert first["mapping_sha256"] == mapping.mapping_sha256
    assert ledger.status()["active_decisions"] == 1

    revoked = ledger.revoke(
        first["decision_record_id"],
        expected_revision=first["revision"],
        evidence_sha256="8" * 64,
        actor="user:security-admin",
    )
    assert revoked["status"] == "revoked"
    assert ledger.status()["revoked_decisions"] == 1
