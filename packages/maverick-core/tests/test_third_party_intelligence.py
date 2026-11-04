from __future__ import annotations

import hashlib
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from maverick import third_party_intelligence as intelligence


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


AUTO_KINDS = tuple(sorted(intelligence.MANDATORY_AUTOAPPROVAL_KINDS))


def citation(label: str = "official") -> list[dict[str, object]]:
    return [
        {
            "citation_id": f"cite-{label}",
            "title": "Licensed source evidence",
            "uri": f"https://intelligence.example/evidence/{label}",
            "pinpoint": "Record 1",
        }
    ]


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(
    tmp_path: Path, clock: Clock
) -> intelligence.ThirdPartyIntelligenceStore:
    return intelligence.ThirdPartyIntelligenceStore(
        tmp_path / "third-party.sqlite3",
        config_gate=lambda: None,
        clock=clock,
        token_factory=lambda: "x" * 43,
    )


def create_vendor(
    store: intelligence.ThirdPartyIntelligenceStore,
    *,
    tenant: str = "tenant-a",
    vendor_id: str = "vendor-1",
    criticality: int = 1,
    data_access_level: str = "limited",
) -> intelligence.VendorProfile:
    return store.upsert_vendor(
        tenant,
        vendor_id=vendor_id,
        display_label="Pseudonymous Vendor 1",
        entity_identity_sha256=digest(f"{tenant}:{vendor_id}:governed-identity"),
        encrypted_profile_ref=f"vault-cipher-{vendor_id}",
        profile_key_ref=f"kms-key-{vendor_id}",
        territories=["EU", "US"],
        service_categories=["cloud_service"],
        inherent_risk_level=1,
        criticality=criticality,
        data_access_level=data_access_level,
        owner_ref="vendor-owner",
        actor_ref="vendor-admin",
        idempotency_key=f"create-{vendor_id}",
    )


def enroll_source(
    store: intelligence.ThirdPartyIntelligenceStore,
    kind: str,
    *,
    tenant: str = "tenant-a",
    completeness: float = 1.0,
    valid_for: float = 3_600,
    purposes: list[str] | None = None,
    suffix: str = "v1",
) -> tuple[intelligence.IntelligenceSource, intelligence.SourceSnapshot]:
    source_id = f"source-{kind}"
    source = store.enroll_source(
        tenant,
        source_id=source_id,
        provider=f"fixture-{kind}",
        kind=kind,
        provenance_uri=f"https://intelligence.example/{kind}",
        credential_env=f"{kind.upper()}_INTELLIGENCE_TOKEN",
        license_ref=f"licensed-{kind}-2026",
        rights_basis="Customer-approved screening, monitoring, and exchange agreement.",
        purposes=purposes
        or ["screening", "monitoring", "risk_scoring", "edd", "exchange"],
        territories=["EU", "US"],
        retention_seconds=86_400,
        actor_ref="source-admin",
        idempotency_key=f"enroll-{source_id}-{suffix}",
    )
    source = store.approve_source(
        tenant,
        source_id,
        expected_revision=source.revision,
        approver_ref="source-counsel",
        approved=True,
        rationale="License, purpose, territory, and data rights independently reviewed.",
        idempotency_key=f"approve-{source_id}-{suffix}",
    )
    now = store._clock()
    snapshot = store.record_source_snapshot(
        tenant,
        source_id,
        snapshot_id=f"snapshot-{kind}-{suffix}",
        dataset_revision=f"dataset-{suffix}",
        observed_at=now - 10,
        valid_until=now + valid_for,
        completeness=completeness,
        record_count=100,
        evidence_sha256=digest(f"{kind}:{suffix}:evidence"),
        citations=citation(f"{kind}-{suffix}"),
        provenance_uri=f"https://intelligence.example/{kind}",
        actor_ref="snapshot-worker",
        idempotency_key=f"snapshot-{kind}-{suffix}",
    )
    return source, snapshot


def setup_sources(
    store: intelligence.ThirdPartyIntelligenceStore,
    kinds: tuple[str, ...],
    *,
    completeness: float = 1.0,
) -> tuple[dict[str, intelligence.IntelligenceSource], dict[str, str]]:
    sources: dict[str, intelligence.IntelligenceSource] = {}
    snapshots: dict[str, str] = {}
    for kind in kinds:
        source, snapshot = enroll_source(store, kind, completeness=completeness)
        sources[kind] = source
        snapshots[kind] = snapshot.snapshot_id
    return sources, snapshots


def start_run(
    store: intelligence.ThirdPartyIntelligenceStore,
    vendor: intelligence.VendorProfile,
    snapshots: dict[str, str],
    *,
    run_id: str = "run-1",
) -> intelligence.ScreeningRun:
    return store.start_screening_run(
        vendor.tenant_id,
        run_id=run_id,
        vendor_id=vendor.vendor_id,
        subject_identity_sha256=vendor.entity_identity_sha256,
        snapshot_bindings=snapshots,
        requested_kinds=sorted(snapshots),
        initiated_by="screening-operator",
        idempotency_key=f"start-{run_id}",
    )


def create_approved_policy(
    store: intelligence.ThirdPartyIntelligenceStore,
    kinds: tuple[str, ...],
    *,
    policy_id: str = "low-risk-policy",
    minimum_completeness: float = 0.95,
    max_age: int = 300,
    max_criticality: int = 2,
    max_data_access: str = "limited",
) -> intelligence.RiskPolicy:
    weights = dict.fromkeys(intelligence.RISK_FACTOR_KEYS, 1)
    policy = store.create_risk_policy(
        "tenant-a",
        policy_id=policy_id,
        required_source_kinds=list(kinds),
        maximum_source_age_seconds=max_age,
        minimum_completeness=minimum_completeness,
        factor_weights=weights,
        maximum_autoapproval_score=10,
        allow_low_risk_autoapproval=True,
        allowed_territories=["EU", "US"],
        maximum_vendor_criticality=max_criticality,
        maximum_data_access_level=max_data_access,
        authored_by="risk-author",
        idempotency_key=f"author-{policy_id}",
    )
    return store.approve_risk_policy(
        "tenant-a",
        policy.policy_id,
        policy.version,
        approver_ref="risk-approver",
        approved=True,
        rationale="Low-risk gate and fixed hard stops independently approved.",
        idempotency_key=f"approve-{policy_id}",
    )


def test_config_gate_is_exact_and_default_off(monkeypatch) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert intelligence.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": True,
                "intelligence": {"enabled": True},
            }
        },
    )
    assert intelligence.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": True,
                "intelligence": {"enable": True},
            }
        },
    )
    assert intelligence.enabled() is True


def test_constructor_requires_gate_and_creates_private_wal_database(tmp_path: Path) -> None:
    with pytest.raises(intelligence.ThirdPartyIntelligenceConfigError):
        intelligence.ThirdPartyIntelligenceStore(
            tmp_path / "blocked.sqlite3",
            config_gate=lambda: (_ for _ in ()).throw(
                intelligence.ThirdPartyIntelligenceConfigError("disabled")
            ),
        )
    path = tmp_path / "private" / "authority.sqlite3"
    intelligence.ThirdPartyIntelligenceStore(path, config_gate=lambda: None)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_unicode_tenant_isolation_strict_ids_and_secret_safe_profile(store) -> None:
    decomposed = "Acme Cafe\u0301 Group"
    canonical = "Acme Caf\u00e9 Group"
    vendor = create_vendor(store, tenant=decomposed)
    assert vendor.tenant_id == canonical
    assert store.get_vendor(canonical, vendor.vendor_id) == vendor
    with pytest.raises(intelligence.ThirdPartyIntelligenceNotFound):
        store.get_vendor("Other Group", vendor.vendor_id)
    with pytest.raises(intelligence.ThirdPartyIntelligenceValidationError):
        store.get_vendor(canonical, "vendor 1")
    with sqlite3.connect(store.path) as connection:
        payload = connection.execute(
            "SELECT payload_json FROM vendors WHERE tenant_id=? AND vendor_id=?",
            (canonical, vendor.vendor_id),
        ).fetchone()[0]
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    data = store.path.read_bytes()
    assert b"Very Secret Legal Name" not in data
    assert b"actual-provider-token" not in data
    assert vendor.entity_identity_sha256 in payload


def test_context_heads_are_bounded_tenant_exact_and_count_current_records(store) -> None:
    first = create_vendor(store, vendor_id="vendor-1")
    create_vendor(store, vendor_id="vendor-2")

    assert store.list_vendors("tenant-a", limit=1) == (first,)
    assert store.list_vendors("tenant-b", limit=1) == ()
    assert store.list_sources("tenant-a", limit=1) == ()
    assert store.list_source_snapshots("tenant-a", limit=1) == ()
    assert store.list_screening_runs("tenant-a", limit=1) == ()
    assert store.list_risk_decisions("tenant-a", limit=1) == ()
    assert store.list_edd_cases("tenant-a", limit=1) == ()
    assert store.list_monitors("tenant-a", limit=1) == ()
    assert store.list_monitoring_alerts("tenant-a", limit=1) == ()
    assert store.context_record_counts("tenant-a") == {
        "sources": 0,
        "source_snapshots": 0,
        "vendors": 2,
        "screening_runs": 0,
        "risk_decisions": 0,
        "edd_cases": 0,
        "monitors": 0,
        "monitoring_alerts": 0,
    }


def test_source_requires_independent_approval_and_rotation_invalidates_snapshot(store) -> None:
    source = store.enroll_source(
        "tenant-a",
        source_id="source-sanctions",
        provider="fixture-sanctions",
        kind="sanctions",
        provenance_uri="https://intelligence.example/sanctions",
        credential_env="SANCTIONS_TOKEN",
        license_ref="license-v1",
        rights_basis="Licensed screening use.",
        purposes=["screening", "risk_scoring"],
        territories=["EU", "US"],
        retention_seconds=86_400,
        actor_ref="source-admin",
        idempotency_key="source-sanctions-v1",
    )
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.approve_source(
            "tenant-a",
            source.source_id,
            expected_revision=source.revision,
            approver_ref="source-admin",
            approved=True,
            rationale="Self approval must fail.",
            idempotency_key="self-approval",
        )
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.record_source_snapshot(
            "tenant-a",
            source.source_id,
            snapshot_id="blocked-snapshot",
            dataset_revision="v1",
            observed_at=1_799_999_990,
            valid_until=1_800_001_000,
            completeness=1.0,
            record_count=1,
            evidence_sha256=digest("blocked"),
            citations=citation("blocked"),
            provenance_uri="https://intelligence.example/sanctions",
            actor_ref="worker",
            idempotency_key="blocked-snapshot",
        )
    source = store.approve_source(
        "tenant-a",
        source.source_id,
        expected_revision=source.revision,
        approver_ref="source-counsel",
        approved=True,
        rationale="Licensed rights reviewed.",
        idempotency_key="approve-sanctions-v1",
    )
    old_snapshot = store.record_source_snapshot(
        "tenant-a",
        source.source_id,
        snapshot_id="snapshot-sanctions-v1",
        dataset_revision="v1",
        observed_at=1_799_999_990,
        valid_until=1_800_001_000,
        completeness=1.0,
        record_count=10,
        evidence_sha256=digest("sanctions-v1"),
        citations=citation("sanctions-v1"),
        provenance_uri="https://intelligence.example/sanctions",
        actor_ref="worker",
        idempotency_key="snapshot-sanctions-v1",
    )
    rotated = store.enroll_source(
        "tenant-a",
        source_id=source.source_id,
        provider="fixture-sanctions",
        kind="sanctions",
        provenance_uri="https://intelligence.example/sanctions",
        credential_env="SANCTIONS_TOKEN_V2",
        license_ref="license-v2",
        rights_basis="Rotated licensed screening use.",
        purposes=["screening", "risk_scoring"],
        territories=["EU", "US"],
        retention_seconds=86_400,
        actor_ref="source-admin",
        expected_revision=source.revision,
        idempotency_key="source-sanctions-v2",
    )
    rotated = store.approve_source(
        "tenant-a",
        rotated.source_id,
        expected_revision=rotated.revision,
        approver_ref="source-counsel",
        approved=True,
        rationale="Rotated license reviewed.",
        idempotency_key="approve-sanctions-v2",
    )
    vendor = create_vendor(store)
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        start_run(store, vendor, {"sanctions": old_snapshot.snapshot_id})
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.create_monitor(
            "tenant-a",
            monitor_id="unlicensed-monitor",
            vendor_id=vendor.vendor_id,
            source_bindings={"sanctions": rotated.source_id},
            destination_ref="alert-sink",
            cadence_seconds=60,
            created_by="monitor-admin",
            idempotency_key="unlicensed-monitor",
        )
    revoked = store.revoke_source(
        "tenant-a",
        rotated.source_id,
        expected_revision=rotated.revision,
        actor_ref="source-counsel",
        rationale="Provider contract ended.",
        idempotency_key="revoke-sanctions",
    )
    assert revoked.state == "revoked"


def test_source_territory_and_screening_identity_are_exactly_bound(store) -> None:
    vendor = create_vendor(store)
    source = store.enroll_source(
        "tenant-a",
        source_id="eu-only-watchlist",
        provider="fixture-watchlist",
        kind="watchlist",
        provenance_uri="https://intelligence.example/watchlist",
        credential_env="WATCHLIST_TOKEN",
        license_ref="eu-only-license",
        rights_basis="Licensed only for EU subjects.",
        purposes=["screening"],
        territories=["EU"],
        retention_seconds=86_400,
        actor_ref="source-admin",
        idempotency_key="enroll-eu-watchlist",
    )
    source = store.approve_source(
        "tenant-a",
        source.source_id,
        expected_revision=source.revision,
        approver_ref="source-counsel",
        approved=True,
        rationale="EU territorial right reviewed.",
        idempotency_key="approve-eu-watchlist",
    )
    snapshot = store.record_source_snapshot(
        "tenant-a",
        source.source_id,
        snapshot_id="eu-watchlist-snapshot",
        dataset_revision="v1",
        observed_at=store._clock() - 10,
        valid_until=store._clock() + 600,
        completeness=1.0,
        record_count=10,
        evidence_sha256=digest("eu-watchlist"),
        citations=citation("eu-watchlist"),
        provenance_uri=source.provenance_uri,
        actor_ref="snapshot-worker",
        idempotency_key="eu-watchlist-snapshot",
    )
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        start_run(store, vendor, {"watchlist": snapshot.snapshot_id})
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.start_screening_run(
            "tenant-a",
            run_id="wrong-subject-run",
            vendor_id=vendor.vendor_id,
            subject_identity_sha256=digest("another-entity"),
            snapshot_bindings={"watchlist": snapshot.snapshot_id},
            requested_kinds=["watchlist"],
            initiated_by="screening-operator",
            idempotency_key="wrong-subject-run",
        )


def test_vendor_relationships_use_cas_and_participate_in_integrity(store) -> None:
    vendor = create_vendor(store)
    related = create_vendor(store, vendor_id="subprocessor-1")
    relationship = store.upsert_relationship(
        "tenant-a",
        relationship_id="relationship-1",
        vendor_id=vendor.vendor_id,
        related_vendor_id=related.vendor_id,
        relationship_type="subprocessor",
        scope_ref="service-scope-1",
        criticality=2,
        data_access_level="limited",
        actor_ref="vendor-admin",
        idempotency_key="relationship-1-create",
    )
    assert store.list_relationships("tenant-a", vendor.vendor_id) == (relationship,)
    with pytest.raises(intelligence.ThirdPartyIntelligenceConflict):
        store.upsert_relationship(
            "tenant-a",
            relationship_id=relationship.relationship_id,
            vendor_id=vendor.vendor_id,
            related_vendor_id=related.vendor_id,
            relationship_type="subprocessor",
            scope_ref="changed-scope",
            criticality=2,
            data_access_level="limited",
            actor_ref="vendor-admin",
            expected_revision=0,
            idempotency_key="stale-relationship-update",
        )
    assert store.verify_integrity("tenant-a").verified_records >= 3


@pytest.mark.parametrize("kind", ["sanctions", "pep", "adverse_media"])
def test_mandatory_match_kinds_block_until_independent_review(store, kind) -> None:
    vendor = create_vendor(store)
    _sources, snapshots = setup_sources(store, (kind,))
    run = start_run(store, vendor, snapshots, run_id=f"run-{kind}")
    finding = store.record_finding(
        "tenant-a",
        run.run_id,
        finding_id=f"finding-{kind}",
        source_id=f"source-{kind}",
        kind=kind,
        candidate_ref=f"candidate-{kind}",
        match_confidence=0.01,
        severity="low",
        observed_at=store._clock(),
        valid_until=store._clock() + 600,
        evidence_sha256=digest(f"finding-{kind}"),
        citations=citation(f"finding-{kind}"),
        detected_by="screening-worker",
        idempotency_key=f"record-finding-{kind}",
    )
    with pytest.raises(intelligence.ThirdPartyIntelligenceConflict):
        store.complete_screening_run(
            "tenant-a",
            run.run_id,
            expected_revision=run.revision,
            actor_ref="screening-operator",
            idempotency_key=f"premature-complete-{kind}",
        )
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.review_finding(
            "tenant-a",
            finding.finding_id,
            disposition="false_positive",
            expected_revision=finding.revision,
            reviewer_ref="screening-worker",
            rationale="Self disposition must fail.",
            idempotency_key=f"self-review-{kind}",
        )
    store.review_finding(
        "tenant-a",
        finding.finding_id,
        disposition="false_positive",
        expected_revision=finding.revision,
        reviewer_ref="match-reviewer",
        rationale="Identifier mismatch documented against encrypted source records.",
        idempotency_key=f"review-{kind}",
    )
    completed = store.complete_screening_run(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        actor_ref="screening-operator",
        idempotency_key=f"complete-{kind}",
    )
    assert completed.state == "complete"


def test_clear_complete_fresh_screening_can_autoapprove_under_approved_policy(store) -> None:
    kinds = tuple(sorted(intelligence.SOURCE_KINDS))
    vendor = create_vendor(store)
    _sources, snapshots = setup_sources(store, kinds)
    run = start_run(store, vendor, snapshots)
    run = store.complete_screening_run(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        actor_ref="screening-operator",
        idempotency_key="complete-clear-run",
    )
    policy = create_approved_policy(store, kinds)
    decision = store.evaluate_risk(
        "tenant-a",
        decision_id="decision-clear",
        vendor_id=vendor.vendor_id,
        run_id=run.run_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        actor_ref="risk-engine",
        idempotency_key="evaluate-clear",
    )
    assert decision.status == "auto_approved"
    assert decision.autoapproved is True
    assert decision.reason_codes == ()
    assert decision.factors == {"criticality": 1, "inherent_risk": 1}


def test_autoapproval_policy_cannot_omit_mandatory_sources_and_versions_use_cas(store) -> None:
    weights = dict.fromkeys(intelligence.RISK_FACTOR_KEYS, 1)
    with pytest.raises(intelligence.ThirdPartyIntelligenceValidationError):
        store.create_risk_policy(
            "tenant-a",
            policy_id="unsafe-policy",
            required_source_kinds=["performance"],
            maximum_source_age_seconds=300,
            minimum_completeness=0.95,
            factor_weights=weights,
            maximum_autoapproval_score=10,
            allow_low_risk_autoapproval=True,
            allowed_territories=["EU", "US"],
            maximum_vendor_criticality=2,
            maximum_data_access_level="limited",
            authored_by="risk-author",
            idempotency_key="unsafe-policy",
        )
    first = create_approved_policy(store, AUTO_KINDS, policy_id="versioned-policy")
    second = store.create_risk_policy(
        "tenant-a",
        policy_id=first.policy_id,
        required_source_kinds=AUTO_KINDS,
        maximum_source_age_seconds=180,
        minimum_completeness=0.99,
        factor_weights=weights,
        maximum_autoapproval_score=5,
        allow_low_risk_autoapproval=True,
        allowed_territories=["EU", "US"],
        maximum_vendor_criticality=1,
        maximum_data_access_level="limited",
        authored_by="risk-author",
        expected_latest_version=first.version,
        idempotency_key="versioned-policy-v2",
    )
    assert second.version == 2 and second.state == "pending"
    assert store.get_risk_policy("tenant-a", first.policy_id, 1) == first
    with pytest.raises(intelligence.ThirdPartyIntelligenceConflict):
        store.create_risk_policy(
            "tenant-a",
            policy_id=first.policy_id,
            required_source_kinds=AUTO_KINDS,
            maximum_source_age_seconds=180,
            minimum_completeness=0.99,
            factor_weights=weights,
            maximum_autoapproval_score=5,
            allow_low_risk_autoapproval=True,
            allowed_territories=["EU", "US"],
            maximum_vendor_criticality=1,
            maximum_data_access_level="limited",
            authored_by="risk-author",
            expected_latest_version=1,
            idempotency_key="stale-policy-v2",
        )


def test_incomplete_stale_or_out_of_scope_evidence_never_autoapproves(store, clock) -> None:
    kinds = AUTO_KINDS
    vendor = create_vendor(store)
    _sources, snapshots = setup_sources(store, kinds, completeness=0.5)
    run = start_run(store, vendor, snapshots)
    run = store.complete_screening_run(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        actor_ref="screening-operator",
        idempotency_key="complete-incomplete-run",
    )
    policy = create_approved_policy(store, kinds, max_age=60)
    clock.advance(61)
    decision = store.evaluate_risk(
        "tenant-a",
        decision_id="decision-incomplete",
        vendor_id=vendor.vendor_id,
        run_id=run.run_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        actor_ref="risk-engine",
        idempotency_key="evaluate-incomplete",
    )
    assert decision.status == "human_review"
    assert decision.autoapproved is False
    assert any("stale_incomplete_or_unlicensed" in item for item in decision.reason_codes)


def test_relationship_scope_and_confirmed_sanctions_are_hard_stops(store) -> None:
    vendor = create_vendor(store)
    related = create_vendor(store, vendor_id="critical-subprocessor")
    store.upsert_relationship(
        "tenant-a",
        relationship_id="critical-chain",
        vendor_id=vendor.vendor_id,
        related_vendor_id=related.vendor_id,
        relationship_type="subprocessor",
        scope_ref="sensitive-chain",
        criticality=5,
        data_access_level="sensitive",
        actor_ref="vendor-admin",
        idempotency_key="critical-chain",
    )
    kinds = AUTO_KINDS
    _sources, snapshots = setup_sources(store, kinds)
    run = start_run(store, vendor, snapshots)
    finding = store.record_finding(
        "tenant-a",
        run.run_id,
        finding_id="sanctions-match",
        source_id="source-sanctions",
        kind="sanctions",
        candidate_ref="candidate-1",
        match_confidence=0.99,
        severity="critical",
        observed_at=store._clock(),
        valid_until=store._clock() + 600,
        evidence_sha256=digest("sanctions-match"),
        citations=citation("sanctions-match"),
        detected_by="screening-worker",
        idempotency_key="record-sanctions-match",
    )
    store.review_finding(
        "tenant-a",
        finding.finding_id,
        disposition="confirmed",
        expected_revision=finding.revision,
        reviewer_ref="match-reviewer",
        rationale="Independent identifiers match the licensed record.",
        idempotency_key="confirm-sanctions-match",
    )
    run = store.complete_screening_run(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        actor_ref="screening-operator",
        idempotency_key="complete-blocked-run",
    )
    assert run.state == "blocked"
    policy = create_approved_policy(store, kinds)
    decision = store.evaluate_risk(
        "tenant-a",
        decision_id="blocked-decision",
        vendor_id=vendor.vendor_id,
        run_id=run.run_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        actor_ref="risk-engine",
        idempotency_key="evaluate-blocked",
    )
    assert decision.status == "human_review"
    assert "hard_stop_sanctions" in decision.reason_codes
    assert "relationship_criticality_exceeds_scope" in decision.reason_codes
    assert "relationship_data_access_exceeds_scope" in decision.reason_codes


def test_human_override_and_rollback_are_immutable_explainable_receipts(store) -> None:
    kinds = AUTO_KINDS
    vendor = create_vendor(store)
    _sources, snapshots = setup_sources(store, kinds)
    run = start_run(store, vendor, snapshots)
    run = store.complete_screening_run(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        actor_ref="screening-operator",
        idempotency_key="complete-for-override",
    )
    policy = create_approved_policy(store, kinds)
    initial = store.evaluate_risk(
        "tenant-a",
        decision_id="initial-decision",
        vendor_id=vendor.vendor_id,
        run_id=run.run_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        actor_ref="risk-engine",
        idempotency_key="initial-evaluation",
    )
    override = store.override_risk_decision(
        "tenant-a",
        initial.decision_id,
        override_decision_id="manual-rejection",
        status="rejected",
        expected_revision=initial.revision,
        actor_ref="risk-officer",
        rationale="New contractual issue requires rejection.",
        idempotency_key="manual-rejection",
    )
    assert override.status == "rejected" and override.autoapproved is False
    rollback = store.rollback_risk_decision(
        "tenant-a",
        override.decision_id,
        restore_decision_id=initial.decision_id,
        rollback_decision_id="rollback-rejection",
        actor_ref="risk-director",
        rationale="Contractual issue was entered against the wrong vendor.",
        idempotency_key="rollback-rejection",
    )
    assert rollback.status == initial.status
    assert rollback.autoapproved is False
    assert store.get_risk_decision("tenant-a", initial.decision_id) == initial


def test_edd_tasks_evidence_decision_and_escalation_are_governed(store) -> None:
    vendor = create_vendor(store)
    _source, snapshot = enroll_source(store, "compliance")
    case = store.open_edd_case(
        "tenant-a",
        case_id="edd-1",
        vendor_id=vendor.vendor_id,
        reason="enhanced_review_required",
        severity="high",
        opened_by="edd-owner",
        idempotency_key="open-edd-1",
    )
    case = store.set_edd_task(
        "tenant-a",
        case.case_id,
        task_id="verify-control",
        title="Verify compliance control",
        assignee_ref="analyst",
        due_at=store._clock() + 600,
        status="complete",
        evidence_sha256=digest("task-complete"),
        expected_revision=case.revision,
        actor_ref="analyst",
        idempotency_key="complete-control-task",
    )
    with pytest.raises(intelligence.ThirdPartyIntelligenceConflict):
        store.decide_edd_case(
            "tenant-a",
            case.case_id,
            decision="approved",
            rationale="Evidence absent.",
            expected_revision=case.revision,
            reviewer_ref="edd-reviewer",
            idempotency_key="premature-edd-decision",
        )
    case = store.add_edd_evidence(
        "tenant-a",
        case.case_id,
        evidence_id="control-evidence",
        snapshot_id=snapshot.snapshot_id,
        evidence_sha256=digest("control-evidence"),
        citations=citation("edd-control"),
        summary="Evidence retained in the encrypted case vault.",
        expected_revision=case.revision,
        actor_ref="analyst",
        idempotency_key="add-control-evidence",
    )
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.decide_edd_case(
            "tenant-a",
            case.case_id,
            decision="approved",
            rationale="Self decision must fail.",
            expected_revision=case.revision,
            reviewer_ref="edd-owner",
            idempotency_key="self-edd-decision",
        )
    decided = store.decide_edd_case(
        "tenant-a",
        case.case_id,
        decision="approved",
        rationale="Tasks and licensed evidence independently reviewed.",
        expected_revision=case.revision,
        reviewer_ref="edd-reviewer",
        idempotency_key="approve-edd-1",
    )
    assert decided.state == "decided" and decided.decision == "approved"
    escalated_case = store.open_edd_case(
        "tenant-a",
        case_id="edd-escalated",
        vendor_id=vendor.vendor_id,
        reason="urgent_adverse_change",
        severity="critical",
        opened_by="edd-owner",
        idempotency_key="open-edd-escalated",
    )
    escalated = store.decide_edd_case(
        "tenant-a",
        escalated_case.case_id,
        decision="escalated",
        rationale="Immediate executive and counsel review required.",
        expected_revision=escalated_case.revision,
        reviewer_ref="edd-reviewer",
        idempotency_key="escalate-edd",
    )
    assert escalated.state == "escalated"


def test_monitor_change_detection_outbox_retry_ack_and_revoke(store, clock) -> None:
    vendor = create_vendor(store)
    _source, snapshot = enroll_source(store, "breach_intelligence")
    monitor = store.create_monitor(
        "tenant-a",
        monitor_id="breach-monitor",
        vendor_id=vendor.vendor_id,
        source_bindings={"breach_intelligence": "source-breach_intelligence"},
        destination_ref="third-party-alert-sink",
        cadence_seconds=60,
        created_by="monitor-admin",
        idempotency_key="create-breach-monitor",
    )
    baseline = store.record_monitor_observation(
        "tenant-a",
        monitor.monitor_id,
        snapshot_bindings={"breach_intelligence": snapshot.snapshot_id},
        observation_sha256=digest("baseline"),
        evidence_sha256=digest("baseline-evidence"),
        citations=citation("baseline"),
        expected_revision=monitor.revision,
        actor_ref="monitor-worker",
        idempotency_key="monitor-baseline",
    )
    assert baseline.changed is False and baseline.alert is None
    clock.advance(60)
    changed = store.record_monitor_observation(
        "tenant-a",
        monitor.monitor_id,
        snapshot_bindings={"breach_intelligence": snapshot.snapshot_id},
        observation_sha256=digest("changed"),
        evidence_sha256=digest("changed-evidence"),
        citations=citation("changed"),
        expected_revision=baseline.monitor.revision,
        actor_ref="monitor-worker",
        idempotency_key="monitor-changed",
    )
    assert changed.changed is True and changed.alert is not None
    delivery = store.claim_outbox(
        "tenant-a", worker_id="delivery-worker", lease_seconds=30
    )[0]
    failed = store.fail_outbox(
        "tenant-a",
        delivery.delivery_id,
        lease_token=delivery.lease_token or "",
        error_code="temporary_outage",
        backoff_seconds=10,
    )
    assert failed.state == "pending" and failed.attempt == 1
    clock.advance(10)
    retry = store.claim_outbox(
        "tenant-a", worker_id="delivery-worker", lease_seconds=30
    )[0]
    delivered = store.acknowledge_outbox(
        "tenant-a", retry.delivery_id, lease_token=retry.lease_token or ""
    )
    assert delivered.state == "delivered"
    revoked = store.revoke_monitor(
        "tenant-a",
        changed.monitor.monitor_id,
        expected_revision=changed.monitor.revision,
        actor_ref="monitor-admin",
        idempotency_key="revoke-monitor",
    )
    assert revoked.state == "revoked"


def test_source_revocation_cancels_pending_monitor_delivery(store, clock) -> None:
    vendor = create_vendor(store)
    source, snapshot = enroll_source(store, "cyber_posture")
    monitor = store.create_monitor(
        "tenant-a",
        monitor_id="cyber-monitor",
        vendor_id=vendor.vendor_id,
        source_bindings={"cyber_posture": source.source_id},
        destination_ref="risk-alert-sink",
        cadence_seconds=60,
        created_by="monitor-admin",
        idempotency_key="create-cyber-monitor",
    )
    baseline = store.record_monitor_observation(
        "tenant-a",
        monitor.monitor_id,
        snapshot_bindings={"cyber_posture": snapshot.snapshot_id},
        observation_sha256=digest("cyber-baseline"),
        evidence_sha256=digest("cyber-baseline-evidence"),
        citations=citation("cyber-baseline"),
        expected_revision=monitor.revision,
        actor_ref="monitor-worker",
        idempotency_key="cyber-baseline",
    )
    clock.advance(60)
    store.record_monitor_observation(
        "tenant-a",
        monitor.monitor_id,
        snapshot_bindings={"cyber_posture": snapshot.snapshot_id},
        observation_sha256=digest("cyber-change"),
        evidence_sha256=digest("cyber-change-evidence"),
        citations=citation("cyber-change"),
        expected_revision=baseline.monitor.revision,
        actor_ref="monitor-worker",
        idempotency_key="cyber-change",
    )
    store.revoke_source(
        "tenant-a",
        source.source_id,
        expected_revision=source.revision,
        actor_ref="source-counsel",
        rationale="Monitoring rights withdrawn.",
        idempotency_key="revoke-cyber-source",
    )
    assert store.claim_outbox("tenant-a", worker_id="delivery-worker") == ()


def test_exchange_requires_consent_reviews_limits_lineage_and_withdrawal(store, clock) -> None:
    vendor = create_vendor(store)
    source, snapshot = enroll_source(store, "performance")
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.create_exchange_consent(
            "tenant-a",
            consent_id="denied-consent",
            vendor_id=vendor.vendor_id,
            audience="exchange-member",
            purpose="benchmarking",
            allowed_metrics=["availability_band"],
            explicit_consent=False,
            expires_at=clock.value + 86_400,
            granted_by="vendor-owner",
            idempotency_key="denied-consent",
        )
    consent = store.create_exchange_consent(
        "tenant-a",
        consent_id="exchange-consent",
        vendor_id=vendor.vendor_id,
        audience="exchange-member",
        purpose="benchmarking",
        allowed_metrics=["availability_band"],
        explicit_consent=True,
        expires_at=clock.value + 86_400,
        granted_by="vendor-owner",
        idempotency_key="exchange-consent",
    )
    assert consent.anonymity_proven is False and consent.privacy_reviewed is False
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.contribute_exchange(
            "tenant-a",
            consent.consent_id,
            contribution_id="premature-contribution",
            metric_id="availability_band",
            value_band="high",
            audience="exchange-member",
            purpose="benchmarking",
            evidence_sha256=digest("premature"),
            lineage_refs=[f"snapshot:{snapshot.snapshot_id}"],
            retention_seconds=86_400,
            contributed_by="exchange-worker",
            idempotency_key="premature-contribution",
        )
    consent = store.review_exchange_consent(
        "tenant-a",
        consent.consent_id,
        inclusion_approved=True,
        privacy_review_ref="privacy-review-1",
        anonymity_proof_ref=None,
        expected_revision=consent.revision,
        reviewer_ref="privacy-reviewer",
        rationale="Audience, purpose, and non-anonymous disclosure reviewed.",
        idempotency_key="review-exchange-consent",
    )
    contribution = store.contribute_exchange(
        "tenant-a",
        consent.consent_id,
        contribution_id="availability-contribution",
        metric_id="availability_band",
        value_band="high",
        audience="exchange-member",
        purpose="benchmarking",
        evidence_sha256=digest("availability-evidence"),
        lineage_refs=[f"snapshot:{snapshot.snapshot_id}"],
        retention_seconds=86_400,
        contributed_by="exchange-worker",
        idempotency_key="availability-contribution",
    )
    assert contribution.anonymous is False
    with pytest.raises(intelligence.ThirdPartyIntelligencePermissionDenied):
        store.query_exchange(
            "tenant-a",
            audience="exchange-member",
            purpose="benchmarking",
            metric_id="availability_band",
            principal_ref="unrelated-principal",
        )
    assert store.query_exchange(
        "tenant-a",
        audience="exchange-member",
        purpose="benchmarking",
        metric_id="availability_band",
        principal_ref="exchange-member",
    ) == (contribution,)
    store.revoke_source(
        "tenant-a",
        source.source_id,
        expected_revision=source.revision,
        actor_ref="source-counsel",
        rationale="Exchange data rights withdrawn.",
        idempotency_key="revoke-performance-source",
    )
    assert store.query_exchange(
        "tenant-a",
        audience="exchange-member",
        purpose="benchmarking",
        metric_id="availability_band",
        principal_ref="exchange-member",
    ) == ()
    withdrawn = store.withdraw_exchange_consent(
        "tenant-a",
        consent.consent_id,
        expected_revision=consent.revision,
        actor_ref="vendor-owner",
        rationale="Vendor withdrew its exchange contribution consent.",
        idempotency_key="withdraw-exchange-consent",
    )
    assert withdrawn.state == "withdrawn"
    assert store.query_exchange(
        "tenant-a",
        audience="exchange-member",
        purpose="benchmarking",
        metric_id="availability_band",
        principal_ref="exchange-member",
    ) == ()


def test_anonymity_claim_is_true_only_with_reviewed_proof(store, clock) -> None:
    vendor = create_vendor(store)
    _source, snapshot = enroll_source(store, "performance")
    consent = store.create_exchange_consent(
        "tenant-a",
        consent_id="anonymous-consent",
        vendor_id=vendor.vendor_id,
        audience="exchange-member",
        purpose="benchmarking",
        allowed_metrics=["performance_band"],
        explicit_consent=True,
        expires_at=clock.value + 86_400,
        granted_by="vendor-owner",
        idempotency_key="anonymous-consent",
    )
    consent = store.review_exchange_consent(
        "tenant-a",
        consent.consent_id,
        inclusion_approved=True,
        privacy_review_ref="privacy-review-2",
        anonymity_proof_ref="anonymity-proof-2",
        expected_revision=consent.revision,
        reviewer_ref="privacy-reviewer",
        rationale="Anonymity and privacy artifacts reviewed.",
        idempotency_key="review-anonymous-consent",
    )
    contribution = store.contribute_exchange(
        "tenant-a",
        consent.consent_id,
        contribution_id="anonymous-contribution",
        metric_id="performance_band",
        value_band="medium",
        audience="exchange-member",
        purpose="benchmarking",
        evidence_sha256=digest("anonymous-evidence"),
        lineage_refs=[f"snapshot:{snapshot.snapshot_id}"],
        retention_seconds=86_400,
        contributed_by="exchange-worker",
        idempotency_key="anonymous-contribution",
    )
    assert consent.anonymity_proven is True
    assert contribution.anonymous is True and contribution.privacy_reviewed is True


def test_integrity_tamper_retention_and_concurrent_vendor_cas(store, clock) -> None:
    vendor = create_vendor(store)
    _source, _snapshot = enroll_source(store, "compliance")
    baseline = store.verify_integrity("tenant-a")
    assert baseline.verified_records >= 3

    def update(index: int) -> str:
        try:
            store.upsert_vendor(
                "tenant-a",
                vendor_id=vendor.vendor_id,
                display_label=f"Pseudonymous Vendor {index}",
                entity_identity_sha256=vendor.entity_identity_sha256,
                encrypted_profile_ref=vendor.encrypted_profile_ref,
                profile_key_ref=vendor.profile_key_ref,
                territories=vendor.territories,
                service_categories=vendor.service_categories,
                inherent_risk_level=vendor.inherent_risk_level,
                criticality=vendor.criticality,
                data_access_level=vendor.data_access_level,
                owner_ref=vendor.owner_ref,
                actor_ref="vendor-admin",
                expected_revision=vendor.revision,
                idempotency_key=f"concurrent-vendor-{index}",
            )
        except intelligence.ThirdPartyIntelligenceConflict:
            return "conflict"
        return "updated"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(update, [2, 3]))
    assert sorted(outcomes) == ["conflict", "updated"]
    clock.advance(86_401)
    purged = store.purge_expired("tenant-a", actor_ref="retention-worker")
    assert purged["source_snapshots"] == 1
    with sqlite3.connect(store.path) as connection:
        original = connection.execute(
            "SELECT payload_json,integrity_sha256 FROM vendors "
            "WHERE tenant_id='tenant-a' AND vendor_id='vendor-1'"
        ).fetchone()
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE vendors SET payload_json='{}' WHERE tenant_id='tenant-a' "
            "AND vendor_id='vendor-1'"
        )
    with pytest.raises(intelligence.ThirdPartyIntelligenceIntegrityError):
        store.verify_integrity("tenant-a")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE vendors SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id='tenant-a' AND vendor_id='vendor-1'",
            original,
        )
        connection.execute(
            "UPDATE audit_events SET payload_json='{}' "
            "WHERE tenant_id='tenant-a' AND sequence=1"
        )
    with pytest.raises(intelligence.ThirdPartyIntelligenceIntegrityError):
        store.verify_integrity("tenant-a")


def test_idempotency_binding_tamper_is_detected_before_replay(store) -> None:
    vendor = create_vendor(store)
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE operations SET result_id='forged-vendor' "
            "WHERE tenant_id='tenant-a'"
        )
    with pytest.raises(intelligence.ThirdPartyIntelligenceIntegrityError):
        store.upsert_vendor(
            "tenant-a",
            vendor_id=vendor.vendor_id,
            display_label=vendor.display_label,
            entity_identity_sha256=vendor.entity_identity_sha256,
            encrypted_profile_ref=vendor.encrypted_profile_ref,
            profile_key_ref=vendor.profile_key_ref,
            territories=vendor.territories,
            service_categories=vendor.service_categories,
            inherent_risk_level=vendor.inherent_risk_level,
            criticality=vendor.criticality,
            data_access_level=vendor.data_access_level,
            owner_ref=vendor.owner_ref,
            actor_ref="vendor-admin",
            idempotency_key="create-vendor-1",
        )
