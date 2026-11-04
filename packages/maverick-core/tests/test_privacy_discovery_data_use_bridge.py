from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from maverick import data_use_governance as data_use
from maverick import privacy_data_discovery as discovery
from maverick import privacy_discovery_data_use_bridge as bridge

TENANT = "tenant-a"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Rows:
    def __init__(self, fields: dict[str, object]) -> None:
        self.fields = fields

    def iter_rows(self, *, source, credential_env, limits, deadline):
        del source, credential_env, limits, deadline
        yield discovery.StructuredRecord("raw-record-location", self.fields)


class Harness:
    def __init__(self, tmp_path: Path) -> None:
        self.clock = Clock()
        self.discovery_path = tmp_path / "privacy-discovery.sqlite3"
        self.data_use_path = tmp_path / "data-use.sqlite3"
        self.bridge_path = tmp_path / "discovery-data-use-bridge.sqlite3"
        self.discovery = discovery.PrivacyDataDiscoveryStore(
            self.discovery_path,
            config_gate=lambda: None,
            clock=self.clock,
            evidence_key_resolver=lambda _name: b"e" * 32,
        )
        self.data_use = data_use.DataUseGovernanceStore(
            self.data_use_path,
            clock=self.clock,
        )
        self.bridge = bridge.PrivacyDiscoveryDataUseBridgeStore(
            self.bridge_path,
            discovery_store=self.discovery,
            data_use_store=self.data_use,
            config_gate=lambda: None,
            principal_resolver=lambda: "operator@example.test",
            digest_key_resolver=lambda _tenant: b"b" * 32,
            clock=self.clock,
        )
        self.source = self.discovery.enroll_source(
            TENANT,
            source_id="customer-db",
            kind="structured",
            provider="fixture",
            origin="https://private-source.example.test",
            resource_ref="raw-customer-table-location",
            credential_env="PRIVATE_DISCOVERY_CREDENTIAL",
            evidence_key_env="PRIVATE_DISCOVERY_EVIDENCE_KEY",
            actor_ref="privacy-owner-ref",
            idempotency_key="source-enrollment",
        )
        self.asset = self.data_use.put_asset(
            TENANT,
            "customers",
            asset_type="table",
            catalog_binding_sha256=digest("catalog:customers"),
            expected_revision=0,
            idempotency_key="asset-enrollment",
        )
        self.scan_counter = 0

    def scan_and_approve(
        self,
        fields: dict[str, object],
        *,
        freshness_seconds: int = 1_800,
    ) -> tuple[discovery.ScanReport, tuple[bridge.ClassificationPin, ...]]:
        self.scan_counter += 1
        operation = f"scan-{self.scan_counter}"
        self.discovery.enqueue_scan(
            TENANT,
            self.source.source_id,
            limits=discovery.ScanLimits(),
            max_attempts=3,
            retention_seconds=3_600,
            actor_ref="privacy-owner",
            idempotency_key=operation,
        )
        coordinator = discovery.PrivacyDataDiscoveryCoordinator(
            self.discovery,
            structured_sources={"fixture": Rows(fields)},
            clock=self.clock,
            credential_ref_present=lambda _name: True,
        )
        result = coordinator.run_once(TENANT, worker_id=f"worker-{self.scan_counter}")
        assert not result.failed_jobs
        report = result.completed_reports[0]
        assert report.completeness == "complete_within_declared_bounds"
        findings = self.discovery.list_findings(
            TENANT,
            report_id=report.report_id,
            limit=2_000,
        )
        assert findings
        pins: list[bridge.ClassificationPin] = []
        for index, finding in enumerate(findings):
            proposal = self.discovery.propose_review(
                TENANT,
                finding.finding_id,
                decision="confirmed",
                effective_category=finding.category,
                evidence_sha256=digest(f"review-evidence:{operation}:{index}"),
                freshness_seconds=freshness_seconds,
                expected_finding_revision=finding.revision,
                prepared_by=f"review-preparer-{index}",
                idempotency_key=f"review-proposal:{operation}:{index}",
            )
            self.discovery.approve_review(
                TENANT,
                proposal.review_id,
                approved_by=f"review-approver-{index}",
                expected_version=proposal.version,
                expected_integrity_sha256=proposal.integrity_sha256,
                idempotency_key=f"review-approval:{operation}:{index}",
            )
            approved = self.discovery.get_review(TENANT, proposal.review_id)
            current_finding = self.discovery.get_finding(TENANT, finding.finding_id)
            pins.append(
                bridge.ClassificationPin(
                    finding_id=current_finding.finding_id,
                    finding_revision=current_finding.revision,
                    finding_integrity_sha256=current_finding.integrity_sha256,
                    review_id=approved.review_id,
                    review_version=approved.version,
                    review_integrity_sha256=approved.integrity_sha256,
                )
            )
        return report, tuple(pins)

    def propose(
        self,
        report: discovery.ScanReport,
        pins: tuple[bridge.ClassificationPin, ...],
        *,
        bridge_revision: int,
        idempotency_key: str,
        context: dict | None = None,
    ) -> dict:
        current_source = self.discovery.get_source(TENANT, self.source.source_id)
        current_asset = self.data_use.get_record(TENANT, "asset", "customers")
        assert current_asset is not None
        current_context = (
            self.data_use.get_context_authority(
                TENANT,
                "customers",
                "observed_classification",
            )
            if context is None
            else context
        )
        return self.bridge.propose(
            TENANT,
            "customer-classification",
            "customers",
            current_source.source_id,
            report.report_id,
            pins,
            expected_source_revision=current_source.revision,
            expected_source_integrity_sha256=current_source.integrity_sha256,
            expected_report_revision=1,
            expected_report_integrity_sha256=report.integrity_sha256,
            expected_asset_revision=current_asset["revision"],
            expected_asset_record_sha256=current_asset["record_sha256"],
            expected_context_revision=(
                0 if current_context is None else current_context["revision"]
            ),
            expected_context_record_sha256=(
                None if current_context is None else current_context["record_sha256"]
            ),
            expected_bridge_revision=bridge_revision,
            retained_until=self.clock() + 1_200,
            idempotency_key=idempotency_key,
        )

    def reconcile(self, proposal: dict, *, idempotency_key: str) -> dict:
        return self.bridge.reconcile(
            TENANT,
            proposal["proposal_id"],
            expected_proposal_integrity_sha256=proposal["integrity_sha256"],
            expected_bridge_revision=proposal["expected_bridge_revision"],
            idempotency_key=idempotency_key,
        )


@pytest.fixture()
def harness(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def test_exact_default_off_gate_requires_all_four_sections(monkeypatch) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    incomplete = {
        "privacy_automation": {
            "enable": True,
            "data_discovery": {"enable": True},
            "discovery_data_use_bridge": {"enable": True},
        }
    }
    monkeypatch.setattr(config, "load_config", lambda: incomplete)
    assert bridge.enabled() is False
    enabled = {
        **incomplete,
        "data_use_governance": {"enable": True},
    }
    monkeypatch.setattr(config, "load_config", lambda: enabled)
    assert bridge.enabled() is True


def test_public_context_read_is_exact_integrity_checked_and_non_authorizing(
    harness: Harness,
) -> None:
    store = harness.data_use
    assert store.get_context_authority(TENANT, "customers", "observed_classification") is None
    created = store.put_context_authority(
        TENANT,
        "customers",
        "observed_classification",
        values=["email_address"],
        source_system="manual-review",
        source_revision=1,
        source_authority_sha256=digest("manual-source"),
        evidence_sha256=digest("manual-evidence"),
        reviewer_id="manual-reviewer",
        reviewer_authority_sha256=digest("manual-reviewer"),
        observed_at=harness.clock() - 10,
        fresh_until=harness.clock() + 300,
        expected_revision=0,
        idempotency_key="manual-context",
    )
    assert store.get_context_authority(TENANT, "customers", "observed_classification") == created
    assert store.get_context_authority("tenant-b", "customers", "observed_classification") is None
    with pytest.raises(data_use.DataUseValidationError):
        store.get_context_authority(TENANT, "customers", "invented_context")
    assert store.status()["context_authorities_required"] == list(data_use.CONTEXT_KINDS)

    with sqlite3.connect(harness.data_use_path) as connection:
        connection.execute(
            "UPDATE data_use_records SET record_sha256=? WHERE tenant_id=? "
            "AND record_type='context'",
            ("0" * 64, TENANT),
        )
    with pytest.raises(data_use.DataUseCorruptionError):
        store.get_context_authority(TENANT, "customers", "observed_classification")


def test_desired_reconcile_is_digest_only_idempotent_and_other_contexts_remain_absent(
    harness: Harness,
) -> None:
    report, pins = harness.scan_and_approve({"email": "raw.person@example.test"})
    proposal = harness.propose(
        report,
        pins,
        bridge_revision=0,
        idempotency_key="proposal-desired",
    )
    assert proposal["action"] == "desired"
    assert proposal["source_snapshot"]["report_revision"] == 1
    assert proposal["source_snapshot"]["report_completeness"] == ("complete_within_declared_bounds")
    assert proposal["source_snapshot"]["estate_completeness_inferred"] is False
    assert proposal["desired_context"]["values"]
    application = harness.reconcile(proposal, idempotency_key="apply-desired")
    assert application["outcome"] == "applied"
    assert application["bridge_revision"] == 1
    context = harness.data_use.get_context_authority(
        TENANT,
        "customers",
        "observed_classification",
    )
    assert context is not None
    assert context["record_sha256"] == application["after_context"]["record_sha256"]
    assert context["source_authority_sha256"] == proposal["source_snapshot"]["authority_sha256"]
    for kind in ("business_purpose", "regulatory", "consent"):
        assert harness.data_use.get_context_authority(TENANT, "customers", kind) is None
    replay = harness.reconcile(proposal, idempotency_key="apply-desired")
    assert replay == application
    verification = harness.bridge.verify_integrity(TENANT)
    assert verification["proposals"] == 1
    assert verification["applications"] == 1
    assert verification["history"] == 1
    assert verification["audit_events"] >= 2
    assert harness.bridge.product_boundaries()["estate_completeness_inferred"] is False
    assert harness.bridge.product_boundaries()["provider_writes"] is False

    persisted = harness.bridge_path.read_bytes()
    for raw in (
        b"raw.person@example.test",
        b"private-source.example.test",
        b"raw-customer-table-location",
        b"raw-record-location",
        b"PRIVATE_DISCOVERY_CREDENTIAL",
        b"operator@example.test",
        b"review-preparer-0",
        b"review-approver-0",
    ):
        assert raw not in persisted


def test_no_change_is_deterministic_and_does_not_rewrite_context(harness: Harness) -> None:
    report, pins = harness.scan_and_approve({"email": "person@example.test"})
    first = harness.propose(
        report,
        pins,
        bridge_revision=0,
        idempotency_key="proposal-first",
    )
    harness.reconcile(first, idempotency_key="apply-first")
    context_before = harness.data_use.get_context_authority(
        TENANT,
        "customers",
        "observed_classification",
    )
    assert context_before is not None
    no_change = harness.propose(
        report,
        pins,
        bridge_revision=1,
        idempotency_key="proposal-no-change",
    )
    assert no_change["action"] == "no_change"
    accepted = harness.reconcile(no_change, idempotency_key="apply-no-change")
    assert accepted["outcome"] == "no_change"
    context_after = harness.data_use.get_context_authority(
        TENANT,
        "customers",
        "observed_classification",
    )
    assert context_after == context_before
    assert harness.bridge.get_head(TENANT, "customer-classification")["revision"] == 2


def test_context_and_source_drift_fail_before_overwrite(harness: Harness) -> None:
    report, pins = harness.scan_and_approve({"email": "person@example.test"})
    proposal = harness.propose(
        report,
        pins,
        bridge_revision=0,
        idempotency_key="proposal-context-drift",
    )
    external = harness.data_use.put_context_authority(
        TENANT,
        "customers",
        "observed_classification",
        values=["external_authority"],
        source_system="independent-source",
        source_revision=1,
        source_authority_sha256=digest("external-source"),
        evidence_sha256=digest("external-evidence"),
        reviewer_id="external-reviewer",
        reviewer_authority_sha256=digest("external-reviewer"),
        observed_at=harness.clock() - 1,
        fresh_until=harness.clock() + 300,
        expected_revision=0,
        idempotency_key="external-context",
    )
    with pytest.raises(bridge.DiscoveryDataUseBridgeConflict):
        harness.reconcile(proposal, idempotency_key="apply-context-drift")
    current = harness.data_use.get_context_authority(
        TENANT,
        "customers",
        "observed_classification",
    )
    assert current == external

    other = Harness(harness.bridge_path.parent / "other")
    report2, pins2 = other.scan_and_approve({"email": "person@example.test"})
    proposal2 = other.propose(
        report2,
        pins2,
        bridge_revision=0,
        idempotency_key="proposal-source-drift",
    )
    source = other.discovery.get_source(TENANT, "customer-db")
    other.discovery.set_source_state(
        TENANT,
        source.source_id,
        state="suspended",
        expected_revision=source.revision,
        actor_ref="privacy-owner",
        idempotency_key="suspend-source",
    )
    with pytest.raises(bridge.DiscoveryDataUseBridgeConflict):
        other.reconcile(proposal2, idempotency_key="apply-source-drift")
    assert (
        other.data_use.get_context_authority(
            TENANT,
            "customers",
            "observed_classification",
        )
        is None
    )


def test_incomplete_pin_set_and_stale_review_never_create_context(harness: Harness) -> None:
    report, pins = harness.scan_and_approve(
        {
            "email": "person@example.test",
            "phone": "202-555-0117",
        },
        freshness_seconds=120,
    )
    assert len(pins) > 1
    with pytest.raises(bridge.DiscoveryDataUseBridgeConflict, match="fully pinned"):
        harness.propose(
            report,
            pins[:-1],
            bridge_revision=0,
            idempotency_key="proposal-incomplete",
        )
    harness.clock.advance(121)
    with pytest.raises(bridge.DiscoveryDataUseBridgeConflict, match="stale"):
        harness.propose(
            report,
            pins,
            bridge_revision=0,
            idempotency_key="proposal-stale",
        )
    assert (
        harness.data_use.get_context_authority(
            TENANT,
            "customers",
            "observed_classification",
        )
        is None
    )


def test_reconcile_then_fresh_rollback_restores_prior_context(harness: Harness) -> None:
    report_one, pins_one = harness.scan_and_approve(
        {"email": "person@example.test"},
    )
    proposal_one = harness.propose(
        report_one,
        pins_one,
        bridge_revision=0,
        idempotency_key="proposal-one",
    )
    application_one = harness.reconcile(proposal_one, idempotency_key="apply-one")
    first_values = application_one["after_context"]["values"]

    report_two, pins_two = harness.scan_and_approve(
        {"medical_condition": "asthma"},
    )
    proposal_two = harness.propose(
        report_two,
        pins_two,
        bridge_revision=1,
        idempotency_key="proposal-two",
    )
    assert proposal_two["action"] == "reconcile"
    application_two = harness.reconcile(proposal_two, idempotency_key="apply-two")
    assert application_two["after_context"]["values"] != first_values
    current = harness.data_use.get_context_authority(
        TENANT,
        "customers",
        "observed_classification",
    )
    assert current is not None
    rollback = harness.bridge.propose_rollback(
        TENANT,
        "customer-classification",
        target_bridge_revision=1,
        expected_bridge_revision=2,
        expected_context_revision=current["revision"],
        expected_context_record_sha256=current["record_sha256"],
        retained_until=harness.clock() + 1_000,
        idempotency_key="rollback-to-one",
    )
    assert rollback["action"] == "rollback"
    restored = harness.reconcile(rollback, idempotency_key="apply-rollback")
    assert restored["action"] == "rollback"
    assert restored["after_context"]["values"] == first_values
    assert restored["after_context"]["revision"] == current["revision"] + 1
    history = harness.bridge.history(TENANT, "customer-classification")
    assert [item["action"] for item in history["items"]] == [
        "rollback",
        "reconcile",
        "desired",
    ]


def test_bridge_cas_retention_and_integrity_tamper_detection(harness: Harness) -> None:
    report, pins = harness.scan_and_approve({"email": "person@example.test"})
    first = harness.propose(
        report,
        pins,
        bridge_revision=0,
        idempotency_key="proposal-cas-first",
    )
    stale = harness.propose(
        report,
        pins,
        bridge_revision=0,
        idempotency_key="proposal-cas-stale",
    )
    harness.reconcile(first, idempotency_key="apply-cas-first")
    with pytest.raises(bridge.DiscoveryDataUseBridgeConflict, match="head"):
        harness.reconcile(stale, idempotency_key="apply-cas-stale")

    harness.clock.advance(1_201)
    purged = harness.bridge.purge_expired(
        TENANT,
        cutoff=harness.clock(),
        idempotency_key="purge-bridge",
    )
    assert purged == {
        "proposals": 2,
        "applications": 1,
        "history": 1,
        "heads": 1,
    }
    assert harness.bridge.get_head(TENANT, "customer-classification") is None
    assert (
        harness.bridge.purge_expired(
            TENANT,
            cutoff=harness.clock(),
            idempotency_key="purge-bridge",
        )
        == purged
    )
    verified = harness.bridge.verify_integrity(TENANT)
    assert verified["operations"] >= 4
    assert verified["audit_events"] >= 3

    other = Harness(harness.bridge_path.parent / "tamper")
    report2, pins2 = other.scan_and_approve({"email": "person@example.test"})
    proposal = other.propose(
        report2,
        pins2,
        bridge_revision=0,
        idempotency_key="proposal-tamper",
    )
    with sqlite3.connect(other.bridge_path) as connection:
        connection.execute("DROP TRIGGER pddb_proposals_no_update")
        connection.execute(
            "UPDATE pddb_proposals SET integrity_sha256=? WHERE tenant_id=? AND proposal_id=?",
            ("0" * 64, TENANT, proposal["proposal_id"]),
        )
    with pytest.raises(bridge.DiscoveryDataUseBridgeIntegrityError):
        other.bridge.verify_integrity(TENANT)

    indexed = Harness(harness.bridge_path.parent / "index-tamper")
    report3, pins3 = indexed.scan_and_approve({"email": "person@example.test"})
    proposal3 = indexed.propose(
        report3,
        pins3,
        bridge_revision=0,
        idempotency_key="proposal-index-tamper",
    )
    with sqlite3.connect(indexed.bridge_path) as connection:
        connection.execute("DROP TRIGGER pddb_proposals_no_update")
        connection.execute(
            "UPDATE pddb_proposals SET action=? WHERE tenant_id=? AND proposal_id=?",
            ("reconcile", TENANT, proposal3["proposal_id"]),
        )
    with pytest.raises(
        bridge.DiscoveryDataUseBridgeIntegrityError,
        match="action index binding",
    ):
        indexed.bridge.get_proposal(TENANT, proposal3["proposal_id"])
    with pytest.raises(
        bridge.DiscoveryDataUseBridgeIntegrityError,
        match="action index binding",
    ):
        indexed.bridge.verify_integrity(TENANT)
