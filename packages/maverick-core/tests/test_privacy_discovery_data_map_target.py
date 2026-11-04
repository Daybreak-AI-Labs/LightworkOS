from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest
from maverick.privacy_data_discovery_remediation import (
    RemediationClaim,
    RemediationReconciliationProbe,
)
from maverick.privacy_discovery_data_map_target import (
    PrivacyDiscoveryDataMapIntegrityError,
    PrivacyDiscoveryDataMapTarget,
)


class Clock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def claim(*, decision="confirmed", category="email_address"):
    return RemediationClaim(
        schema="lightwork.privacy-data-discovery-remediation-claim.v1",
        work_id="PDRW-work-1",
        tenant_sha256="1" * 64,
        source_id="source-a",
        report_id="PDR-report-a",
        finding_id="PDF-finding-a",
        review_id="PDRV-review-a",
        review_version=1,
        decision=decision,
        category=category,
        evidence_sha256="2" * 64,
        authority_sha256="3" * 64,
        callback_idempotency_sha256="4" * 64,
        report_completeness_sha256="5" * 64,
        completeness_claimed=False,
        attempt=1,
        lease_owner_sha256="6" * 64,
        lease_token="lwdrm1." + "A" * 43,
        lease_until=1100.0,
        work_revision=2,
    )


def probe(value):
    return RemediationReconciliationProbe(
        schema="lightwork.privacy-data-discovery-remediation-reconcile.v1",
        work_id=value.work_id,
        tenant_sha256=value.tenant_sha256,
        source_id=value.source_id,
        report_id=value.report_id,
        finding_id=value.finding_id,
        review_id=value.review_id,
        review_version=value.review_version,
        decision=value.decision,
        category=value.category,
        evidence_sha256=value.evidence_sha256,
        authority_sha256=value.authority_sha256,
        callback_idempotency_sha256=value.callback_idempotency_sha256,
        report_completeness_sha256=value.report_completeness_sha256,
        completeness_claimed=False,
        attempt=value.attempt,
    )


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def target(tmp_path, clock):
    return PrivacyDiscoveryDataMapTarget(
        tmp_path / "data-map.sqlite3",
        retention_seconds=60,
        config_gate=lambda: None,
        clock=clock,
    )


def test_positive_claim_is_idempotent_and_reconcilable(target) -> None:
    value = claim()
    first = target(value)
    second = target(value)
    assert first == second
    assert first.outcome == "applied"
    rows = target.list_observations(value.tenant_sha256)
    assert len(rows) == 1
    assert rows[0].category == "email_address"
    assert rows[0].tenant_sha256 == value.tenant_sha256
    reconciled = target.reconcile(probe(value))
    assert reconciled.outcome == "applied"
    assert reconciled.receipt_sha256 == first.receipt_sha256


def test_false_positive_creates_explicit_no_change_receipt(target) -> None:
    value = claim(decision="false_positive", category=None)
    result = target(value)
    assert result.outcome == "no_change"
    assert target.list_observations(value.tenant_sha256)[0].category is None
    assert target.reconcile(probe(value)).outcome == "no_change"


def test_authority_mismatch_reconciles_unknown_and_cannot_overwrite(target) -> None:
    value = claim()
    target(value)
    mismatch = replace(probe(value), authority_sha256="7" * 64)
    assert target.reconcile(mismatch).outcome == "unknown"


def test_retention_purge_keeps_reconciliation_tombstone(target, clock) -> None:
    value = claim()
    original = target(value)
    clock.advance(61)
    assert target.purge_expired() == 1
    assert target.list_observations(value.tenant_sha256) == ()
    reconciled = target.reconcile(probe(value))
    assert reconciled.outcome == "applied"
    assert reconciled.receipt_sha256 == original.receipt_sha256
    assert target(value) == original
    verified = target.verify_integrity()
    assert verified.observations == 0
    assert verified.tombstones == 1


def test_integrity_tamper_is_detected(target) -> None:
    value = claim()
    target(value)
    with sqlite3.connect(target.path) as connection:
        connection.execute(
            "UPDATE observations SET payload_json='{}' "
            "WHERE callback_idempotency_sha256=?",
            (value.callback_idempotency_sha256,),
        )
    with pytest.raises(PrivacyDiscoveryDataMapIntegrityError):
        target.verify_integrity()


def test_product_boundaries_do_not_overclaim() -> None:
    posture = PrivacyDiscoveryDataMapTarget.product_boundaries()
    assert posture["raw_values_persisted"] is False
    assert posture["provider_writes"] is False
    assert posture["article_30_ropa_completeness_claimed"] is False
    assert posture["live_provider_acceptance_verified"] is False
