from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, replace

import pytest
from maverick import privacy_data_discovery_remediation as remediation
from maverick.privacy_data_discovery import (
    EnrolledSource,
    Finding,
    ReviewedClassification,
    ReviewProposal,
    ScanReport,
)


def _digest(character: str) -> str:
    return character * 64


@dataclass
class Clock:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class PublicDiscoveryAuthority:
    def __init__(self, tenant_id: str = "tenant-a") -> None:
        self.tenant_id = tenant_id
        self.source = EnrolledSource(
            tenant_id=tenant_id,
            source_id="source-a",
            kind="structured",
            provider="fixture",
            origin="https://private.example.test",
            resource_ref="private-resource",
            credential_env="PRIVATE_CREDENTIAL",
            evidence_key_env="PRIVATE_EVIDENCE_KEY",
            state="active",
            revision=1,
            enrolled_at=100.0,
            updated_at=100.0,
            integrity_sha256=_digest("1"),
        )
        self.report = ScanReport(
            report_id="report-a",
            tenant_id=tenant_id,
            source_id="source-a",
            job_id="job-a",
            started_at=100.0,
            finished_at=110.0,
            records_seen=1,
            files_seen=0,
            bytes_seen=100,
            findings_count=1,
            ambiguous_count=0,
            completeness="bounded_complete",
            truncation_reasons=(),
            error_codes=(),
            limitations=("declared_source_scope_only",),
            retention_until=20_000.0,
            integrity_sha256=_digest("2"),
        )
        self.finding = Finding(
            finding_id="finding-a",
            tenant_id=tenant_id,
            report_id="report-a",
            source_id="source-a",
            category="email_address",
            confidence=0.99,
            ambiguous=False,
            location_sha256=_digest("3"),
            evidence_sha256=_digest("4"),
            detector="fixture",
            revision=2,
            integrity_sha256=_digest("5"),
        )
        self.review = ReviewProposal(
            review_id="review-a",
            tenant_id=tenant_id,
            finding_id="finding-a",
            decision="confirmed",
            effective_category="email_address",
            prepared_by="preparer-private",
            prepared_at=200.0,
            evidence_sha256=_digest("6"),
            freshness_seconds=3_600,
            status="approved",
            approved_by="approver-private",
            approved_at=300.0,
            version=1,
            integrity_sha256=_digest("7"),
        )
        self.latest = self.review
        self.source_reads = 0
        self.drift_on_second_resolution = False

    def get_source(self, tenant_id: str, source_id: str) -> EnrolledSource:
        assert tenant_id == self.tenant_id
        assert source_id == self.source.source_id
        self.source_reads += 1
        if self.drift_on_second_resolution and self.source_reads >= 2:
            return replace(
                self.source,
                revision=2,
                integrity_sha256=_digest("8"),
            )
        return self.source

    def get_report(self, tenant_id: str, report_id: str) -> ScanReport:
        assert tenant_id == self.tenant_id
        assert report_id == self.report.report_id
        return self.report

    def get_finding(self, tenant_id: str, finding_id: str) -> Finding:
        assert tenant_id == self.tenant_id
        assert finding_id == self.finding.finding_id
        return self.finding

    def get_review(self, tenant_id: str, review_id: str) -> ReviewProposal:
        assert tenant_id == self.tenant_id
        assert review_id == self.review.review_id
        return self.review

    def list_reviews(
        self,
        tenant_id: str,
        finding_id: str,
        *,
        limit: int,
    ) -> tuple[ReviewProposal, ...]:
        assert tenant_id == self.tenant_id
        assert finding_id == self.finding.finding_id
        assert limit == 1
        return (self.latest,)

    def update(self) -> ReviewedClassification:
        return ReviewedClassification(
            tenant_id=self.tenant_id,
            source_id=self.source.source_id,
            report_id=self.report.report_id,
            finding_id=self.finding.finding_id,
            review_id=self.review.review_id,
            decision=self.review.decision,
            category=self.review.effective_category,
            evidence_sha256=self.review.evidence_sha256,
            reviewed_at=float(self.review.approved_at),
            review_version=self.review.version,
        )


@pytest.fixture
def environment(tmp_path):
    clock = Clock()
    authority = PublicDiscoveryAuthority()
    store = remediation.PrivacyDataDiscoveryRemediationStore(
        tmp_path / "remediation.sqlite3",
        tenant_id="tenant-a",
        discovery_store=authority,
        principal_resolver=lambda: "operator-private",
        config_gate=lambda: None,
        clock=clock,
        default_retention_seconds=1_000,
    )
    return store, authority, clock


def _enqueue(environment, **kwargs):
    store, authority, _clock = environment
    return store.enqueue_review(authority.update(), **kwargs)


def _claim(environment, **kwargs):
    store, _authority, _clock = environment
    claims = store.claim_ready(worker_id="worker-a", **kwargs)
    assert len(claims) == 1
    return claims[0]


def test_constructor_requires_gate_and_public_authority(tmp_path) -> None:
    authority = PublicDiscoveryAuthority()

    with pytest.raises(RuntimeError, match="closed"):
        remediation.PrivacyDataDiscoveryRemediationStore(
            tmp_path / "closed.sqlite3",
            tenant_id="tenant-a",
            discovery_store=authority,
            principal_resolver=lambda: "operator",
            config_gate=lambda: (_ for _ in ()).throw(RuntimeError("closed")),
        )

    with pytest.raises(remediation.PrivacyDiscoveryRemediationConfigError):
        remediation.PrivacyDataDiscoveryRemediationStore(
            tmp_path / "invalid.sqlite3",
            tenant_id="tenant-a",
            discovery_store=object(),
            principal_resolver=lambda: "operator",
            config_gate=lambda: None,
        )


def test_approved_callback_is_durable_idempotent_and_privacy_safe(environment) -> None:
    store, authority, _clock = environment
    first = store.enqueue_review(authority.update())
    replay = store.enqueue_review(authority.update())
    callback = store.make_review_callback()
    callback(authority.update())

    assert first.created is True
    assert first.no_change is False
    assert replay.created is False
    assert replay.no_change is True
    assert replay.work == first.work
    assert store.state_counts()["queued"] == 1

    with sqlite3.connect(store.path) as connection:
        payload = connection.execute("SELECT payload_json FROM remediation_work").fetchone()[0]
    lowered = payload.lower()
    for private in (
        authority.source.origin,
        authority.source.resource_ref,
        authority.source.credential_env,
        authority.source.evidence_key_env,
        authority.finding.location_sha256,
        "preparer-private",
        "approver-private",
        "operator-private",
        "tenant-a",
    ):
        assert private.lower() not in lowered


@pytest.mark.parametrize("failure", ["cross_tenant", "unapproved", "superseded", "revoked"])
def test_enqueue_rejects_non_current_or_revoked_authority(environment, failure) -> None:
    store, authority, _clock = environment
    update = authority.update()
    if failure == "cross_tenant":
        update = replace(update, tenant_id="tenant-b")
    elif failure == "unapproved":
        authority.review = replace(authority.review, status="pending", approved_at=None)
    elif failure == "superseded":
        authority.latest = replace(
            authority.review,
            review_id="review-new",
            version=2,
            integrity_sha256=_digest("8"),
        )
    else:
        authority.source = replace(authority.source, state="revoked")

    with pytest.raises(remediation.PrivacyDiscoveryRemediationAuthorityError):
        store.enqueue_review(update)
    assert store.state_counts()["total"] == 0


def test_double_read_detects_authority_drift(environment) -> None:
    store, authority, _clock = environment
    authority.drift_on_second_resolution = True

    with pytest.raises(
        remediation.PrivacyDiscoveryRemediationAuthorityError,
        match="drifted",
    ):
        store.enqueue_review(authority.update())


def test_claim_projection_is_exact_and_acknowledgement_is_idempotent(environment) -> None:
    store, _authority, _clock = environment
    _enqueue(environment)
    claim = _claim(environment)
    assert claim.tenant_sha256 != "tenant-a"
    assert claim.completeness_claimed is False

    with pytest.raises(remediation.PrivacyDiscoveryRemediationLeaseLost):
        store.validate_claim_authority(replace(claim, category="phone_number"))

    result = remediation.RemediationCallbackResult(
        outcome="applied",
        receipt_sha256=_digest("a"),
        authority_sha256=claim.authority_sha256,
    )
    completed = store.acknowledge(claim, result)
    replay = store.acknowledge(claim, result)
    assert completed.state == "applied"
    assert replay == completed

    with pytest.raises(remediation.PrivacyDiscoveryRemediationConflict):
        store.acknowledge(
            claim,
            replace(result, receipt_sha256=_digest("b")),
        )


@pytest.mark.parametrize("outcome", ["applied", "no_change"])
def test_worker_records_applied_and_no_change(environment, outcome) -> None:
    store, _authority, _clock = environment
    _enqueue(environment)
    seen = []

    def callback(claim):
        seen.append(claim)
        return remediation.RemediationCallbackResult(
            outcome=outcome,
            receipt_sha256=_digest("a"),
            authority_sha256=claim.authority_sha256,
        )

    result = remediation.PrivacyDataDiscoveryRemediationWorker(
        store,
        callback=callback,
    ).run_once(worker_id="worker-a")
    assert result.claimed == 1
    assert getattr(result, outcome) == 1
    assert len(seen) == 1
    assert store.list_work()[0].state == outcome


def test_retry_dead_letter_and_explicit_replay(environment) -> None:
    store, _authority, clock = environment
    enqueued = _enqueue(environment, max_attempts=2)

    def retry(_claim):
        raise remediation.RemediationRetryableError("provider_unavailable")

    worker = remediation.PrivacyDataDiscoveryRemediationWorker(
        store,
        callback=retry,
        retry_backoff=lambda _attempt: 1,
    )
    first = worker.run_once(worker_id="worker-a")
    assert first.retried == 1
    clock.advance(2)
    second = worker.run_once(worker_id="worker-a")
    assert second.dead_lettered == 1
    dead = store.get_work(enqueued.work.work_id)
    assert dead.state == "dead_letter"

    replayed = store.replay_dead_letter(
        dead.work_id,
        expected_revision=dead.revision,
        idempotency_key="replay-a",
    )
    same = store.replay_dead_letter(
        dead.work_id,
        expected_revision=dead.revision,
        idempotency_key="replay-a",
    )
    assert replayed.state == "queued"
    assert replayed.attempts == 0
    assert same == replayed


def test_permanent_failure_dead_letters_without_provider_text(environment) -> None:
    store, _authority, _clock = environment
    _enqueue(environment)

    def fail(_claim):
        raise remediation.RemediationPermanentError("target_rejected")

    result = remediation.PrivacyDataDiscoveryRemediationWorker(
        store,
        callback=fail,
    ).run_once(worker_id="worker-a")
    assert result.dead_lettered == 1
    assert store.list_work()[0].last_error_code == "target_rejected"


def test_unknown_callback_and_expired_lease_become_ambiguous(environment) -> None:
    store, _authority, clock = environment
    first = _enqueue(environment)

    def unknown(_claim):
        raise RuntimeError("private provider response")

    result = remediation.PrivacyDataDiscoveryRemediationWorker(
        store,
        callback=unknown,
    ).run_once(worker_id="worker-a")
    assert result.ambiguous == 1
    ambiguous = store.get_work(first.work.work_id)
    assert ambiguous.state == "ambiguous"
    assert "private provider response" not in json.dumps(
        ambiguous.__dict__ if hasattr(ambiguous, "__dict__") else str(ambiguous)
    )
    assert store.claim_ready(worker_id="worker-a") == ()

    second_authority = PublicDiscoveryAuthority()
    second_authority.review = replace(
        second_authority.review,
        review_id="review-b",
        integrity_sha256=_digest("8"),
    )
    second_authority.latest = second_authority.review
    second_authority.finding = replace(
        second_authority.finding,
        finding_id="finding-b",
        integrity_sha256=_digest("9"),
    )
    second_authority.review = replace(
        second_authority.review,
        finding_id="finding-b",
    )
    second_authority.latest = second_authority.review

    # Lease recovery is exercised with a fresh isolated store to avoid mixing authorities.
    recovered_store = remediation.PrivacyDataDiscoveryRemediationStore(
        store.path.parent / "recovered.sqlite3",
        tenant_id="tenant-a",
        discovery_store=second_authority,
        principal_resolver=lambda: "operator",
        config_gate=lambda: None,
        clock=clock,
        default_retention_seconds=1_000,
    )
    recovered_store.enqueue_review(second_authority.update())
    recovered_store.claim_ready(worker_id="crashed", lease_seconds=1)
    clock.advance(2)
    assert recovered_store.claim_ready(worker_id="replacement") == ()
    assert recovered_store.list_work()[0].state == "ambiguous"


@pytest.mark.parametrize("outcome", ["applied", "no_change"])
def test_reconcile_ambiguous_terminal_outcome_is_idempotent(environment, outcome) -> None:
    store, _authority, _clock = environment
    enqueued = _enqueue(environment)
    claim = _claim(environment)
    ambiguous = store.fail_claim(
        claim,
        error_code="acknowledgement_unknown",
        disposition="ambiguous",
    )

    def reconcile(probe):
        return remediation.RemediationReconciliationResult(
            outcome=outcome,
            authority_sha256=probe.authority_sha256,
            receipt_sha256=_digest("a"),
        )

    completed = store.reconcile_ambiguous(
        enqueued.work.work_id,
        expected_revision=ambiguous.revision,
        idempotency_key="reconcile-a",
        reconciler=reconcile,
    )
    replay = store.reconcile_ambiguous(
        enqueued.work.work_id,
        expected_revision=ambiguous.revision,
        idempotency_key="reconcile-a",
        reconciler=lambda _probe: (_ for _ in ()).throw(AssertionError("not called")),
    )
    assert completed.state == outcome
    assert replay == completed


def test_reconcile_absent_requeues_or_cancels_when_authority_revoked(environment) -> None:
    store, authority, _clock = environment
    first = _enqueue(environment)
    first_claim = _claim(environment)
    first_ambiguous = store.fail_claim(
        first_claim,
        error_code="outcome_unknown",
        disposition="ambiguous",
    )

    def absent(probe):
        return remediation.RemediationReconciliationResult(
            outcome="absent",
            authority_sha256=probe.authority_sha256,
        )

    queued = store.reconcile_ambiguous(
        first.work.work_id,
        expected_revision=first_ambiguous.revision,
        idempotency_key="absent-a",
        reconciler=absent,
    )
    assert queued.state == "queued"

    second_claim = _claim(environment)
    second_ambiguous = store.fail_claim(
        second_claim,
        error_code="outcome_unknown",
        disposition="ambiguous",
    )
    authority.source = replace(authority.source, state="revoked")
    cancelled = store.reconcile_ambiguous(
        first.work.work_id,
        expected_revision=second_ambiguous.revision,
        idempotency_key="absent-b",
        reconciler=absent,
    )
    assert cancelled.state == "cancelled"
    assert cancelled.last_error_code == "authority_stale_or_revoked"


def test_reconcile_unknown_stays_ambiguous_and_is_idempotent(environment) -> None:
    store, _authority, _clock = environment
    enqueued = _enqueue(environment)
    claim = _claim(environment)
    ambiguous = store.fail_claim(
        claim,
        error_code="outcome_unknown",
        disposition="ambiguous",
    )

    def unknown(probe):
        return remediation.RemediationReconciliationResult(
            outcome="unknown",
            authority_sha256=probe.authority_sha256,
        )

    result = store.reconcile_ambiguous(
        enqueued.work.work_id,
        expected_revision=ambiguous.revision,
        idempotency_key="unknown-a",
        reconciler=unknown,
    )
    replay = store.reconcile_ambiguous(
        enqueued.work.work_id,
        expected_revision=ambiguous.revision,
        idempotency_key="unknown-a",
        reconciler=lambda _probe: (_ for _ in ()).throw(AssertionError("not called")),
    )
    assert result.state == "ambiguous"
    assert replay == result


def test_manual_cancel_is_revision_bound_and_refuses_ambiguous(environment) -> None:
    store, _authority, _clock = environment
    work = _enqueue(environment).work
    cancelled = store.cancel_work(
        work.work_id,
        reason_code="operator_revoked",
        expected_revision=work.revision,
        idempotency_key="cancel-a",
    )
    replay = store.cancel_work(
        work.work_id,
        reason_code="operator_revoked",
        expected_revision=work.revision,
        idempotency_key="cancel-a",
    )
    assert cancelled.state == "cancelled"
    assert replay == cancelled

    with pytest.raises(remediation.PrivacyDiscoveryRemediationConflict):
        store.cancel_work(
            work.work_id,
            reason_code="other",
            expected_revision=cancelled.revision,
            idempotency_key="cancel-b",
        )


def test_integrity_tamper_detection_and_retention_purge(environment) -> None:
    store, _authority, clock = environment
    _enqueue(environment, retention_seconds=60)
    verified = store.verify_integrity()
    assert verified.current_records == 1
    assert verified.history_records == 1
    assert verified.audit_events == 1

    clock.advance(61)
    assert store.purge_expired(cutoff=clock.value, idempotency_key="purge-a") == 1
    assert store.purge_expired(cutoff=clock.value, idempotency_key="purge-a") == 1
    assert store.state_counts()["total"] == 0
    assert store.verify_integrity().audit_events == 2

    replacement = store.enqueue_review(_authority.update())
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE remediation_work SET payload_json='{}' WHERE work_id=?",
            (replacement.work.work_id,),
        )
        connection.commit()
    with pytest.raises(remediation.PrivacyDiscoveryRemediationIntegrityError):
        store.get_work(replacement.work.work_id)


def test_constructor_bound_tenant_isolation_and_boundaries(tmp_path) -> None:
    clock = Clock()
    authority_a = PublicDiscoveryAuthority("tenant-a")
    authority_b = PublicDiscoveryAuthority("tenant-b")
    path = tmp_path / "shared.sqlite3"
    store_a = remediation.PrivacyDataDiscoveryRemediationStore(
        path,
        tenant_id="tenant-a",
        discovery_store=authority_a,
        principal_resolver=lambda: "operator-a",
        config_gate=lambda: None,
        clock=clock,
    )
    store_b = remediation.PrivacyDataDiscoveryRemediationStore(
        path,
        tenant_id="tenant-b",
        discovery_store=authority_b,
        principal_resolver=lambda: "operator-b",
        config_gate=lambda: None,
        clock=clock,
    )
    work = store_a.enqueue_review(authority_a.update()).work
    with pytest.raises(remediation.PrivacyDiscoveryRemediationNotFound):
        store_b.get_work(work.work_id)
    assert store_b.state_counts()["total"] == 0

    boundaries = store_a.product_boundaries()
    assert boundaries["approved_reviews_only"] is True
    assert boundaries["raw_locations_persisted"] is False
    assert boundaries["network_io"] is False
    assert boundaries["provider_writes"] is False
    assert boundaries["ambiguous_outcomes_optimistically_retried"] is False
