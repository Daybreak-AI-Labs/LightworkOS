from __future__ import annotations

import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from maverick import privacy_data_discovery as discovery


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Rows:
    def __init__(self, rows: list[discovery.StructuredRecord]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, str, float]] = []

    def iter_rows(self, *, source, credential_env, limits, deadline):
        self.calls.append((source.origin, credential_env, deadline))
        yield from self.rows


class Documents:
    def __init__(self, documents: list[discovery.UnstructuredDocument]) -> None:
        self.documents = documents
        self.calls: list[tuple[str, str, float]] = []

    def iter_documents(self, *, source, credential_env, limits, deadline):
        self.calls.append((source.origin, credential_env, deadline))
        yield from self.documents


class BrokenRows:
    def iter_rows(self, *, source, credential_env, limits, deadline):
        del source, credential_env, limits, deadline
        raise RuntimeError("alice@example.com super-secret adapter detail")
        yield  # pragma: no cover


class TickingRows:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock

    def iter_rows(self, *, source, credential_env, limits, deadline):
        del source, credential_env, limits, deadline
        yield discovery.StructuredRecord("row-1", {"email": "one@example.com"})
        self.clock.advance(2)
        yield discovery.StructuredRecord("row-2", {"email": "two@example.com"})


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: Path, clock: Clock) -> discovery.PrivacyDataDiscoveryStore:
    return discovery.PrivacyDataDiscoveryStore(
        tmp_path / "privacy.sqlite3",
        config_gate=lambda: None,
        clock=clock,
        evidence_key_resolver=lambda _name: b"evidence-key-material-32-bytes!!!",
    )


def enroll(
    store: discovery.PrivacyDataDiscoveryStore,
    *,
    tenant: str = "tenant-a",
    source_id: str = "customer-db",
    kind: str = "structured",
    provider: str = "fixture",
) -> discovery.EnrolledSource:
    return store.enroll_source(
        tenant,
        source_id=source_id,
        kind=kind,
        provider=provider,
        origin="https://data.example.com",
        resource_ref="customer-table",
        credential_env="PRIVACY_SOURCE_TOKEN",
        evidence_key_env="PRIVACY_EVIDENCE_HMAC_KEY",
        actor_ref="privacy-owner",
        idempotency_key=f"enroll-{tenant}-{source_id}",
    )


def enqueue_and_run(
    store: discovery.PrivacyDataDiscoveryStore,
    adapter: Rows | Documents,
    *,
    tenant: str = "tenant-a",
    source_id: str = "customer-db",
    kind: str = "structured",
    limits: discovery.ScanLimits | None = None,
    operation: str = "manual-scan-1",
) -> discovery.ScanReport:
    store.enqueue_scan(
        tenant,
        source_id,
        limits=limits or discovery.ScanLimits(),
        max_attempts=3,
        retention_seconds=3_600,
        actor_ref="privacy-owner",
        idempotency_key=operation,
    )
    coordinator = discovery.PrivacyDataDiscoveryCoordinator(
        store,
        structured_sources={"fixture": adapter} if kind == "structured" else {},
        unstructured_sources={"fixture": adapter} if kind == "unstructured" else {},
        clock=store._clock,
        credential_ref_present=lambda _name: True,
    )
    result = coordinator.run_once(tenant, worker_id="worker-1")
    assert not result.failed_jobs
    assert len(result.completed_reports) == 1
    return result.completed_reports[0]


def test_config_gate_is_default_off_and_requires_both_sections(monkeypatch) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert discovery.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"privacy_automation": {"enable": True, "data_discovery": {}}},
    )
    assert discovery.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "privacy_automation": {
                "enable": True,
                "data_discovery": {"enable": True},
            }
        },
    )
    assert discovery.enabled() is True


def test_constructor_enforces_gate_and_creates_private_database(tmp_path: Path) -> None:
    with pytest.raises(discovery.PrivacyDataDiscoveryConfigError):
        discovery.PrivacyDataDiscoveryStore(
            tmp_path / "blocked.sqlite3",
            config_gate=lambda: (_ for _ in ()).throw(
                discovery.PrivacyDataDiscoveryConfigError("disabled")
            ),
        )
    db = tmp_path / "private" / "store.sqlite3"
    discovery.PrivacyDataDiscoveryStore(db, config_gate=lambda: None)
    assert db.is_file()
    if os.name != "nt":
        assert db.stat().st_mode & 0o077 == 0


def test_canonical_tenant_ids_normalize_unicode_and_preserve_isolation(store) -> None:
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    source = store.enroll_source(
        decomposed,
        source_id="customer-db",
        kind="structured",
        provider="fixture",
        origin="https://data.example.com",
        resource_ref="customer-table",
        credential_env="PRIVACY_SOURCE_TOKEN",
        evidence_key_env="PRIVACY_EVIDENCE_HMAC_KEY",
        actor_ref="privacy-owner",
        idempotency_key="acme-source-enroll",
    )

    assert source.tenant_id == canonical
    assert store.get_source(canonical, "customer-db") == source
    assert store.list_sources("Other Corp") == ()
    with pytest.raises(discovery.PrivacyDataDiscoveryValidationError):
        store.get_source(canonical, "customer db")


@pytest.mark.parametrize(
    "origin",
    [
        "http://data.example.com",
        "https://user:pass@data.example.com",
        "https://data.example.com/path",
        "https://data.example.com?x=1",
        "https://127.0.0.1",
        "https://localhost",
    ],
)
def test_source_enrollment_rejects_non_exact_or_local_origins(store, origin) -> None:
    with pytest.raises(discovery.PrivacyDataDiscoveryValidationError):
        store.enroll_source(
            "tenant-a",
            source_id="bad-source",
            kind="structured",
            provider="fixture",
            origin=origin,
            resource_ref="table-a",
            credential_env="SOURCE_TOKEN",
            evidence_key_env="EVIDENCE_KEY",
            actor_ref="owner",
            idempotency_key=f"bad-{hash(origin)}".replace("-", "x"),
        )


def test_source_enrollment_is_cas_idempotent_and_secret_free(store) -> None:
    source = enroll(store)
    assert source.origin == "https://data.example.com"
    assert source.credential_env == "PRIVACY_SOURCE_TOKEN"
    same = enroll(store)
    assert same == source
    with pytest.raises(discovery.PrivacyDataDiscoveryConflict, match="different"):
        store.enroll_source(
            "tenant-a",
            source_id="customer-db",
            kind="structured",
            provider="changed",
            origin="https://data.example.com",
            resource_ref="customer-table",
            credential_env="PRIVACY_SOURCE_TOKEN",
            evidence_key_env="PRIVACY_EVIDENCE_HMAC_KEY",
            actor_ref="owner",
            idempotency_key="enroll-tenant-a-customer-db",
        )
    with pytest.raises(discovery.PrivacyDataDiscoveryValidationError):
        store.enroll_source(
            "tenant-a",
            source_id="raw-secret",
            kind="structured",
            provider="fixture",
            origin="https://data.example.com",
            resource_ref="table",
            credential_env="sk-live-secret-value",
            evidence_key_env="EVIDENCE_KEY",
            actor_ref="owner",
            idempotency_key="secret-ref",
        )


def test_source_update_requires_cas_and_revocation_stops_enqueue(store) -> None:
    source = enroll(store)
    with pytest.raises(discovery.PrivacyDataDiscoveryConflict):
        store.set_source_state(
            "tenant-a",
            source.source_id,
            state="revoked",
            expected_revision=99,
            actor_ref="owner",
            idempotency_key="bad-cas",
        )
    revoked = store.set_source_state(
        "tenant-a",
        source.source_id,
        state="revoked",
        expected_revision=source.revision,
        actor_ref="owner",
        idempotency_key="revoke-source",
    )
    assert revoked.revision == 2
    with pytest.raises(discovery.PrivacyDataDiscoveryConflict, match="not active"):
        store.enqueue_scan(
            "tenant-a",
            source.source_id,
            limits=discovery.ScanLimits(),
            max_attempts=2,
            retention_seconds=100,
            actor_ref="owner",
            idempotency_key="blocked-scan",
        )


def test_tenant_isolation_applies_to_sources_jobs_and_reports(store) -> None:
    enroll(store, tenant="tenant-a")
    enroll(store, tenant="tenant-b")
    report = enqueue_and_run(
        store,
        Rows([discovery.StructuredRecord("row-1", {"email": "a@example.com"})]),
        tenant="tenant-a",
    )
    assert len(store.list_sources("tenant-b")) == 1
    assert store.list_reports("tenant-b") == ()
    with pytest.raises(discovery.PrivacyDataDiscoveryNotFound):
        store.get_report("tenant-b", report.report_id)


def test_evidence_and_location_digests_are_tenant_scoped(store) -> None:
    enroll(store, tenant="tenant-a")
    enroll(store, tenant="tenant-b")
    shared = Rows(
        [discovery.StructuredRecord("row-1", {"email": "same@example.com"})]
    )
    report_a = enqueue_and_run(store, shared, tenant="tenant-a")
    report_b = enqueue_and_run(store, shared, tenant="tenant-b")
    finding_a = store.list_findings("tenant-a", report_id=report_a.report_id)[0]
    finding_b = store.list_findings("tenant-b", report_id=report_b.report_id)[0]
    assert finding_a.evidence_sha256 != finding_b.evidence_sha256
    assert finding_a.location_sha256 != finding_b.location_sha256


def test_structured_scan_detects_common_categories_without_persisting_values(store) -> None:
    enroll(store)
    secret_email = "alice.sensitive@example.com"
    secret_card = "4111 1111 1111 1111"
    secret_ip = "203.0.113.17"
    rows = Rows(
        [
            discovery.StructuredRecord(
                "row-1",
                {
                    "email": secret_email,
                    "phone": "+1 212-555-0199",
                    "payment": secret_card,
                    "network": secret_ip,
                    "patient_diagnosis": "condition-red",
                },
            )
        ]
    )
    report = enqueue_and_run(store, rows)
    assert report.completeness == "complete_within_declared_bounds"
    assert report.records_seen == 1
    findings = store.list_findings("tenant-a", report_id=report.report_id)
    categories = {finding.category for finding in findings}
    assert {"email_address", "phone_number", "payment_card", "ip_address"} <= categories
    assert "health_information" in categories
    assert all(len(finding.evidence_sha256) == 64 for finding in findings)
    database_bytes = store.path.read_bytes()
    for raw in (secret_email, secret_card, secret_ip, "condition-red"):
        assert raw.encode() not in database_bytes
    assert rows.calls[0][0] == "https://data.example.com"
    assert rows.calls[0][1] == "PRIVACY_SOURCE_TOKEN"


def test_unknown_and_ambiguous_findings_are_explicit_and_deterministic() -> None:
    detector_a = discovery.PersonalDataDetector(b"a" * 32)
    detector_b = discovery.PersonalDataDetector(b"b" * 32)
    first = detector_a.detect_field(
        "passport_note", "unparseable", location=b"source-row"
    )
    second = detector_a.detect_field(
        "passport_note", "unparseable", location=b"source-row"
    )
    different_key = detector_b.detect_field(
        "passport_note", "unparseable", location=b"source-row"
    )
    assert first == second
    assert first[0].ambiguous is True
    assert first[0].category == "government_identifier"
    assert first[0].evidence_sha256 != different_key[0].evidence_sha256
    unknown = detector_a.detect_field(
        "personal_email_note", {}, location=b"source-row"
    )
    assert any(item.category == "unknown_personal_data" for item in unknown)


def test_scan_bounds_records_fields_bytes_findings_and_reports_truncation(store) -> None:
    enroll(store)
    rows = Rows(
        [
            discovery.StructuredRecord(
                f"row-{index}",
                {"email": f"person{index}@example.com", "phone": "212-555-0199"},
            )
            for index in range(5)
        ]
    )
    report = enqueue_and_run(
        store,
        rows,
        limits=discovery.ScanLimits(
            max_records=2,
            max_files=1,
            max_bytes=10_000,
            max_seconds=10,
            max_findings=2,
            max_fields_per_record=1,
            max_record_bytes=1_000,
            max_document_bytes=1_000,
        ),
    )
    assert report.completeness == "bounded_partial"
    assert report.findings_count == 2
    assert set(report.truncation_reasons) & {"finding_limit", "field_limit"}


def test_cooperative_deadline_is_explicitly_reported(store, clock) -> None:
    enroll(store)
    report = enqueue_and_run(
        store,
        TickingRows(clock),
        limits=discovery.ScanLimits(max_seconds=1),
        operation="deadline-scan",
    )
    assert report.records_seen == 1
    assert "time_limit" in report.truncation_reasons
    assert report.completeness == "bounded_partial"


def test_unstructured_scan_reports_unsupported_files_and_never_stores_text(store) -> None:
    enroll(store, source_id="docs", kind="unstructured")
    raw_text = "Private dossier for alice@example.com and SSN 123-45-6789"
    adapter = Documents(
        [
            discovery.UnstructuredDocument("doc-1", "text/plain", raw_text),
            discovery.UnstructuredDocument("doc-2", "application/pdf", b"raw pdf"),
        ]
    )
    report = enqueue_and_run(
        store,
        adapter,
        source_id="docs",
        kind="unstructured",
        operation="docs-scan",
    )
    assert report.files_seen == 2
    assert "unsupported_media_type" in report.error_codes
    assert report.completeness == "bounded_partial"
    assert raw_text.encode() not in store.path.read_bytes()


def test_schedule_is_cas_governed_and_enqueues_once_per_due_slot(store, clock) -> None:
    enroll(store)
    schedule = store.upsert_schedule(
        "tenant-a",
        schedule_id="daily",
        source_id="customer-db",
        interval_seconds=3_600,
        limits=discovery.ScanLimits(max_records=5),
        max_attempts=3,
        retention_seconds=7_200,
        active=True,
        expected_revision=0,
        actor_ref="owner",
        idempotency_key="create-daily",
        next_run_at=clock(),
    )
    assert schedule.revision == 1
    first = store.enqueue_due("tenant-a", now=clock())
    second = store.enqueue_due("tenant-a", now=clock())
    assert len(first) == 1
    assert second == ()
    assert store.get_schedule("tenant-a", "daily").next_run_at == clock() + 3_600
    with pytest.raises(discovery.PrivacyDataDiscoveryConflict):
        store.upsert_schedule(
            "tenant-a",
            schedule_id="daily",
            source_id="customer-db",
            interval_seconds=10,
            limits=discovery.ScanLimits(),
            max_attempts=3,
            retention_seconds=100,
            active=True,
            expected_revision=0,
            actor_ref="owner",
            idempotency_key="wrong-revision",
        )


def test_leases_recover_then_dead_letter_after_bounded_attempts(store, clock) -> None:
    enroll(store)
    job = store.enqueue_scan(
        "tenant-a",
        "customer-db",
        limits=discovery.ScanLimits(),
        max_attempts=2,
        retention_seconds=100,
        actor_ref="owner",
        idempotency_key="lease-recovery",
    )
    first = store.claim_jobs(
        "tenant-a", worker_id="worker-a", lease_seconds=10, now=clock()
    )[0]
    assert first.attempts == 1
    clock.advance(11)
    second = store.claim_jobs(
        "tenant-a", worker_id="worker-b", lease_seconds=10, now=clock()
    )[0]
    assert second.attempts == 2
    clock.advance(11)
    assert store.claim_jobs(
        "tenant-a", worker_id="worker-c", lease_seconds=10, now=clock()
    ) == ()
    final = store.get_job("tenant-a", job.job_id)
    assert final.state == "dead_letter"
    assert final.last_error_code == "stale_lease_exhausted"


def test_retry_backoff_dead_letter_and_replay_are_bounded(store, clock) -> None:
    enroll(store)
    job = store.enqueue_scan(
        "tenant-a",
        "customer-db",
        limits=discovery.ScanLimits(),
        max_attempts=1,
        retention_seconds=100,
        actor_ref="owner",
        idempotency_key="dead-letter",
    )
    leased = store.claim_jobs("tenant-a", worker_id="worker", now=clock())[0]
    dead = store.fail_job(
        "tenant-a",
        leased.job_id,
        worker_id="worker",
        error_code="adapter_error",
        now=clock(),
    )
    assert dead.state == "dead_letter"
    replayed = store.replay_dead_letter(
        "tenant-a",
        job.job_id,
        expected_revision=dead.revision,
        actor_ref="operator",
        idempotency_key="replay-one",
        now=clock(),
    )
    assert replayed.state == "queued"
    assert replayed.attempts == 0
    assert store.list_jobs("tenant-a", state="queued") == (replayed,)


def test_adapter_failures_are_sanitized_and_retry_without_leaking_detail(store) -> None:
    enroll(store)
    store.enqueue_scan(
        "tenant-a",
        "customer-db",
        limits=discovery.ScanLimits(),
        max_attempts=3,
        retention_seconds=100,
        actor_ref="owner",
        idempotency_key="broken-adapter",
    )
    coordinator = discovery.PrivacyDataDiscoveryCoordinator(
        store,
        structured_sources={"fixture": BrokenRows()},
        credential_ref_present=lambda _name: True,
    )
    result = coordinator.run_once("tenant-a", worker_id="worker")
    assert result.completed_reports == ()
    assert result.failed_jobs[0].state == "queued"
    assert result.failed_jobs[0].last_error_code == "adapter_error"
    database_bytes = store.path.read_bytes()
    assert b"alice@example.com" not in database_bytes
    assert b"super-secret" not in database_bytes


def test_missing_credential_reference_fails_closed(store) -> None:
    enroll(store)
    store.enqueue_scan(
        "tenant-a",
        "customer-db",
        limits=discovery.ScanLimits(),
        max_attempts=2,
        retention_seconds=100,
        actor_ref="owner",
        idempotency_key="missing-credential",
    )
    coordinator = discovery.PrivacyDataDiscoveryCoordinator(
        store,
        structured_sources={"fixture": Rows([])},
        credential_ref_present=lambda _name: False,
    )
    result = coordinator.run_once("tenant-a", worker_id="worker")
    assert result.failed_jobs[0].last_error_code == "credential_unavailable"


def test_inventory_and_report_diff_use_digest_only_fingerprints(store) -> None:
    enroll(store)
    first = enqueue_and_run(
        store,
        Rows([discovery.StructuredRecord("row-1", {"email": "one@example.com"})]),
        operation="diff-first",
    )
    second = enqueue_and_run(
        store,
        Rows(
            [
                discovery.StructuredRecord(
                    "row-1", {"email": "one@example.com", "phone": "212-555-0199"}
                )
            ]
        ),
        operation="diff-second",
    )
    snapshot = store.inventory("tenant-a")
    assert snapshot.report_ids == (second.report_id,)
    assert snapshot.unreviewed_count == second.findings_count
    diff = store.diff_reports("tenant-a", first.report_id, second.report_id)
    assert diff.added_finding_sha256
    assert diff.unchanged_count >= 1
    assert all(len(item) == 64 for item in diff.added_finding_sha256)


def test_rotating_key_material_never_reports_pseudonym_changes_as_real_data_changes(store):
    enroll(store)
    adapter = Rows([discovery.StructuredRecord("row", {"email": "one@example.com"})])
    first = enqueue_and_run(store, adapter, operation="before-key-rotation")
    store._evidence_key_resolver = lambda _name: b"changed-evidence-material-32-bytes!"
    second = enqueue_and_run(store, adapter, operation="after-key-rotation")
    assert first.evidence_key_fingerprint != second.evidence_key_fingerprint
    with pytest.raises(discovery.PrivacyDataDiscoveryValidationError, match="different or unverified evidence key"):
        store.diff_reports("tenant-a", first.report_id, second.report_id)


def test_source_updated_during_scan_cannot_publish_report_under_current_source(store):
    enrolled = enroll(store)

    class ChangedScope:
        def iter_rows(self, **kwargs):
            store.enroll_source("tenant-a", source_id=enrolled.source_id, kind="structured", provider="fixture",
                origin="https://changed.example.com", resource_ref=enrolled.resource_ref, credential_env=enrolled.credential_env,
                evidence_key_env=enrolled.evidence_key_env, actor_ref="privacy-owner", expected_revision=enrolled.revision,
                idempotency_key="change-source-during-scan")
            yield discovery.StructuredRecord("row", {"email": "one@example.com"})

    store.enqueue_scan("tenant-a", enrolled.source_id, limits=discovery.ScanLimits(), actor_ref="privacy-owner",
                       idempotency_key="scan-current-source", max_attempts=3, retention_seconds=3600)
    coordinator = discovery.PrivacyDataDiscoveryCoordinator(store, structured_sources={"fixture": ChangedScope()},
        clock=store._clock, credential_ref_present=lambda _name: True)
    # The commit-time source check refuses the report; run_once records that
    # as a sanitized "source_changed" failure (so independent jobs in the batch
    # still run) instead of raising out of the worker loop.
    result = coordinator.run_once("tenant-a", worker_id="worker")
    assert result.completed_reports == ()
    assert [job.last_error_code for job in result.failed_jobs] == ["source_changed"]
    assert store.list_reports("tenant-a") == ()


def test_review_requires_fresh_four_eyes_and_calls_only_after_approval(tmp_path, clock) -> None:
    updates: list[discovery.ReviewedClassification] = []
    store = discovery.PrivacyDataDiscoveryStore(
        tmp_path / "review.sqlite3",
        config_gate=lambda: None,
        clock=clock,
        evidence_key_resolver=lambda _name: b"x" * 32,
        review_callback=updates.append,
    )
    enroll(store)
    report = enqueue_and_run(
        store,
        Rows([discovery.StructuredRecord("row", {"email": "a@example.com"})]),
    )
    finding = store.list_findings("tenant-a", report_id=report.report_id)[0]
    proposal = store.propose_review(
        "tenant-a",
        finding.finding_id,
        decision="confirmed",
        effective_category=finding.category,
        evidence_sha256=finding.evidence_sha256,
        freshness_seconds=60,
        expected_finding_revision=1,
        prepared_by="reviewer-a",
        idempotency_key="prepare-review",
    )
    assert updates == []
    with pytest.raises(discovery.PrivacyDataDiscoveryConflict, match="four-eyes"):
        store.approve_review(
            "tenant-a",
            proposal.review_id,
            approved_by="reviewer-a",
            expected_version=proposal.version,
            expected_integrity_sha256=proposal.integrity_sha256,
            idempotency_key="bad-self-approve",
        )
    approved = store.approve_review(
        "tenant-a",
        proposal.review_id,
        approved_by="reviewer-b",
        expected_version=proposal.version,
        expected_integrity_sha256=proposal.integrity_sha256,
        idempotency_key="approve-review",
    )
    assert approved.review_id == proposal.review_id
    assert updates == [approved]
    assert store.list_reviews(
        "tenant-a", finding_id=finding.finding_id
    ) == (store.get_review("tenant-a", proposal.review_id),)
    same = store.approve_review(
        "tenant-a",
        proposal.review_id,
        approved_by="reviewer-b",
        expected_version=proposal.version,
        expected_integrity_sha256=proposal.integrity_sha256,
        idempotency_key="approve-review",
    )
    assert same == approved
    assert updates == [approved]


def test_stale_review_and_false_positive_inventory_workflow(store, clock) -> None:
    enroll(store)
    report = enqueue_and_run(
        store,
        Rows([discovery.StructuredRecord("row", {"email": "a@example.com"})]),
    )
    finding = store.list_findings("tenant-a", report_id=report.report_id)[0]
    proposal = store.propose_review(
        "tenant-a",
        finding.finding_id,
        decision="false_positive",
        effective_category=None,
        evidence_sha256=finding.evidence_sha256,
        freshness_seconds=10,
        expected_finding_revision=1,
        prepared_by="reviewer-a",
        idempotency_key="prepare-false-positive",
    )
    clock.advance(11)
    with pytest.raises(discovery.PrivacyDataDiscoveryConflict, match="stale"):
        store.approve_review(
            "tenant-a",
            proposal.review_id,
            approved_by="reviewer-b",
            expected_version=1,
            expected_integrity_sha256=proposal.integrity_sha256,
            idempotency_key="stale-approval",
        )
    fresh = store.propose_review(
        "tenant-a",
        finding.finding_id,
        decision="confirmed",
        effective_category=finding.category,
        evidence_sha256=finding.evidence_sha256,
        freshness_seconds=10,
        expected_finding_revision=1,
        prepared_by="reviewer-c",
        idempotency_key="replace-expired-review",
    )
    assert fresh.version == 2
    assert store.get_review("tenant-a", proposal.review_id).status == "expired"


def test_false_positive_is_removed_from_effective_inventory(store) -> None:
    enroll(store)
    report = enqueue_and_run(
        store,
        Rows([discovery.StructuredRecord("row", {"email": "a@example.com"})]),
    )
    finding = store.list_findings("tenant-a", report_id=report.report_id)[0]
    proposal = store.propose_review(
        "tenant-a",
        finding.finding_id,
        decision="false_positive",
        effective_category=None,
        evidence_sha256=finding.evidence_sha256,
        freshness_seconds=60,
        expected_finding_revision=1,
        prepared_by="reviewer-a",
        idempotency_key="fp-proposal",
    )
    store.approve_review(
        "tenant-a",
        proposal.review_id,
        approved_by="reviewer-b",
        expected_version=1,
        expected_integrity_sha256=proposal.integrity_sha256,
        idempotency_key="fp-approval",
    )
    snapshot = store.inventory("tenant-a")
    assert snapshot.false_positive_count == 1
    assert snapshot.unreviewed_count == report.findings_count - 1


def test_callback_failure_does_not_rollback_durable_approval(tmp_path, clock) -> None:
    def fail_callback(_update):
        raise RuntimeError("external ROPA outage containing secret")

    store = discovery.PrivacyDataDiscoveryStore(
        tmp_path / "callback.sqlite3",
        config_gate=lambda: None,
        clock=clock,
        evidence_key_resolver=lambda _name: b"x" * 32,
        review_callback=fail_callback,
    )
    enroll(store)
    report = enqueue_and_run(
        store,
        Rows([discovery.StructuredRecord("row", {"email": "a@example.com"})]),
    )
    finding = store.list_findings("tenant-a", report_id=report.report_id)[0]
    proposal = store.propose_review(
        "tenant-a",
        finding.finding_id,
        decision="confirmed",
        effective_category=finding.category,
        evidence_sha256=finding.evidence_sha256,
        freshness_seconds=60,
        expected_finding_revision=1,
        prepared_by="a",
        idempotency_key="callback-prepare",
    )
    with pytest.raises(discovery.PrivacyDataDiscoveryAdapterError):
        store.approve_review(
            "tenant-a",
            proposal.review_id,
            approved_by="b",
            expected_version=1,
            expected_integrity_sha256=proposal.integrity_sha256,
            idempotency_key="callback-approve",
        )
    assert store.get_review("tenant-a", proposal.review_id).status == "approved"
    assert store.audit_events("tenant-a")[-1].action == "review_callback_failed"
    assert b"external ROPA outage" not in store.path.read_bytes()


def test_report_integrity_tamper_is_detected(store) -> None:
    enroll(store)
    report = enqueue_and_run(store, Rows([]))
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE reports SET payload_json='{}' WHERE tenant_id=? AND report_id=?",
            ("tenant-a", report.report_id),
        )
    with pytest.raises(discovery.PrivacyDataDiscoveryIntegrityError):
        store.get_report("tenant-a", report.report_id)


def test_audit_chain_detects_tampering(store) -> None:
    enroll(store)
    assert store.verify_audit_chain("tenant-a") is True
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE audit_events SET integrity_sha256=? WHERE tenant_id=? AND sequence=1",
            ("0" * 64, "tenant-a"),
        )
    with pytest.raises(discovery.PrivacyDataDiscoveryIntegrityError):
        store.verify_audit_chain("tenant-a")


def test_retention_purge_removes_reports_and_is_idempotent(store, clock) -> None:
    enroll(store)
    report = enqueue_and_run(store, Rows([]))
    clock.advance(3_601)
    assert store.purge_expired(
        "tenant-a",
        actor_ref="retention-worker",
        idempotency_key="purge-window-1",
        now=clock(),
    ) == 1
    with pytest.raises(discovery.PrivacyDataDiscoveryNotFound):
        store.get_report("tenant-a", report.report_id)
    assert store.purge_expired(
        "tenant-a",
        actor_ref="retention-worker",
        idempotency_key="purge-window-1",
        now=clock(),
    ) == 1


def test_privacy_posture_is_candid_about_limits() -> None:
    posture = discovery.PrivacyDataDiscoveryStore.privacy_posture()
    assert posture["raw_values_persisted"] is False
    assert posture["credential_values_persisted"] is False
    assert posture["completeness_claim"] is False
    assert posture["live_provider_acceptance"] is False


def test_scan_limits_validate_closed_bounds() -> None:
    assert discovery.ScanLimits().validated() == discovery.ScanLimits()
    with pytest.raises(discovery.PrivacyDataDiscoveryValidationError):
        replace(discovery.ScanLimits(), max_seconds=float("nan")).validated()
    with pytest.raises(discovery.PrivacyDataDiscoveryValidationError):
        replace(discovery.ScanLimits(), max_findings=100_001).validated()


def test_approval_queue_keeps_older_waiting_reviews_past_the_list_cap(store, monkeypatch) -> None:
    """The status filter runs before the newest-N cap, so a review still
    waiting for approval never drops out behind newer decided ones."""
    enroll(store)
    report = enqueue_and_run(
        store,
        Rows([
            discovery.StructuredRecord(f"row-{n}", {f"email_{n}": f"p{n}@example.com"})
            for n in range(4)
        ]),
    )
    findings = store.list_findings("tenant-a", report_id=report.report_id)
    assert len(findings) >= 3

    def propose(finding, key):
        return store.propose_review(
            "tenant-a", finding.finding_id, decision="confirmed",
            effective_category=finding.category, evidence_sha256=finding.evidence_sha256,
            freshness_seconds=600, expected_finding_revision=1,
            prepared_by="reviewer-a", idempotency_key=key)

    waiting = propose(findings[0], "waiting")
    for n, finding in enumerate(findings[1:3], start=1):
        proposal = propose(finding, f"decided-{n}")
        store.approve_review(
            "tenant-a", proposal.review_id, approved_by="reviewer-b",
            expected_version=proposal.version,
            expected_integrity_sha256=proposal.integrity_sha256,
            idempotency_key=f"approve-{n}")
    monkeypatch.setattr(discovery, "_MAX_LIST", 2)
    queue = store.list_all_reviews("tenant-a", status="pending", limit=2)
    assert [r.review_id for r in queue] == [waiting.review_id]
    assert len(store.list_all_reviews("tenant-a", limit=2)) == 2
