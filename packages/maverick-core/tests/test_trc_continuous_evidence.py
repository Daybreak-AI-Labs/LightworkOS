from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest
from maverick.trc_continuous_evidence import (
    COMPLIANCE_CONCLUSIONS_WRITTEN,
    CONTROL_IMPLEMENTATION_MUTATED,
    RAW_CREDENTIALS_PERSISTED,
    RAW_PROVIDER_PAYLOAD_PERSISTED,
    ContinuousEvidenceConflict,
    ContinuousEvidenceIntegrityError,
    ContinuousEvidencePermissionDenied,
    ContinuousEvidenceStore,
    ContinuousEvidenceValidationError,
    run_claimed_collection,
)
from maverick.trc_evidence_collectors import (
    CollectionRequest,
    CollectorRegistry,
    ControlEvidence,
    EvidenceCollectorValidationError,
    EvidencePage,
    LocalSoc2Collector,
    validate_page,
    validate_request,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Principal:
    def __init__(self, value: str = "maker@example.test") -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value


class StaticCollector:
    collector_id = "test_collector_v1"

    def __init__(self, *, status: str = "observed", secret: str = "not-stored") -> None:
        self.status = status
        self.secret = secret
        self.handles: list[object | None] = []

    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        assert cursor is None
        self.handles.append(request.credential_handle)
        items = tuple(
            ControlEvidence(
                control_ref=control,
                status=self.status,
                reason_code="technical_test_result",
                evidence_sha256=SHA_A if self.status == "observed" else SHA_B,
                source_revision_sha256=SHA_C,
            )
            for control in request.control_refs
        )
        return EvidencePage(
            items=items,
            next_cursor=None,
            terminal=True,
            complete=True,
            incomplete_reason=None,
            source_revision_sha256=SHA_C,
            artifact_sha256=SHA_D,
            bytes_read=512,
            provider_request_sha256=SHA_A,
        )


class IncompleteCollector(StaticCollector):
    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        return EvidencePage(
            items=(),
            next_cursor=None,
            terminal=True,
            complete=False,
            incomplete_reason="access_denied",
            source_revision_sha256=SHA_C,
            artifact_sha256=SHA_D,
            bytes_read=12,
            provider_request_sha256=SHA_A,
        )


class SecretFailureCollector(StaticCollector):
    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        raise RuntimeError(f"provider exploded: {self.secret}")


class TruncatedCollector(StaticCollector):
    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        self.calls += 1
        items = ()
        if self.calls == 1:
            items = tuple(
                ControlEvidence(
                    control_ref=control,
                    status="observed",
                    reason_code="technical_test_result",
                    evidence_sha256=SHA_A,
                    source_revision_sha256=SHA_C,
                )
                for control in request.control_refs
            )
        return EvidencePage(
            items=items,
            next_cursor=f"cursor-{self.calls}",
            terminal=False,
            complete=False,
            incomplete_reason="provider_truncated",
            source_revision_sha256=SHA_C,
            artifact_sha256=SHA_D,
            bytes_read=1,
            provider_request_sha256=SHA_A,
        )


def make_store(tmp_path, *, tenant: str = "tenant-a"):
    clock = Clock()
    principal = Principal()
    store = ContinuousEvidenceStore(
        tmp_path / "continuous-evidence.sqlite3",
        tenant_id=tenant,
        principal_resolver=principal,
        config_gate=lambda: None,
        clock=clock,
        lease_token_factory=lambda: "lwtrc1." + "x" * 43,
        default_retention_seconds=86_400,
    )
    return store, clock, principal


def approve_definition(store: ContinuousEvidenceStore, principal: Principal):
    definition = store.register_definition(
        definition_id="test_definition",
        version=1,
        collector_id="test_collector_v1",
        collector_schema_version=1,
        collector_key_id="key_v1",
        capability_revision=7,
        allowed_control_refs=("control-a", "control-b"),
    )
    with pytest.raises(ContinuousEvidencePermissionDenied):
        store.approve_definition(
            definition.definition_id,
            definition.version,
            expected_integrity_sha256=definition.integrity_sha256,
        )
    principal.value = "independent-approver@example.test"
    return store.approve_definition(
        definition.definition_id,
        definition.version,
        expected_integrity_sha256=definition.integrity_sha256,
    )


def enroll(store: ContinuousEvidenceStore, definition):
    return store.enroll(
        enrollment_id="enrollment-a",
        definition_id=definition.definition_id,
        definition_version=definition.version,
        expected_definition_integrity_sha256=definition.integrity_sha256,
        asset_scope_sha256=SHA_A,
        credential_profile_sha256=SHA_B,
        control_refs=("control-b", "control-a"),
        interval_seconds=60,
        operation_id="enroll-a",
    )


def test_end_to_end_collection_is_digest_only_and_review_pending(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enrollment = enroll(store, definition)
    assert enrollment.control_refs == ("control-a", "control-b")

    jobs = store.enqueue_due()
    assert len(jobs) == 1
    claimed = store.claim_jobs(worker_id="worker-a", lease_seconds=60)
    assert len(claimed) == 1
    collector = StaticCollector()
    credential = object()
    outcome = run_claimed_collection(
        store,
        claimed[0],
        registry=CollectorRegistry({collector.collector_id: collector}),
        resolve_credential=lambda *_args: credential,
    )

    assert outcome.job.state == "completed"
    assert outcome.run is not None and outcome.run.complete
    assert [item.status for item in outcome.observations] == ["observed", "observed"]
    assert outcome.alerts == ()
    assert collector.handles == [credential]
    assert COMPLIANCE_CONCLUSIONS_WRITTEN is False
    assert CONTROL_IMPLEMENTATION_MUTATED is False
    assert RAW_PROVIDER_PAYLOAD_PERSISTED is False
    assert RAW_CREDENTIALS_PERSISTED is False

    database = (tmp_path / "continuous-evidence.sqlite3").read_bytes()
    assert b"not-stored" not in database
    assert b"maker@example.test" not in database
    verification = store.verify_integrity()
    assert verification.definitions == 1
    assert verification.enrollments == 1
    assert verification.jobs == 1
    assert verification.runs == 1
    assert verification.observations == 2
    assert verification.alerts == 0
    assert verification.audit_events >= 5


def test_second_collection_creates_change_alert_without_compliance_decision(tmp_path):
    store, clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    first = store.claim_jobs(worker_id="worker-a") if store.enqueue_due() else ()
    first_outcome = run_claimed_collection(
        store,
        first[0],
        registry=CollectorRegistry({"test_collector_v1": StaticCollector()}),
        resolve_credential=lambda *_args: None,
    )
    assert first_outcome.alerts == ()

    clock.advance(61)
    assert len(store.enqueue_due()) == 1
    second = store.claim_jobs(worker_id="worker-b")[0]
    second_outcome = run_claimed_collection(
        store,
        second,
        registry=CollectorRegistry({"test_collector_v1": StaticCollector(status="failed")}),
        resolve_credential=lambda *_args: None,
    )
    assert second_outcome.job.state == "completed"
    assert len(second_outcome.alerts) == 2
    assert {alert.current_status for alert in second_outcome.alerts} == {"failed"}
    assert len(store.list_alerts()) == 2


def test_incomplete_terminal_page_never_becomes_complete(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    outcome = run_claimed_collection(
        store,
        claimed,
        registry=CollectorRegistry({"test_collector_v1": IncompleteCollector()}),
        resolve_credential=lambda *_args: None,
    )
    assert outcome.job.state == "incomplete"
    assert outcome.run is not None
    assert outcome.run.complete is False
    assert outcome.run.incomplete_reason == "access_denied"
    assert outcome.observations == ()


def test_provider_errors_are_sanitized_and_dead_letter_can_be_replayed(tmp_path):
    store, clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due(max_attempts=1)
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    secret = "token-super-secret-value"
    outcome = run_claimed_collection(
        store,
        claimed,
        registry=CollectorRegistry({"test_collector_v1": SecretFailureCollector(secret=secret)}),
        resolve_credential=lambda *_args: secret,
        retry_backoff_seconds=10,
    )
    assert outcome.job.state == "dead_letter"
    assert outcome.job.error_code == "collector_error"
    assert secret.encode() not in (tmp_path / "continuous-evidence.sqlite3").read_bytes()

    replayed = store.requeue_dead_letter(
        outcome.job.job_id,
        expected_revision=outcome.job.revision,
        operation_id="replay-a",
    )
    assert replayed.state == "queued"
    clock.advance(1)
    claimed_again = store.claim_jobs(worker_id="worker-b")[0]
    recovered = run_claimed_collection(
        store,
        claimed_again,
        registry=CollectorRegistry({"test_collector_v1": StaticCollector()}),
        resolve_credential=lambda *_args: None,
    )
    assert recovered.job.state == "completed"


def test_revocation_cancels_claim_and_blocks_stale_result(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    current = store.get_enrollment("enrollment-a")
    revoked = store.update_enrollment_state(
        current.enrollment_id,
        state="revoked",
        expected_revision=current.revision,
        expected_integrity_sha256=current.integrity_sha256,
    )
    assert revoked.state == "revoked"
    assert store.get_job(claimed.job.job_id).state == "cancelled"
    with pytest.raises(ContinuousEvidenceConflict):
        run_claimed_collection(
            store,
            claimed,
            registry=CollectorRegistry({"test_collector_v1": StaticCollector()}),
            resolve_credential=lambda *_args: None,
        )


def test_same_database_remains_tenant_isolated(tmp_path):
    store_a, _clock_a, principal_a = make_store(tmp_path, tenant="tenant-a")
    approve_definition(store_a, principal_a)
    store_b, _clock_b, _principal_b = make_store(tmp_path, tenant="tenant-b")
    with pytest.raises(Exception, match="not found"):
        store_b.get_definition("test_definition", 1)
    assert store_b.verify_integrity().definitions == 0


def test_tamper_is_detected(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    approve_definition(store, principal)
    with sqlite3.connect(tmp_path / "continuous-evidence.sqlite3") as connection:
        connection.execute(
            "UPDATE trc_definitions SET payload_json='{}' WHERE definition_id='test_definition'"
        )
    with pytest.raises(Exception, match="integrity"):
        store.get_definition("test_definition", 1)


def test_retention_purge_is_bounded_and_preserves_audit(tmp_path):
    store, clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    outcome = run_claimed_collection(
        store,
        claimed,
        registry=CollectorRegistry({"test_collector_v1": StaticCollector()}),
        resolve_credential=lambda *_args: None,
    )
    current = store.get_enrollment("enrollment-a")
    store.update_enrollment_state(
        current.enrollment_id,
        state="revoked",
        expected_revision=current.revision,
        expected_integrity_sha256=current.integrity_sha256,
    )
    before = store.verify_integrity()
    clock.advance(86_401)
    purged = store.purge_expired(cutoff=clock.value, limit=100)
    assert purged.jobs == 1
    assert purged.runs == 1
    assert purged.observations == 2
    assert purged.enrollments == 1
    assert store.list_runs() == ()
    assert store.list_observations() == ()
    after = store.verify_integrity()
    assert after.audit_events == before.audit_events + 1
    assert outcome.run is not None


def test_retention_delete_guard_and_missing_history_detection(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    database = tmp_path / "continuous-evidence.sqlite3"

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            connection.execute("DELETE FROM trc_definition_history")
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER trc_enrollment_history_guard_delete")
        connection.execute(
            "DELETE FROM trc_enrollment_history WHERE enrollment_id=? AND revision=1",
            ("enrollment-a",),
        )
    with pytest.raises(ContinuousEvidenceIntegrityError, match="history"):
        store.verify_integrity()


def test_complete_collection_rejects_observations_not_present_in_pages(tmp_path):
    store, clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    enrollment = store.get_enrollment("enrollment-a")
    item_a = ControlEvidence(
        "control-a",
        "observed",
        "technical_test_result",
        SHA_A,
        SHA_C,
    )
    fabricated_b = replace(item_a, control_ref="control-b", evidence_sha256=SHA_B)
    page = EvidencePage(
        items=(item_a,),
        next_cursor=None,
        terminal=True,
        complete=True,
        incomplete_reason=None,
        source_revision_sha256=SHA_C,
        artifact_sha256=SHA_D,
        bytes_read=1,
        provider_request_sha256=SHA_A,
    )
    with pytest.raises(ContinuousEvidenceValidationError, match="exactly match"):
        store.complete_collection(
            claimed=claimed,
            definition=definition,
            enrollment=enrollment,
            pages=(page,),
            observations=(item_a, fabricated_b),
            complete=True,
            incomplete_reason=None,
            started_at=clock.value,
        )


def test_page_bound_exhaustion_is_durably_incomplete(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    collector = TruncatedCollector()
    outcome = run_claimed_collection(
        store,
        claimed,
        registry=CollectorRegistry({collector.collector_id: collector}),
        resolve_credential=lambda *_args: None,
    )
    assert collector.calls == 50
    assert outcome.job.state == "incomplete"
    assert outcome.run is not None
    assert outcome.run.complete is False
    assert outcome.run.incomplete_reason == "provider_truncated"
    assert outcome.run.page_count == 50


def test_due_schedule_does_not_invalidate_an_existing_live_job(tmp_path):
    store, clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    first = store.enqueue_due()
    assert len(first) == 1
    clock.advance(61)
    assert store.enqueue_due() == ()
    claimed = store.claim_jobs(worker_id="worker-a")
    assert len(claimed) == 1
    assert claimed[0].job.job_id == first[0].job_id


def test_definition_drift_cancels_exact_claim_without_collector_io(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    enroll(store, definition)
    store.enqueue_due()
    claimed = store.claim_jobs(worker_id="worker-a")[0]
    store.retire_definition(
        definition.definition_id,
        definition.version,
        expected_integrity_sha256=definition.integrity_sha256,
    )
    collector = StaticCollector()
    outcome = run_claimed_collection(
        store,
        claimed,
        registry=CollectorRegistry({collector.collector_id: collector}),
        resolve_credential=lambda *_args: object(),
    )
    assert outcome.job.state == "cancelled"
    assert outcome.job.error_code == "collector_authority_changed"
    assert collector.handles == []


def test_idempotent_enrollment_replay_returns_original_immutable_revision(tmp_path):
    store, _clock, principal = make_store(tmp_path)
    definition = approve_definition(store, principal)
    original = enroll(store, definition)
    paused = store.update_enrollment_state(
        original.enrollment_id,
        state="paused",
        expected_revision=original.revision,
        expected_integrity_sha256=original.integrity_sha256,
    )
    assert paused.revision == 2
    replayed = enroll(store, definition)
    assert replayed == original


def test_collector_contract_rejects_hostile_pagination_and_scope():
    request = CollectionRequest(
        tenant_sha256=SHA_A,
        definition_id="definition-a",
        definition_version=1,
        definition_integrity_sha256=SHA_B,
        collector_id="test_collector_v1",
        collector_schema_version=1,
        collector_key_id="key-v1",
        capability_revision=1,
        enrollment_id="enrollment-a",
        enrollment_revision=1,
        enrollment_integrity_sha256=SHA_C,
        asset_scope_sha256=SHA_D,
        control_refs=("control-a",),
        window_started_at=1.0,
        window_ended_at=2.0,
    )
    assert validate_request(request) is request
    hostile = EvidencePage(
        items=(ControlEvidence("other-control", "observed", "ok", SHA_A, SHA_B),),
        next_cursor="cursor-a",
        terminal=True,
        complete=True,
        incomplete_reason=None,
        source_revision_sha256=SHA_C,
        artifact_sha256=SHA_D,
        bytes_read=1,
        provider_request_sha256=SHA_A,
    )
    with pytest.raises(EvidenceCollectorValidationError):
        validate_page(hostile, expected_controls=request.control_refs)


def test_local_soc2_collector_is_closed_and_single_page(monkeypatch):
    import maverick.soc2

    monkeypatch.setattr(
        maverick.soc2,
        "collect_soc2_evidence",
        lambda: {
            "version": "test",
            "controls": {"tenant_isolation": {"status": "enabled", "enabled": True}},
            "audit_log": {"status": "unsigned"},
            "audit_signing_key": {"status": "absent"},
        },
    )
    request = CollectionRequest(
        tenant_sha256=SHA_A,
        definition_id="local-definition",
        definition_version=1,
        definition_integrity_sha256=SHA_B,
        collector_id="local_soc2_v1",
        collector_schema_version=1,
        collector_key_id="local-key-v1",
        capability_revision=1,
        enrollment_id="local-enrollment",
        enrollment_revision=1,
        enrollment_integrity_sha256=SHA_C,
        asset_scope_sha256=SHA_D,
        control_refs=("audit_log", "tenant_isolation"),
        window_started_at=1.0,
        window_ended_at=2.0,
    )
    page = LocalSoc2Collector().fetch(request, None)
    assert page.complete and page.terminal
    assert [item.status for item in page.items] == ["unknown", "observed"]
    with pytest.raises(EvidenceCollectorValidationError):
        LocalSoc2Collector().fetch(replace(request, control_refs=("not-supported",)), None)
