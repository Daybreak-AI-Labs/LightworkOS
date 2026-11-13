from __future__ import annotations

import hashlib
import inspect
import sqlite3
import time
from collections import Counter
from pathlib import Path

import pytest
from maverick import privacy_rights_orchestration as rights


class MutableClock:
    def __init__(self, value: float = 2_000_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def authority(tmp_path: Path):
    actor = {"value": "operator"}
    clock = MutableClock()
    token_counter = {"value": 0}

    def token() -> str:
        token_counter["value"] += 1
        return f"lease-token-{token_counter['value']}"

    store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / "privacy-rights.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=clock,
        token_factory=token,
    )
    return store, actor, clock


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def enroll_all(
    store: rights.PrivacyRightsOrchestrationStore,
    tenant: str,
    source: str,
    *,
    key: str,
) -> rights.SourceEnrollment:
    return store.enroll_source(
        tenant,
        source,
        adapter_ref="provider-adapter-v1",
        credential_ref="env:PROVIDER_RIGHTS_TOKEN",
        capabilities=sorted(rights.TASK_PHASES),
        expected_revision=0,
        idempotency_key=key,
    )


def open_verified(
    store: rights.PrivacyRightsOrchestrationStore,
    clock: MutableClock,
    tenant: str,
    case_id: str,
    requested_rights: list[str],
) -> rights.RightsCase:
    case = store.open_case(
        tenant,
        case_id,
        request_version=1,
        external_request_ref=f"external request for {case_id}",
        subject_reference=f"person@example.test/{case_id}",
        rights=requested_rights,
        retained_until=clock() + 600,
        idempotency_key=f"open-{case_id}",
    )
    return store.set_identity_verification(
        tenant,
        case_id,
        status="verified",
        evidence_sha256=digest(f"identity-{case_id}"),
        evidence_ref=f"identity:{case_id}",
        expected_revision=case.revision,
        idempotency_key=f"verify-{case_id}",
    )


def task_by_phase(tasks: tuple[rights.SourceTask, ...], phase: str) -> rights.SourceTask:
    return next(task for task in tasks if task.phase == phase)


def complete_callback_phase(
    store: rights.PrivacyRightsOrchestrationStore,
    tenant: str,
    case_id: str,
    source_id: str,
    task: rights.SourceTask,
    *,
    suffix: str,
) -> rights.SourceEvidenceReceipt:
    claimed = store.claim_callbacks(
        tenant,
        limit=1,
        lease_seconds=30,
        idempotency_key=f"claim-{suffix}",
    )
    assert len(claimed) == 1
    callback = claimed[0]
    assert callback.phase == task.phase
    acknowledged = store.ack_callback(
        tenant,
        callback.callback_id,
        lease_token=callback.lease_token or "",
        acknowledgement_sha256=digest(f"ack-{suffix}"),
        acknowledgement_ref=f"ack:{suffix}",
        expected_revision=callback.revision,
        idempotency_key=f"ack-{suffix}",
    )
    assert acknowledged.state == "acked"
    return store.record_source_evidence(
        tenant,
        case_id,
        source_id,
        task.phase,
        evidence_id=f"evidence:{suffix}",
        status="complete",
        provider_evidence_sha256=digest(f"evidence-{suffix}"),
        record_count=2,
        opaque_ref=f"provider-receipt:{suffix}",
        expected_task_revision=task.revision,
        idempotency_key=f"record-{suffix}",
    )


def complete_local_phase(
    store: rights.PrivacyRightsOrchestrationStore,
    tenant: str,
    case_id: str,
    source_id: str,
    task: rights.SourceTask,
    *,
    suffix: str,
) -> rights.SourceEvidenceReceipt:
    return store.record_source_evidence(
        tenant,
        case_id,
        source_id,
        task.phase,
        evidence_id=f"evidence:{suffix}",
        status="complete",
        provider_evidence_sha256=digest(f"evidence-{suffix}"),
        record_count=2,
        opaque_ref=f"local-receipt:{suffix}",
        expected_task_revision=task.revision,
        idempotency_key=f"record-{suffix}",
    )


def test_two_level_config_gate_is_strict_default_off(monkeypatch, tmp_path: Path) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    for configured in (
        {},
        {"privacy_automation": {"enable": True}},
        {
            "privacy_automation": {
                "enable": False,
                "rights_orchestration": {"enable": True},
            }
        },
        {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": False},
            }
        },
    ):
        monkeypatch.setattr(config, "load_config", lambda value=configured: value)
        assert rights.enabled() is False
        with pytest.raises(rights.PrivacyRightsConfigError):
            rights.PrivacyRightsOrchestrationStore(
                tmp_path / f"off-{len(configured)}.sqlite3",
                principal_resolver=lambda: "operator",
            )

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "privacy_automation": {
                "enable": True,
                "rights_orchestration": {"enable": True},
            }
        },
    )
    assert rights.enabled() is True


def test_tenant_canonicalization_isolation_and_opaque_not_found(authority) -> None:
    store, _actor, _clock = authority
    composed = "Caf\u00e9"
    decomposed = "Cafe\u0301"
    source = enroll_all(store, decomposed, "directory", key="source-canonical")
    assert source.tenant_id == composed
    assert store.get_source(composed, "directory") == source

    enroll_all(store, "tenant-b", "directory", key="source-b")
    assert len(store.list_sources(composed)) == 1
    assert len(store.list_sources("tenant-b")) == 1
    with pytest.raises(rights.PrivacyRightsNotFound):
        store.get_source("tenant-c", "directory")


def test_public_operations_cannot_accept_spoofed_actor_and_require_principal(
    tmp_path: Path,
) -> None:
    for name, method in inspect.getmembers(
        rights.PrivacyRightsOrchestrationStore, predicate=inspect.isfunction
    ):
        if name.startswith("_") or name == "product_boundaries":
            continue
        parameters = inspect.signature(method).parameters
        assert "actor" not in parameters
        assert "actor_ref" not in parameters

    store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / "no-principal.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: None,
        digest_key_resolver=lambda _tenant: b"k" * 32,
    )
    with pytest.raises(rights.PrivacyRightsPermissionDenied):
        store.list_sources("tenant-a")


def test_source_enrollment_idempotency_conflict_and_reference_only_schema(
    authority,
) -> None:
    store, _actor, _clock = authority
    first = enroll_all(store, "tenant-a", "crm", key="enroll-crm")
    replay = enroll_all(store, "tenant-a", "crm", key="enroll-crm")
    assert replay == first

    with pytest.raises(rights.PrivacyRightsConflict):
        store.enroll_source(
            "tenant-a",
            "crm",
            adapter_ref="provider-adapter-v1",
            credential_ref="env:PROVIDER_RIGHTS_TOKEN",
            capabilities=["discover"],
            expected_revision=0,
            idempotency_key="enroll-crm",
        )
    with pytest.raises(rights.PrivacyRightsValidationError):
        store.enroll_source(
            "tenant-a",
            "bad-origin",
            adapter_ref="https://provider.example",
            credential_ref="literal-provider-secret",
            capabilities=["discover"],
            expected_revision=0,
            idempotency_key="bad-source",
        )


def test_raw_subject_request_and_provider_secrets_never_enter_sqlite(authority) -> None:
    store, _actor, clock = authority
    raw_subject = "very.private.person@example.test"
    raw_request = "provider-ticket-PII-12345"
    literal_secret = "top-secret-provider-password"
    store.enroll_source(
        "tenant-a",
        "crm",
        adapter_ref="adapter-ref-v1",
        credential_ref="vault:rights-token-ref",
        capabilities=["discover", "retrieve", "redact"],
        expected_revision=0,
        idempotency_key="source",
    )
    case = store.open_case(
        "tenant-a",
        "case-private",
        request_version=2,
        external_request_ref=raw_request,
        subject_reference=raw_subject,
        rights=["access"],
        retained_until=clock() + 600,
        idempotency_key="open-private",
    )
    assert case.subject_sha256 != digest(raw_subject)
    assert case.external_request_sha256 != digest(raw_request)
    assert raw_subject not in repr(case)
    assert raw_request not in repr(case)

    database_bytes = store.path.read_bytes()
    wal_path = Path(f"{store.path}-wal")
    if wal_path.exists():
        database_bytes += wal_path.read_bytes()
    for forbidden in (raw_subject, raw_request, literal_secret, "https://provider.example"):
        assert forbidden.encode() not in database_bytes


def test_identity_evidence_gate_and_access_vs_deletion_plans(authority) -> None:
    store, _actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    case = store.open_case(
        "tenant-a",
        "case-access",
        request_version=1,
        external_request_ref="request-access",
        subject_reference="subject-access",
        rights=["access"],
        retained_until=clock() + 600,
        idempotency_key="open-access",
    )
    with pytest.raises(rights.PrivacyRightsConflict, match="identity"):
        store.plan_source_tasks(
            "tenant-a",
            case.case_id,
            "crm",
            expected_case_revision=case.revision,
            idempotency_key="plan-before-identity",
        )
    with pytest.raises(rights.PrivacyRightsValidationError):
        store.set_identity_verification(
            "tenant-a",
            case.case_id,
            status="verified",
            evidence_sha256=None,
            evidence_ref=None,
            expected_revision=case.revision,
            idempotency_key="bad-identity",
        )
    verified = store.set_identity_verification(
        "tenant-a",
        case.case_id,
        status="verified",
        evidence_sha256=digest("identity"),
        evidence_ref="identity:receipt",
        expected_revision=case.revision,
        idempotency_key="identity",
    )
    access_tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        expected_case_revision=verified.revision,
        idempotency_key="plan-access",
    )
    assert {task.phase for task in access_tasks} == {"discover", "retrieve", "redact"}
    assert not any(task.destructive for task in access_tasks)

    deletion = open_verified(
        store, clock, "tenant-a", "case-delete", ["erasure"]
    )
    deletion_tasks = store.plan_source_tasks(
        "tenant-a",
        deletion.case_id,
        "crm",
        expected_case_revision=deletion.revision,
        idempotency_key="plan-delete",
    )
    assert {task.phase for task in deletion_tasks} == {
        "discover",
        "delete",
        "verify_delete",
    }
    assert task_by_phase(deletion_tasks, "delete").destructive is True
    with pytest.raises(rights.PrivacyRightsConflict):
        store.create_response_package(
            "tenant-a",
            deletion.case_id,
            "package-delete",
            object_ref="object:delete",
            package_sha256=digest("package"),
            encryption_key_ref="vault:package-key",
            expires_at=clock() + 60,
            expected_case_revision=deletion.revision + 1,
            idempotency_key="package-delete",
        )


def test_legal_hold_retention_and_four_eyes_block_destructive_dispatch(
    authority,
) -> None:
    store, actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    case = open_verified(store, clock, "tenant-a", "case-delete", ["erasure"])
    tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        expected_case_revision=case.revision,
        idempotency_key="plan",
    )
    delete_task = task_by_phase(tasks, "delete")

    with pytest.raises(rights.PrivacyRightsPermissionDenied, match="distinct"):
        store.approve_destructive_work(
            "tenant-a",
            delete_task.task_id,
            expected_revision=delete_task.revision,
            idempotency_key="self-approve",
        )

    case = store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=True,
        evidence_sha256=digest("hold"),
        evidence_ref="hold:1",
        expected_revision=case.revision + 1,
        idempotency_key="hold-on",
    )
    actor["value"] = "approver"
    with pytest.raises(rights.PrivacyRightsConflict, match="legal hold"):
        store.approve_destructive_work(
            "tenant-a",
            delete_task.task_id,
            expected_revision=delete_task.revision,
            idempotency_key="approve-on-hold",
        )
    case = store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=False,
        evidence_sha256=digest("hold-release"),
        evidence_ref="hold:release",
        expected_revision=case.revision,
        idempotency_key="hold-off",
    )
    case = store.set_retention_gate(
        "tenant-a",
        case.case_id,
        blocks_deletion=True,
        rule_ref="rule:retain",
        evidence_sha256=digest("retention"),
        expected_revision=case.revision,
        idempotency_key="retain-on",
    )
    with pytest.raises(rights.PrivacyRightsConflict, match="retention"):
        store.approve_destructive_work(
            "tenant-a",
            delete_task.task_id,
            expected_revision=delete_task.revision,
            idempotency_key="approve-retained",
        )
    case = store.set_retention_gate(
        "tenant-a",
        case.case_id,
        blocks_deletion=False,
        rule_ref="rule:released",
        evidence_sha256=digest("retention-release"),
        expected_revision=case.revision,
        idempotency_key="retain-off",
    )
    approved = store.approve_destructive_work(
        "tenant-a",
        delete_task.task_id,
        expected_revision=delete_task.revision,
        idempotency_key="approve-delete",
    )
    assert approved.approved_by == "approver"

    case = store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=True,
        evidence_sha256=digest("late-hold"),
        evidence_ref="hold:late",
        expected_revision=case.revision,
        idempotency_key="late-hold",
    )
    discover = task_by_phase(tasks, "discover")
    complete_callback_phase(
        store,
        "tenant-a",
        case.case_id,
        "crm",
        discover,
        suffix="delete-discover",
    )
    assert (
        store.claim_callbacks(
            "tenant-a",
            limit=10,
            lease_seconds=30,
            idempotency_key="claim-held-delete",
        )
        == ()
    )
    case = store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=False,
        evidence_sha256=digest("late-release"),
        evidence_ref="hold:late-release",
        expected_revision=case.revision,
        idempotency_key="late-release",
    )
    claimed = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=30,
        idempotency_key="claim-unheld-delete",
    )
    assert claimed[0].phase == "delete"


def test_callback_progress_survives_restart_and_does_not_starve_work_behind_holds(authority, monkeypatch, record_property):
    store, actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="fair-source")
    held_cases = []
    for index in range(11):
        clock.advance(1)
        actor["value"] = "planner"
        case = open_verified(store, clock, "tenant-a", f"fair-{index}", ["erasure"])
        task = store.plan_source_tasks(
            "tenant-a", case.case_id, "crm", phases=["delete"], max_attempts=3,
            expected_case_revision=case.revision, idempotency_key=f"plan-fair-{index}",
        )[0]
        actor["value"] = "approver"
        store.approve_destructive_work("tenant-a", task.task_id, expected_revision=task.revision,
                                       idempotency_key=f"approve-fair-{index}")
        if index < 10:
            case = store.get_case("tenant-a", case.case_id)
            held_cases.append(store.set_legal_hold(
                "tenant-a", case.case_id, active=True, evidence_sha256=digest(f"hold-{index}"),
                evidence_ref=f"hold:{index}", expected_revision=case.revision,
                idempotency_key=f"hold-fair-{index}",
            ))
    actor["value"] = "source-worker"
    original_ready = rights.PrivacyRightsOrchestrationStore._callback_ready
    scanned = []

    def count_ready(self, connection, tenant, callback):
        scanned.append(callback.callback_id)
        return original_ready(self, connection, tenant, callback)

    monkeypatch.setattr(rights.PrivacyRightsOrchestrationStore, "_callback_ready", count_ready)
    # Count real SQLite statements, including connection PRAGMAs, without
    # retaining their expanded arguments (which can contain protected data).
    sql_counts = Counter()
    native_connect = sqlite3.connect

    def traced_connect(*args, **kwargs):
        connection = native_connect(*args, **kwargs)
        connection.set_trace_callback(lambda statement: sql_counts.update(
            [statement.lstrip().split(None, 1)[0].upper()],
        ))
        return connection

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    start = time.perf_counter()
    assert store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, source_ids=["crm"],
                                 idempotency_key="fair-poll-1") == ()
    blocked_ms = (time.perf_counter() - start) * 1000
    blocked_sql = dict(sql_counts)
    assert len(scanned) == 10
    # Production request handlers may construct a store per call. Progress
    # must survive that boundary, not live only on one Python instance.
    reopened = rights.PrivacyRightsOrchestrationStore(
        store.path, config_gate=lambda: None, principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32, clock=clock,
    )
    sql_counts.clear()
    next_claim = reopened.claim_callbacks("tenant-a", limit=1, lease_seconds=30, source_ids=["crm"],
                                         idempotency_key="fair-poll-2")
    frontier_sql = dict(sql_counts)
    assert len(next_claim) == 1 and next_claim[0].case_id == "fair-10"
    assert len(scanned) == 11
    for index, case in enumerate(held_cases):
        reopened.set_legal_hold(
            "tenant-a", case.case_id, active=False, evidence_sha256=digest(f"release-{index}"),
            evidence_ref=f"release:{index}", expected_revision=case.revision,
            idempotency_key=f"release-fair-{index}",
        )
    released = []
    durations = []
    runnable_sql = []
    for index in range(10):
        sql_counts.clear()
        start = time.perf_counter()
        claimed = reopened.claim_callbacks("tenant-a", limit=1, lease_seconds=30, source_ids=["crm"],
                                           idempotency_key=f"released-poll-{index}")
        durations.append((time.perf_counter() - start) * 1000)
        runnable_sql.append(dict(sql_counts))
        assert len(claimed) == 1
        released.append(claimed[0].case_id)
    assert set(released) == {case.case_id for case in held_cases}
    assert len(scanned) == 21
    assert reopened.claim_callbacks("tenant-a", limit=1, lease_seconds=30, source_ids=["crm"],
                                    idempotency_key="all-leased") == ()
    record_property("blocked_candidates_examined", 10)
    record_property("eligible_candidate_found_on_poll", 2)
    record_property("released_candidates_examined", 10)
    record_property("held_page_ms", blocked_ms)
    record_property("runnable_claim_ms", durations)
    record_property("blocked_page_sql_statements", blocked_sql)
    record_property("eligible_frontier_sql_statements", frontier_sql)
    record_property("runnable_poll_sql_statements", runnable_sql)
    assert blocked_sql["BEGIN"] == blocked_sql["COMMIT"] == 1
    assert blocked_sql["SELECT"] > frontier_sql["SELECT"]
    assert all(counts["BEGIN"] == counts["COMMIT"] == 1 for counts in runnable_sql)
    assert all(counts["SELECT"] < blocked_sql["SELECT"] for counts in runnable_sql)


def test_callback_progress_is_source_scoped_and_rolled_back_with_claim_failure(authority, monkeypatch):
    from maverick.privacy_callback_scan import CallbackScan

    store, _actor, clock = authority
    for source in ("crm", "erp"):
        enroll_all(store, "tenant-a", source, key=f"scope-{source}")
        for index in range(12):
            case = open_verified(store, clock, "tenant-a", f"scope-{source}-{index}", ["access"])
            store.plan_source_tasks(
                "tenant-a", case.case_id, source, phases=["discover"], max_attempts=3,
                expected_case_revision=case.revision, idempotency_key=f"scope-plan-{source}-{index}",
            )
    save = CallbackScan.save

    def fail_after_cursor(self):
        save(self)
        raise RuntimeError("injected transaction failure")

    with monkeypatch.context() as scoped:
        scoped.setattr(CallbackScan, "save", fail_after_cursor)
        with pytest.raises(RuntimeError, match="injected"):
            store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, source_ids=["crm"],
                                  idempotency_key="scope-rollback")
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_callback_scan_progress").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM rights_callbacks WHERE state='leased'").fetchone()[0] == 0
    for source in ("crm", "erp"):
        result = store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, source_ids=[source],
                                       idempotency_key=f"scope-claim-{source}")
        assert len(result) == 1 and result[0].source_id == source
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_callback_scan_progress").fetchone()[0] == 2


def _seed_claim_history(store, created_at, count, prefix):
    with store._connect() as connection:
        store._begin(connection)
        for index in range(count):
            key = f"{prefix}-{index}"
            batch_id = "batch:" + hashlib.sha256(key.encode()).hexdigest()[:32]
            store._insert(
                connection, "rights_claim_batches", ("tenant_id", "batch_id", "created_at"),
                ("tenant-a", batch_id, created_at),
                {"tenant_id": "tenant-a", "batch_id": batch_id, "created_at": created_at, "callbacks": []},
            )
            store._record_operation(connection, "tenant-a", key, "f" * 64, "claim_batch", batch_id)


def test_claim_history_cleanup_visits_expired_rows_and_uses_index(authority, monkeypatch, record_property):
    store, _actor, clock = authority
    store._claim_history_retention_seconds = 60
    _seed_claim_history(store, clock(), 2000, "retained")
    _seed_claim_history(store, clock() - 61, 3, "expired")
    validated = []
    validate = store._claim_batch

    def counted(row, **kwargs):
        validated.append(row["batch_id"])
        return validate(row, **kwargs)

    monkeypatch.setattr(store, "_claim_batch", counted)
    assert store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, idempotency_key="history-scan") == ()
    assert len(validated) == 3
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_claim_batches").fetchone()[0] == 2000
        assert connection.execute("SELECT COUNT(*) FROM rights_operations WHERE result_kind='claim_batch'").fetchone()[0] == 2000
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM rights_claim_batches WHERE tenant_id=? AND created_at<=? "
            "ORDER BY created_at,batch_id LIMIT ?", ("tenant-a", clock() - 60, 128),
        ).fetchall()
    assert any("rights_claim_expiry" in row[-1] for row in plan)
    record_property("retained_receipts", 2000)
    record_property("expired_receipts_validated", len(validated))
    record_property("expiry_query_plan", [row[-1] for row in plan])


def test_claim_history_expiry_prevents_replay_before_cleanup_reaches_the_receipt(authority):
    store, _actor, clock = authority
    store._claim_history_retention_seconds = 60
    enroll_all(store, "tenant-a", "crm", key="expiry-source")
    case = open_verified(store, clock, "tenant-a", "expiry-case", ["access"])
    store.plan_source_tasks("tenant-a", case.case_id, "crm", phases=["discover"], max_attempts=3,
                            expected_case_revision=case.revision, idempotency_key="expiry-plan")
    original = store.claim_callbacks("tenant-a", limit=1, lease_seconds=300, idempotency_key="expiry-target")
    assert len(original) == 1
    _seed_claim_history(store, clock() - 10, 200, "older-history")
    clock.advance(61)
    assert store.claim_callbacks("tenant-a", limit=1, lease_seconds=300, idempotency_key="expiry-target") == ()
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_claim_batches").fetchone()[0] == 72
        # The active lease survives history cleanup and is not reissued.
        assert connection.execute("SELECT state,lease_until FROM rights_callbacks").fetchone() == (
            "leased", clock() + 239,
        )


def test_claim_history_paired_cleanup_rolls_back_and_rejects_tampered_projection(authority):
    store, _actor, clock = authority
    store._claim_history_retention_seconds = 60
    _seed_claim_history(store, clock() - 61, 1, "rollback-history")
    with sqlite3.connect(store.path) as connection:
        connection.execute("CREATE TRIGGER fail_receipt_delete BEFORE DELETE ON rights_claim_batches "
                           "BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, idempotency_key="rollback-poll")
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rights_claim_batches").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM rights_operations WHERE result_kind='claim_batch'").fetchone()[0] == 1
        connection.execute("DROP TRIGGER fail_receipt_delete")
        connection.execute("UPDATE rights_claim_batches SET created_at=1")
    with pytest.raises(rights.PrivacyRightsIntegrityError, match="time/binding"):
        store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, idempotency_key="tampered-poll")
    with pytest.raises(rights.PrivacyRightsIntegrityError, match="time/binding"):
        store.verify_integrity("tenant-a")


def test_claim_history_v1_migration_is_atomic_and_validates_existing_receipts(authority):
    store, actor, clock = authority
    _seed_claim_history(store, clock(), 4, "legacy-history")
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP INDEX rights_claim_expiry")
        connection.execute("DROP INDEX rights_operation_result")
        connection.execute("DROP TRIGGER rights_claim_created_required")
        connection.execute("ALTER TABLE rights_claim_batches DROP COLUMN created_at")
        connection.execute("UPDATE metadata SET value='1' WHERE key='schema_version'")
        connection.execute("CREATE TRIGGER fail_migration BEFORE UPDATE ON rights_claim_batches "
                           "BEGIN SELECT RAISE(ABORT,'injected migration failure'); END")

    def reopen():
        return rights.PrivacyRightsOrchestrationStore(
            store.path, config_gate=lambda: None, principal_resolver=lambda: actor["value"],
            digest_key_resolver=lambda _tenant: b"k" * 32, clock=clock,
        )

    with pytest.raises(sqlite3.IntegrityError, match="injected migration"):
        reopen()
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] == "1"
        assert "created_at" not in {row[1] for row in connection.execute("PRAGMA table_info(rights_claim_batches)")}
        connection.execute("DROP TRIGGER fail_migration")
    migrated = reopen()
    assert migrated.verify_integrity("tenant-a").verified_records == 8
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] == "2"
        assert connection.execute("SELECT DISTINCT created_at FROM rights_claim_batches").fetchall() == [(clock(),)]
    assert reopen().verify_integrity("tenant-a").verified_records == 8


@pytest.mark.parametrize("created_at", [None, "malformed", float("inf"), -1])
def test_claim_history_malformed_projection_is_rejected_on_lookup(authority, created_at):
    store, _actor, clock = authority
    _seed_claim_history(store, clock(), 1, "invalid-time")
    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE rights_claim_batches SET created_at=?", (created_at,))
    with pytest.raises(rights.PrivacyRightsIntegrityError, match="time/binding"):
        store.claim_callbacks("tenant-a", limit=1, lease_seconds=30, idempotency_key="invalid-time-0")


def test_claim_history_legacy_insert_cannot_silently_escape_the_expiry_index(authority):
    store, _actor, _clock = authority
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="created_at projection"):
            connection.execute(
                "INSERT INTO rights_claim_batches(tenant_id,batch_id,payload_json,integrity_sha256) VALUES(?,?,?,?)",
                ("tenant-a", "old-writer", "{}", "f" * 64),
            )


def test_default_lease_token_accepts_urlsafe_leading_symbols(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(rights.secrets, "token_urlsafe", lambda _size: "_leading-token")
    actor = {"value": "operator"}
    clock = MutableClock()
    store = rights.PrivacyRightsOrchestrationStore(
        tmp_path / "default-token.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        digest_key_resolver=lambda _tenant: b"k" * 32,
        clock=clock,
    )
    enroll_all(store, "tenant-a", "crm", key="source-default-token")
    case = open_verified(store, clock, "tenant-a", "case-default-token", ["access"])
    store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        phases=["discover"],
        max_attempts=2,
        expected_case_revision=case.revision,
        idempotency_key="plan-default-token",
    )

    claimed = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-default-token",
    )

    assert claimed[0].lease_token == "lease:_leading-token"


def test_callback_lease_recovery_dead_letter_requeue_and_ack(authority) -> None:
    store, _actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    case = open_verified(store, clock, "tenant-a", "case-retry", ["access"])
    tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        phases=["discover"],
        max_attempts=2,
        expected_case_revision=case.revision,
        idempotency_key="plan",
    )
    first = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-1",
    )[0]
    assert first.state == "leased"
    exported_while_leased = store.export_case(
        "tenant-a",
        case.case_id,
        "export:no-lease-token",
        retained_until=clock() + 120,
        idempotency_key="export-no-lease-token",
    )
    assert first.lease_token not in repr(exported_while_leased)
    assert "callbacks" not in exported_while_leased.body
    assert store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-1",
    ) == (first,)

    clock.advance(11)
    recovered = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-recovery",
    )[0]
    assert recovered.recovery_count == 1
    assert recovered.lease_token != first.lease_token
    failed = store.fail_callback(
        "tenant-a",
        recovered.callback_id,
        lease_token=recovered.lease_token or "",
        error_code="provider_unavailable",
        retry_delay_seconds=0,
        expected_revision=recovered.revision,
        idempotency_key="fail-1",
    )
    assert failed.state == "pending"
    second = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-2",
    )[0]
    dead = store.fail_callback(
        "tenant-a",
        second.callback_id,
        lease_token=second.lease_token or "",
        error_code="provider_unavailable",
        retry_delay_seconds=0,
        expected_revision=second.revision,
        idempotency_key="fail-2",
    )
    assert dead.state == "dead_letter"
    requeued = store.requeue_callback(
        "tenant-a",
        dead.callback_id,
        expected_revision=dead.revision,
        idempotency_key="requeue",
    )
    assert requeued.state == "pending"
    assert requeued.attempts == 0
    final_claim = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-final",
    )[0]
    acked = store.ack_callback(
        "tenant-a",
        final_claim.callback_id,
        lease_token=final_claim.lease_token or "",
        acknowledgement_sha256=digest("ack"),
        acknowledgement_ref="ack:final",
        expected_revision=final_claim.revision,
        idempotency_key="ack-final",
    )
    assert acked.state == "acked"
    receipt = store.record_source_evidence(
        "tenant-a",
        case.case_id,
        "crm",
        "discover",
        evidence_id="evidence:final",
        status="complete",
        provider_evidence_sha256=digest("provider-receipt"),
        record_count=1,
        opaque_ref="provider:final",
        expected_task_revision=tasks[0].revision,
        idempotency_key="evidence-final",
    )
    assert receipt.provider_evidence_sha256 == digest("provider-receipt")


def test_ambiguous_provider_outcome_requires_exact_reconciliation(authority) -> None:
    store, _actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source-ambiguous")
    case = open_verified(store, clock, "tenant-a", "case-ambiguous", ["access"])
    task = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        phases=["discover"],
        max_attempts=3,
        expected_case_revision=case.revision,
        idempotency_key="plan-ambiguous",
    )[0]
    assert store.get_task("tenant-a", task.task_id) == task

    claimed = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-ambiguous-1",
    )[0]
    ambiguous = store.mark_callback_ambiguous(
        "tenant-a",
        claimed.callback_id,
        lease_token=claimed.lease_token or "",
        operation_sha256=digest("provider-operation-1"),
        operation_ref="provider-op:1",
        error_code="provider_outcome_unknown",
        expected_revision=claimed.revision,
        idempotency_key="ambiguous-1",
    )
    assert ambiguous.state == "ambiguous"
    assert ambiguous.ambiguous_operation_sha256 == digest("provider-operation-1")
    assert ambiguous.lease_token is None
    assert store.list_callbacks("tenant-a", state="ambiguous") == (ambiguous,)
    assert store.list_callbacks("tenant-a", limit=1) == (ambiguous,)

    clock.advance(30)
    assert (
        store.claim_callbacks(
            "tenant-a",
            limit=1,
            lease_seconds=10,
            idempotency_key="claim-must-not-replay",
        )
        == ()
    )

    unknown = store.reconcile_ambiguous_callback(
        "tenant-a",
        ambiguous.callback_id,
        disposition="unknown",
        provider_evidence_sha256=digest("reconcile-unknown"),
        provider_evidence_ref="reconcile:unknown",
        retry_delay_seconds=0,
        expected_revision=ambiguous.revision,
        idempotency_key="reconcile-unknown",
    )
    assert unknown.state == "ambiguous"
    assert unknown.ambiguous_operation_sha256 == digest("reconcile-unknown")

    absent = store.reconcile_ambiguous_callback(
        "tenant-a",
        ambiguous.callback_id,
        disposition="absent",
        provider_evidence_sha256=digest("reconcile-absent"),
        provider_evidence_ref="reconcile:absent",
        retry_delay_seconds=5,
        expected_revision=unknown.revision,
        idempotency_key="reconcile-absent",
    )
    assert absent.state == "pending"
    assert absent.ambiguous_operation_sha256 is None
    assert (
        store.claim_callbacks(
            "tenant-a",
            limit=1,
            lease_seconds=10,
            idempotency_key="claim-before-backoff",
        )
        == ()
    )

    clock.advance(5)
    retried = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=10,
        idempotency_key="claim-after-reconciliation",
    )[0]
    second_ambiguous = store.mark_callback_ambiguous(
        "tenant-a",
        retried.callback_id,
        lease_token=retried.lease_token or "",
        operation_sha256=digest("provider-operation-2"),
        operation_ref="provider-op:2",
        error_code="provider_outcome_unknown",
        expected_revision=retried.revision,
        idempotency_key="ambiguous-2",
    )
    applied = store.reconcile_ambiguous_callback(
        "tenant-a",
        retried.callback_id,
        disposition="applied",
        provider_evidence_sha256=digest("reconcile-applied"),
        provider_evidence_ref="reconcile:applied",
        retry_delay_seconds=0,
        expected_revision=second_ambiguous.revision,
        idempotency_key="reconcile-applied",
    )
    assert applied.state == "acked"
    assert applied.acknowledgement_sha256 == digest("reconcile-applied")
    assert applied.ambiguous_at is None
    completed_task = store.get_task("tenant-a", task.task_id)
    assert completed_task.state == "complete"
    assert completed_task.evidence_id is not None
    assert store.list_callbacks("tenant-a", state="ambiguous") == ()


def test_provider_callback_and_evidence_complete_atomically(authority) -> None:
    store, _actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source-atomic")
    case = open_verified(store, clock, "tenant-a", "case-atomic", ["access"])
    task = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        phases=["discover"],
        expected_case_revision=case.revision,
        idempotency_key="plan-atomic",
    )[0]
    claimed = store.claim_callbacks(
        "tenant-a",
        limit=1,
        lease_seconds=30,
        idempotency_key="claim-atomic",
    )[0]

    callback, evidence = store.complete_callback(
        "tenant-a",
        claimed.callback_id,
        lease_token=claimed.lease_token or "",
        acknowledgement_sha256=digest("atomic-ack"),
        acknowledgement_ref="provider:atomic-ack",
        evidence_status="complete",
        provider_evidence_sha256=digest("atomic-evidence"),
        record_count=2,
        opaque_ref="provider:atomic-evidence",
        expected_revision=claimed.revision,
        idempotency_key="complete-atomic",
    )
    assert callback.state == "acked"
    assert evidence.evidence_id.startswith("evidence:")
    completed_task = store.get_task("tenant-a", task.task_id)
    assert completed_task.state == "complete"
    assert completed_task.evidence_id == evidence.evidence_id

    replay = store.complete_callback(
        "tenant-a",
        claimed.callback_id,
        lease_token=claimed.lease_token or "",
        acknowledgement_sha256=digest("atomic-ack"),
        acknowledgement_ref="provider:atomic-ack",
        evidence_status="complete",
        provider_evidence_sha256=digest("atomic-evidence"),
        record_count=2,
        opaque_ref="provider:atomic-evidence",
        expected_revision=claimed.revision,
        idempotency_key="complete-atomic",
    )
    assert replay == (callback, evidence)
    assert store.verify_integrity("tenant-a").verified_records > 0


def test_completeness_manifest_names_enrolled_covered_and_uncovered(authority) -> None:
    store, _actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="crm")
    enroll_all(store, "tenant-a", "archive", key="archive")
    case = open_verified(store, clock, "tenant-a", "case-coverage", ["access"])
    tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        phases=["discover"],
        expected_case_revision=case.revision,
        idempotency_key="plan-crm",
    )
    complete_callback_phase(
        store,
        "tenant-a",
        case.case_id,
        "crm",
        tasks[0],
        suffix="coverage",
    )
    manifest = store.build_completeness_manifest(
        "tenant-a",
        case.case_id,
        "manifest:coverage",
        expected_case_revision=case.revision + 1,
        idempotency_key="manifest",
    )
    assert manifest.enrolled_source_ids == ("archive", "crm")
    assert manifest.covered_source_ids == ("crm",)
    assert manifest.uncovered_sources == (
        {"source_id": "archive", "reason": "not_planned"},
    )
    assert manifest.estate_completeness_claimed is False
    assert "does not discover or infer" in manifest.limitation


def test_access_package_closure_four_eyes_export_integrity_and_purge(authority) -> None:
    store, actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    case = open_verified(store, clock, "tenant-a", "case-complete", ["access"])
    tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        expected_case_revision=case.revision,
        idempotency_key="plan",
    )
    complete_callback_phase(
        store,
        "tenant-a",
        case.case_id,
        "crm",
        task_by_phase(tasks, "discover"),
        suffix="complete-discover",
    )
    complete_callback_phase(
        store,
        "tenant-a",
        case.case_id,
        "crm",
        task_by_phase(tasks, "retrieve"),
        suffix="complete-retrieve",
    )
    complete_local_phase(
        store,
        "tenant-a",
        case.case_id,
        "crm",
        task_by_phase(tasks, "redact"),
        suffix="complete-redact",
    )
    manifest = store.build_completeness_manifest(
        "tenant-a",
        case.case_id,
        "manifest:complete",
        expected_case_revision=case.revision + 1,
        idempotency_key="manifest",
    )
    assert manifest.covered_source_ids == ("crm",)
    package = store.create_response_package(
        "tenant-a",
        case.case_id,
        "package:complete",
        object_ref="encrypted-object:complete",
        package_sha256=digest("package"),
        encryption_key_ref="vault:response-key",
        expires_at=clock() + 60,
        expected_case_revision=case.revision + 2,
        idempotency_key="package",
    )
    assert package.delivery_performed is False
    assert store.get_response_package("tenant-a", package.package_id) == package
    exported = store.export_case(
        "tenant-a",
        case.case_id,
        "export:complete",
        retained_until=clock() + 90,
        idempotency_key="export",
    )
    assert exported.body["limitations"]["provider_operations_performed"] is False

    actor["value"] = "operator"
    with pytest.raises(rights.PrivacyRightsPermissionDenied, match="distinct"):
        store.approve_case_closure(
            "tenant-a",
            case.case_id,
            expected_revision=case.revision + 3,
            idempotency_key="self-closure-approval",
        )
    actor["value"] = "closure-approver"
    approved = store.approve_case_closure(
        "tenant-a",
        case.case_id,
        expected_revision=case.revision + 3,
        idempotency_key="closure-approval",
    )
    actor["value"] = "operator"
    closed = store.close_case(
        "tenant-a",
        case.case_id,
        expected_revision=approved.revision,
        idempotency_key="close",
    )
    assert closed.status == "closed"
    verification = store.verify_integrity("tenant-a")
    assert verification.verified_records > 0
    assert verification.audit_events > 0

    # A hold placed after closure must keep the closed case out of the purge.
    with pytest.raises(rights.PrivacyRightsConflict, match="not open"):
        store.set_identity_verification(
            "tenant-a",
            case.case_id,
            status="pending",
            evidence_sha256=None,
            evidence_ref=None,
            expected_revision=closed.revision,
            idempotency_key="identity-after-close",
        )
    held = store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=True,
        evidence_sha256=digest("hold"),
        evidence_ref="hold:closed",
        expected_revision=closed.revision,
        idempotency_key="hold-after-close",
    )
    assert held.status == "closed"
    assert held.closure_approved_by == "closure-approver"

    clock.advance(601)
    assert store.purge_expired(
        "tenant-a", cutoff=clock(), idempotency_key="purge-held"
    ) == {"packages": 1, "exports": 1, "cases": 0}
    store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=False,
        evidence_sha256=digest("release"),
        evidence_ref="hold:released",
        expected_revision=held.revision,
        idempotency_key="hold-release-after-close",
    )
    purged = store.purge_expired(
        "tenant-a", cutoff=clock(), idempotency_key="purge"
    )
    assert purged == {"packages": 0, "exports": 0, "cases": 1}
    with pytest.raises(rights.PrivacyRightsNotFound):
        store.get_case("tenant-a", case.case_id)
    store.verify_integrity("tenant-a")


def test_closure_is_refused_until_every_required_phase_is_planned(authority) -> None:
    store, actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    case = open_verified(store, clock, "tenant-a", "case-partial", ["erasure"])
    tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        phases=["discover"],
        expected_case_revision=case.revision,
        idempotency_key="plan",
    )
    complete_callback_phase(
        store, "tenant-a", case.case_id, "crm", tasks[0], suffix="partial"
    )
    store.build_completeness_manifest(
        "tenant-a",
        case.case_id,
        "manifest:partial",
        expected_case_revision=case.revision + 1,
        idempotency_key="manifest",
    )
    actor["value"] = "closure-approver"
    with pytest.raises(rights.PrivacyRightsConflict, match="every phase"):
        store.approve_case_closure(
            "tenant-a",
            case.case_id,
            expected_revision=case.revision + 2,
            idempotency_key="closure-approval",
        )
    assert store.get_case("tenant-a", case.case_id).closure_approved_by is None


def test_integrity_verification_detects_tampering(authority) -> None:
    store, _actor, _clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    store.verify_integrity("tenant-a")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE rights_sources SET payload_json=? "
            "WHERE tenant_id=? AND source_id=?",
            ('{"tenant_id":"tenant-a"}', "tenant-a", "crm"),
        )
    with pytest.raises(rights.PrivacyRightsIntegrityError):
        store.verify_integrity("tenant-a")


def test_integrity_verification_is_strictly_tenant_scoped(authority) -> None:
    store, _actor, _clock = authority
    enroll_all(store, "tenant-a", "crm-a", key="source-a")
    enroll_all(store, "tenant-b", "crm-b", key="source-b")
    before = store.verify_integrity("tenant-a")
    tenant_b_before = store.verify_integrity("tenant-b")
    assert before.verified_records == tenant_b_before.verified_records

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE rights_sources SET payload_json=? "
            "WHERE tenant_id=? AND source_id=?",
            ('{"tenant_id":"tenant-b"}', "tenant-b", "crm-b"),
        )

    after = store.verify_integrity("tenant-a")
    assert after == before
    with pytest.raises(rights.PrivacyRightsIntegrityError):
        store.verify_integrity("tenant-b")


def test_product_boundaries_make_no_provider_or_completeness_claim() -> None:
    boundaries = rights.PrivacyRightsOrchestrationStore.product_boundaries()
    assert boundaries == {
        "provider_neutral": True,
        "network_io": False,
        "provider_writes": False,
        "identity_verification_performed": False,
        "response_delivery_performed": False,
        "raw_subject_persisted": False,
        "raw_external_request_ref_persisted": False,
        "credential_values_persisted": False,
        "provider_origins_persisted": False,
        "estate_completeness_claimed": False,
        "live_provider_acceptance_verified": False,
    }


def _record_connections(monkeypatch) -> list[sqlite3.Connection]:
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", recording_connect)
    return opened


def test_hold_refusal_closes_every_ledger_connection(authority, monkeypatch) -> None:
    """The destructive-approval gate reads the legal hold through a ledger connection
    that must be closed on refusal, not only committed (Windows keeps it locked)."""
    store, actor, clock = authority
    enroll_all(store, "tenant-a", "crm", key="source")
    case = open_verified(store, clock, "tenant-a", "case-delete", ["erasure"])
    tasks = store.plan_source_tasks(
        "tenant-a",
        case.case_id,
        "crm",
        expected_case_revision=case.revision,
        idempotency_key="plan",
    )
    delete_task = task_by_phase(tasks, "delete")
    store.set_legal_hold(
        "tenant-a",
        case.case_id,
        active=True,
        evidence_sha256=digest("hold"),
        evidence_ref="hold:1",
        expected_revision=case.revision + 1,
        idempotency_key="hold-on",
    )
    actor["value"] = "approver"
    opened = _record_connections(monkeypatch)
    try:
        with pytest.raises(rights.PrivacyRightsConflict, match="legal hold"):
            store.approve_destructive_work(
                "tenant-a",
                delete_task.task_id,
                expected_revision=delete_task.revision,
                idempotency_key="approve-on-hold",
            )
        assert opened, "the approval gate should read the ledger"
        for connection in opened:
            with pytest.raises(sqlite3.ProgrammingError):  # a closed connection refuses work
                connection.execute("SELECT 1")
    finally:
        for connection in opened:
            connection.close()
