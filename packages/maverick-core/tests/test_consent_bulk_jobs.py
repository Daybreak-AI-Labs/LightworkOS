from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest
from maverick.consent_bulk_jobs import (
    ConsentBulkJobConflict,
    ConsentBulkJobError,
    ConsentBulkJobLimits,
    ConsentBulkJobStore,
    ConsentBulkJobValidationError,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _ids() -> Callable[[str], str]:
    counter = 0

    def factory(prefix: str) -> str:
        nonlocal counter
        counter += 1
        return f"{prefix}-{counter:08d}"

    return factory


def _store(tmp_path: Path, now: list[float], **limits: int) -> ConsentBulkJobStore:
    return ConsentBulkJobStore(
        tmp_path / "bulk.sqlite3",
        clock=lambda: now[0],
        id_factory=_ids(),
        limits=ConsentBulkJobLimits(**limits),
    )


def _export_items(*profiles: str) -> list[dict[str, object]]:
    return [
        {"item_id": f"item-{index}", "profile_id": profile, "receipt_limit": 500}
        for index, profile in enumerate(profiles, 1)
    ]


def test_export_job_has_progress_download_and_credit_lifecycle(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=10)
    created = store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=_export_items("profile-a", "profile-b"),
        actor_sha256=_digest("operator"),
        scheduled_for=None,
        idempotency_key="export-request-0001",
    )
    assert created["state"] == "queued"
    assert created["progress_percent"] == 0.0
    assert store.credit_detail("tenant-a") == {
        "available": 8,
        "reserved": 2,
        "consumed": 0,
        "revision": 2,
        "updated_at": now[0],
    }

    first = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker"),
        executor=lambda operation, item: {
            "operation": operation,
            "profile_id": item["profile_id"],
            "receipts": [{"receipt_id": f"r-{item['profile_id']}"}],
        },
        batch_size=1,
    )
    assert first["state"] == "running"
    assert first["progress_percent"] == 50.0

    finished = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker"),
        executor=lambda operation, item: {
            "operation": operation,
            "profile_id": item["profile_id"],
            "receipts": [{"receipt_id": f"r-{item['profile_id']}"}],
        },
        batch_size=10,
    )
    assert finished["state"] == "succeeded"
    assert finished["progress_percent"] == 100.0
    artifact = store.download_artifact("tenant-a", created["job_id"])
    assert artifact["schema"] == "lightwork.consent-bulk-export.v1"
    assert artifact["item_count"] == 2
    assert artifact["artifact_sha256"] == finished["artifact_sha256"]
    assert store.credit_detail("tenant-a")["consumed"] == 2
    assert store.credit_detail("tenant-a")["reserved"] == 0
    assert store.verify_integrity("tenant-a")["integrity_valid"] is True


def test_exact_final_batch_transitions_job_to_terminal_state(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=2)
    created = store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=_export_items("profile-a", "profile-b"),
        actor_sha256=_digest("operator"),
        scheduled_for=None,
        idempotency_key="export-exact-batch-0001",
    )

    finished = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker"),
        executor=lambda _operation, item: {"profile_id": item["profile_id"]},
        batch_size=2,
    )

    assert finished["state"] == "succeeded"
    assert finished["progress_percent"] == 100.0


def test_create_is_idempotent_and_rebinding_is_rejected(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=3)
    kwargs = {
        "kind": "export",
        "operation": "export_receipts",
        "items": _export_items("profile-a"),
        "actor_sha256": _digest("operator"),
        "scheduled_for": None,
        "idempotency_key": "export-request-0002",
    }
    first = store.create_job("tenant-a", **kwargs)
    now[0] += 60
    replay = store.create_job("tenant-a", **kwargs)
    assert replay == first
    assert store.created_job_for_request("tenant-a", idempotency_key=kwargs["idempotency_key"],
                                         actor_sha256=kwargs["actor_sha256"]) == first
    assert store.created_job_for_request("tenant-a", idempotency_key=kwargs["idempotency_key"],
                                         actor_sha256=_digest("another operator")) is None
    assert store.created_job_for_request("tenant-b", idempotency_key=kwargs["idempotency_key"],
                                         actor_sha256=kwargs["actor_sha256"]) is None
    assert store.credit_detail("tenant-a")["reserved"] == 1
    with pytest.raises(ConsentBulkJobConflict, match="different content"):
        store.create_job(
            "tenant-a",
            **{**kwargs, "items": _export_items("profile-b")},
        )


def test_non_ascii_stored_digests_are_refused_not_type_errors(tmp_path: Path) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest instead
    # of the store's idempotency conflict and integrity refusals.
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=2)
    kwargs = {
        "kind": "export",
        "operation": "export_receipts",
        "items": _export_items("profile-a"),
        "actor_sha256": _digest("operator"),
        "scheduled_for": None,
        "idempotency_key": "export-request-non-ascii",
    }
    store.create_job("tenant-a", **kwargs)
    with sqlite3.connect(store.path) as connection:
        connection.execute("DROP TRIGGER consent_bulk_idempotency_no_update")
        connection.execute("DROP TRIGGER consent_bulk_events_no_update")
        connection.execute("UPDATE consent_bulk_idempotency SET request_sha256=?", ("é" * 64,))
        connection.execute("UPDATE consent_bulk_events SET event_sha256=?", ("é" * 64,))
    with pytest.raises(ConsentBulkJobConflict, match="different content"):
        store.create_job("tenant-a", **kwargs)
    with pytest.raises(ConsentBulkJobError, match="event integrity"):
        store.verify_integrity("tenant-a")


def test_queued_cancel_refunds_and_terminal_cancel_is_rejected(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=2)
    created = store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=_export_items("profile-a", "profile-b"),
        actor_sha256=_digest("operator"),
        scheduled_for=None,
        idempotency_key="export-request-0003",
    )
    cancelled = store.cancel_job(
        "tenant-a",
        created["job_id"],
        expected_revision=created["revision"],
        idempotency_key="cancel-request-0001",
    )
    assert cancelled["state"] == "cancelled"
    assert cancelled["credits_refunded"] == 2
    assert store.credit_detail("tenant-a")["available"] == 2
    with pytest.raises(ConsentBulkJobConflict, match="terminal"):
        store.cancel_job(
            "tenant-a",
            created["job_id"],
            expected_revision=cancelled["revision"],
            idempotency_key="cancel-request-0002",
        )


def test_failed_item_uses_closed_error_and_never_persists_message(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=1)
    created = store.create_job(
        "tenant-a",
        kind="mutation",
        operation="delete_subject",
        items=[
            {
                "item_id": "delete-1",
                "profile_id": "profile-a",
                "expected_revision": 3,
                "reason_code": "verified-erasure",
            }
        ],
        actor_sha256=_digest("operator"),
        scheduled_for=None,
        idempotency_key="mutation-request-0001",
    )

    def fail(_operation: str, _item: object) -> dict[str, object]:
        raise RuntimeError("secret provider detail must never persist")

    result = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker"),
        executor=fail,
    )
    assert result["state"] == "failed"
    history = store.history("tenant-a", created["job_id"], limit=100)
    serialized = repr(history)
    assert "secret provider detail" not in serialized
    assert "worker_failure" in serialized


def test_scheduling_lease_recovery_and_resume(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now, lease_seconds=5)
    store.ensure_credit_account("tenant-a", initial_credits=2)
    created = store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=_export_items("profile-a", "profile-b"),
        actor_sha256=_digest("operator"),
        scheduled_for=now[0] + 10,
        idempotency_key="export-request-0004",
    )
    with pytest.raises(ConsentBulkJobConflict, match="not scheduled"):
        store.run_job(
            "tenant-a",
            created["job_id"],
            worker_sha256=_digest("worker-a"),
            executor=lambda _operation, item: dict(item),
        )
    now[0] += 10
    running = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker-a"),
        executor=lambda _operation, item: dict(item),
        batch_size=1,
    )
    assert running["state"] == "running"
    now[0] += 6
    recovered = store.recover_expired_leases("tenant-a")
    assert recovered["recovered_job_ids"] == [created["job_id"]]
    finished = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker-b"),
        executor=lambda _operation, item: dict(item),
        batch_size=10,
    )
    assert finished["state"] == "succeeded"


def test_closed_item_contract_and_credit_quota(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=1)
    with pytest.raises(ConsentBulkJobValidationError, match="shape"):
        store.create_job(
            "tenant-a",
            kind="export",
            operation="export_receipts",
            items=[
                {
                    "item_id": "item-1",
                    "profile_id": "profile-a",
                    "raw_email": "forbidden@example.test",
                }
            ],
            actor_sha256=_digest("operator"),
            scheduled_for=None,
            idempotency_key="export-request-0005",
        )
    with pytest.raises(ConsentBulkJobConflict, match="credits"):
        store.create_job(
            "tenant-a",
            kind="export",
            operation="export_receipts",
            items=_export_items("profile-a", "profile-b"),
            actor_sha256=_digest("operator"),
            scheduled_for=None,
            idempotency_key="export-request-0006",
        )


@pytest.mark.parametrize("receipt_limit", [0, 501, 100_000, True])
def test_unsupported_export_size_is_rejected_before_job_or_credit_reservation(
    tmp_path: Path, receipt_limit: object,
) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=1)
    before = store.credit_detail("tenant-a")

    with pytest.raises(ConsentBulkJobValidationError, match="receipt_limit"):
        store.create_job(
            "tenant-a",
            kind="export",
            operation="export_receipts",
            items=[{
                "item_id": "export-too-wide",
                "profile_id": "profile-a",
                "receipt_limit": receipt_limit,
            }],
            actor_sha256=_digest("operator"),
            scheduled_for=None,
            idempotency_key="unsupported-export-size",
        )

    assert store.list_jobs("tenant-a")["jobs"] == []
    assert store.credit_detail("tenant-a") == before


def test_unsupported_export_position_is_rejected_before_job_or_credit_reservation(
    tmp_path: Path,
) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=1)
    before = store.credit_detail("tenant-a")

    with pytest.raises(ConsentBulkJobValidationError, match="saved position"):
        store.create_job(
            "tenant-a",
            kind="export",
            operation="export_receipts",
            items=[{
                "item_id": "export-position",
                "profile_id": "profile-a",
                "after_sequence": 0,
            }],
            actor_sha256=_digest("operator"),
            scheduled_for=None,
            idempotency_key="unsupported-export-position",
        )

    assert store.list_jobs("tenant-a")["jobs"] == []
    assert store.credit_detail("tenant-a") == before


def test_receipt_reactivation_has_a_closed_lifecycle_item_contract(tmp_path: Path) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now)
    store.ensure_credit_account("tenant-a", initial_credits=2)
    created = store.create_job(
        "tenant-a",
        kind="mutation",
        operation="reactivate",
        items=[
            {
                "item_id": "reactivate-1",
                "profile_id": "profile-a",
                "receipt_id": "receipt-a",
                "reactivation_at": now[0] + 3_600,
                "expected_revision": 4,
            }
        ],
        actor_sha256=_digest("operator"),
        scheduled_for=None,
        idempotency_key="reactivate-request-0001",
    )
    assert created["operation"] == "reactivate"

    with pytest.raises(ConsentBulkJobValidationError, match="shape"):
        store.create_job(
            "tenant-a",
            kind="mutation",
            operation="reactivate",
            items=[
                {
                    "item_id": "reactivate-2",
                    "profile_id": "profile-a",
                    "expected_revision": 4,
                    "policy_id": "old-edit-shape",
                    "policy_version": 1,
                    "context": {},
                    "choices": [],
                }
            ],
            actor_sha256=_digest("operator"),
            scheduled_for=None,
            idempotency_key="reactivate-request-0002",
        )


def test_oversized_combined_export_fails_terminally_instead_of_stranding_lease(
    tmp_path: Path,
) -> None:
    now = [1_800_000_000.0]
    store = _store(tmp_path, now, max_artifact_bytes=1_024)
    store.ensure_credit_account("tenant-a", initial_credits=1)
    created = store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=_export_items("profile-a"),
        actor_sha256=_digest("operator"),
        scheduled_for=None,
        idempotency_key="oversized-export-0001",
    )

    finished = store.run_job(
        "tenant-a",
        created["job_id"],
        worker_sha256=_digest("worker"),
        executor=lambda _operation, _item: {"payload": "x" * 2_000},
    )

    assert finished["state"] == "failed"
    assert finished["completed_at"] == now[0]
    history = store.history("tenant-a", created["job_id"], limit=100)
    assert "artifact_too_large" in repr(history)
