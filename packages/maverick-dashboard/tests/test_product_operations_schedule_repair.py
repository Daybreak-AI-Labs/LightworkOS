"""Reviewed recurrence repair invokes the native service and exact durable receipt."""
import pytest
from fastapi import HTTPException
from maverick.job_queue import JobQueue
from maverick_dashboard import draft_api, schedule_ops_api
from maverick_dashboard import product_operations_connections as operations
from starlette.requests import Request


@pytest.fixture
def parked(tmp_path, monkeypatch):
    from maverick import job_queue
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(job_queue, "DEFAULT_DB", tmp_path / "jobs.db")
    monkeypatch.setattr(operations, "require_permission", lambda *args: None)
    monkeypatch.setattr(schedule_ops_api, "require_permission", lambda *args: None)
    monkeypatch.setattr(operations, "caller_principal", lambda *args: "user:admin")
    monkeypatch.setattr(schedule_ops_api, "caller_principal", lambda *args: "user:admin")
    monkeypatch.setattr(draft_api, "context_for", lambda *args: "a" * 64)
    queue = JobQueue()
    first = queue.enqueue("noop", {"__cron__": "* * * * *", "owner": "user:owner"}, run_at=100)
    with queue._conn() as connection:
        connection.execute("UPDATE jobs SET status='failed',attempts=1,recurrence_reconcile_required=1 WHERE id=?", (first,))
    request = Request({"type": "http", "method": "POST", "scheme": "http", "path": "/api/v1/copilot/product-operations/execute",
                       "headers": [(b"host", b"127.0.0.1"), (b"origin", b"http://127.0.0.1")]})
    args = {"job_id": first, "action": "rearm", "successor_id": None,
            "old_workers_stopped": True, "rationale": "Verified old workers stopped"}
    return queue, request, args


def test_repair_uses_native_receipt_and_never_replays_historical_work(parked):
    queue, request, args = parked
    preview = operations.repair_prepare(request, {}, args)
    result = operations.repair_execute(request, {}, args, preview.native, "b" * 32)
    # The details read in plain words: the continuation, and no repeated history.
    assert result.status == "confirmed" and result.details["Historical work repeated"] is False
    again = operations.repair_recover(request, {}, args, preview.native, "b" * 32)
    assert again.status == "replayed"
    assert again.details["Recorded continuation"] == result.details["Recorded continuation"]
    assert queue.get(args["job_id"]).status == "failed"
    assert len(queue.list(status="pending")) == 1


def test_repair_requires_explicit_shutdown_attestation_and_current_compatible_successor(parked):
    _queue, request, args = parked
    with pytest.raises(HTTPException) as error:
        operations.repair_prepare(request, {}, {**args, "old_workers_stopped": False})
    assert error.value.status_code == 422
    with pytest.raises(HTTPException) as error:
        operations.repair_prepare(request, {}, {**args, "action": "link_successor", "successor_id": 999})
    assert error.value.status_code == 409


def test_intervening_recovery_evidence_and_revocation_refuse(parked, monkeypatch):
    queue, request, args = parked
    preview = operations.repair_prepare(request, {}, args)
    with queue._conn() as connection:
        connection.execute("UPDATE jobs SET last_error='changed after review' WHERE id=?", (args["job_id"],))
    with pytest.raises(HTTPException) as error:
        operations.repair_execute(request, {}, args, preview.native, "c" * 32)
    assert error.value.status_code == 409 and not queue.list(status="pending")
    def denied(*args):
        raise HTTPException(403, "Administrator role revoked")
    monkeypatch.setattr(operations, "require_permission", denied)
    with pytest.raises(HTTPException) as error:
        operations.repair_recover(request, {}, args, preview.native, "c" * 32)
    assert error.value.status_code == 403
