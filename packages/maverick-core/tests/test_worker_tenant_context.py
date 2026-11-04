"""Tenant restoration at the durable worker dispatch boundary."""
from __future__ import annotations


def _isolate(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)


def test_worker_pins_payload_tenant_and_restores_ambient_context(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.job_queue import JobQueue
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick.tenant.registry import create_tenant
    from maverick.worker import Worker

    create_tenant("acme")
    q = JobQueue(db_path=tmp_path / "jobs.db")
    q.enqueue("observe", {"tenant": "acme"})
    seen: list[str | None] = []
    worker = Worker(queue=q, idle_sleep=0.0)
    worker.register("observe", lambda _job: seen.append(current_tenant_id()))

    ambient = set_tenant("ambient")
    try:
        assert worker.run_once() is True
        assert seen == ["acme"]
        assert current_tenant_id() == "ambient"
    finally:
        reset_tenant(ambient)


def test_suspended_tenant_fails_before_dispatch_or_cron_rearm(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.job_queue import JobQueue
    from maverick.tenant.registry import create_tenant, suspend_tenant
    from maverick.worker import Worker

    create_tenant("acme")
    suspend_tenant("acme")
    q = JobQueue(db_path=tmp_path / "jobs.db")
    job_id = q.enqueue(
        "observe",
        {"tenant": "acme", "__cron__": "*/5 * * * *"},
        run_at=1000.0,
    )
    called: list[bool] = []
    worker = Worker(
        queue=q, idle_sleep=0.0, retry_after=0.0, max_attempts=1,
    )
    worker.register("observe", lambda _job: called.append(True))

    assert worker.run_once() is True
    assert called == []
    assert q.get(job_id).status == "failed"
    assert not [
        job
        for job in q.list(status="pending", limit=100)
        if job.id != job_id and job.payload.get("__cron__")
    ]


def test_worker_scrubs_secret_from_durable_handler_error(tmp_path):
    from maverick.job_queue import JobQueue
    from maverick.worker import Worker

    q = JobQueue(db_path=tmp_path / "jobs.db")
    job_id = q.enqueue("fail", {})
    worker = Worker(
        queue=q, idle_sleep=0.0, retry_after=0.0, max_attempts=1,
    )
    secret = "ghp_" + "Z" * 36  # pragma: allowlist secret

    def fail(_job):
        raise RuntimeError(f"Authorization: Bearer {secret}")

    worker.register("fail", fail)
    assert worker.run_once() is True
    error = q.get(job_id).last_error
    assert secret not in error
    assert "REDACTED" in error


def test_run_goal_payload_restores_concurrency_and_suite_identity():
    from maverick.worker import _run_identity_kwargs

    kwargs = _run_identity_kwargs({
        "channel": "api",
        "user_id": "alice",
        "concurrency_principal": "user:alice",
        "allowed_suites": ["finance"],
    })
    assert kwargs == {
        "channel": "api",
        "user_id": "alice",
        "concurrency_principal": "user:alice",
        "allowed_suites": frozenset({"finance"}),
    }
