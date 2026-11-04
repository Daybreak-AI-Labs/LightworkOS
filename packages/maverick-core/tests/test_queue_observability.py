"""Job-queue backlog + dead-letter visibility: counts() and the `queue` CLI."""
from __future__ import annotations

from maverick.job_queue import JobQueue
from maverick.paths import tenant_scope


def _queue(tmp_path) -> JobQueue:
    return JobQueue(db_path=tmp_path / "jobs.db")


def test_counts_groups_by_status(tmp_path):
    q = _queue(tmp_path)
    q.enqueue("start_goal", {"a": 1})
    q.enqueue("start_goal", {"a": 2})
    # Claim + fail one permanently (retry_after=None) -> dead-letter 'failed'.
    job = q.claim()
    assert job is not None
    q.fail(job.id, "boom", retry_after=None)
    assert q.get(job.id).status == "failed"
    counts = q.counts()
    assert counts.get("pending", 0) >= 1
    assert counts.get("failed", 0) == 1


def test_cli_queue_status_and_failed(tmp_path, monkeypatch):
    import maverick.job_queue as jq
    from click.testing import CliRunner
    from maverick.cli import main

    # The CLI's JobQueue() uses the module DEFAULT_DB; point it at a tmp DB so
    # our seeded queue and the CLI share the same file.
    monkeypatch.setattr(jq, "DEFAULT_DB", tmp_path / "jobs.db")
    q = jq.JobQueue()  # now resolves to tmp_path/jobs.db

    q.enqueue("start_goal", {"x": 1})
    job = q.claim()
    q.fail(job.id, "kaboom-error", retry_after=None)
    assert q.get(job.id).status == "failed"

    runner = CliRunner()
    r = runner.invoke(main, ["queue", "status"])
    assert r.exit_code == 0, r.output
    assert "failed" in r.output

    r = runner.invoke(main, ["queue", "failed"])
    assert r.exit_code == 0, r.output
    assert "kaboom-error" in r.output


def test_default_db_is_resolved_lazily_inside_tenant_scope(tmp_path, monkeypatch):
    import maverick.job_queue as jq

    # job_queue was imported before either scope. Its default must still follow
    # the active tenant at construction time instead of freezing to root.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(jq, "DEFAULT_DB", None)

    with tenant_scope(tenant="fleet-a"):
        first = jq.JobQueue()
    with tenant_scope(tenant="fleet-b"):
        second = jq.JobQueue()

    assert first.db_path == tmp_path / "tenants" / "fleet-a" / "jobs.db"
    assert second.db_path == tmp_path / "tenants" / "fleet-b" / "jobs.db"
    assert first.db_path != second.db_path


def test_dispatch_envelope_claim_is_atomic_and_prunable(tmp_path):
    db_path = tmp_path / "jobs.db"
    first = JobQueue(db_path=db_path)
    second = JobQueue(db_path=db_path)

    assert first.claim_dispatch_envelope(
        "message_abcdefghijklmnop",
        "nonce_abcdefghijklmnop",
        expires_at=200,
        now=100,
    )
    assert not second.claim_dispatch_envelope(
        "message_abcdefghijklmnop",
        "different_nonce_value",
        expires_at=200,
        now=100,
    )
    assert second.prune_dispatch_envelope_claims(now=199) == 0
    assert second.prune_dispatch_envelope_claims(now=200) == 1
