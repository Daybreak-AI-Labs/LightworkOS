"""Background work summary on the Action Center (read-only)."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import job_queue, world_model
    from maverick_dashboard.app import app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    queue = job_queue.JobQueue(tmp_path / "jobs.db")
    monkeypatch.setattr(job_queue, "JobQueue", lambda *a, **k: queue)
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), queue


def test_summary_counts_work_and_describes_failures_plainly(client) -> None:
    test_client, queue = client
    queue.enqueue("start_goal", {"title": "Weekly digest"})
    failing = queue.enqueue("start_goal", {"title": "Monthly report"})
    job = queue.claim()
    while job is not None and job.id != failing:
        job = queue.claim()
    assert job is not None
    queue.fail(job.id, "timed out calling token=sk-abcdefghijklmnopqrstuvwxyz123456", expected_attempts=job.attempts, max_attempts=1)
    body = test_client.get("/api/v1/queue/summary").json()
    assert body["failed"] == 1 and body["failed_items"][0]["what"] == "Scheduled task"
    item = body["failed_items"][0]
    assert item["title"] == "Monthly report" and item["problem"] == "It took too long."
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in item["detail"]  # pragma: allowlist secret


def test_summary_needs_the_admin_permission(client, monkeypatch) -> None:
    from fastapi import HTTPException
    from maverick_dashboard import queue_status_api

    test_client, _queue = client
    seen = []

    def deny(_request, permission):
        seen.append(permission)
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(queue_status_api, "require_permission", deny)
    assert test_client.get("/api/v1/queue/summary").status_code == 403
    assert seen == ["admin"]


def test_action_center_shows_background_work_and_reads_plainly(client, monkeypatch) -> None:
    from maverick_dashboard import action_center_api

    from test_support.plain_language import developer_terms

    test_client, _queue = client
    monkeypatch.setattr(action_center_api.config, "get_features", lambda: {"action_center": True})
    monkeypatch.setattr(action_center_api.config, "config_source_errors", lambda **kwargs: [])
    page = test_client.get("/action-center")
    assert page.status_code == 200
    assert 'id="ac-queue"' in page.text and "/api/v1/queue/summary" in page.text
    assert "Actions to double-check in other apps" in page.text
    assert developer_terms(page.text) == []
