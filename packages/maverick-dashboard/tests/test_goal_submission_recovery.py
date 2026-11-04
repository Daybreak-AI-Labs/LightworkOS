"""Keyed API submissions that stopped between admission and dispatch: a replay
runs them once with the client's limits; chat recovery never re-runs them."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.attachment_submissions import SubmissionStore
from maverick.world_model import WorldModel
from maverick_dashboard import api
from maverick_dashboard import app as dashboard


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    world = WorldModel(tmp_path / "world.db")
    for module in (api, dashboard):
        monkeypatch.setattr(module, "_world", lambda: world)
        monkeypatch.setattr(module, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)
    runs: list = []

    async def run(goal_id, *args, **kwargs):
        runs.append((goal_id, args, kwargs))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"},
                        raise_server_exceptions=False)
    yield client, world, runs
    world.close()


def _interrupt_first_claim(monkeypatch):
    real = SubmissionStore.claim_dispatch
    calls = {"n": 0}

    def flaky(self, key, **guard):  # guard: the current-authority effect_guard
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("crash between admission and dispatch")
        return real(self, key, **guard)
    monkeypatch.setattr(SubmissionStore, "claim_dispatch", flaky)


def test_a_replay_runs_an_interrupted_draft_once_with_its_limits(isolated, monkeypatch):
    client, world, runs = isolated
    _interrupt_first_claim(monkeypatch)
    headers = {"Idempotency-Key": "k1"}
    body = {"title": "T", "max_dollars": 0.1, "max_wall_seconds": 5}
    assert client.post("/api/v1/goals", headers=headers, json=body).status_code == 500
    receipt = client.get("/api/v1/goal-submissions/receipt", headers=headers).json()
    assert receipt["state"] == "not_dispatched" and not runs
    second = client.post("/api/v1/goals", headers=headers, json=body)
    assert second.status_code == 201 and second.headers["idempotency-replayed"] == "true"
    assert second.json()["status"] != "draft"
    assert len(runs) == 1 and runs[0][1][:2] == (0.1, 5)
    third = client.post("/api/v1/goals", headers=headers, json=body)
    assert third.status_code == 201 and len(runs) == 1           # never twice
    assert client.get("/api/v1/goal-submissions/receipt", headers=headers).json()["state"] == "accepted"


def test_chat_recovery_refuses_an_api_draft(isolated, monkeypatch):
    client, world, runs = isolated
    monkeypatch.setattr(SubmissionStore, "claim_dispatch",
                        lambda self, key: (_ for _ in ()).throw(RuntimeError("blip")))
    client.post("/api/v1/goals", headers={"Idempotency-Key": "k2"},
                json={"title": "T", "max_dollars": 0.1})
    goal_id = world.list_goals()[0].id
    response = client.post(f"/chat/goal/{goal_id}/recover-submission", follow_redirects=False)
    assert response.status_code == 409 and "Idempotency-Key" in response.text and not runs


def test_only_the_submitter_can_recover_a_draft(isolated, monkeypatch):
    client, world, runs = isolated
    goal_id = world.create_goal("T", "", owner="user:alice")
    monkeypatch.setattr(dashboard, "caller_principal", lambda request: "user:admin")
    monkeypatch.setattr(dashboard, "assert_goal_access", lambda request, goal: None)
    response = client.post(f"/chat/goal/{goal_id}/recover-submission", follow_redirects=False)
    assert response.status_code == 403 and not runs


def test_a_flow_retry_allowance_cannot_exceed_the_deployment_ceiling(monkeypatch):
    import inspect
    source = inspect.getsource(api.retry_flow_run_endpoint)
    assert "configured_goal_ceiling_dollars()" in source and "per-run ceiling" in source


def test_attachment_files_are_published_before_the_admission_lock(tmp_path, monkeypatch):
    """On SQLite the admission transaction holds the world's write lock: sealing
    and writing files must happen before it, not inside it."""
    from types import SimpleNamespace

    from maverick_dashboard import attachment_submission as sub
    events: list = []
    monkeypatch.setattr(sub, "_read_staged", lambda record: b"data")
    monkeypatch.setattr(sub.attachments, "_publish_attachment",
                        lambda dest, data, sha: events.append("publish"))
    monkeypatch.setattr(sub.attachments, "_root_for_goal", lambda goal_id: tmp_path)
    monkeypatch.setattr(sub.attachments, "s3_mirror_enabled", lambda: False)

    def admit(self, goal_id, records, *, publish=None):
        events.append(("admit", publish is None))
        return [1]
    monkeypatch.setattr(SubmissionStore, "admit", admit)
    monkeypatch.setattr(SubmissionStore, "__init__", lambda self, world: None)
    record = SimpleNamespace(filename="a.txt", mime="text/plain", size_bytes=4, sha256="0" * 64)
    world = SimpleNamespace(list_attachments=lambda goal_id: [])
    sub.publish_batch(world, 1, [record])
    assert events == ["publish", ("admit", True)]
