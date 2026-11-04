"""Help page: a local draft for a task that stopped, and the
Savings / Performance additions from ``proof`` and ``charts``."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _stopped_task(owner: str, title: str) -> int:
    from maverick_dashboard._shared import _world
    world = _world()
    goal = world.create_goal(title, owner=owner, execution_principal=owner)
    world.append_event(goal, "planner", "error", "failed with key sk-ant-api03-" + "z" * 40)
    world.set_goal_status(goal, "blocked")
    return goal


def test_people_see_only_their_own_stopped_tasks_and_get_a_local_draft(client, monkeypatch):
    mine = _stopped_task("user:vic@example.com", "Quarterly summary")
    theirs = _stopped_task("user:other@example.com", "Someone else's work")
    _as(monkeypatch, "viewer", "user:vic@example.com")
    tasks = client.get("/api/v1/support/issue-report/tasks").json()["tasks"]
    assert [t["id"] for t in tasks] == [mine]
    made = client.post("/api/v1/support/issue-report", json={"task": mine}).json()
    assert "url" not in made  # preparation cannot navigate outside Lightwork
    assert "Quarterly summary" in made["title"]
    assert "sk-ant-api03-" + "z" * 40 not in made["body"]
    assert "maverick report-issue" not in made["body"]
    assert "stopped Lightwork task" in made["body"]
    assert "Nothing is sent automatically" in made["summary"]
    reviewed = client.post("/api/v1/support/issue-report/review", json={
        "task": mine, "title": "Reviewed title", "body": "Business details removed",
    }).json()
    assert reviewed == {"title": "Reviewed title", "body": "Business details removed"}
    assert "Quarterly summary" not in str(reviewed)
    assert client.post("/api/v1/support/issue-report", json={"task": theirs}).status_code == 404
    assert client.post("/api/v1/support/issue-report", json={"task": 999999}).status_code == 404
    assert client.post("/api/v1/support/issue-report", json={"task": 0}).status_code == 422


def test_task_draft_includes_installed_version_and_redacted_result(client, monkeypatch):
    from maverick_dashboard import __version__
    from maverick_dashboard._shared import _world

    task = _stopped_task("user:vic@example.com", "Provider test")
    secret = "sk-ant-api03-" + "z" * 40
    _world().set_goal_status(task, "blocked", result=f"provider HTTP 500; credential {secret}")
    _as(monkeypatch, "viewer", "user:vic@example.com")
    response = client.post("/api/v1/support/issue-report", json={"task": task})
    assert response.status_code == 200
    draft = response.json()
    assert f"Version: {__version__}" in draft["body"]
    assert "provider HTTP 500" in draft["body"]
    assert secret not in str(draft)
    assert "no error events recorded" not in draft["body"].lower()
    assert "url" not in draft

    completed = _world().create_goal("Private completed work", owner="user:vic@example.com")
    _world().set_goal_status(completed, "done", result="private completed output")
    refused = client.post("/api/v1/support/issue-report", json={"task": completed})
    assert refused.status_code == 409
    assert "private completed output" not in refused.text


def test_support_search_finds_old_tasks_and_deep_link_rechecks_access(client, monkeypatch):
    oldest = _stopped_task("user:vic@example.com", "Oldest quarterly task")
    for index in range(59):
        _stopped_task("user:vic@example.com", f"Later task {index}")
    other = _stopped_task("user:other@example.com", "Oldest private task")
    _as(monkeypatch, "viewer", "user:vic@example.com")
    found = client.get("/api/v1/support/issue-report/tasks", params={"query": "Oldest"}).json()
    assert [row["id"] for row in found["tasks"]] == [oldest]
    page = client.get("/api/v1/support/issue-report/tasks", params={"selected": oldest}).json()
    assert page["selected"]["id"] == oldest and page["next_offset"] is not None
    second = client.get("/api/v1/support/issue-report/tasks", params={"offset": page["next_offset"]}).json()
    assert set(row["id"] for row in page["tasks"]).isdisjoint(row["id"] for row in second["tasks"])
    assert client.get("/api/v1/support/issue-report/tasks", params={"selected": other}).status_code == 404
    assert client.get("/api/v1/support/issue-report/tasks", params={"after": "2026-02-30"}).status_code == 422
    assert client.get("/api/v1/support/issue-report/tasks", params={"after": "2026-10-01", "before": "2026-09-01"}).status_code == 422


def test_review_scrubs_edits_and_rechecks_task_authority(client, monkeypatch):
    mine = _stopped_task("user:vic@example.com", "Private account")
    _as(monkeypatch, "viewer", "user:vic@example.com")
    secret = "sk-ant-api03-" + "z" * 40
    payload = {"task": mine, "title": "Share selected details", "body": "New key " + secret}
    response = client.post("/api/v1/support/issue-report/review", json=payload)
    assert response.status_code == 200 and secret not in str(response.json())
    assert response.headers["cache-control"] == "private, no-store"
    _as(monkeypatch, "viewer", "user:other@example.com")
    assert client.post("/api/v1/support/issue-report/review", json=payload).status_code == 404


def test_help_page_offers_the_bug_report(client):
    page = client.get("/help")
    assert page.status_code == 200
    assert 'id="issue-report-form"' in page.text and "/static/lightwork-support-ops.js" in page.text
    assert "Prepare the bug report" in page.text
    assert "Copy reviewed draft" in page.text and "Download reviewed draft" in page.text
    assert "Send reviewed draft to GitHub" not in page.text
    assert "no support inbox set up" in page.text
    assert client.get("/static/lightwork-support-ops.js").status_code == 200


def test_value_report_adds_learning_and_record_checks(client, monkeypatch):
    data = client.get("/api/v1/insights/value-report", params={"days": 90}).json()
    assert data["improvement"] is None and "Not enough learning checkpoints" in data["learning"]
    assert data["record"] and data["vendors"] == []
    assert client.get("/api/v1/insights/value-report", params={"days": 3}).status_code == 422
    from maverick import workforce_value
    monkeypatch.setattr(workforce_value, "_coverage_trend", lambda cutoff: [("2026-09-01", 2), ("2026-09-20", 5)])
    better = client.get("/api/v1/insights/value-report").json()
    assert better["improvement"] == 3 and "cover 3 more" in better["learning"]
    page = client.get("/savings")
    assert 'id="value-report-form"' in page.text and "/static/lightwork-insights-ops.js" in page.text


def test_charts_are_for_installation_administrators(client, monkeypatch):
    from maverick import tool_latency
    tool_latency.record("read_file", 12.0)
    data = client.get("/api/v1/insights/charts", params={"days": 7}).json()
    assert len(data["tasks"]) == 7 and any(r["tool"] == "read_file" for r in data["tools"])
    assert client.get("/api/v1/insights/charts", params={"days": 8}).status_code == 422
    assert 'id="ops-charts-form"' in client.get("/perf").text
    _as(monkeypatch, "operator", "user:olive@example.com")
    assert client.get("/api/v1/insights/charts").status_code == 403
    assert client.get("/api/v1/insights/value-report").status_code == 200


def test_support_picker_pages_stopped_tasks_and_decrypts_only_those(client, monkeypatch):
    from maverick import world_model
    from maverick_dashboard._shared import _world

    stopped = []
    for index in range(130):
        if index % 3 == 0:
            done = _world().create_goal(f"Finished {index}", owner="user:vic@example.com")
            _world().set_goal_status(done, "done", result="finished output")
        else:
            stopped.append(_stopped_task("user:vic@example.com", f"Stopped {index}"))
    _as(monkeypatch, "viewer", "user:vic@example.com")
    decrypted: list[int] = []
    real_get_goals = world_model.WorldModel.get_goals

    def counting(self, goal_ids):
        decrypted.extend(goal_ids)
        return real_get_goals(self, goal_ids)

    monkeypatch.setattr(world_model.WorldModel, "get_goals", counting)
    seen, cursor = [], 0
    while cursor is not None:
        page = client.get("/api/v1/support/issue-report/tasks", params={"offset": cursor}).json()
        seen.extend(row["id"] for row in page["tasks"])
        cursor = page["next_offset"]
    assert seen == sorted(stopped, reverse=True)
    assert set(decrypted) and set(decrypted) <= set(stopped)

