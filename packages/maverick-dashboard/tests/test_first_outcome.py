"""Get started offers eight department first outcomes on sample data and the
click path either starts the marked sample task or says plainly that no AI
service is ready."""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

DEPARTMENTS = ["finance", "privacy", "security", "legal", "hr", "procurement", "customer_support", "tax"]


def _route_state(configured: bool) -> dict:
    return {"status": "configured" if configured else "incomplete", "configured": configured,
            "detail": "offline", "evidence": {"kind": "offline_configuration", "live_provider_verified": False}}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path, *, ready: bool):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_WORKDIR", str(tmp_path / "work"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")
    import maverick.domain_edit as de
    monkeypatch.setattr(de, "list_agents", list)
    config.reset_config_cache()
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import onboarding_state
    dashboard._world_cache.clear()
    monkeypatch.setattr(onboarding_state, "selected_model_route_state", lambda: _route_state(ready))
    return world_model


def test_get_started_renders_the_eight_departments(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, ready=True)
    page = _client().get("/start").text
    assert "Run your first task on sample data" in page
    for department in DEPARTMENTS:
        assert f'<option value="{department}"' in page
    assert page.count("data-lands-in=") == 8
    assert 'data-lands-in="Approvals"' in page and 'data-lands-in="Results"' in page
    assert "never counts as real evidence" in page
    assert 'id="first-outcome-run"' in page
    # The eight are also listed for the page script and for tests.
    listing = _client().get("/api/v1/first-outcome").json()
    assert [row["department"] for row in listing["outcomes"]] == DEPARTMENTS
    assert listing["ready"] is True and listing["selected"] == "finance"


def test_get_started_says_plainly_when_no_provider_is_ready(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, ready=False)
    page = _client().get("/start").text
    assert "No AI service is ready yet" in page
    assert 'href="/settings#settings-integrations">Connect an AI service first</a>' in page


def test_before_ai_is_connected_the_sample_button_explains_instead_of_failing(monkeypatch, tmp_path):
    """The run button used to stay enabled and answer 409. Before an AI service
    is ready it is a link to connect one; the task can still be previewed."""
    _isolate(monkeypatch, tmp_path, ready=False)
    page = _client().get("/start").text
    assert 'id="first-outcome-run"' not in page
    assert re.search(r'<a [^>]*id="first-outcome-connect"[^>]*href="/settings#settings-integrations"', page)
    assert 'id="first-outcome-department"' in page  # the task text still previews
    _isolate(monkeypatch, tmp_path, ready=True)
    page = _client().get("/start").text
    assert 'id="first-outcome-run"' in page and 'id="first-outcome-connect"' not in page


def test_recorded_department_is_preselected(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, ready=True)
    cfg = tmp_path / "config.toml"
    cfg.write_text('[first_outcome]\ndepartment = "tax"\nsample_workspace_created = true\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import config
    config.reset_config_cache()
    try:
        page = _client().get("/start").text
        assert '<option value="tax" data-goal="Sample' not in page  # goal text has no prefix
        assert 'value="tax"' in page and 'value="tax" data-goal="Read this tax notice' in page
        assert page.split('value="tax"', 1)[1].split(">", 1)[0].endswith("selected")
    finally:
        config.reset_config_cache()


def test_run_without_a_ready_provider_returns_a_plain_message_and_link(monkeypatch, tmp_path):
    world_model = _isolate(monkeypatch, tmp_path, ready=False)
    r = _client().post("/api/v1/first-outcome/run", json={"department": "finance"})
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["ready"] is False and detail["href"] == "/settings#settings-integrations"
    assert "Connect an AI service" in detail["detail"]
    # Nothing was created: no goal, no sample workspace.
    assert world_model.WorldModel(tmp_path / "world.db").list_goals() == []
    assert not (tmp_path / "work" / "sample-outcomes").exists()


def test_run_with_a_ready_provider_creates_marked_sample_goal(monkeypatch, tmp_path):
    world_model = _isolate(monkeypatch, tmp_path, ready=True)
    from maverick_dashboard import first_outcome_api

    started = []

    async def fake_run(goal_id, max_dollars, max_wall_seconds, max_depth, **kwargs):
        started.append((goal_id, kwargs))

    monkeypatch.setattr(first_outcome_api, "run_goal_in_background_async", fake_run)
    r = _client().post("/api/v1/first-outcome/run", json={"department": "security"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["sample"] is True and body["pack"] == "itgrc_incident_response" and body["lands_in"] == "Approvals"
    assert body["href"] == f"/chat/goal/{body['goal_id']}"
    # The sample workspace exists under the sandbox workdir and is flagged.
    from maverick import sample_outcomes
    workspace = tmp_path / "work" / "sample-outcomes" / "security"
    assert sample_outcomes.is_sample_workspace(workspace)
    assert (workspace / "mailbox_export.csv").is_file()
    # The goal runs as the pack, is titled and evented as sample data, and was dispatched once.
    world = world_model.WorldModel(tmp_path / "world.db")
    goal = world.get_goal(body["goal_id"])
    assert goal.domain == "itgrc_incident_response" and goal.title.startswith("Sample: ")
    assert "sample-outcomes/security/mailbox_export.csv" in goal.description
    assert sample_outcomes.is_sample_goal(world, goal)
    assert [e.kind for e in world.goal_events(goal.id)] == ["sample_data"]
    assert started == [(goal.id, {"allowed_suites": started[0][1]["allowed_suites"]})]


def test_run_rejects_unknown_department_and_viewers(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, ready=True)
    assert _client().post("/api/v1/first-outcome/run", json={"department": "marketing"}).status_code == 404
    assert _client().post("/api/v1/first-outcome/run", json={}).status_code == 422
    from fastapi import HTTPException
    from maverick_dashboard import first_outcome_api

    def deny(request, permission):
        raise HTTPException(403, "read-only")

    monkeypatch.setattr(first_outcome_api, "require_permission", deny)
    assert _client().post("/api/v1/first-outcome/run", json={"department": "hr"}).status_code == 403


def test_the_sample_request_bubble_shows_the_plain_task_not_internal_instructions(monkeypatch, tmp_path):
    world_model = _isolate(monkeypatch, tmp_path, ready=True)
    from maverick import sample_outcomes
    from maverick_dashboard import first_outcome_api

    async def fake_run(*args, **kwargs):
        return None

    monkeypatch.setattr(first_outcome_api, "run_goal_in_background_async", fake_run)
    started = _client().post("/api/v1/first-outcome/run", json={"department": "finance"})
    assert started.status_code == 201, started.text
    goal_id = started.json()["goal_id"]
    # The run still gets the file instructions it needs ...
    goal = world_model.WorldModel(tmp_path / "world.db").get_goal(goal_id)
    assert "read_file" in goal.description
    # ... but the person's message bubble shows only what they asked for.
    page = _client().get(f"/chat/goal/{goal_id}").text
    bubble = page.split('<div class="msg msg--user">', 1)[1].split('<details id="attachments-panel"', 1)[0]
    assert "invoices to purchase orders and receipts, and list every exception" in bubble
    assert "made-up sample files" in bubble
    # The bubble recognises a sample brief by the rule it starts with.
    assert sample_outcomes.SAMPLE_RULE.startswith("This task runs on bundled sample data.")
    assert sample_outcomes.goal_description("finance").startswith(sample_outcomes.SAMPLE_RULE)
    for internal in ("read_file", "sample-outcomes/", "README.md", "Hand the result"):
        assert internal not in bubble, internal
