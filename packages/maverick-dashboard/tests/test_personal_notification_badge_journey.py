"""A signed-in owner sees finished work through the same alert source as the inbox."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal


@pytest.fixture
def client_and_actor(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    (tmp_path / "config.toml").write_text("[notifications]\npersonal_alerts = true\n", encoding="utf-8")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    dashboard._world_cache.clear()
    actor = {"principal": "user:alice"}

    async def bind(request: Request):
        request.state.principal = VerifiedPrincipal(sub=(actor["principal"]).removeprefix("user:"), issuer="https://idp.test", audience="lightwork")
        return request.state.principal

    dashboard.app.dependency_overrides[auth.require_principal_in_request_context] = bind
    monkeypatch.setattr(auth, "role_for_principal", lambda _principal: "operator")
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            yield client, actor, dashboard._world(), tmp_path
    finally:
        dashboard.app.dependency_overrides.clear()
        dashboard._world_cache.clear()
        config.reset_config_cache()


@pytest.mark.parametrize("path", ["/goals", "/chat"])
def test_both_shells_serve_the_advertised_notification_badge(client_and_actor, path):
    client, _actor, _world, _home = client_and_actor
    page = client.get(path)
    assert page.status_code == 200
    scripts = re.findall(
        r'src="(/static/lightwork-notification-badge\.js(?:\?[^"]*)?)"', page.text,
    )
    assert len(scripts) == 1
    assert "?v=" in scripts[0]

    response = client.get(scripts[0])
    assert response.status_code == 200
    assert response.headers["content-type"].split(";", 1)[0] == "application/javascript"
    source = (Path(__file__).resolve().parents[1]
              / "maverick_dashboard/static/lightwork-notification-badge.js")
    assert response.content == source.read_bytes()


def test_finished_task_bell_to_owner_inbox_and_seen_state(client_and_actor):
    client, actor, world, _tmp_path = client_and_actor
    page = client.get("/chat")
    assert page.status_code == 200
    assert 'id="personal-notification-link"' in page.text
    assert 'data-enabled="true"' in page.text
    assert client.get("/api/v1/notifications/personal/summary").json()["unseen"] == 0

    own = world.create_goal("Owner's private task", owner="user:alice")
    other = world.create_goal("Other person's private task", owner="user:bob")
    world.set_goal_status(own, "done", result="Owner's private result")
    world.set_goal_status(other, "done", result="Other person's private result")
    summary = client.get("/api/v1/notifications/personal/summary")
    assert summary.status_code == 200
    assert summary.headers["Cache-Control"] == "private, no-store"
    assert summary.json()["unseen"] == 1
    assert "private task" not in summary.text and "private result" not in summary.text

    inbox = client.get("/api/v1/notifications/personal").json()
    assert [(row["goal_id"], row["title"]) for row in inbox["items"]] == [
        (own, "Owner's private task")]
    marked = client.post("/api/v1/notifications/personal/seen", json={
        "context": inbox["context"], "item_id": inbox["items"][0]["id"],
    })
    assert marked.status_code == 200
    assert marked.json()["items"][0]["seen_at"] is not None, marked.json()["items"]
    assert client.get("/api/v1/notifications/personal/summary").json()["unseen"] == 0

    actor["principal"] = "user:bob"
    assert client.get("/api/v1/notifications/personal/summary").json()["unseen"] == 1
    assert [(row["goal_id"], row["title"]) for row in
            client.get("/api/v1/notifications/personal").json()["items"]] == [
                (other, "Other person's private task")]
    assert "Owner's private task" not in client.get("/notifications").text


def test_disabled_alerts_have_a_working_explanation_page(client_and_actor):
    from maverick import config

    client, _actor, _world, home = client_and_actor
    (home / "config.toml").write_text("[notifications]\npersonal_alerts = false\n", encoding="utf-8")
    config.reset_config_cache()
    page = client.get("/notifications")
    assert page.status_code == 200
    assert "Personal task alerts are turned off" in page.text
    assert 'id="notification-preferences"' not in page.text
    assert client.get("/api/v1/notifications/personal/summary").status_code == 403


def test_disabled_personal_preferences_stop_the_api_and_background_enrollment(client_and_actor):
    from maverick import config, personal_notification_recipients
    from maverick_dashboard import personal_notification_scheduler

    client, _actor, world, home = client_and_actor
    (home / "config.toml").write_text(
        "[features]\npersonal_preferences = false\n[notifications]\n"
        "personal_alerts = true\npersonal_background = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    assert "Personal preferences are turned off" in client.get("/notifications").text
    assert client.get("/api/v1/notifications/personal/summary").status_code == 403
    assert personal_notification_scheduler._enabled() is False
    world.create_goal("Task while alerts are unavailable", owner="user:alice")
    assert personal_notification_recipients.principals() == []


def test_owner_is_enrolled_at_task_creation_and_first_check_catches_fast_outcomes(
    client_and_actor, monkeypatch,
):
    from maverick import personal_identity, personal_notification_recipients

    client, _actor, world, _home = client_and_actor
    monkeypatch.setattr(personal_identity, "principal_current", lambda actor: actor == "user:alice")
    completed = world.create_goal("Finished before inbox opened", owner="user:alice")
    failed = world.create_goal("Failed before inbox opened", owner="user:alice")
    waiting = world.create_goal("Waiting before inbox opened", owner="user:alice")
    other = world.create_goal("Another person's task", owner="user:bob")
    assert personal_notification_recipients.principals() == ["user:alice"]

    world.set_goal_status(completed, "done", result="Private result")
    world.set_goal_status(failed, "failed", result="Private failure")
    world.ask("Private question", waiting)
    world.set_goal_status(other, "done", result="Another private result")

    first = client.get("/api/v1/notifications/personal")
    assert first.status_code == 200
    rows = first.json()["items"]
    assert {(row["goal_id"], row["category"]) for row in rows} == {
        (completed, "completed"), (failed, "failed"), (waiting, "needs-decision")}
    # Each alert opens its task; a question opens it with the answer box in view.
    assert all(row["href"] == f'/chat/goal/{row["goal_id"]}'
               + ("#question-panel" if row["category"] == "needs-decision" else "") for row in rows)
    assert "Private result" not in first.text and "Another person's task" not in first.text
    second = client.get("/api/v1/notifications/personal").json()["items"]
    assert {row["id"] for row in second} == {row["id"] for row in rows}


def test_in_app_alerts_are_on_for_a_fresh_install(client_and_actor):
    """Nothing configured: the bell works for finished work, questions and
    approvals; email, Slack and Teams stay off until someone sets them up."""
    from maverick import config

    client, _actor, world, home = client_and_actor
    (home / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    page = client.get("/chat")
    assert 'id="personal-notification-link"' in page.text and 'data-enabled="true"' in page.text
    assert "turned off" not in client.get("/notifications").text
    own = world.create_goal("Fresh install task", owner="user:alice")
    world.set_goal_status(own, "done", result="Private result")
    waiting = world.create_goal("Needs an answer", owner="user:alice")
    world.ask("Which quarter?", waiting)
    inbox = client.get("/api/v1/notifications/personal").json()
    assert {(row["goal_id"], row["category"]) for row in inbox["items"]} == {
        (own, "completed"), (waiting, "needs-decision")}
    assert inbox["background_enabled"] is False
    assert inbox["preferences"]["external_links"] == []


def test_background_observer_records_owner_outcomes_without_an_open_inbox(
    client_and_actor, monkeypatch,
):
    from maverick import config, personal_identity, personal_notification_recipients
    from maverick_dashboard import personal_notification_scheduler as scheduler

    client, _actor, world, home = client_and_actor
    monkeypatch.setattr(personal_identity, "principal_current", lambda actor: actor == "user:alice")
    completed = world.create_goal("Background completion", owner="user:alice")
    waiting = world.create_goal("Background question", owner="user:alice")
    world.set_goal_status(completed, "done", result="Private result")
    world.ask("Private question", waiting)
    assert personal_notification_recipients.status("user:alice")["last_observed_at"] is None

    (home / "config.toml").write_text(
        "[notifications]\npersonal_alerts = true\npersonal_background = true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    assert scheduler.observe("user:alice") is True
    assert personal_notification_recipients.status("user:alice")["last_observed_at"] is not None
    rows = client.get("/api/v1/notifications/personal").json()["items"]
    assert {(row["goal_id"], row["category"]) for row in rows} == {
        (completed, "completed"), (waiting, "needs-decision"),
    }
    # Each alert opens its task; a question opens it with the answer box in view.
    assert all(row["href"] == f'/chat/goal/{row["goal_id"]}'
               + ("#question-panel" if row["category"] == "needs-decision" else "") for row in rows)
