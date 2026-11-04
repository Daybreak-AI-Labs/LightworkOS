"""People control their alerts from the alert itself (NOT-2).

One click mutes a task, or every alert from the agent behind it; both are
undone from the same inbox or from notification preferences. "Preview
today's summary" shows exactly what the daily summary would send, built by the
real digest builder, and something already seen in the app is not repeated in
the summary.
"""
from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal


@pytest.fixture
def client_and_world(monkeypatch, tmp_path):
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

    async def bind(request: Request):
        request.state.principal = VerifiedPrincipal(sub=("user:alice").removeprefix("user:"), issuer="https://idp.test", audience="lightwork")
        return request.state.principal

    dashboard.app.dependency_overrides[auth.require_principal_in_request_context] = bind
    monkeypatch.setattr(auth, "role_for_principal", lambda _principal: "operator")
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            yield client, dashboard._world()
    finally:
        dashboard.app.dependency_overrides.clear()
        dashboard._world_cache.clear()
        config.reset_config_cache()


def _finished(world, title, *, domain=""):
    goal = world.create_goal(title, owner="user:alice", domain=domain) if domain else world.create_goal(
        title, owner="user:alice")
    world.set_goal_status(goal, "done", result="PRIVATE RESULT TEXT")
    return goal


def test_mute_this_task_from_the_alert_and_undo_it(client_and_world):
    client, world = client_and_world
    goal = _finished(world, "Quarterly vendor review")
    inbox = client.get("/api/v1/notifications/personal").json()
    [item] = inbox["items"]
    assert item["reason"] == "You started this task" and item["action"] == "Review the result"
    muted = client.post("/api/v1/notifications/personal/mute", json={
        "context": inbox["context"], "item_id": item["id"], "scope": "task"})
    assert muted.status_code == 200, muted.text
    body = muted.json()
    assert body["items"] == []
    assert str(goal) in body["preferences"]["muted_tasks"]
    assert body["muted"]["scope"] == "task" and body["muted"]["key"] == str(goal)
    assert body["muted"]["label"] == "Quarterly vendor review"
    undone = client.post("/api/v1/notifications/personal/unmute", json={
        "context": inbox["context"], "scope": "task", "key": str(goal)})
    assert undone.status_code == 200, undone.text
    assert [row["goal_id"] for row in undone.json()["items"]] == [goal]
    assert undone.json()["preferences"]["muted_tasks"] == {}


def test_mute_alerts_from_this_agent_covers_its_other_tasks(client_and_world):
    client, world = client_and_world
    first = _finished(world, "First finance task", domain="finance_ap")
    _finished(world, "Second finance task", domain="finance_ap")
    other = _finished(world, "Privacy task", domain="privacy_dsar")
    inbox = client.get("/api/v1/notifications/personal").json()
    item = next(row for row in inbox["items"] if row["goal_id"] == first)
    assert item["agent"] == "finance_ap" and item["agent_label"] == "finance ap"
    body = client.post("/api/v1/notifications/personal/mute", json={
        "context": inbox["context"], "item_id": item["id"], "scope": "agent"}).json()
    assert [row["goal_id"] for row in body["items"]] == [other]
    assert "finance_ap" in body["preferences"]["muted_agents"]
    restored = client.post("/api/v1/notifications/personal/unmute", json={
        "context": inbox["context"], "scope": "agent", "key": "finance_ap"}).json()
    assert len(restored["items"]) == 3


def test_mute_refuses_a_stale_alert_or_an_alert_without_an_agent(client_and_world):
    client, world = client_and_world
    _finished(world, "No agent named")
    inbox = client.get("/api/v1/notifications/personal").json()
    [item] = inbox["items"]
    stale = client.post("/api/v1/notifications/personal/mute", json={
        "context": inbox["context"], "item_id": "f" * 64, "scope": "task"})
    assert stale.status_code == 409
    no_agent = client.post("/api/v1/notifications/personal/mute", json={
        "context": inbox["context"], "item_id": item["id"], "scope": "agent"})
    assert no_agent.status_code == 409
    assert "agent" in no_agent.json()["detail"]
    other_account = client.post("/api/v1/notifications/personal/mute", json={
        "context": "x", "item_id": item["id"], "scope": "task"})
    assert other_account.status_code == 409


def test_preview_today_summary_is_exactly_what_the_digest_would_send(client_and_world):
    from maverick import daily_digest

    client, world = client_and_world
    _finished(world, "Board pack summary")
    preview = client.get("/api/v1/me/digest/preview")
    assert preview.status_code == 200, preview.text
    assert preview.headers["Cache-Control"] == "private, no-store"
    body = preview.json()
    digest = daily_digest.compose_digest(world, "user:alice", can_decide=True, time_zone="UTC")
    assert body["text"] == daily_digest.render_text(digest, dashboard_url=daily_digest.dashboard_url())
    assert body["subject"] == f"Your Lightwork summary for {digest['date_label']}"
    assert "Board pack summary" in body["text"] and "PRIVATE RESULT TEXT" not in body["text"]
    # Honest about delivery: the workspace summary is off and nothing is linked.
    assert body["would_send"] is False
    assert any("turned off for this workspace" in note for note in body["notes"])


def test_a_result_already_seen_in_the_app_is_left_out_of_the_summary(client_and_world):
    client, world = client_and_world
    _finished(world, "Seen in the app already")
    inbox = client.get("/api/v1/notifications/personal").json()
    client.post("/api/v1/notifications/personal/seen", json={
        "context": inbox["context"], "item_id": inbox["items"][0]["id"]})
    body = client.get("/api/v1/me/digest/preview").json()
    assert "Seen in the app already" not in body["text"]
    assert any("already saw" in note for note in body["notes"])
    # My work, the in-app page, still lists it.
    assert "Seen in the app already" in client.get("/me").text


def test_both_preference_pages_offer_the_summary_preview(client_and_world):
    client, _world = client_and_world
    for page in ("/notifications", "/me"):
        text = client.get(page).text
        assert 'data-digest-preview' in text, page
        assert "Preview today's summary" in text or "Preview today&#39;s summary" in text, page


def test_a_task_the_person_can_no_longer_open_does_not_take_down_the_inbox(client_and_world, monkeypatch):
    """A department grant that was removed leaves old tasks owned by the person but
    closed to them; one such task used to answer 404 for the whole inbox."""
    from maverick_dashboard import suite_grants

    client, world = client_and_world
    open_goal = _finished(world, "General task")
    _finished(world, "Finance task", domain="finance_ap")
    monkeypatch.setattr(suite_grants, "granted_suites", lambda _principal: frozenset({"legal"}))

    inbox = client.get("/api/v1/notifications/personal")
    assert inbox.status_code == 200, inbox.text
    assert [row["goal_id"] for row in inbox.json()["items"]] == [open_goal]
    summary = client.get("/api/v1/notifications/personal/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["unseen"] == 1
