"""One run-status vocabulary for the chat badge, the composer and the recents."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick.world_model import WorldModel
from maverick_dashboard import api
from maverick_dashboard import app as dashboard
from maverick_dashboard.run_status import status_label


@pytest.fixture
def chat(monkeypatch, tmp_path):
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(dashboard, "require_provider_or_400", lambda: None)
    monkeypatch.setattr(dashboard, "check_goal_rate_limit", lambda request: None)

    async def run(goal_id, **kwargs):
        return None

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()


def _send(client, title="Prepare our report"):
    response = client.post("/chat/send", data={"title": title}, follow_redirects=False)
    assert response.status_code == 303, response.text
    return int(response.headers["location"].rsplit("/", 1)[1])


def _badge(page):
    match = re.search(r'<span id="status"[^>]*>(.*)', page)
    assert match is not None
    return re.sub(r"<[^>]+>", "", match.group(1)).strip()


def _recents(client):
    sidebar = client.get("/chat").text.split('id="content"')[0]
    return dict(re.findall(
        r'<li><a\b[^>]*data-conversation-root="(\d+)"[^>]*>.*?</a>(.*?)</li>', sidebar, re.DOTALL,
    ))


def test_status_words_cover_the_orchestrator_states():
    assert status_label("active") == "Working"
    assert status_label("running") == "Working"
    assert status_label("pending") == "Queued"
    assert status_label("blocked") == "Paused"
    assert status_label("blocked", "provider_connection") == "Stopped"
    assert status_label("blocked", "spending_limit") == "Paused"
    assert status_label("cancelled") == "Stopped"
    assert status_label("done") == "Done"
    assert status_label("failed") == "Failed"
    assert status_label("mystery") == ""


def test_recents_say_working_while_the_task_is_active(chat):
    client, world = chat
    goal_id = _send(client)
    world.set_goal_status(goal_id, "active")
    row = _recents(client)[str(goal_id)]
    assert ">Working</span>" in row
    assert "cs-list__status--active" in row


def test_recents_and_badge_agree_on_a_run_that_stopped_on_the_ai_connection(chat):
    client, world = chat
    goal_id = _send(client)
    world.set_goal_status(goal_id, "blocked", result="provider_error:connection")
    row = _recents(client)[str(goal_id)]
    assert ">Stopped</span>" in row
    page = client.get(f"/chat/goal/{goal_id}").text
    assert _badge(page) == "Stopped"  # the same word as the recents row


def test_badge_never_shows_the_raw_active_status(chat):
    client, world = chat
    goal_id = _send(client)
    world.set_goal_status(goal_id, "active")
    page = client.get(f"/chat/goal/{goal_id}").text
    assert _badge(page) == "Working"
    # The page loads the shared vocabulary before its own script uses it.
    assert "lightwork-run-status.js" in page
    assert page.index("lightwork-run-status.js") < page.index("window.LightworkRunStatus")


def test_the_shared_vocabulary_is_served_to_the_browser(chat):
    client, _world = chat
    response = client.get("/static/lightwork-run-status.js")
    assert response.status_code == 200
    assert "LightworkRunStatus" in response.text
