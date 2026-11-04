"""When the AI has not resolved something, a person is one step away
with the task attached -- after a second rejected answer from the same agent
or specialist, and on every task that stopped or did not finish."""
from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture
def world(tmp_path, monkeypatch):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.dashboard_overrides_path", lambda: tmp_path / "dashboard.toml")
    w = world_model.WorldModel(tmp_path / "world.db")
    yield w
    w.close()


def _done(world, title, domain="proc_po_chaser", status="done"):
    gid = world.create_goal(title, "", domain=domain)
    episode = world.start_episode(gid)
    world.end_episode(episode, "Three are overdue.", "success")
    world.set_goal_status(gid, status, result="Three are overdue.")
    return gid


def _rate(gid, rating):
    review = client.get(f"/api/v1/goals/{gid}/answer-feedback").json()
    return client.post(f"/api/v1/goals/{gid}/feedback", json={
        "rating": rating, "revision": review["revision"], "expected_context": review["context"],
        "operation_id": uuid4().hex}).json()


def test_a_second_rejected_answer_offers_a_person_with_the_task_attached(world):
    first, second, third = (_done(world, f"Overdue POs {n}") for n in range(3))
    assert _rate(first, "down").get("hand_off") is None
    offered = _rate(second, "down")["hand_off"]
    assert offered == {"label": "Get help from a person",
                       "href": f"/help?from=/chat/goal/{second}&task={second}#get-help"}
    assert _rate(third, "up").get("hand_off") is None  # a useful answer needs no hand-off


def test_the_answer_panel_carries_the_hand_off_and_a_stopped_task_shows_it(world):
    from pathlib import Path

    panel = (Path(__file__).resolve().parents[1] / "maverick_dashboard/templates/_chat_answer_panel.html").read_text(encoding="utf-8")
    assert 'id="feedback-hand-off" hidden' in panel and "data-get-help>{{ ui('Get help from a person') }}" in panel
    stopped = panel[panel.index("{% if goal.status in ('blocked', 'failed') %}"):]
    stopped = stopped[:stopped.index("{% endif %}")]
    assert '#get-help" data-get-help>' in stopped
    script = (Path(__file__).resolve().parents[1] / "maverick_dashboard/static/lightwork-answer-panel.js").read_text(encoding="utf-8")
    assert "value.hand_off" in script
