"""A stopped run's kernel text never becomes a customer answer or export."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def chat_env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dashboard

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard._world_cache.clear()
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()


def test_stopped_result_is_not_an_answer_or_download(chat_env):
    client, world = chat_env
    goal_id = world.create_goal("Prepare the report", "")
    raw = "internal error: TenantRegistryError user:private@example.com C:\\secrets\\provider.key"
    world.set_goal_status(goal_id, "failed", result=raw)

    panel = client.get(f"/chat/goal/{goal_id}/answer-panel")
    assert panel.status_code == 200
    assert raw not in panel.text
    assert 'id="copy-result"' not in panel.text
    assert 'id="saved-answer-source"' not in panel.text
    assert client.get(f"/chat/goal/{goal_id}/download.md").status_code == 409


def test_provider_failure_is_stopped_with_a_working_connection_route(chat_env):
    client, world = chat_env
    goal_id = world.create_goal("Prepare the report", "")
    world.set_goal_status(goal_id, "blocked", result="provider connection refused")

    page = client.get(f"/chat/goal/{goal_id}")
    assert page.status_code == 200
    assert re.search(r'data-status="blocked"[^>]* hidden>Stopped</span>', page.text)
    # AI keys live in Settings (Connections > Provider keys), row focused.
    assert 'id="halt-action-link" href="/settings?focus=ai-provider#settings-integrations"' in page.text
    assert "couldn&#39;t reach the AI service" in page.text or "couldn&#x27;t reach the AI service" in page.text


def test_stopped_prior_turn_is_sanitized_in_page_and_paged_history(chat_env):
    client, world = chat_env
    root = world.create_goal("First question", "")
    raw = "internal error: TenantRegistryError user:private@example.com C:\\secrets\\provider.key"
    world.set_goal_status(root, "failed", result=raw)
    conversation = world.get_or_create_conversation("web", f"local/{root}")
    world.append_turn(conversation.id, "user", "First question", goal_id=root)
    world.append_turn(conversation.id, "assistant", raw, goal_id=root)
    child = world.create_goal("Second question", "", parent_id=root)
    world.append_turn(conversation.id, "user", "Second question", goal_id=child)

    page = client.get(f"/chat/goal/{child}")
    assert page.status_code == 200
    assert raw not in page.text
    assert "workspace is paused" in page.text.lower()

    history = client.get(f"/api/v1/goals/{child}/thread-history")
    assert history.status_code == 200
    assert raw not in history.text
    assistant = next(turn for turn in history.json()["turns"] if turn["role"] == "assistant")
    assert assistant["stop"]["kind"] == "workspace_paused"
    assert "workspace is paused" in assistant["content"].lower()
