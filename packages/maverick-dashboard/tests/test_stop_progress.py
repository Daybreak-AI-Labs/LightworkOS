"""A stopped task says what it finished and what is left, and Stop is one action."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick.world_model import WorldModel
from maverick_dashboard import api
from maverick_dashboard import app as dashboard
from maverick_dashboard.stop_progress import summarize

TEMPLATE = Path(dashboard.__file__).parent / "templates" / "chat_goal.html"


@pytest.fixture
def chat(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_DURABLE", raising=False)
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(dashboard, "_world", lambda: world)
    monkeypatch.setattr(api, "_world", lambda: world)
    yield TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()


def _planned(world, statuses):
    goal = world.create_goal("Prepare the vendor report", "")
    for number, status in enumerate(statuses, start=1):
        step = world.create_goal(f"Step {number}: part {number}", "", parent_id=goal)
        world.set_goal_status(step, status)
    world.set_goal_status(goal, "cancelled", result="cancelled by operator")
    return goal


def test_planned_steps_split_into_done_and_not_done(chat):
    _client, world = chat
    goal = _planned(world, ["done", "done", "cancelled", "pending"])
    progress = summarize(world, world.get_goal(goal))
    assert progress["headline"] == {"text": "Stopped at step {step} of {total}.", "values": {"step": 3, "total": 4}}
    assert progress["done"] == ["Step 1: part 1", "Step 2: part 2"]
    assert progress["remaining"] == ["Step 3: part 3", "Step 4: part 4"]
    assert progress["mode"] == "retry" and progress["saved_step"] is None


def test_unplanned_task_lists_its_recorded_steps_in_plain_words(chat):
    _client, world = chat
    goal = world.create_goal("Summarize spend", "")
    world.append_event(goal, "orchestrator-0-abc123", "observation", "tool=read_file -> vendor,amount")
    world.append_event(goal, "orchestrator-0-abc123", "observation", "tool=web_search -> 10 results")
    world.set_goal_status(goal, "cancelled", result="cancelled by operator")
    progress = summarize(world, world.get_goal(goal))
    assert progress["done"] == ["Read a file", "Searched the web"]
    assert progress["remaining"] == []
    assert progress["remaining_note"] == "Lightwork had not planned the remaining steps yet."
    assert progress["headline"]["values"] == {"count": 2}


def test_running_task_has_no_stop_progress(chat):
    _client, world = chat
    goal = world.create_goal("Still working", "")
    world.set_goal_status(goal, "active")
    assert summarize(world, world.get_goal(goal)) is None


def test_saved_progress_turns_try_again_into_resume(chat, monkeypatch):
    _client, world = chat
    goal = _planned(world, ["done", "pending"])
    from maverick_dashboard import stop_progress
    monkeypatch.setattr(stop_progress, "saved_step", lambda world, goal_id: 4)
    progress = summarize(world, world.get_goal(goal))
    assert progress["mode"] == "resume"
    assert progress["next"]["values"] == {"step": 4}


def test_saved_step_reads_the_real_checkpoint_store(chat, monkeypatch):
    _client, world = chat
    from maverick import checkpoint
    from maverick_dashboard.stop_progress import saved_step
    goal = _planned(world, ["done", "pending"])
    assert saved_step(world, goal) is None  # saving progress is off by default
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    episode = world.start_episode(goal)
    from maverick.budget import Budget
    assert checkpoint.Checkpointer(world).save(
        goal_id=goal, agent_id="orchestrator-0", step_seq=3, episode_id=episode,
        messages=[{"role": "user", "content": "brief"}], budget=Budget())
    assert saved_step(world, goal) == 3


def test_halt_card_and_api_show_progress(chat):
    client, world = chat
    goal = _planned(world, ["done", "pending"])
    page = client.get(f"/chat/goal/{goal}").text
    card = page.split('id="halt-card"', 1)[1].split('id="halt-resume-form"', 1)[0]
    assert "Stopped at step 2 of 2." in card
    assert "Step 1: part 1" in card and "Step 2: part 2" in card
    assert 'data-resume-mode="retry"' in page
    body = client.get(f"/api/v1/goals/{goal}/stop-progress").json()
    assert body["progress"]["done"] == ["Step 1: part 1"]
    assert re.search(r'id="halt-resume"[^>]*>(<span[^>]*>)?Try again', page)


def test_stop_progress_respects_task_access(chat, monkeypatch):
    client, world = chat
    goal = _planned(world, ["done"])
    from fastapi import HTTPException
    from maverick_dashboard import auth

    def deny(request, goal):
        raise HTTPException(404, "no such goal")
    monkeypatch.setattr(auth, "assert_goal_access", deny)
    assert client.get(f"/api/v1/goals/{goal}/stop-progress").status_code == 404


def test_stop_is_one_action_without_a_confirmation_dialog():
    source = TEMPLATE.read_text(encoding="utf-8")
    handler = source.split("cancelBtn.addEventListener('click'", 1)[1].split("});\n", 1)[0]
    assert "mvConfirm" not in handler and "confirm(" not in handler
    assert "/cancel" in handler
