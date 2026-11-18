"""Resuming a stopped task without saved progress repeats finished paid work.

Field finding: after a budget stop, resume repeated every paid search (Tavily
calls 10 -> 32, $3.75 in all). With durable execution off, a resumed attempt
starts a new conversation, so nothing it already paid for can be reused. The
person is told before resuming, with the last attempt's spend.
"""
from __future__ import annotations

from maverick import goal_resume
from maverick.budget import Budget
from maverick.world_model import WorldModel


def _stopped_goal(tmp_path, spent=1.16):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("Research competitor pricing", "")
    episode = world.start_episode(goal_id)
    world.end_episode(episode, "stopped", "interrupted", cost_dollars=spent, tool_calls=10)
    world.set_goal_status(goal_id, "blocked", result="Stopped: this goal hit your spending limit")
    return world, goal_id


def test_resume_without_saved_progress_warns_with_the_expected_respend(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_DURABLE", raising=False)
    world, goal_id = _stopped_goal(tmp_path)
    notice = goal_resume.respend_notice(world, goal_id)
    assert "from the beginning" in notice
    assert "paid" in notice
    assert "$1.16" in notice


def test_resume_with_saved_progress_does_not_warn(tmp_path, monkeypatch):
    from maverick.checkpoint import Checkpointer

    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    world, goal_id = _stopped_goal(tmp_path)
    episode = world.list_episodes(goal_id=goal_id)[0].id
    Checkpointer(world).save(goal_id=goal_id, episode_id=episode, agent_id="orchestrator-0",
                             step_seq=4, messages=[{"role": "user", "content": "brief"}],
                             budget=Budget(max_dollars=2))
    assert goal_resume.respend_notice(world, goal_id) == ""


def test_resume_of_unpaid_work_has_nothing_to_warn_about(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_DURABLE", raising=False)
    world, goal_id = _stopped_goal(tmp_path, spent=0.0)
    assert goal_resume.respend_notice(world, goal_id) == ""
