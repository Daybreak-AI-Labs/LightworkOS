"""Semantic alerts survive missed polls, old task age and transaction rollback."""
import time

import pytest
from maverick.personal_notifications import PersonalInbox, validate_preferences
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    value = WorldModel(tmp_path / "world.db")
    yield value
    value.close()


def revision(world, goal):
    row = world.conn.execute("SELECT alert_state_revision,alert_result_revision FROM goals WHERE id=?", (goal,)).fetchone()
    return tuple(row)


def test_semantic_generation_ignores_heartbeat_and_detects_return_between_polls(world):
    goal = world.create_goal("Owned", owner="user:a")
    world.set_goal_status(goal, "blocked")
    first = revision(world, goal)
    world.set_goal_status(goal, "blocked")
    assert revision(world, goal) == first
    world.set_goal_status(goal, "active")
    world.set_goal_status(goal, "blocked")
    assert revision(world, goal)[0] == first[0] + 2
    with pytest.raises(RuntimeError), world._writing() as connection:
        connection.execute("UPDATE goals SET status='done' WHERE id=?", (goal,))
        raise RuntimeError("roll back native mutation")
    assert revision(world, goal)[0] == first[0] + 2
    assert world.get_goal(goal).status == "blocked"


def test_result_generation_only_counts_changes_after_completion(world):
    goal = world.create_goal("Owned", owner="user:a")
    world.set_goal_status(goal, "active", result="partial")
    world.set_goal_status(goal, "done", result="finished")
    assert revision(world, goal)[1] == 0
    world.set_goal_status(goal, "done", result="reviewed")
    assert revision(world, goal)[1] == 1


def test_projection_pages_old_problem_before_newer_history_and_owner_isolation(world):
    old = world.create_goal("Old unresolved task", owner="user:a")
    world.set_goal_status(old, "blocked")
    foreign = world.create_goal("Private to someone else", owner="user:b")
    with world._writing() as connection:
        connection.execute("UPDATE goals SET updated_at=1 WHERE id=?", (old,))
        for number in range(510):
            connection.execute("INSERT INTO goals(title,status,created_at,updated_at,owner) VALUES(?,?,?,?,?)",
                               (f"Recent {number}", "done", time.time(), time.time(), "user:a"))
    seen, after = [], 0
    while batch := world.personal_alert_goals("user:a", since=time.time() - 86400, after_id=after, limit=100):
        seen.extend(row[0].id for row in batch)
        after = batch[-1][0].id
    assert old in seen and foreign not in seen
    assert len(seen) == len(set(seen)) == 511


def test_inbox_does_not_drop_sources_after_one_thousand(tmp_path):
    inbox = PersonalInbox("user:a", tmp_path / "inbox.enc")
    sources = [{"ref": f"goal:{number}:state", "version": "blocked:1", "category": "blocked",
                "goal_id": number, "project_id": None} for number in range(1, 1005)]
    first = inbox.refresh(sources, validate_preferences({}))
    again = inbox.refresh(sources, validate_preferences({}))
    assert len(first["items"]) == len(again["items"]) == 1004
    assert {row["id"] for row in first["items"]} == {row["id"] for row in again["items"]}


def test_completed_edit_after_absence_notifies_once_and_identical_content_does_not(tmp_path):
    inbox = PersonalInbox("user:a", tmp_path / "inbox.enc")
    preferences = validate_preferences({"events": ["changed-result"]})
    inbox.refresh([], preferences)
    source = {"ref": "goal:1:result", "version": "digest:1", "semantic_digest": "digest",
              "changed_after_completion": True, "category": "changed-result", "goal_id": 1}
    assert len(inbox.refresh([source], preferences)["items"]) == 1
    source["version"] = "digest:2"
    assert not inbox.refresh([source], preferences)["items"]


def test_seen_state_and_revocation_remain_separate_from_delivery(tmp_path):
    inbox = PersonalInbox("user:a", tmp_path / "inbox.enc")
    preferences = validate_preferences({})
    source = {"ref": "goal:1:state", "version": "blocked:1", "category": "blocked", "goal_id": 1}
    row = inbox.refresh([source], preferences)["items"][0]
    assert row["delivered_at"] and row["seen_at"] is None
    seen = inbox.refresh([source], preferences, seen_id=row["id"])["items"][0]
    assert seen["seen_at"]
    assert not inbox.refresh([], preferences)["items"]
