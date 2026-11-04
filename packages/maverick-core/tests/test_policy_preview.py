"""Previews of a policy change before it is saved: blocking tools,
a shorter keep period and a data use rule. Report only, from the record."""
from __future__ import annotations

import time

import pytest
from maverick import policy_preview

NOW = 1_800_000_000.0


@pytest.fixture
def world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    w = WorldModel(tmp_path / "world.db")
    yield w
    w.close()
    config.reset_config_cache()


def _call(name, goal, agent, *, ago=86400.0):
    return {"kind": "tool_call", "name": name, "goal_id": goal, "agent": agent, "ts": NOW - ago}


def test_blocking_a_tool_counts_its_recorded_calls_tasks_agents_and_people(world):
    ana = world.create_goal("Pay invoices", owner="user:ana")
    ben = world.create_goal("Check vendors", owner="user:ben")
    events = [_call("web_fetch", ana, "finance_ap"), _call("web_fetch", ana, "finance_ap"),
              _call("web_fetch", ben, "vendor_review"), _call("shell", ben, "vendor_review"),
              _call("web_fetch", ben, "vendor_review", ago=40 * 86400.0),  # older than 30 days
              {"kind": "goal_created", "ts": NOW - 10}]
    shown = policy_preview.tool_block(["web_fetch"], now=NOW, events=events)
    assert (shown["calls"], shown["tasks"], shown["agents"], shown["people"]) == (3, 2, 2, 2)
    assert shown["recorded"] is True and "activity record" in shown["basis"]
    one = policy_preview.tool_block(["web_fetch"], agent="finance_ap", now=NOW, events=events)
    assert (one["calls"], one["tasks"], one["agents"], one["people"]) == (2, 1, 1, 1)


def test_no_record_says_so_instead_of_guessing(world):
    shown = policy_preview.tool_block(["web_fetch"], now=NOW, events=[])
    assert shown["recorded"] is False and shown["calls"] == 0
    assert "nothing to count" in shown["basis"]
    with pytest.raises(ValueError):
        policy_preview.tool_block([], now=NOW, events=[])


def test_a_shorter_keep_period_counts_what_the_next_clean_up_would_delete(world, tmp_path):
    import sqlite3

    goal = world.create_goal("Old task", owner="user:ana")
    old = world.append_event(goal, "agent", "status", "old progress")
    world.append_event(goal, "agent", "status", "new progress")
    db = sqlite3.connect(str(tmp_path / "world.db"))
    with db:
        db.execute("UPDATE goal_events SET ts = ? WHERE id = ?", (time.time() - 90 * 86400, old))
    shown = policy_preview.retention("events_days", "30")
    assert shown["count"] == 1 and shown["unit"] == "task progress update"
    assert "Nothing was deleted" in shown["basis"]
    assert db.execute("SELECT COUNT(*) FROM goal_events WHERE goal_id = ?", (goal,)).fetchone()[0] == 2
    db.close()
    assert policy_preview.retention("messages_days", "")["days"] is None
    with pytest.raises(ValueError):
        policy_preview.retention("events_days", "0")
    with pytest.raises(ValueError):
        policy_preview.retention("goals_days", "30")


def test_a_data_use_rule_counts_the_recorded_requests_it_would_cover():
    rule = {"scope": {"asset_ids": ["crm"], "actions": ["export"]},
            "conditions": {}, "controls": [{"control_id": "c1", "effect": "deny"}]}
    requests = [
        {"asset_id": "crm", "action": "export", "project_id": "p1", "requester_id": "ana", "field_ids": ["email"], "created_at": NOW - 100},
        {"asset_id": "crm", "action": "export", "project_id": "p2", "requester_id": "ben", "field_ids": ["email"], "created_at": NOW - 100},
        {"asset_id": "crm", "action": "read", "project_id": "p1", "requester_id": "ana", "field_ids": ["email"], "created_at": NOW - 100},
        {"asset_id": "hr", "action": "export", "project_id": "p1", "requester_id": "ana", "field_ids": ["salary"], "created_at": NOW - 100},
        {"asset_id": "crm", "action": "export", "project_id": "p3", "requester_id": "cy", "field_ids": ["email"], "created_at": NOW - 40 * 86400},
    ]
    shown = policy_preview.data_use_rule(rule, requests, now=NOW)
    assert (shown["considered"], shown["requests"], shown["projects"], shown["people"]) == (4, 2, 2, 2)
    assert shown["effects"] == ["deny"] and shown["conditional"] is False
    conditional = policy_preview.data_use_rule({**rule, "conditions": {"consent_any": ["marketing"]}}, requests, now=NOW)
    assert conditional["conditional"] is True and "may cover fewer" in conditional["basis"]
