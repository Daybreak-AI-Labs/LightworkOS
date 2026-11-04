"""Result sets resolve the at-rest policy and the key once per query.

Decoding row by row checked the policy (the compliance profile configuration)
and loaded the key for every sealed field: listing 500 approvals took 250-450
ms, and a page reading 500 runs or facts paid the same again. Each batch must
read exactly as its rows decoded one at a time.
"""
from __future__ import annotations

import sqlite3

import pytest
from maverick import crypto_at_rest, world_model
from maverick.episode_reporting import iter_episodes


def _counting(monkeypatch, *names):
    calls = {"n": 0}
    for name in names:
        original = getattr(crypto_at_rest, name)

        def counting(*args, _original=original, **kwargs):
            calls["n"] += 1
            return _original(*args, **kwargs)

        monkeypatch.setattr(crypto_at_rest, name, counting)
    return calls


def _rows(path, sql):
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql).fetchall()


@pytest.fixture
def sealed_world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    path = tmp_path / "w.db"
    wm = world_model.WorldModel(path)
    for i in range(25):
        gid = wm.create_goal(f"goal {i}", f"description {i}")
        episode = wm.start_episode(gid)
        wm.end_episode(episode, f"summary {i}", "success" if i % 2 else "failure", cost_dollars=0.5)
        wm.upsert_fact(f"customer.{i}", f"prefers email {i}", episode)
        wm.create_approval(f"email.send #{i}", scope="crm", detail=f"draft {i}")
    return wm, path


READS = {
    "list_approvals": lambda wm: wm.list_approvals(limit=100),
    "pending_approvals": lambda wm: wm.pending_approvals(),
    "list_goals": lambda wm: wm.list_goals(limit=100),
    "list_episodes": lambda wm: wm.list_episodes(limit=100),
    "get_facts": lambda wm: wm.get_facts(),
    "get_facts_with_trust": lambda wm: wm.get_facts_with_trust(),
    "fact_records": lambda wm: wm.fact_records(limit=100),
    "iter_episodes": lambda wm: list(iter_episodes(wm)),
}


@pytest.mark.parametrize("read", sorted(READS))
def test_a_query_checks_the_policy_and_loads_the_key_once(sealed_world, monkeypatch, read):
    wm, _ = sealed_world
    policy = _counting(monkeypatch, "at_rest_enabled")
    keys = _counting(monkeypatch, "_load_or_create_key", "_resolve_key_by_id")
    result = READS[read](wm)
    assert len(result) == 25
    assert policy["n"] == 1
    assert keys["n"] == 1


def _with_legacy_rows(path):
    # Rows written before encryption was on keep their plaintext.
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE approvals SET action = 'legacy action', scope = NULL WHERE id = 1")
        conn.execute("UPDATE goals SET title = 'legacy title' WHERE id = 1")
        conn.execute("UPDATE episodes SET outcome = 'legacy outcome' WHERE id = 1")
        conn.execute("UPDATE facts SET value = 'legacy value' WHERE key = 'customer.1'")


@pytest.mark.parametrize("strict", ["0", "1"])
def test_each_batch_reads_exactly_as_its_rows_one_at_a_time(sealed_world, monkeypatch, strict):
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", strict)
    wm, path = sealed_world
    _with_legacy_rows(path)
    approvals = _rows(path, "SELECT * FROM approvals ORDER BY requested_at DESC, id DESC")
    assert approvals[0]["action"] != "email.send #24", "the column is really sealed"
    assert wm.list_approvals(limit=100) == [world_model._approval_from_row(r) for r in approvals]
    pending = _rows(path, "SELECT * FROM approvals WHERE status = 'pending' ORDER BY id")
    assert wm.pending_approvals() == [world_model._approval_from_row(r) for r in pending]
    goals = _rows(path, "SELECT * FROM goals ORDER BY id")
    assert world_model._goals_from_rows(goals) == [world_model._goal_from_row(r) for r in goals]
    episodes = wm.list_episodes(limit=100)
    by_id = {e.id: e for e in episodes}
    raw = {r["id"]: r for r in _rows(path, "SELECT * FROM episodes")}
    for episode_id, row in raw.items():
        assert by_id[episode_id].outcome == world_model._dec_field(row["outcome"])
    assert {e.id: e.outcome for e in iter_episodes(wm)} == {e.id: e.outcome for e in episodes}
    facts = _rows(path, "SELECT key, value, trust_tier FROM facts ORDER BY id DESC")
    assert wm.get_facts() == {r["key"]: world_model._dec_field(r["value"]) for r in facts}
    assert wm.get_facts_with_trust() == {
        r["key"]: (world_model._dec_field(r["value"]), int(r["trust_tier"])) for r in facts}
    assert {r["key"]: r["value"] for r in wm.fact_records(limit=100)} == {
        r["key"]: world_model._dec_field(r["value"]) for r in facts}
    withheld = world_model._UNSEALED_WITHHELD
    legacy = {a.id: a for a in wm.list_approvals(limit=100)}[1]
    assert legacy.scope is None
    assert legacy.action == (withheld if strict == "1" else "legacy action")
    assert wm.get_facts()["customer.1"] == (withheld if strict == "1" else "legacy value")
    assert wm.get_facts()["customer.2"] == "prefers email 2"


def test_with_encryption_off_values_pass_through_untouched(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    path = tmp_path / "w.db"
    wm = world_model.WorldModel(path)
    wm.create_approval("email.send", scope="crm", detail="hello")
    rows = _rows(path, "SELECT * FROM approvals")
    assert rows[0]["action"] == "email.send"
    assert world_model._approvals_from_rows(rows) == [world_model._approval_from_row(rows[0])]
    assert world_model._approvals_from_rows([]) == []
    assert world_model._goals_from_rows([]) == []
    assert world_model._episode_spends_from_rows([]) == []


@pytest.mark.parametrize("strict", ["0", "1"])
def test_goals_read_together_equal_goals_read_one_by_one(sealed_world, monkeypatch, strict):
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", strict)
    wm, path = sealed_world
    _with_legacy_rows(path)
    ids = [1, 2, 3, 25, 999]
    one_by_one = {gid: wm.get_goal(gid) for gid in ids}
    together = wm.get_goals(ids + [2])
    assert together == {gid: goal for gid, goal in one_by_one.items() if goal is not None}
    assert 999 not in together and together[1].title == (
        world_model._UNSEALED_WITHHELD if strict == "1" else "legacy title")
    rows = {r["id"]: r for r in _rows(path, "SELECT * FROM goals")}
    assert wm.get_goal(2) == world_model._goal_from_row(rows[2])


@pytest.mark.parametrize("read", ["get_goal", "get_goals"])
def test_a_goal_read_loads_the_key_once(sealed_world, monkeypatch, read):
    # Each sealed field (title, description, result) loaded the key again.
    wm, _ = sealed_world
    keys = _counting(monkeypatch, "_load_or_create_key", "_resolve_key_by_id")
    goal = wm.get_goal(3) if read == "get_goal" else wm.get_goals(range(1, 26))[3]
    assert goal.title == "goal 2" and keys["n"] == 1


def test_goals_by_id_falls_back_to_one_read_per_goal(sealed_world):
    wm, _ = sealed_world

    class OneByOne:
        def get_goal(self, goal_id):
            return wm.get_goal(goal_id)

    assert world_model.goals_by_id(OneByOne(), [3, 1, 3, 999]) == wm.get_goals([1, 3])


def test_experience_recall_reads_its_goals_together(sealed_world, monkeypatch):
    from maverick import experience

    wm, _ = sealed_world
    monkeypatch.setattr(experience, "enabled", lambda: True)
    singles = []

    class OneByOne:
        def list_episodes(self, **kwargs):
            return wm.list_episodes(**kwargs)

        def get_goal(self, goal_id):
            singles.append(goal_id)
            return wm.get_goal(goal_id)

    expected = experience.recall(OneByOne(), "goal 7 follow-up")
    assert expected and singles, "the fallback reads each goal"
    original = wm.get_goal
    monkeypatch.setattr(wm, "get_goal", lambda goal_id: singles.append(goal_id) or original(goal_id))
    singles.clear()
    assert experience.recall(wm, "goal 7 follow-up") == expected and singles == []
