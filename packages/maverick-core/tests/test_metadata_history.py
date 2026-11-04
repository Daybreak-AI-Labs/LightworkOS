"""Historical metadata windows preserve encrypted bodies and source authority."""
import json
import time

import pytest
from maverick import config
from maverick.metadata_history import HistoryChanged, sql_window, world_window
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    config.reset_config_cache()
    with WorldModel(tmp_path / "history.db") as value:
        yield value
    config.reset_config_cache()


def seed(world, count=10050):
    with world._writing() as connection:
        connection.executemany("INSERT INTO goals(title,description,status,created_at,updated_at,owner,domain) VALUES(?,?,'done',?,?,?,?)",
            [("Oldest match" if index == 0 else "Recent task " + str(index), "NEVER_SEARCH_PRIVATE_BODY", 1000 + index, 1000 + index, "user:alice", "") for index in range(count)])
        connection.execute("INSERT INTO goals(title,description,status,created_at,updated_at,owner,domain) VALUES('Other-owner secret','body','done',0,0,'user:bob','')")
        connection.execute("INSERT INTO goals(title,description,status,created_at,updated_at,owner,domain) VALUES('Hidden department','body','done',0,0,'user:alice','security')")


def test_oldest_of_ten_thousand_is_findable_in_bounded_native_window(world):
    seed(world)
    start = time.monotonic()
    value = world_window(world, source="tasks", owner="user:alice", allowed_domain=lambda domain: domain != "security", oldest=True)
    elapsed = time.monotonic() - start
    assert len(value.rows) == 250 and value.next_offset == 250
    assert value.rows[0]["title"] == "Oldest match"
    assert "NEVER_SEARCH_PRIVATE_BODY" not in json.dumps(value.rows)
    assert "Other-owner secret" not in json.dumps(value.rows)
    assert "Hidden department" not in json.dumps(value.rows)
    assert elapsed < 5, f"Native metadata window took {elapsed:.3f}s for 10050 records"
    print(f"10050 task metadata rows: {elapsed:.4f}s, 250 returned")
    exact = world_window(world, source="tasks", owner="user:alice", allowed_domain=lambda domain: domain != "security", after=1000, before=1001)
    assert len(exact.rows) == 1 and exact.next_offset is None


def test_epochs_change_for_metadata_edits_but_private_bodies_are_not_selected(world):
    seed(world, 3)
    args = dict(source="tasks", owner="user:alice", allowed_domain=lambda _: True)
    before = world_window(world, **args)
    with world._writing() as connection:
        connection.execute("UPDATE goals SET title='Changed' WHERE id=1")
    assert before.snapshot != world_window(world, **args).snapshot
    with world._writing() as connection:
        connection.execute("UPDATE goals SET description='Changed private body' WHERE id=1")
    assert "description" not in world_window(world, **args).rows[0]


def test_private_fact_names_are_excluded_before_snapshot_even_mixed_case(world):
    world.upsert_fact("shared", "DO_NOT_RETURN_VALUE")
    world.upsert_fact("USER:alice", "private")
    world.upsert_fact("Goal:8:private", "private")
    args = dict(source="facts", owner="user:alice", allowed_domain=lambda _: True)
    before = world_window(world, **args)
    assert [row["key"] for row in before.rows] == ["shared"]
    assert "DO_NOT_RETURN_VALUE" not in json.dumps(before.rows)
    world.upsert_fact("user:bob", "another private value")
    assert before.snapshot == world_window(world, **args).snapshot


def test_project_window_has_no_description_or_child_task_load(world):
    world.create_project("My project", description="PRIVATE PROJECT CONTENT", owner="user:alice")
    world.create_project("Other project", owner="user:bob")
    value = world_window(world, source="projects", owner="user:alice", allowed_domain=lambda _: True)
    assert [row["name"] for row in value.rows] == ["My project"]
    assert "description" not in value.rows[0]


def test_concurrent_native_change_rejects_window(world):
    seed(world, 2)
    calls = 0
    def execute(sql, params=()):
        nonlocal calls
        calls += 1
        if calls == 3:
            world.conn.execute("UPDATE goals SET title='Concurrent' WHERE id=1")
        return world.conn.execute(sql, params)
    with pytest.raises(HistoryChanged):
        sql_window(execute, table="goals", columns="id,title", stamp="id,title", order="id")


def test_native_assessment_history_reaches_beyond_thousand_without_bodies(tmp_path, monkeypatch):
    import os

    from maverick import assessment
    directory = tmp_path / "assessments"
    directory.mkdir()
    monkeypatch.setattr(assessment, "_assessments_dir", lambda: directory)
    for index in range(1005):
        path = directory / (f"assessment-{index:04d}.json")
        path.write_text(json.dumps({"id":path.stem, "type":"pia", "subject":"Oldest" if index == 0 else "Recent",
                                   "status":"draft", "revision":1, "answers":{"private":"NEVER_RETURN"}}), encoding="utf-8")
        os.utime(path, (1000 + index, 1000 + index))
    ordinary, count = assessment.list_saved_heads(limit=1000)
    assert count == 1005 and len(ordinary) == 1000
    value = assessment.history_heads(oldest=True)
    assert value.rows[0]["subject"] == "Oldest" and len(value.rows) == 250
    assert "NEVER_RETURN" not in json.dumps(value.rows)
    older = assessment.history_heads(offset=1000)
    assert len(older.rows) == 5 and older.rows[-1]["subject"] == "Oldest" and older.next_offset is None
    assert older.snapshot == assessment.history_heads().snapshot
    only = assessment.history_heads(after=1000, before=1001)
    assert len(only.rows) == 1 and only.rows[0]["subject"] == "Oldest"


def test_scan_budget_requires_narrowing_and_date_filter_uses_owner_index(world, monkeypatch):
    from maverick import metadata_history
    seed(world, 10)
    monkeypatch.setattr(metadata_history, "MAX_METADATA", 5)
    args = dict(source="tasks", owner="user:alice", allowed_domain=lambda domain: not domain)
    with pytest.raises(metadata_history.HistoryNarrowing):
        world_window(world, **args)
    assert len(world_window(world, **args, after=1000, before=1001).rows) == 1
    plan = world._read_all("EXPLAIN QUERY PLAN SELECT id,title,status FROM goals WHERE owner=? AND created_at>=? AND created_at<? ORDER BY created_at,id", ("user:alice", 1000, 1001))
    assert any("idx_goals_owner_created_history" in row[3] for row in plan)


def test_assessment_window_excludes_denied_metadata_before_matches(tmp_path, monkeypatch):
    from maverick import assessment
    directory = tmp_path / "assessments"
    directory.mkdir()
    monkeypatch.setattr(assessment, "_assessments_dir", lambda: directory)
    (directory / "visible.json").write_text(json.dumps({"id":"visible", "type":"pia", "revision":1}), encoding="utf-8")
    before = assessment.history_heads(allowed_types={"pia"})
    (directory / "private.json").write_text(json.dumps({"id":"private", "type":"soc2", "revision":1}), encoding="utf-8")
    after = assessment.history_heads(allowed_types={"pia"})
    assert before.rows == after.rows
    assert "private" not in json.dumps(after.rows)
    assert after.next_offset is None
