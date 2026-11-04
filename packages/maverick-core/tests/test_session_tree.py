"""Session forking: counterfactual runs recorded beside what actually ran —
replay without re-execution, lineage in the sidecar, and a tree read that
survives corruption and erased runs."""
from __future__ import annotations

import json

import pytest
from maverick import session_tree as st


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _run(steps=("planned", "called the API", "wrote the file"),
         owner="ada@corp.test"):
    """A parent run: one goal with an ordered event trail."""
    from maverick.world_model import open_world
    world = open_world()
    gid = world.create_goal("ship the migration", "cutover plan", owner=owner,
                            domain="platform")
    ids = [world.append_event(gid, "planner", "status", s) for s in steps]
    return gid, ids


def _contents(goal_id):
    from maverick.world_model import open_world
    return [e.content for e in open_world().goal_events(goal_id, limit=500)]


def test_disabled_plane_refuses_to_fork(monkeypatch, tmp_path):
    gid, _ = _run()
    (tmp_path / "config.toml").write_text("[session_tree]\nenable = false\n")
    from maverick import config
    config.reset_config_cache()
    assert st.enabled() is False
    with pytest.raises(st.SessionTreeError, match="off"):
        st.fork(gid)


def test_fork_copies_the_trail_up_to_the_event_and_no_further():
    gid, ids = _run()
    child = st.fork(gid, at_event=ids[1], label="try the blue/green path",
                    forked_by="ada@corp.test")
    copied = _contents(child)
    assert copied[:2] == ["planned", "called the API"]
    assert "wrote the file" not in copied
    # ...and the branch says where it came from.
    assert copied[-1].startswith(f"forked from goal #{gid} at event #{ids[1]}")
    assert "try the blue/green path" in copied[-1]
    # The parent is untouched -- a fork records, it never rewrites history.
    assert _contents(gid) == ["planned", "called the API", "wrote the file"]


def test_fork_creates_a_real_goal_owned_by_the_same_principal():
    from maverick.world_model import open_world
    gid, _ = _run(owner="ada@corp.test")
    child = st.fork(gid)
    goal = open_world().get_goal(child)
    assert goal is not None and goal.id == child != gid
    assert goal.owner == "ada@corp.test"
    assert goal.domain == "platform"
    assert f"fork of #{gid}" in goal.title


def test_fork_without_an_event_copies_the_whole_trail():
    gid, _ = _run()
    child = st.fork(gid)
    copied = _contents(child)
    assert copied[:3] == ["planned", "called the API", "wrote the file"]
    assert copied[-1].endswith("at its full trail by operator")


def test_fork_refuses_an_unknown_goal_and_an_out_of_range_event():
    gid, ids = _run()
    with pytest.raises(st.SessionTreeError, match="does not exist"):
        st.fork(999_999)
    with pytest.raises(st.SessionTreeError, match="not on goal"):
        st.fork(gid, at_event=max(ids) + 1000)
    # An event id belonging to a DIFFERENT goal is out of range too.
    other, other_ids = _run(steps=("unrelated",))
    with pytest.raises(st.SessionTreeError, match="not on goal"):
        st.fork(gid, at_event=other_ids[0])
    assert other != gid


def test_depth_cap_refuses_the_fork_past_max_depth(tmp_path):
    from maverick import config
    (tmp_path / "config.toml").write_text("[session_tree]\nmax_depth = 2\n")
    config.reset_config_cache()
    gid, _ = _run()
    child = st.fork(gid)              # depth 1
    grandchild = st.fork(child)       # depth 2 -- at the cap
    with pytest.raises(st.SessionTreeError, match="max_depth"):
        st.fork(grandchild)           # depth 3 -- past it


def test_lineage_reports_parent_children_depth_and_root():
    gid, _ = _run()
    a = st.fork(gid, label="alternative A")
    b = st.fork(gid, label="alternative B")
    deep = st.fork(a)

    root = st.lineage(gid)
    assert root["parent"] is None and root["depth"] == 0 and root["root"] == gid
    assert root["children"] == sorted([a, b])

    branch = st.lineage(a)
    assert branch["parent"] == gid and branch["depth"] == 1
    assert branch["root"] == gid and branch["children"] == [deep]
    assert branch["label"] == "alternative A"

    assert st.lineage(deep)["depth"] == 2
    assert st.lineage(deep)["root"] == gid


def test_tree_nests_grandchildren_under_one_root():
    gid, ids = _run()
    a = st.fork(gid, at_event=ids[0], label="A")
    deep = st.fork(a, label="A2")
    st.fork(gid, label="B")

    node = st.tree(gid)
    assert node["goal_id"] == gid and node["label"] == ""
    assert [c["label"] for c in node["children"]] == ["A", "B"]
    first = node["children"][0]
    assert first["goal_id"] == a and first["forked_at_event"] == ids[0]
    assert [c["goal_id"] for c in first["children"]] == [deep]


def test_roots_lists_forked_runs_newest_first():
    older, _ = _run()
    st.fork(older)
    newer, _ = _run()
    st.fork(newer)
    st.fork(newer)
    rows = st.roots()
    assert [r["goal_id"] for r in rows] == [newer, older]
    assert rows[0]["forks"] == 2 and rows[1]["forks"] == 1
    assert rows[0]["status"] == "pending"


def test_a_corrupt_sidecar_degrades_to_empty(caplog):
    gid, _ = _run()
    st.fork(gid)
    st.registry_path().write_text("{not json at all")
    with caplog.at_level("WARNING"):
        assert st.roots() == []
        assert st.lineage(gid) == {
            "goal_id": gid, "parent": None, "children": [], "depth": 0,
            "root": gid, "label": "", "forked_at_event": None}
        assert st.tree(gid)["children"] == []
    assert "unreadable" in caplog.text


def test_cyclic_lineage_is_refused_rather_than_walked():
    gid, _ = _run()
    child = st.fork(gid)
    # Only a hand-edited/corrupt sidecar can do this -- fork() always mints a
    # fresh child id -- but walking it would hang, so it must refuse.
    st.registry_path().write_text(json.dumps({
        str(gid): {"parent_goal_id": child, "forked_at_event": None},
        str(child): {"parent_goal_id": gid, "forked_at_event": None},
    }))
    with pytest.raises(st.SessionTreeError, match="cyclic"):
        st.fork(gid)
    assert st.lineage(gid)["root"] == gid   # reads degrade, they don't raise
    assert st.roots() == []


def test_tree_skips_a_deleted_child_goal():
    from maverick.world_model import open_world
    gid, _ = _run()
    kept = st.fork(gid, label="kept")
    gone = st.fork(gid, label="erased")
    world = open_world()
    with world._writing() as conn:            # simulate an erasure/retention drop
        conn.execute("DELETE FROM goal_events WHERE goal_id = ?", (gone,))
        conn.execute("DELETE FROM goals WHERE id = ?", (gone,))
    node = st.tree(gid)
    assert [c["goal_id"] for c in node["children"]] == [kept]


def test_fork_audits_session_forked(monkeypatch, tmp_path):
    import maverick.audit.writer as w
    from maverick.audit.writer import AuditLog
    log = AuditLog(audit_dir=tmp_path / "audit")
    monkeypatch.setattr(w, "default_audit_log", lambda: log)
    gid, ids = _run()
    child = st.fork(gid, at_event=ids[1], label="counterfactual",
                    forked_by="ada@corp.test")
    rows = [e for e in log.tail(200) if e.get("kind") == "session_forked"]
    assert len(rows) == 1
    row = rows[0]
    assert row["parent_goal_id"] == gid and row["child_goal_id"] == child
    assert row["at_event"] == ids[1] and row["forked_by"] == "ada@corp.test"
    assert row["label"] == "counterfactual" and row["replayed_events"] == 2


def test_forking_never_executes_anything(monkeypatch):
    # The whole point: a branch is a record, so no sandbox and no tool runs.
    from maverick.sandbox import LocalBackend
    called = []
    monkeypatch.setattr(LocalBackend, "exec",
                        lambda self, cmd, timeout=None: called.append(cmd))
    gid, _ = _run()
    st.fork(gid)
    assert called == []
