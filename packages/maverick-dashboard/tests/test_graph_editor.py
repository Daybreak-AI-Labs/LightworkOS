"""Visual graph editor: layered layout (pure), forest API, structural edits.

The layout is computed server-side (maverick_dashboard.goal_tree) so the
page JS stays a thin renderer; edits go through POST endpoints that mutate
the goals table via the world model.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.goal_tree import (
    descendant_ids,
    forest_html,
    forest_view,
    layered_layout,
)

# ---------- pure layout ----------

def test_layout_single_chain_descends_by_depth():
    nodes = [{"id": 1, "parent_id": None}, {"id": 2, "parent_id": 1},
             {"id": 3, "parent_id": 2}]
    pos = layered_layout(nodes)
    assert pos[1][0] == 0 and pos[2][0] == 1 and pos[3][0] == 2
    # one leaf -> the whole chain shares its row
    assert pos[1][1] == pos[2][1] == pos[3][1] == 0.0


def test_layout_leaves_get_distinct_rows_and_parent_centers():
    nodes = [{"id": 1, "parent_id": None}, {"id": 2, "parent_id": 1},
             {"id": 3, "parent_id": 1}]
    pos = layered_layout(nodes)
    assert pos[2][1] != pos[3][1]
    assert pos[1][1] == pytest.approx((pos[2][1] + pos[3][1]) / 2)


def test_layout_forest_and_missing_parent_treated_as_root():
    nodes = [{"id": 1, "parent_id": None}, {"id": 5, "parent_id": 99}]
    pos = layered_layout(nodes)
    assert pos[1][0] == 0 and pos[5][0] == 0
    assert pos[1][1] != pos[5][1]


def test_layout_cycle_does_not_hang():
    nodes = [{"id": 1, "parent_id": 2}, {"id": 2, "parent_id": 1}]
    pos = layered_layout(nodes)
    assert set(pos) == {1, 2}


def test_descendant_ids():
    pairs = [(1, None), (2, 1), (3, 2), (4, None)]
    assert descendant_ids(pairs, 1) == {2, 3}
    assert descendant_ids(pairs, 2) == {3}
    assert descendant_ids(pairs, 4) == set()


def test_forest_view_edges_and_pixel_coords():
    nodes = [
        {"id": 1, "parent_id": None, "title": "root", "status": "pending"},
        {"id": 2, "parent_id": 1, "title": "kid", "status": "done"},
    ]
    view = forest_view(nodes)
    assert view["count"] == 2
    assert [1, 2] in view["edges"]
    by_id = {n["id"]: n for n in view["nodes"]}
    assert by_id[2]["x"] > by_id[1]["x"]          # children sit one layer right
    assert by_id[1]["depth"] == 0 and by_id[2]["depth"] == 1


def test_forest_html_escapes_titles():
    html = forest_html([{"id": 1, "parent_id": None,
                         "title": "<script>x</script>", "status": "pending"}])
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_forest_html_empty():
    assert "No tasks yet" in forest_html([])


# ---------- API + page ----------

@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    w = world_model.WorldModel(tmp_path / "world.db")
    yield w
    w.close()


@pytest.fixture
def client(world, monkeypatch):
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    monkeypatch.setattr(app_mod, "_world", lambda: world)
    monkeypatch.setattr(api_mod, "_world", lambda: world)
    return TestClient(app_mod.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture
def tree(world):
    g1 = world.create_goal("root", "r")
    g2 = world.create_goal("child A", "a", parent_id=g1)
    g3 = world.create_goal("grandchild", "g", parent_id=g2)
    g4 = world.create_goal("other root", "o")
    return g1, g2, g3, g4


def test_goal_tree_api_returns_layout(client, tree):
    g1, g2, g3, g4 = tree
    r = client.get("/api/v1/goal-tree")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 4
    by_id = {n["id"]: n for n in data["nodes"]}
    assert {"x", "y", "depth", "title", "status"} <= set(by_id[g1])
    assert [g1, g2] in data["edges"] and [g2, g3] in data["edges"]
    assert by_id[g4]["depth"] == 0


def test_graph_editor_page_renders(client, tree):
    r = client.get("/graph-editor")
    assert r.status_code == 200
    assert 'id="ge-svg"' in r.text
    # labeled editor controls (keyboard path) + the API it talks to
    assert 'for="ge-select"' in r.text and 'for="ge-title"' in r.text
    assert 'for="ge-parent"' in r.text and 'for="ge-child-title"' in r.text
    assert "/api/v1/goal-tree" in r.text
    # noscript fallback carries the real tree
    assert "<noscript>" in r.text and "root" in r.text


def test_retitle_persists(client, world, tree):
    g1, *_ = tree
    r = client.post(f"/api/v1/goals/{g1}/retitle", json={"title": "renamed root", "expected_updated_at": world.get_goal(g1).updated_at})
    assert r.status_code == 204
    assert world.get_goal(g1).title == "renamed root"


def test_retitle_rejects_blank_and_missing(client, world, tree):
    g1, *_ = tree
    assert client.post(f"/api/v1/goals/{g1}/retitle",
                       json={"title": "   ", "expected_updated_at": world.get_goal(g1).updated_at}).status_code == 400
    assert client.post("/api/v1/goals/99999/retitle",
                       json={"title": "x", "expected_updated_at": 1}).status_code == 404


def test_reparent_moves_subtree(client, world, tree):
    g1, g2, g3, g4 = tree
    r = client.post(f"/api/v1/goals/{g4}/reparent", json={"parent_id": g1, "expected_updated_at": world.get_goal(g4).updated_at})
    assert r.status_code == 204
    assert world.get_goal(g4).parent_id == g1


def test_reparent_to_root(client, world, tree):
    g1, g2, *_ = tree
    r = client.post(f"/api/v1/goals/{g2}/reparent", json={"parent_id": None, "expected_updated_at": world.get_goal(g2).updated_at})
    assert r.status_code == 204
    assert world.get_goal(g2).parent_id is None


def test_reparent_refuses_cycles_and_self(client, world, tree):
    g1, g2, g3, g4 = tree
    # under its own grandchild -> cycle
    r = client.post(f"/api/v1/goals/{g1}/reparent", json={"parent_id": g3, "expected_updated_at": world.get_goal(g1).updated_at})
    assert r.status_code == 400
    assert "descendant" in r.json()["detail"]
    assert world.get_goal(g1).parent_id is None  # unchanged
    # under itself
    assert client.post(f"/api/v1/goals/{g1}/reparent",
                       json={"parent_id": g1, "expected_updated_at": world.get_goal(g1).updated_at}).status_code == 400
    # under a goal that doesn't exist
    assert client.post(f"/api/v1/goals/{g1}/reparent",
                       json={"parent_id": 4242, "expected_updated_at": world.get_goal(g1).updated_at}).status_code == 404


def test_create_child_is_pending_and_not_started(client, world, tree):
    g1, *_ = tree
    r = client.post(f"/api/v1/goals/{g1}/children",
                    json={"title": "new subgoal", "description": "details",
                          "operation_id": "new-child-operation-1"})
    assert r.status_code == 201
    body = r.json()
    assert body["status"] == "pending"
    child = world.get_goal(body["id"])
    assert child.parent_id == g1
    assert child.description == "details"


def test_create_child_rejects_blank_title_and_missing_parent(client, tree):
    g1, *_ = tree
    assert client.post(f"/api/v1/goals/{g1}/children",
                       json={"title": " ", "operation_id": "blank-child-operation-1"}).status_code == 400
    assert client.post("/api/v1/goals/99999/children",
                       json={"title": "x", "operation_id": "missing-child-operation-1"}).status_code == 404


def test_mutations_blocked_cross_origin(client, world, tree):
    """The central CSRF gate covers the new endpoints (no Origin -> 403)."""
    g1, *_ = tree
    bare = TestClient(client.app, base_url="http://127.0.0.1")  # no Origin header
    r = bare.post(f"/api/v1/goals/{g1}/retitle", json={"title": "evil"})
    assert r.status_code == 403
    assert world.get_goal(g1).title == "root"


def test_task_map_page_reads_plainly(tmp_path, monkeypatch):
    """The map speaks of tasks and never shows raw status keys or #ids."""
    from fastapi.testclient import TestClient
    from maverick import world_model
    from maverick_dashboard.app import app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from test_support.plain_language import developer_terms

    r = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/graph-editor")
    assert r.status_code == 200
    assert "Task map" in r.text and "Add smaller task" in r.text
    assert "request failed (" not in r.text and '"#" + n.id' not in r.text
    assert developer_terms(r.text) == []
