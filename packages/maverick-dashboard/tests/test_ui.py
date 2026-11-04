"""Dashboard pages: the plan tree, trajectory replay and the cost CSV export."""
from __future__ import annotations

import pytest

# Skip the module entirely if FastAPI isn't installed.
fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


@pytest.fixture
def world_with_tree(tmp_path, monkeypatch):
    """A WorldModel with a small parent/child goal tree + episodes."""
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.world_model import WorldModel
    db_path = tmp_path / "world.db"
    w = WorldModel(db_path)
    # Root + 2 children + 1 grandchild + episodes for cost rollup.
    g1 = w.create_goal("root task", "high-level")
    g2 = w.create_goal("subtask A", "child of 1", parent_id=g1)
    g3 = w.create_goal("subtask B", "child of 1", parent_id=g1)
    g4 = w.create_goal("sub-subtask", "child of 2", parent_id=g2)
    # Add a couple episodes for cost rollup.
    import time as _t
    w.conn.execute(
        "INSERT INTO episodes(goal_id, started_at, ended_at, outcome, "
        "cost_dollars, input_tokens, output_tokens, tool_calls) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        (g2, _t.time() - 100, _t.time(), "succeeded", 0.05, 1000, 200, 3),
    )
    w.conn.execute(
        "INSERT INTO episodes(goal_id, started_at, ended_at, outcome, "
        "cost_dollars, input_tokens, output_tokens, tool_calls) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        (g3, _t.time() - 50, _t.time(), "failed", 0.02, 500, 100, 1),
    )
    # An event for trajectory rendering.
    w.append_event(g1, "orchestrator", "tool", "called shell: ls")
    w.append_event(g2, "coder", "tool", "called read_file")
    w.commit() if hasattr(w, "commit") else w.conn.commit()
    yield w, g1, g2, g3, g4
    w.close()


@pytest.fixture
def client(world_with_tree, monkeypatch):
    """Wired-up TestClient sharing the same world db as the fixture."""
    # Patch the dashboard's _world() to point at our test db.
    from maverick_dashboard import app as app_mod
    w, g1, g2, g3, g4 = world_with_tree
    monkeypatch.setattr(app_mod, "_world", lambda: w)
    return TestClient(app_mod.app, base_url="http://127.0.0.1")


def test_plan_tree_api_returns_root_with_children(client, world_with_tree):
    _, g1, g2, g3, g4 = world_with_tree
    resp = client.get(f"/api/v1/goals/{g1}/tree")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == g1
    assert data["title"] == "root task"
    child_ids = sorted(c["id"] for c in data["children"])
    assert g2 in child_ids
    assert g3 in child_ids
    # g4 is grandchild of g2.
    g2_node = next(c for c in data["children"] if c["id"] == g2)
    grand_ids = [c["id"] for c in g2_node["children"]]
    assert g4 in grand_ids


def test_plan_tree_api_includes_episode_dollars(client, world_with_tree):
    _, g1, g2, _g3, _g4 = world_with_tree
    resp = client.get(f"/api/v1/goals/{g1}/tree")
    data = resp.json()
    g2_node = next(c for c in data["children"] if c["id"] == g2)
    assert g2_node["dollars"] == pytest.approx(0.05, abs=1e-6)


def test_plan_tree_api_unknown_goal_returns_404(client):
    resp = client.get("/api/v1/goals/99999/tree")
    assert resp.status_code == 404


def test_plan_tree_html_renders(client, world_with_tree):
    _, g1, *_ = world_with_tree
    resp = client.get(f"/goals/{g1}/plan")
    assert resp.status_code == 200
    body = resp.text
    # Renders the root task link + the page title.
    assert f'href="/chat/goal/{g1}"' in body
    assert "Plan tree" in body or "plan tree" in body.lower()


def test_trajectory_html_renders(client, world_with_tree):
    _, g1, *_ = world_with_tree
    resp = client.get(f"/goals/{g1}/trajectory")
    assert resp.status_code == 200
    body = resp.text
    assert "Step-by-step history" in body
    # The scrubber input is present.
    assert 'id="scrub"' in body
    # Our seeded event content shows up.
    assert "shell: ls" in body


def test_cost_csv_headers_and_rows(client, world_with_tree):
    resp = client.get("/api/v1/cost.csv")
    assert resp.status_code == 200
    body = resp.text
    lines = body.strip().splitlines()
    assert lines[0].startswith("episode_id,goal_id")
    # At least the 2 episodes we seeded.
    assert len(lines) >= 3


def test_cost_csv_month_filter_rejects_bad_format(client):
    resp = client.get("/api/v1/cost.csv?month=NOTAMONTH")
    assert resp.status_code == 400


def test_cost_csv_month_filter_accepts_valid_format(client):
    resp = client.get("/api/v1/cost.csv?month=2026-04")
    assert resp.status_code == 200
    # Header always present even when no rows match.
    assert "episode_id" in resp.text


def test_goals_page_includes_plan_and_replay_links(client, world_with_tree):
    resp = client.get("/goals")
    assert resp.status_code == 200
    body = resp.text
    # Both per-row links appear.
    assert "plan" in body
    assert "replay" in body or "trajectory" in body
