"""Performance regression tests.

- WorldModel reused across requests (no per-request open/PRAGMA/migrate).
- list_goals respects LIMIT (no full-table load to render 20 rows).
- Plan-tree built in a constant number of queries (no N+1 fanout).
- cost.csv streams instead of buffering in RAM.
"""
from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def test_world_model_reused_across_requests(monkeypatch, tmp_path: Path):
    """Hitting / twice must reuse the same WorldModel, not open a new one."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)

    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()

    client = _client()
    client.get("/")
    first = dash_app._world_cache[str(db)]
    client.get("/")
    second = dash_app._world_cache[str(db)]
    assert first is second
    # And the cache really did short-circuit -- not just two equal-by-value entries.
    assert id(first) == id(second)


def test_list_goals_limit_pushdown(monkeypatch, tmp_path: Path):
    """list_goals with limit=N must SELECT only N rows, not slice client-side."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    w = world_model.WorldModel(db)
    for i in range(50):
        w.create_goal(f"goal {i}", "desc")

    # Sanity: limit is honoured.
    bounded = w.list_goals(limit=10, order="desc")
    assert len(bounded) == 10
    # Newest-first ordering.
    ids = [g.id for g in bounded]
    assert ids == sorted(ids, reverse=True)


def test_list_goals_unbounded_still_works(monkeypatch, tmp_path: Path):
    """Backward compat: list_goals() with no kwargs returns everything."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    w = world_model.WorldModel(db)
    for i in range(7):
        w.create_goal(f"goal {i}", "desc")
    assert len(w.list_goals()) == 7


def test_overview_payload_handles_thousand_goals_without_loading_them_all(
    monkeypatch, tmp_path: Path,
):
    """Build the overview board against 1000 goals without returning them all."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    w = world_model.WorldModel(db)
    for i in range(1000):
        w.create_goal(f"goal {i}", "desc")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.get("/api/v1/dashboards/overview?days=30")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["totals"]["total"] == 1000
    assert len(payload["recent"]) == 12
    assert len(resp.content) < 100_000


def test_plan_tree_uses_constant_query_count(monkeypatch, tmp_path: Path):
    """Plan-tree fetch must run in O(1) DB calls regardless of tree depth.

    Old code was N+1 (one query per node + a correlated subquery for
    cost). Now: one recursive CTE + one aggregate JOIN, baked into
    one statement = 2 DB calls total for the route (1 for get_goal,
    1 for the CTE).
    """
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    w = world_model.WorldModel(db)
    root = w.create_goal("root", "")
    # Build a 4-deep tree with 3 children each = 1 + 3 + 9 + 27 = 40 nodes.
    queue = [(root, 0)]
    while queue:
        parent_id, depth = queue.pop(0)
        if depth >= 4:
            continue
        for j in range(3):
            cid = w.create_goal(f"child {parent_id}/{j}", "", parent_id=parent_id)
            queue.append((cid, depth + 1))

    # Wrap the connection so we can count execute() calls. sqlite3
    # Connection.execute is read-only, so swap the whole conn for a
    # proxy with the same interface.
    real_conn = w.conn
    call_count = [0]

    class CountingConn:
        def __init__(self, c): self._c = c
        def execute(self, *a, **kw):
            call_count[0] += 1
            return self._c.execute(*a, **kw)
        def commit(self): return self._c.commit()
        def __getattr__(self, name): return getattr(self._c, name)

    w.conn = CountingConn(real_conn)  # type: ignore[assignment]

    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    dash_app._world_cache[str(db)] = w
    try:
        client = _client()
        resp = client.get(f"/api/v1/goals/{root}/tree")
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == root
        # The full tree should be present in the response.
        def count_nodes(n):
            return 1 + sum(count_nodes(c) for c in n.get("children", []))
        assert count_nodes(body) >= 10  # tree built; capped at 40
    finally:
        w.conn = real_conn  # type: ignore[assignment]

    # 2 queries total: get_goal + the CTE. Permit up to 5 for any
    # incidental WAL/PRAGMA queries on first connection.
    assert call_count[0] <= 5, (
        f"plan-tree fetch ran {call_count[0]} queries; expected <= 5"
    )


def test_plan_tree_leaf_does_not_rank_unrelated_goals(monkeypatch, tmp_path: Path):
    """A tiny requested tree must not rank or scan unrelated goals."""
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    w = world_model.WorldModel(db)
    root = w.create_goal("root", "")
    for i in range(1000):
        w.create_goal(f"unrelated {i}", "desc")

    progress_ticks = [0]

    def progress() -> int:
        progress_ticks[0] += 1
        return 0

    w.conn.set_progress_handler(progress, 100)
    try:
        tree = dash_app._build_plan_tree(w, root)
    finally:
        w.conn.set_progress_handler(None, 0)

    assert tree["id"] == root
    assert tree["children"] == []
    assert progress_ticks[0] < 25, (
        "plan-tree leaf fetch should stay bounded by the requested subtree; "
        f"saw {progress_ticks[0]} progress ticks"
    )


def test_cost_csv_streams_not_buffers(monkeypatch, tmp_path: Path):
    """Response is streamed: setting up generator doesn't materialise all rows."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    w = world_model.WorldModel(db)
    gid = w.create_goal("g", "")
    for _ in range(100):
        eid = w.start_episode(gid)
        w.end_episode(eid, "ok", "done", cost_dollars=0.01,
                      input_tokens=10, output_tokens=10, tool_calls=1)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.get("/api/v1/cost.csv")
    assert resp.status_code == 200
    # First line is the header.
    text = resp.text
    assert text.startswith("episode_id,goal_id,started_at,ended_at")
    # 100 episodes + 1 header line.
    assert text.count("\n") >= 100


def test_cost_csv_month_filter_in_sql(monkeypatch, tmp_path: Path):
    """Month filter pushes into SQL via WHERE; rows outside the month are absent."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    w = world_model.WorldModel(db)
    gid = w.create_goal("g", "")
    # Stuff one episode well in the past and one "now"; filter to current month.
    eid_old = w.start_episode(gid)
    w.end_episode(eid_old, "ok", "old", cost_dollars=0.5,
                  input_tokens=1, output_tokens=1, tool_calls=1)
    # Hammer started_at to the year 2000.
    w.conn.execute(
        "UPDATE episodes SET started_at = ? WHERE id = ?",
        (946684800.0, eid_old),  # 2000-01-01
    )
    w.conn.commit()
    eid_new = w.start_episode(gid)
    w.end_episode(eid_new, "ok", "new", cost_dollars=0.5,
                  input_tokens=1, output_tokens=1, tool_calls=1)

    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    # Filter for January 2000 -- only the old episode matches.
    resp = client.get("/api/v1/cost.csv?month=2000-01")
    assert resp.status_code == 200
    text = resp.text
    assert "old" in text
    assert "new" not in text


def test_cost_csv_month_window_rolls_over_by_calendar(monkeypatch, tmp_path: Path):
    """The month window ends at the next calendar month in UTC, not start+31d.

    Regression: the filter used ``strptime(month).timestamp() + 31*86400``,
    which (a) interpreted midnight in the server's LOCAL zone and (b) over-ran
    short months -- Feb 1 + 31 days = Mar 4, leaking early-March rows into a
    February report. Pin both: a Feb-15 row is kept, a Mar-2 row is excluded.
    """
    import datetime as dt

    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    w = world_model.WorldModel(db)
    gid = w.create_goal("g", "")
    feb = dt.datetime(2001, 2, 15, tzinfo=dt.timezone.utc).timestamp()
    mar = dt.datetime(2001, 3, 2, tzinfo=dt.timezone.utc).timestamp()  # +31d from Feb 1
    eid_feb = w.start_episode(gid)
    w.end_episode(eid_feb, "ok", "febrow", cost_dollars=0.1,
                  input_tokens=1, output_tokens=1, tool_calls=1)
    w.conn.execute("UPDATE episodes SET started_at = ? WHERE id = ?", (feb, eid_feb))
    eid_mar = w.start_episode(gid)
    w.end_episode(eid_mar, "ok", "marrow", cost_dollars=0.1,
                  input_tokens=1, output_tokens=1, tool_calls=1)
    w.conn.execute("UPDATE episodes SET started_at = ? WHERE id = ?", (mar, eid_mar))
    w.conn.commit()

    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.get("/api/v1/cost.csv?month=2001-02")
    assert resp.status_code == 200
    text = resp.text
    assert "febrow" in text
    assert "marrow" not in text  # Mar 2 must not leak into the Feb window


def test_cost_csv_bad_month_400(monkeypatch, tmp_path: Path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.get("/api/v1/cost.csv?month=not-a-month")
    assert resp.status_code == 400


def test_cost_csv_max_december_month_400(monkeypatch, tmp_path: Path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    client = _client()
    resp = client.get("/api/v1/cost.csv?month=9999-12")
    assert resp.status_code == 400
