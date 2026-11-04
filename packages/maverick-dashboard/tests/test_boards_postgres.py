"""The dashboard's aggregate pages against a LIVE Postgres world.

Runs only when MAVERICK_PG_DSN is set (the CI ``postgres`` job; locally with a
scratch server). No route here may reach into ``world.conn`` with SQLite-only
SQL, which fails on the psycopg connection (``psycopg.ProgrammingError: the
query has 0 placeholders but 3 parameters were passed``).
"""
from __future__ import annotations

import os
import re
import uuid

import pytest
from fastapi.testclient import TestClient

_DSN = os.environ.get("MAVERICK_PG_DSN")
pytestmark = pytest.mark.skipif(
    not _DSN, reason="MAVERICK_PG_DSN not set (no Postgres service)"
)


@pytest.fixture
def pg(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", _DSN)
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import _shared
    from maverick_dashboard import app as dash_app
    _shared._world_cache.clear()
    try:
        yield dash_app
    finally:
        _shared._world_cache.clear()


def _seed(pg):
    w = pg._world()
    from maverick.world_model_backends.postgres import PostgresWorldModel
    assert isinstance(w, PostgresWorldModel), type(w)
    title = f"pg-board-{uuid.uuid4().hex[:8]}"
    gid = w.create_goal(title, "")
    eid = w.start_episode(gid)
    w.end_episode(gid, eid, outcome="ok", cost_dollars=0.25, input_tokens=10,
                  output_tokens=5, tool_calls=1)
    w.set_goal_status(gid, "done", result="shipped")
    return gid, title


def test_overview_and_plan_pages_render_on_postgres(pg):
    gid, title = _seed(pg)
    client = TestClient(pg.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    r = client.get("/overview")
    assert r.status_code == 200, r.text[:300]
    # Error copy also occurs in the shell's inert translation catalog.
    # Check the rendered page heading, not every embedded JSON string.
    assert re.search(r"<h1\b[^>]*>Overview</h1>", r.text)
    assert not re.search(r"<h1\b[^>]*>Something went wrong</h1>", r.text)
    r = client.get(f"/goals/{gid}/plan")
    assert r.status_code == 200, r.text[:300]
    assert title in r.text


@pytest.mark.parametrize("board", ["overview", "spend", "workforce", "savings", "oversight"])
def test_every_board_api_answers_on_postgres(pg, board):
    _seed(pg)
    client = TestClient(pg.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    r = client.get(f"/api/v1/dashboards/{board}?days=30")
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert body["board"] == board
    if board == "overview":
        assert body["totals"]["done"] >= 1
        assert len(body["daily"]) == 30


def test_cost_csv_export_streams_on_postgres(pg):
    gid, _ = _seed(pg)
    client = TestClient(pg.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    r = client.get("/api/v1/cost.csv")
    assert r.status_code == 200, r.text[:300]
    assert f",{gid}," in r.text
