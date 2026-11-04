"""Overview landing page: an enterprise dashboard, not a consumer tour.

The old "Welcome to Lightwork - 60-second tour" block (with its curl/CLI
crib sheet) was removed for enterprise clients; the page now leads with the
shared hero + a goal stat row backed by real counts from the route context.
"""
from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient


def _client(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return TestClient(dash_app.app, base_url="http://127.0.0.1")


def test_overview_has_no_consumer_tour(monkeypatch, tmp_path):
    body = _client(monkeypatch, tmp_path).get("/overview").text
    assert "60-second tour" not in body
    assert "Welcome to Lightwork" not in body
    assert 'id="tour"' not in body
    assert "maverick_tour_dismissed" not in body
    # The developer crib sheet (curl / CLI) left with the tour.
    assert "curl -X POST" not in body


def test_overview_uses_shared_hero_with_real_counts(monkeypatch, tmp_path):
    client = _client(monkeypatch, tmp_path)
    body = client.get("/overview").text
    assert 'class="hero' in body
    assert "hero-statebox" in body
    # The state box reflects the real (empty) world, not invented numbers.
    assert "0 tasks on record" in body


def test_overview_stat_row_counts_goal_statuses(monkeypatch, tmp_path):
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    active = w.create_goal("ship the quarterly report", "d")
    w.set_goal_status(active, "active")
    done = w.create_goal("reconcile invoices", "d")
    w.set_goal_status(done, "done")

    body = _client(monkeypatch, tmp_path).get("/overview").text
    # Counts render server-side in the hero; the stat row, charts, and the
    # recent-goals list are the client-rendered executive board.
    assert "2 tasks on record" in body
    assert 'id="bd-kpis"' in body and "bd-momentum" in body
    assert "/static/board.js" in body
