"""Executive boards on the Privacy / Finance workspaces: the department
board API rolls the same assessment records the pages list into KPIs, a
residual-risk mix, a 12-month opened-vs-decided series, and per-framework
volume — and the pages ship the board skeleton (stamp + card containers +
board.js, no slicer: the payload is not windowed)."""
from __future__ import annotations

import time

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    # A previous test's cached config (auth mode, ops knobs) or world handle
    # must not leak into these order-independent tests — same idiom as the
    # finance workspace suite's fixture.
    from maverick import config
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()


def test_board_payloads_on_empty_world(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    for board in ("privacy", "finance"):
        r = c.get(f"/api/v1/dashboards/{board}")
        assert r.status_code == 200, board
        d = r.json()
        assert d["board"] == board
        assert d["kpis"]["total"] == 0
        assert len(d["monthly"]) == 12
        assert d["types"] == []


def test_board_payload_with_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    # The board builder imports list_saved/custom_template_records
    # function-locally, so patching the module attributes reaches it.
    import maverick.assessment as assessment
    now = time.time()
    fake = {"type": "pia", "status": "approved", "residual_risk": "high",
            "created_at": now, "decided_at": now, "review_due": True}
    monkeypatch.setattr(assessment, "list_saved", lambda: [fake])
    monkeypatch.setattr(assessment, "custom_template_records", dict)
    c = _client()
    d = c.get("/api/v1/dashboards/privacy").json()
    assert d["kpis"]["total"] == 1
    assert d["kpis"]["approved"] == 1
    assert d["kpis"]["due_review"] == 1
    assert d["risk"]["high"] == 1
    # Opened and decided today land in the newest monthly bucket.
    assert d["monthly"][-1]["opened"] == 1
    assert d["monthly"][-1]["decided"] == 1
    # 'pia' is a privacy type — the finance board must not count it.
    assert c.get("/api/v1/dashboards/finance").json()["kpis"]["total"] == 0


def test_pages_ship_the_board_skeleton_without_slicer(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    for path in ("/privacy", "/finance"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code)
        t = r.text
        assert "/static/board.js" in t, path
        assert 'id="bd-stamp"' in t, path
        for marker in ("bd-flow", "bd-risk", "bd-types"):
            assert marker in t, (path, marker)
        # These boards are not windowed — no time-range slicer.
        assert 'aria-label="Time range"' not in t and "data-days=" not in t, path
