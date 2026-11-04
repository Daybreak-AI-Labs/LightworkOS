"""Live executive boards on /learning and /security: the payloads the pages
fetch (/api/v1/learning and /api/v1/dashboards/security) and the board
skeleton (stamp + card containers + board.js, no slicer — neither payload is
windowed). Charts render client-side; the payload shape is the contract."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import consequence, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    consequence.reset_shared()


def test_security_board_payload_survives_empty_world(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/api/v1/dashboards/security")
    assert r.status_code == 200
    d = r.json()
    assert d["board"] == "security"
    assert d["kpis"] == {"total": 0, "open": 0, "needs_more": 0,
                         "approved": 0, "rejected": 0, "due_review": 0}
    assert len(d["monthly"]) == 12


def test_learning_payload_has_component_counts(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/api/v1/learning")
    assert r.status_code == 200
    d = r.json()
    assert isinstance(d["components_on"], int)
    assert isinstance(d["components_total"], int)
    assert d["components_total"] >= d["components_on"] >= 0


def test_pages_ship_the_board_skeleton_without_slicer(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    for path, markers in (
        ("/learning", ("bd-systems", "bd-acc")),
        ("/security", ("bd-flow", "bd-risk", "bd-frameworks")),
    ):
        t = c.get(path).text
        assert "/static/board.js" in t, path
        assert 'id="bd-stamp"' in t, path
        for marker in markers:
            assert marker in t, (path, marker)
        # Neither payload is windowed — no time-range slicer on these boards.
        assert 'aria-label="Time range"' not in t and "data-days=" not in t, path
