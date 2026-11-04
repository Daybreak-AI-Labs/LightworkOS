"""Executive boards on Savings / Oversight: the board API returns windowed,
owner-scoped payloads, and both pages ship the board skeleton (slicer +
stamp + chart containers + board.js). Charts render client-side; the API
payload is the contract these tests pin."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def _seed_world():
    from maverick.world_model import WorldModel
    w = WorldModel()
    done = w.create_goal("Vendor DPA review", domain="legal_privacy")
    eid = w.start_episode(done)
    w.end_episode(eid, "ok", "success", cost_dollars=1.25,
                  input_tokens=10_000, output_tokens=1_500, tool_calls=6)
    w.set_goal_status(done, "done")
    blocked = w.create_goal("Access recert", domain="sec_access_review")
    w.set_goal_status(blocked, "blocked")
    return w


def test_savings_board_payload_empty_world(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    d = _client().get("/api/v1/dashboards/savings").json()
    assert d["board"] == "savings" and d["days"] == 90
    assert len(d["daily_done"]) == 90
    assert d["report"]["saved"] == 0


def test_savings_board_payload_with_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    d = _client().get("/api/v1/dashboards/savings?days=30").json()
    assert d["days"] == 30
    assert d["report"]["human_cost"] > 0
    # The goal finished today — the last daily bucket carries it.
    assert d["daily_done"][-1]["n"] == 1


def test_oversight_board_payload_empty_world(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    d = _client().get("/api/v1/dashboards/oversight").json()
    assert d["board"] == "oversight" and d["days"] == 90
    assert d["interventions"] == 0
    assert d["halted"] is False
    assert len(d["daily"]) == 90


def test_pages_ship_the_board_skeleton(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_world()
    c = _client()
    for path, markers in (
            ("/savings", ("bd-delivered", "bd-dept-savings")),
            ("/oversight", ("bd-interventions", "bd-fired"))):
        t = c.get(path).text
        assert "/static/board.js" in t, path
        assert 'id="bd-stamp"' in t and 'aria-label="Time range"' in t and 'data-days="90"' in t, path
        for marker in markers:
            assert marker in t, path
