"""Oversight 'why this action' drill-down (/api/v1/oversight/why/{goal_id}).

The supervisor hero feature: answer "why is this agent doing this / why is this
approval being requested" inline on the oversight console — the reasoning/tool
chain + cost-so-far for one goal — without hopping to the trajectory page.

Hermetic like the other dashboard tests (OIDC off, isolated HOME, fresh DB).
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _seed_goal_with_chain(tmp_path):
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("Refactor billing module", "split the invoice service")
    w.append_event(gid, "orchestrator", "plan", "decompose into 3 subtasks")
    w.append_event(gid, "coder", "tool", "ran pytest: 12 passed")
    w.append_event(gid, "verifier", "decision", "accept: tests green")
    ep = w.start_episode(gid)
    w.end_episode(ep, "done", "ok", cost_dollars=0.0731)
    return gid


def test_why_returns_status_cost_summary_and_chain(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    gid = _seed_goal_with_chain(tmp_path)
    r = _client().get(f"/api/v1/oversight/why/{gid}")
    assert r.status_code == 200
    d = r.json()
    assert d["goal_id"] == gid
    assert d["title"] == "Refactor billing module"
    # Cost-so-far is summed from the goal's episodes.
    assert d["cost_dollars"] == 0.0731
    # The by-kind summary rolls up the chain.
    assert d["summary"] == {"plan": 1, "tool": 1, "decision": 1}
    # The chain itself is returned in chronological order, content decoded.
    kinds = [e["kind"] for e in d["events"]]
    assert kinds == ["plan", "tool", "decision"]
    assert d["events"][1]["content"] == "ran pytest: 12 passed"


def test_why_returns_most_recent_events_for_long_running_goal(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("long run", "many events")
    for i in range(450):
        kind = "safe" if i < 400 else "unsafe"
        w.append_event(gid, "agent", kind, f"event-{i + 1}")

    d = _client().get(f"/api/v1/oversight/why/{gid}?limit=40").json()

    assert [e["content"] for e in d["events"]] == [f"event-{i}" for i in range(411, 451)]
    assert d["summary"] == {"unsafe": 40}


def test_why_404_for_unknown_goal(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/api/v1/oversight/why/99999")
    assert r.status_code == 404


def test_why_empty_chain_is_graceful(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("fresh goal", "no events yet")
    d = _client().get(f"/api/v1/oversight/why/{gid}").json()
    assert d["events"] == []
    assert d["summary"] == {}
    assert d["cost_dollars"] == 0.0


def test_oversight_page_exposes_why_drilldown(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/oversight").text
    # The hero affordance is wired into the console: the why-panel target and
    # the drill-down fetch are present.
    assert 'id="why-panel"' in text
    assert "/api/v1/oversight/why/" in text
