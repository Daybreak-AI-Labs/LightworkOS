"""Run-events firehose (WS), inline cost preview, cost breakdown, anomalies."""
from __future__ import annotations

from types import SimpleNamespace

import maverick_dashboard.auth as auth
import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import app as app_mod
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    yield


def _enable_oidc_principal_map(monkeypatch):
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token,
            issuer="https://issuer.example",
            audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _goal(title="t", description="d", owner=""):
    return app_mod._world().create_goal(title, description, owner=owner)


def test_firehose_streams_until_terminal():
    gid = _goal()
    w = app_mod._world()
    w.append_event(gid, "coder", "plan", "step one")
    w.set_goal_status(gid, "done", result="ok")
    with client.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events") as ws:
        first = ws.receive_json()
        assert first["kind"] == "plan" and first["content"] == "step one"
        final = ws.receive_json()
        assert final["kind"] == "status" and final["content"] == "done"


def test_firehose_resume_since_id():
    gid = _goal()
    w = app_mod._world()
    e1 = w.append_event(gid, "a", "k", "one")
    w.append_event(gid, "a", "k", "two")
    w.set_goal_status(gid, "done", result="ok")
    with client.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events?since_id={e1}") as ws:
        msg = ws.receive_json()
        assert msg["content"] == "two"


def test_firehose_unknown_goal():
    with client.websocket_connect("ws://127.0.0.1" + "/ws/v1/runs/99999/events") as ws:
        assert ws.receive_json() == {"error": "no such goal"}


def test_firehose_token_mode_requires_bearer(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "tok")
    gid = _goal()
    from starlette.testclient import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events"):
            pass
    auth_client = TestClient(app, base_url="http://127.0.0.1", headers={"Authorization": "Bearer tok"})
    w = app_mod._world()
    w.set_goal_status(gid, "done", result="ok")
    with auth_client.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events") as ws:
        assert ws.receive_json()["kind"] == "status"


def test_firehose_oidc_enforces_goal_owner(monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    gid = _goal(owner="user:alice")
    w = app_mod._world()
    w.append_event(gid, "coder", "finding", "SECRET_EVENT_FOR_ALICE")
    w.set_goal_status(gid, "done", result="ok")

    alice = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "Authorization": "Bearer alice"},
    )
    with alice.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events") as ws:
        assert ws.receive_json()["content"] == "SECRET_EVENT_FOR_ALICE"

    mallory = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "Authorization": "Bearer mallory"},
    )
    with mallory.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events") as ws:
        assert ws.receive_json() == {"error": "no such goal"}


def test_firehose_loopback_rejects_cross_site_origin():
    gid = _goal()
    evil = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "https://evil.example"})
    from starlette.testclient import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with evil.websocket_connect("ws://127.0.0.1" + f"/ws/v1/runs/{gid}/events"):
            pass


def test_cost_preview_projects_and_verdicts():
    gid = _goal(description="research the market\nwrite the report")
    r = client.get(f"/api/v1/goals/{gid}/cost-preview")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["steps"] == 2
    assert data["total_dollars"] > 0
    assert data["verdict"] in ("OK", "TIGHT", "OVER")
    r2 = client.get(f"/api/v1/goals/{gid}/cost-preview?iterations=3")
    assert r2.json()["total_dollars"] > data["total_dollars"]


class _Ep:
    def __init__(self, goal_id, cost, outcome="success", it=100, ot=50):
        self.goal_id = goal_id
        self.cost_dollars = cost
        self.outcome = outcome
        self.input_tokens = it
        self.output_tokens = ot


def test_cost_breakdown(monkeypatch):
    gid = _goal()
    real_goal = app_mod._world().get_goal(gid)

    class _W:
        def get_goal(self, g):
            return real_goal if g == gid else None

        def list_episodes(self, limit=500, goal_id=None):
            return [_Ep(gid, 0.5), _Ep(gid, 0.2, outcome="error")]

    monkeypatch.setattr(app_mod, "_world", lambda: _W())
    r = client.get(f"/api/v1/goals/{gid}/cost-breakdown")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["total_dollars"] == 0.7
    buckets = {b["bucket"]: b for b in data["buckets"]}
    assert buckets["success"]["dollars"] == 0.5
    assert buckets["error"]["episodes"] == 1
    # Sorted by spend: success first.
    assert data["buckets"][0]["bucket"] == "success"


def test_cost_anomalies(monkeypatch):
    class _W:
        def list_goals(self, *, owner, limit, order):
            assert owner == "" and limit == 10_000 and order == "desc"
            return [SimpleNamespace(id=i, owner="") for i in (*range(1, 9), 99)]

        def list_episodes(self, limit=500):
            eps = [_Ep(i, 0.10) for i in range(1, 9)]
            eps.append(_Ep(99, 25.0))  # the outlier
            eps.append(_Ep(100, 900.0))  # another employee's private task
            return eps

    monkeypatch.setattr(app_mod, "_world", lambda: _W())
    r = client.get("/api/v1/cost/anomalies?threshold_sigma=2")
    assert r.status_code == 200
    data = r.json()
    assert [a["goal_id"] for a in data["anomalies"]] == [99]
    assert data["goals_considered"] == 9


def test_cost_anomalies_needs_baseline(monkeypatch):
    class _W:
        def list_goals(self, *, owner, limit, order):
            assert owner == "" and limit == 10_000 and order == "desc"
            return [SimpleNamespace(id=1, owner="")]

        def list_episodes(self, limit=500):
            return [_Ep(1, 1.0)]

    monkeypatch.setattr(app_mod, "_world", lambda: _W())
    data = client.get("/api/v1/cost/anomalies").json()
    assert data["anomalies"] == [] and "baseline" in data["note"]


def test_tutorial_endpoint():
    gid = _goal("Build the widget", "from scratch")
    w = app_mod._world()
    w.append_event(gid, "planner", "plan", "1. design 2. build")
    w.append_event(gid, "coder", "finding", "the API needs auth")
    r = client.get(f"/api/v1/goals/{gid}/tutorial.md")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert "# Tutorial: Build the widget" in r.text
    assert "the API needs auth" in r.text
    assert client.get("/api/v1/goals/99999/tutorial.md").status_code == 404


def test_replay_storyboard_endpoint():
    gid = _goal("recorded run")
    w = app_mod._world()
    w.append_event(gid, "planner", "plan", "do the thing")
    w.append_event(gid, "coder", "tool", "ran fs")
    r = client.get(f"/api/v1/goals/{gid}/replay-storyboard")
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["frames"]) == 2
    assert data["frames"][0]["kind"] == "plan"
    assert data["ffmpeg_command"][0] == "ffmpeg"
    assert data["total_seconds"] >= 0
    assert client.get("/api/v1/goals/99999/replay-storyboard").status_code == 404


def test_cost_anomalies_owner_scope_matches_a_full_read_and_decrypts_no_goal(monkeypatch):
    from maverick.world_model import WorldModel

    alice = [_goal(f"alice {i}", owner="user:alice") for i in range(6)]
    bob = _goal("bob private", owner="user:bob")
    world = app_mod._world()
    with world._writing() as conn:
        for gid, cost in zip(alice, (0.10, 0.10, 0.10, 0.10, 0.10, 25.0), strict=True):
            conn.execute("INSERT INTO episodes(goal_id, started_at, cost_dollars) VALUES (?, ?, ?)",
                         (gid, 1.0, cost))
        conn.execute("INSERT INTO episodes(goal_id, started_at, cost_dollars) VALUES (?, ?, ?)",
                     (bob, 1.0, 900.0))
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")
    fast = client.get("/api/v1/cost/anomalies?threshold_sigma=1.5")
    assert fast.status_code == 200, fast.text

    class _FullRead:
        """The pre-change read: owner ids from decrypted goal rows."""

        def __init__(self, inner):
            self._inner = inner

        def list_goals(self, **kwargs):
            return self._inner.list_goals(**kwargs)

        def list_episodes(self, **kwargs):
            return self._inner.list_episodes(**kwargs)

    monkeypatch.setattr(app_mod, "_world", lambda: _FullRead(world))
    reference = client.get("/api/v1/cost/anomalies?threshold_sigma=1.5").json()
    assert fast.json() == reference
    assert [a["goal_id"] for a in reference["anomalies"]] == [alice[-1]]
    assert reference["goals_considered"] == 6

    def no_full_decrypt(self, **kwargs):
        raise AssertionError("the anomaly scope must not decrypt the owner's goals")

    monkeypatch.setattr(app_mod, "_world", lambda: world)
    monkeypatch.setattr(WorldModel, "list_goals", no_full_decrypt)
    again = client.get("/api/v1/cost/anomalies?threshold_sigma=1.5")
    assert again.status_code == 200 and again.json() == reference

