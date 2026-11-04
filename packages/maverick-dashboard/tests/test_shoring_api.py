"""Autonomous Shoring API: the Book of Work store + measured SLAs.

Reads floor ``view``, writes floor ``operate``; mutating requests carry a
same-origin Origin (the CSRF contract) and are rejected without one.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import api as api_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_SHORING", raising=False)
    config.reset_config_cache()
    api_mod._world_cache.clear()
    yield
    config.reset_config_cache()
    api_mod._world_cache.clear()


def _enable_oidc(monkeypatch, *, default_role="operator"):
    import maverick_dashboard.auth as auth
    import maverick_dashboard.rbac as rbac

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(rbac, "default_role", lambda: default_role)
    monkeypatch.setattr(
        auth, "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token}))


def _as(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user}", "Origin": "http://127.0.0.1"}


def _seed_goal(domain: str, status: str, cost: float = 1.0):
    from maverick import world_model
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = w.create_goal(f"g {domain}", "seed", domain=domain)
    ep = w.start_episode(gid)
    w.end_episode(ep, "ran", "success", cost_dollars=cost)
    w.set_goal_status(gid, status)
    return w


def _payload(**over):
    body = {
        "key": "ap", "name": "Accounts Payable", "department": "finance_ap",
        "scope": "Invoice to pay", "status": "running", "owner": "cfo",
        "slas": [{"name": "Throughput", "metric": "throughput_per_day", "target": 1.0}],
    }
    body.update(over)
    return body


# ---- GET /api/v1/shoring/book ---------------------------------------------

def test_book_empty_shape():
    r = client.get("/api/v1/shoring/book")
    assert r.status_code == 200
    body = r.json()
    assert body["schema"] == "lightwork.shoring-book.v1"
    assert body["functions"] == []


def test_book_reports_measured_sla():
    _seed_goal("finance_ap", "done")
    client.post("/api/v1/shoring/function", json=_payload())
    fns = client.get("/api/v1/shoring/book").json()["functions"]
    assert len(fns) == 1
    fn = fns[0]
    assert fn["key"] == "ap"
    assert fn["delivered"] == 1
    assert fn["lifecycle"] == "running"
    # 1 delivered over the default 90d window is far under 1/day -> breached.
    sla = fn["slas"][0]
    assert sla["metric"] == "throughput_per_day"
    assert sla["status"] == "breached"


# ---- POST /api/v1/shoring/function ----------------------------------------

def test_post_creates_and_updates():
    assert client.post("/api/v1/shoring/function", json=_payload()).status_code == 200
    # Update by the same key replaces, not duplicates.
    r = client.post("/api/v1/shoring/function",
                    json=_payload(name="AP v2", status="proving"))
    assert r.status_code == 200
    fns = client.get("/api/v1/shoring/book").json()["functions"]
    assert len(fns) == 1
    assert fns[0]["name"] == "AP v2"
    assert fns[0]["lifecycle"] == "proving"


def test_post_validates_bounds():
    # Bad key slug.
    assert client.post("/api/v1/shoring/function",
                       json=_payload(key="Bad Key!")).status_code == 422
    # Unknown SLA metric.
    assert client.post("/api/v1/shoring/function", json=_payload(
        slas=[{"name": "x", "metric": "not_a_metric", "target": 1}])).status_code == 422
    # Unknown lifecycle status.
    assert client.post("/api/v1/shoring/function",
                       json=_payload(status="wibble")).status_code == 422
    # Extra field is forbidden (strict pydantic).
    assert client.post("/api/v1/shoring/function",
                       json=_payload(surprise=1)).status_code == 422
    # Negative SLA target.
    assert client.post("/api/v1/shoring/function", json=_payload(
        slas=[{"name": "x", "metric": "throughput_per_day", "target": -1}])).status_code == 422


def test_post_requires_same_origin():
    bare = TestClient(app, base_url="http://127.0.0.1")  # no Origin on a mutating request
    r = bare.post("/api/v1/shoring/function", json=_payload())
    assert r.status_code in (403, 400)


# ---- DELETE /api/v1/shoring/function/{key} --------------------------------

def test_delete_removes():
    client.post("/api/v1/shoring/function", json=_payload())
    assert client.delete("/api/v1/shoring/function/ap").status_code == 200
    assert client.get("/api/v1/shoring/book").json()["functions"] == []
    # Deleting an absent key is a 404.
    assert client.delete("/api/v1/shoring/function/ap").status_code == 404


# ---- GET /api/v1/shoring/sla ----------------------------------------------

def test_sla_for_one_function():
    _seed_goal("finance_ap", "done")
    client.post("/api/v1/shoring/function", json=_payload())
    r = client.get("/api/v1/shoring/sla", params={"key": "ap"})
    assert r.status_code == 200
    assert r.json()["function"]["key"] == "ap"
    assert client.get("/api/v1/shoring/sla", params={"key": "nope"}).status_code == 404


# ---- exception desk lens ---------------------------------------------------

def test_exception_desk_counts_department_approvals():
    from maverick import world_model
    from maverick.logging_config import reset_goal_context, set_goal_context
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    goal = w.create_goal("Invoice", domain="finance_ap")
    tokens = set_goal_context(goal_id=goal)
    try:
        w.create_approval("wire.transfer", risk="high", scope="payment")
    finally:
        reset_goal_context(tokens)
    w.create_approval("post.tweet", risk="low", scope="marketing")
    client.post("/api/v1/shoring/function", json=_payload())
    fn = client.get("/api/v1/shoring/book").json()["functions"][0]
    assert fn["exception_count"] == 1
    assert fn["exceptions"][0]["action"] == "wire.transfer"
    assert fn["unassigned_exception_count"] == 1


# ---- RBAC: view reads, operate writes -------------------------------------

def test_get_book_allows_viewer(monkeypatch):
    _enable_oidc(monkeypatch, default_role="viewer")
    assert client.get("/api/v1/shoring/book", headers=_as("vic")).status_code == 200


def test_post_denied_to_viewer(monkeypatch):
    _enable_oidc(monkeypatch, default_role="viewer")
    r = client.post("/api/v1/shoring/function", json=_payload(), headers=_as("vic"))
    assert r.status_code == 403


def test_post_allowed_for_operator(monkeypatch):
    _enable_oidc(monkeypatch, default_role="operator")
    r = client.post("/api/v1/shoring/function", json=_payload(), headers=_as("olivia"))
    assert r.status_code == 200


def test_delete_denied_to_viewer(monkeypatch):
    _enable_oidc(monkeypatch, default_role="viewer")
    r = client.delete("/api/v1/shoring/function/ap", headers=_as("vic"))
    assert r.status_code == 403


# ---- the knob --------------------------------------------------------------

def test_disabled_surface_is_404(monkeypatch):
    monkeypatch.setenv("MAVERICK_SHORING", "0")
    assert client.get("/api/v1/shoring/book").status_code == 404
