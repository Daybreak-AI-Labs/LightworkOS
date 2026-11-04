"""POST /api/v1/outcomes -- the Consequence Engine's HTTP ingestion entrypoint."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import consequence as cq
    from maverick import world_model
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    api_mod._world_cache.clear()
    app_mod._world_cache.clear()
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    monkeypatch.setattr("maverick.consequence.shared", lambda: store)
    yield store


@pytest.fixture
def world():
    from maverick_dashboard.api import _world

    return _world()


def _episode(world, *, owner: str = "") -> tuple[int, int]:
    goal_id = world.create_goal("outcome goal", owner=owner)
    episode_id = world.start_episode(goal_id)
    return goal_id, episode_id


def _enable_oidc_principal_map(monkeypatch, *, default_role: str = "operator") -> None:
    import maverick_dashboard.auth as auth
    import maverick_dashboard.rbac as rbac

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(rbac, "default_role", lambda: default_role)

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _as(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user}", "Origin": "http://127.0.0.1"}


def test_record_outcome_endpoint(_isolated, world):
    goal_id, episode_id = _episode(world)
    resp = client.post("/api/v1/outcomes", json={
        "goal_id": goal_id, "episode_id": episode_id, "value": 1.0, "kind": "invoice_paid"})
    assert resp.status_code == 204
    assert _isolated.resolve(goal_id, episode_id) == 1.0


def test_record_outcome_clamps_value(_isolated, world):
    goal_id, episode_id = _episode(world)
    resp = client.post("/api/v1/outcomes", json={
        "goal_id": goal_id, "episode_id": episode_id, "value": 5.0})
    assert resp.status_code == 204
    assert _isolated.resolve(goal_id, episode_id) == 1.0


def test_record_outcome_rejects_bad_body():
    resp = client.post("/api/v1/outcomes", json={"goal_id": "nope"})
    assert resp.status_code == 422   # FastAPI validation


def test_record_outcome_requires_operate_role(_isolated, world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch, default_role="viewer")
    goal_id, episode_id = _episode(world, owner="user:alice")
    resp = client.post(
        "/api/v1/outcomes",
        json={"goal_id": goal_id, "episode_id": episode_id, "value": 0.5},
        headers=_as("alice"),
    )
    assert resp.status_code == 403
    assert _isolated.resolve(goal_id, episode_id) is None


def test_record_outcome_rejects_cross_owner_goal(_isolated, world, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    goal_id, episode_id = _episode(world, owner="user:alice")
    resp = client.post(
        "/api/v1/outcomes",
        json={"goal_id": goal_id, "episode_id": episode_id, "value": 0.5},
        headers=_as("bob"),
    )
    assert resp.status_code == 404
    assert _isolated.resolve(goal_id, episode_id) is None


def test_record_outcome_rejects_unknown_episode(_isolated, world):
    goal_id, _episode_id = _episode(world)
    resp = client.post(
        "/api/v1/outcomes",
        json={"goal_id": goal_id, "episode_id": 999999, "value": 0.5},
    )
    assert resp.status_code == 404
    assert _isolated.resolve(goal_id, 999999) is None
