from __future__ import annotations

from fastapi.testclient import TestClient


def _enable_proxy_identity(monkeypatch):
    import maverick_dashboard.auth as auth

    monkeypatch.setattr(auth, "proxy_auth_enabled", lambda: True)
    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    monkeypatch.setattr(auth, "proxy_header_name", lambda: "X-Forwarded-User")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: False)


def _isolated_app(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    api_mod._world_cache.clear()
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    config.reset_config_cache()
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    return app_mod.app


def test_api_goal_creation_passes_proxy_user_to_runner(monkeypatch, tmp_path):
    _enable_proxy_identity(monkeypatch)
    app = _isolated_app(monkeypatch, tmp_path)
    from maverick_dashboard import rbac
    rbac.set_role("user:alice", "operator")

    from maverick import runner

    calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **kw: calls.append((a, kw)))

    resp = TestClient(app, base_url="http://127.0.0.1").post(
        "/api/v1/goals",
        headers={"Origin": "http://127.0.0.1", "X-Forwarded-User": "alice"},
        json={"title": "secure goal", "description": "run as alice"},
    )

    assert resp.status_code == 201, resp.text
    assert calls
    assert calls[0][1]["channel"] == "api"
    assert calls[0][1]["user_id"] == "alice"


def test_chat_goal_creation_passes_proxy_user_to_runner(monkeypatch, tmp_path):
    _enable_proxy_identity(monkeypatch)
    app = _isolated_app(monkeypatch, tmp_path)
    from maverick_dashboard import rbac
    rbac.set_role("user:bob", "operator")

    from maverick import runner

    calls: list[tuple[tuple, dict]] = []
    monkeypatch.setattr(runner, "run_goal_in_thread", lambda *a, **kw: calls.append((a, kw)))

    resp = TestClient(app, base_url="http://127.0.0.1").post(
        "/chat/send",
        headers={"Origin": "http://127.0.0.1", "X-Forwarded-User": "bob"},
        data={"title": "secure chat goal", "description": "run as bob"},
        follow_redirects=False,
    )

    assert resp.status_code == 303, resp.text
    assert calls
    assert calls[0][1]["channel"] == "dashboard"
    assert calls[0][1]["user_id"] == "bob"


def test_unassigned_proxy_user_can_view_but_cannot_operate(monkeypatch, tmp_path):
    _enable_proxy_identity(monkeypatch)
    app = _isolated_app(monkeypatch, tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Forwarded-User": "alice"})
    assert client.get("/providers").status_code == 200
    assert client.post("/api/v1/goals", json={"title": "work"}).status_code == 403
    assert client.post("/api/v1/approvals/1/approve").status_code == 403


def test_proxy_mode_without_require_auth_never_falls_back_to_local_admin(
    monkeypatch, tmp_path,
):
    import maverick_dashboard.auth as auth

    monkeypatch.delenv("MAVERICK_DASHBOARD_REQUIRE_AUTH", raising=False)
    _enable_proxy_identity(monkeypatch)
    app = _isolated_app(monkeypatch, tmp_path)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    assert client.get("/api/v1/providers").status_code == 401
    assert client.get(
        "/api/v1/providers", headers={"X-Forwarded-User": "alice "}
    ).status_code == 401

    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: False)
    assert client.get(
        "/api/v1/providers", headers={"X-Forwarded-User": "attacker"}
    ).status_code == 401

    monkeypatch.setattr(auth, "proxy_trusts", lambda _host: True)
    assert client.get(
        "/api/v1/providers", headers={"X-Forwarded-User": "alice"}
    ).status_code == 403
    assert client.get(
        "/providers", headers={"X-Forwarded-User": "alice"}
    ).status_code == 200
