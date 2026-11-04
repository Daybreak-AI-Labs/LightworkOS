"""/healthz + /metrics probe the CONFIGURED world backend, not a hard-coded
local world.db -- so a Postgres-backed (HA) deployment reports the DB it
actually uses, and the goal-count gauge reflects the real store.
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _probe_details(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "diagnostic-test-token")
    return client.get("/api/v1/admin/system/probe-details",
                      headers={"Authorization": "Bearer diagnostic-test-token"})


def test_unreadable_auth_posture_keeps_probe_details_redacted(monkeypatch):
    from maverick import oidc
    from maverick_dashboard.health_routes import health_should_redact

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)

    def unavailable():
        raise RuntimeError("auth config unavailable")

    monkeypatch.setattr(oidc, "oidc_enabled", unavailable)
    assert health_should_redact() is True


def test_probe_details_require_authentication_even_when_auth_is_off(monkeypatch):
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    assert client.get("/api/v1/admin/system/probe-details").status_code == 401


def test_public_probes_do_not_disclose_db_exception(monkeypatch):
    from maverick_dashboard import app as dash_app

    class Broken:
        def ping(self):
            raise RuntimeError("sensitive database location")

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(dash_app, "_world", lambda: Broken())
    for path in ("/healthz", "/readyz"):
        response = client.get(path)
        assert response.status_code == 503
        assert set(response.json()) == {"status"}
        assert "sensitive database location" not in response.text


def _use_sqlite(monkeypatch, tmp_path):
    """Point the dashboard's _world() at an isolated SQLite world."""
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return world_model.WorldModel(db)


def test_metrics_goal_counts_from_configured_backend(monkeypatch, tmp_path):
    wm = _use_sqlite(monkeypatch, tmp_path)
    g1 = wm.create_goal("a")
    wm.set_goal_status(g1, "done")
    wm.create_goal("b")  # stays pending

    text = client.get("/metrics").text
    assert "# TYPE maverick_goals_total gauge" in text
    assert 'maverick_goals_total{status="done"} 1' in text
    assert 'maverick_goals_total{status="pending"} 1' in text


def test_health_and_metrics_use_public_inflight_snapshot(monkeypatch, tmp_path):
    _use_sqlite(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import runner

    monkeypatch.setattr(runner, "inflight_goals", lambda: 3)
    # A regression to the semaphore's private ``_value`` would fail loudly.
    monkeypatch.setattr(runner, "_run_semaphore", object())

    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert _probe_details(monkeypatch).json()["checks"]["runner"] == (
        f"in_flight=3/{runner.MAX_CONCURRENT_GOALS}"
    )
    text = client.get("/metrics", headers={"Authorization": "Bearer diagnostic-test-token"}).text
    assert "maverick_concurrent_goals 3" in text


def test_healthz_db_ok_via_ping(monkeypatch, tmp_path):
    _use_sqlite(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    body = client.get("/healthz").json()
    assert "checks" not in body
    assert _probe_details(monkeypatch).json()["checks"]["db"] == "ok"


def test_healthz_db_fail_is_reported(monkeypatch, tmp_path):
    _use_sqlite(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)

    class _Broken:
        def ping(self):
            raise RuntimeError("db down")

    from maverick_dashboard import app as dash_app
    monkeypatch.setattr(dash_app, "_world", lambda: _Broken())
    resp = client.get("/healthz")
    body = resp.json()
    assert resp.status_code == 503
    assert body == {"status": "degraded"}
    assert _probe_details(monkeypatch).json()["checks"]["db"].startswith("fail")


def test_metrics_omits_world_db_bytes_under_postgres(monkeypatch, tmp_path):
    _use_sqlite(monkeypatch, tmp_path)
    # Simulate a Postgres deployment: the SQLite-file size gauge is meaningless,
    # so it must be omitted while the disk-free gauge stays.
    from maverick import world_model_backends
    monkeypatch.setattr(world_model_backends, "is_postgres_configured", lambda: True)
    text = client.get("/metrics").text
    assert "maverick_world_db_bytes" not in text
    assert "# TYPE maverick_data_disk_free_bytes gauge" in text


class _WorldOpenedAsSuperuser:
    rls_bypass_reason = (
        "the Postgres login is a superuser, which bypasses row-level security; "
        "connect with a dedicated login that is neither a superuser nor BYPASSRLS"
    )

    def ping(self):
        return True


def test_healthz_degrades_when_the_login_bypasses_row_level_security(monkeypatch):
    # A superuser or BYPASSRLS login skips every tenant policy: a degraded reason.
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(dash_app, "_world", lambda: _WorldOpenedAsSuperuser())
    resp = client.get("/healthz")
    body = resp.json()
    assert resp.status_code == 503
    assert body["status"] == "degraded"
    assert "checks" not in body
    assert _probe_details(monkeypatch).json()["checks"]["database_role"].startswith(
        "fail: the Postgres login is a superuser, which bypasses row-level security"
    )


def test_healthz_is_unchanged_for_a_login_without_the_bypass(monkeypatch, tmp_path):
    _use_sqlite(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert "checks" not in resp.json()
    assert "database_role" not in _probe_details(monkeypatch).json()["checks"]
