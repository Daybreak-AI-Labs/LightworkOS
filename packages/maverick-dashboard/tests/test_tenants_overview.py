"""Multi-tenant view (/tenants/overview + /api/v1/tenants/overview)."""
from __future__ import annotations

from types import SimpleNamespace

import maverick_dashboard.auth as auth
import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    yield


def _seed_tenant_with_runs_and_spend():
    """Provision 'acme' with two goals (one done, one active) + $1.25 today."""
    from maverick.paths import data_dir
    from maverick.quotas import UsageLedger
    from maverick.tenant import registry as tr
    from maverick.workspace import Workspace
    from maverick.world_model import WorldModel
    tr.create_tenant("acme", plan="enterprise", display_name="Acme Inc",
                     max_daily_dollars=100)
    w = WorldModel(Workspace("acme").db_path)
    gid = w.create_goal("ship it", "")
    w.set_goal_status(gid, "done")
    w.create_goal("audit logs", "")
    w.close()
    UsageLedger(data_dir("usage", "ledger.json", tenant="acme")).record(
        "user:amy", 1.25, 10, 20)


def test_overview_page_empty_state(monkeypatch, tmp_path):
    r = _client().get("/tenants/overview")
    assert r.status_code == 200
    assert "No workspaces yet" in r.text


def test_overview_page_rollup(monkeypatch, tmp_path):
    _seed_tenant_with_runs_and_spend()
    from maverick.tenant import registry as tr
    tr.create_tenant("beta")
    tr.suspend_tenant("beta")
    text = _client().get("/tenants/overview").text
    assert "acme" in text and "Acme Inc" in text and "Enterprise" in text
    assert "Done 1" in text and "Pending 1" in text
    assert "$1.25" in text
    assert "$100.00/day" in text
    # beta: suspended flag + no runs yet.
    assert "Paused" in text and "No tasks yet" in text


def test_overview_api_rollup(monkeypatch, tmp_path):
    _seed_tenant_with_runs_and_spend()
    r = _client().get("/api/v1/tenants/overview")
    assert r.status_code == 200
    rows = r.json()["tenants"]
    assert len(rows) == 1
    acme = rows[0]
    assert acme["id"] == "acme" and acme["suspended"] is False
    assert acme["goals"] == {"done": 1, "pending": 1}
    assert acme["total_goals"] == 2
    assert acme["spend_today"] == 1.25
    assert acme["max_daily_dollars"] == 100.0


def test_overview_queries_postgres_without_local_sqlite_sentinel(monkeypatch, tmp_path):
    import maverick.paths as paths
    import maverick.world_model as world_model
    import maverick.world_model_backends as backends
    import maverick_dashboard.app as app_mod
    from maverick.tenant import registry as tr

    tenant = SimpleNamespace(
        id="acme",
        display_name="Acme",
        plan="enterprise",
        status="active",
        active=True,
        max_daily_dollars=100.0,
    )
    seen_tenants = []

    class _PostgresWorld:
        def goal_status_counts(self):
            seen_tenants.append(paths.current_tenant_id())
            return {"done": 1, "active": 1}

    world = _PostgresWorld()
    closed = []
    monkeypatch.setattr(tr, "list_tenants", lambda: [tenant])
    monkeypatch.setattr(tr, "tenant_spend_today", lambda _tenant: 0.0)
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(world_model, "open_world", lambda: world)
    monkeypatch.setattr(
        world_model, "close_world_if_owned", lambda candidate: closed.append(candidate)
    )

    rows = app_mod._tenant_overview_rows()

    assert rows[0]["goals"] == {"done": 1, "active": 1}
    assert seen_tenants == ["acme"]
    assert paths.current_tenant_id() is None
    assert closed == [world]


def _as_user(monkeypatch, name: str) -> dict:
    """OIDC on; the bearer token string is the subject (no real JWT)."""
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(
        auth, "verify_oidc_token",
        lambda token, **_kw: VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        ),
    )
    return {"Authorization": f"Bearer {name}"}


def test_overview_is_admin_only(monkeypatch, tmp_path):
    _seed_tenant_with_runs_and_spend()
    headers = _as_user(monkeypatch, "mallory")
    # Page: blocked outright -- /tenants is an admin page, so role-based UI
    # visibility 403s a non-admin before the in-page guard even runs (and the
    # roster data still never leaks).
    page = _client().get("/tenants/overview", headers=headers)
    assert page.status_code == 403
    assert "acme" not in page.text
    # API: explicit 403.
    api = _client().get("/api/v1/tenants/overview", headers=headers)
    assert api.status_code == 403


def test_overview_admin_principal_sees_roster(monkeypatch, tmp_path):
    _seed_tenant_with_runs_and_spend()
    headers = _as_user(monkeypatch, "root")
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    r = _client().get("/api/v1/tenants/overview", headers=headers)
    assert r.status_code == 200
    assert r.json()["tenants"][0]["id"] == "acme"
