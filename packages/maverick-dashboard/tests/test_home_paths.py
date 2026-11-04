"""Dashboard control-plane stores honor the governed home override."""
from __future__ import annotations


def test_dashboard_control_stores_honor_maverick_home(tmp_path, monkeypatch):
    home = tmp_path / "isolated-maverick-home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))

    from maverick_dashboard import invites, rbac, ui_visibility

    assert rbac.store_path() == home / "dashboard-users.json"
    assert rbac.tenant_store_path() == home / "dashboard-tenant-roles.json"
    assert invites.store_path() == home / "dashboard-invites.json"
    assert invites._session_secret_path() == home / "dashboard-session.key"
    assert ui_visibility.store_path() == home / "dashboard-ui-visibility.json"
