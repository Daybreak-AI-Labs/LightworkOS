"""Installation security summary: company sign-in reads as configured."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _world(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def test_company_signin_is_unknown_when_its_settings_cannot_be_read(monkeypatch):
    from maverick import oidc
    url = "/api/v1/admin/installation-security"
    r = client.get(url)
    assert r.status_code == 200, r.text
    assert r.json()["summary"]["company_signin"] is False

    def _unreadable():
        raise oidc.OIDCError("unreadable")
    monkeypatch.setattr(oidc, "oidc_enabled_as_configured", _unreadable)
    assert client.get(url).json()["summary"]["company_signin"] is None
