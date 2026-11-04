"""Webhook settings use reviewed effective state; secrets are never echoed."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)


def test_settings_page_shows_webhook_state_without_the_value():
    page = client.get("/settings").text
    assert "Secure connected automations" in page
    assert "not set" in page


def test_save_secret_roundtrip_and_clear():
    generation = client.get("/settings/webhooks").json()["expected_generation"]
    r = client.post("/settings/webhooks",
                    data={"secret": "s3cret-value-123", "expected_generation": generation},  # pragma: allowlist secret
                    follow_redirects=False)
    assert r.status_code == 200

    from maverick.webhooks import _load_config_outbound
    assert _load_config_outbound()[1] == "s3cret-value-123"  # pragma: allowlist secret

    from maverick import config
    persisted = config.dashboard_overrides_path().read_text(encoding="utf-8")
    assert "s3cret-value-123" not in persisted  # pragma: allowlist secret
    assert "MVKAR1:" in persisted

    page = client.get("/settings").text
    assert "Secret set" in page
    assert client.get("/settings/webhooks").json()["configured"] is True
    assert "s3cret-value-123" not in page  # pragma: allowlist secret -- never echoed back

    generation = client.get("/settings/webhooks").json()["expected_generation"]
    r = client.post("/settings/webhooks", data={"secret": "", "action": "remove", "expected_generation": generation},
                    follow_redirects=False)
    assert r.status_code == 200
    assert not _load_config_outbound()[1]


def test_env_secret_still_wins(monkeypatch):
    generation = client.get("/settings/webhooks").json()["expected_generation"]
    client.post("/settings/webhooks",
                data={"secret": "overlay-secret", "expected_generation": generation},  # pragma: allowlist secret
                follow_redirects=False)
    monkeypatch.setenv("MAVERICK_WEBHOOK_SECRET", "env-secret")  # pragma: allowlist secret
    from maverick.webhooks import _load_config_outbound
    assert _load_config_outbound()[1] == "env-secret"  # pragma: allowlist secret


def test_cross_site_save_is_blocked():
    bare = TestClient(app, base_url="http://127.0.0.1")
    assert bare.post("/settings/webhooks",
                     data={"secret": "x"}).status_code == 403


def test_tenant_admin_cannot_set_global_webhook_secret(tmp_path, monkeypatch):
    # The webhook signing secret gates every auth-exempt inbound webhook
    # endpoint deployment-wide -- a principal who is only a TENANT-local admin
    # (global viewer) must be denied, not just a non-admin.
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import auth, rbac

    rbac.set_role("user:alice", "viewer")
    rbac.set_tenant_role("acme", "user:alice", "admin")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    tok = set_tenant("acme")
    try:
        assert auth.role_for_principal("user:alice") == "admin"
        r = client.post("/settings/webhooks", data={"secret": "s"},
                        follow_redirects=False)
    finally:
        reset_tenant(tok)

    assert r.status_code == 403
    from maverick.webhooks import inbound_secret
    assert not inbound_secret()
