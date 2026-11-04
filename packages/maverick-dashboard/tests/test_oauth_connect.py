"""Turnkey 'connect this account' dashboard flow: list providers, build the
consent URL, exchange the code into the sealed vault. Admin-gated mutations."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_list_providers_is_public_and_lists_presets():
    r = client.get("/api/v1/oauth/providers")
    assert r.status_code == 200
    names = {p["name"] for p in r.json()["providers"]}
    assert {"google", "slack", "github"} <= names


def test_connection_context_changes_with_user_or_workspace(monkeypatch):
    monkeypatch.setattr("maverick_dashboard.api._request_identity", lambda request: "user:alice")
    monkeypatch.setattr("maverick.paths.current_tenant_id", lambda: "workspace-a")
    first = client.get("/api/v1/oauth/providers").json()["connection_context"]
    assert first == client.get("/api/v1/oauth/providers").json()["connection_context"]
    monkeypatch.setattr("maverick_dashboard.api._request_identity", lambda request: "user:bob")
    second = client.get("/api/v1/oauth/providers").json()["connection_context"]
    monkeypatch.setattr("maverick.paths.current_tenant_id", lambda: "workspace-b")
    third = client.get("/api/v1/oauth/providers").json()["connection_context"]
    assert len({first, second, third}) == 3
    assert all(len(value) == 64 and "user:" not in value for value in [first, second, third])


def test_authorize_url_requires_vault(monkeypatch):
    monkeypatch.delenv("MAVERICK_OAUTH_VAULT", raising=False)
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: False)
    r = client.post("/api/v1/oauth/slack/authorize-url",
                    json={"redirect_uri": "https://a/cb"})
    assert r.status_code == 403


def test_authorize_url_builds_consent_url(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_ID", "cid-9")
    r = client.post("/api/v1/oauth/slack/authorize-url",
                    json={"redirect_uri": "https://a/cb", "scopes": ["chat:write"]})
    assert r.status_code == 200
    body = r.json()
    assert body["authorize_url"].startswith("https://slack.com/oauth/v2/authorize?")
    assert "client_id=cid-9" in body["authorize_url"]
    assert "scope=chat%3Awrite" in body["authorize_url"]
    assert body["verifier"]


def test_authorize_url_missing_client_id_is_400(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    monkeypatch.delenv("SLACK_OAUTH_CLIENT_ID", raising=False)
    r = client.post("/api/v1/oauth/slack/authorize-url",
                    json={"redirect_uri": "https://a/cb"})
    assert r.status_code == 400
    assert "SLACK_OAUTH_CLIENT_ID" in r.json()["detail"]


def test_authorize_url_unknown_provider_is_404(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    r = client.post("/api/v1/oauth/nope/authorize-url",
                    json={"redirect_uri": "https://a/cb"})
    assert r.status_code == 404


def test_exchange_seals_token_and_reports_connected(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_ID", "cid-9")
    put = {}

    class _Vault:
        def put(self, provider, record):
            put["provider"], put["record"] = provider, record

        def providers(self):
            return ["slack"] if put else []

    monkeypatch.setattr("maverick.oauth_vault.get_vault", lambda *a, **k: _Vault())
    monkeypatch.setattr(
        "maverick.tools.oauth_helper._post_form",
        lambda url, data: {"access_token": "AT", "refresh_token": "RT", "expires_in": 99},
    )
    r = client.post("/api/v1/oauth/slack/exchange",
                    json={"code": "the-code", "redirect_uri": "https://a/cb", "verifier": "v"})
    assert r.status_code == 200
    body = r.json()
    assert body["connected"] is True and body["has_refresh_token"] is True
    assert "access_token" not in body                 # redacted summary only
    assert put["provider"] == "slack" and put["record"]["access_token"] == "AT"


def test_exchange_unknown_provider_is_404(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_OAUTH_VAULT", "1")
    r = client.post("/api/v1/oauth/nope/exchange",
                    json={"code": "c", "redirect_uri": "https://a/cb"})
    assert r.status_code == 404


class _FakeVault:
    """A vault stub that reports one connected provider whose refresh succeeds
    or fails per ``refresh_raises``, and never leaks a token in status()."""

    def __init__(self, *, expired=False, refresh_raises=False):
        self._expired, self._raises = expired, refresh_raises

    def providers(self):
        return ["slack"]

    def status(self, provider, now=None):
        if provider != "slack":
            return None
        return {"provider": "slack", "expired": self._expired, "expires_at": 123.0,
                "scope": "chat:write", "has_refresh_token": True, "obtained_at": 1.0}

    def access_token(self, provider, *, refresher=None, skew=60):
        if self._raises:
            raise RuntimeError("invalid_grant")
        return "" if self._expired and refresher is None else "AT"


def test_providers_includes_token_free_status(monkeypatch):
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: True)
    monkeypatch.setattr("maverick.oauth_vault.get_vault", lambda *a, **k: _FakeVault())
    r = client.get("/api/v1/oauth/providers")
    assert r.status_code == 200
    body = r.json()
    assert body["connected"] == ["slack"]
    st = body["status"]["slack"]
    assert st["scope"] == "chat:write" and "access_token" not in st


def test_test_endpoint_requires_vault(monkeypatch):
    monkeypatch.delenv("MAVERICK_OAUTH_VAULT", raising=False)
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: False)
    r = client.post("/api/v1/oauth/slack/test")
    assert r.status_code == 403


def test_test_endpoint_unknown_provider_is_404(monkeypatch):
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: True)
    r = client.post("/api/v1/oauth/nope/test")
    assert r.status_code == 404


def test_test_endpoint_not_connected_is_404(monkeypatch):
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: True)

    class _Empty:
        def status(self, provider, now=None):
            return None

    monkeypatch.setattr("maverick.oauth_vault.get_vault", lambda *a, **k: _Empty())
    r = client.post("/api/v1/oauth/slack/test")
    assert r.status_code == 404


def test_test_endpoint_ok(monkeypatch):
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: True)
    monkeypatch.setattr("maverick.oauth_vault.get_vault", lambda *a, **k: _FakeVault())
    r = client.post("/api/v1/oauth/slack/test")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True and body["status"]["provider"] == "slack"
    assert "access_token" not in body["status"]


def test_test_endpoint_reports_refresh_failure(monkeypatch):
    monkeypatch.setattr("maverick.oauth_vault.enabled", lambda: True)
    monkeypatch.setattr("maverick.oauth_vault.get_vault",
                        lambda *a, **k: _FakeVault(expired=True, refresh_raises=True))
    r = client.post("/api/v1/oauth/slack/test")
    assert r.status_code == 200            # a stale connection is reported, not a 500
    body = r.json()
    assert body["ok"] is False and "invalid_grant" in body["error"]
