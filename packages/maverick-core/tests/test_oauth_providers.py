"""OAuth provider presets: the turnkey connect registry -- authorize-URL build,
preset-driven refresher, and code exchange that seals into the vault."""
from __future__ import annotations

import pytest
from maverick import oauth_providers as op


def test_catalog_has_major_providers_and_no_secrets():
    names = op.available_providers()
    for expected in ("google", "slack", "github", "microsoft"):
        assert expected in names
    cat = op.provider_catalog()
    blob = repr(cat)
    assert "client_id_env" in blob and "client_secret_env" in blob
    # the catalog names the env vars but never a secret value
    assert "SECRET=" not in blob


def test_build_authorize_url_uses_preset_and_pkce(monkeypatch):
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_ID", "cid-1")
    url, verifier = op.build_authorize_url("slack", redirect_uri="https://a/cb", state="st")
    assert url.startswith("https://slack.com/oauth/v2/authorize?")
    assert "client_id=cid-1" in url
    assert "code_challenge=" in url and "code_challenge_method=S256" in url
    assert "state=st" in url
    assert verifier                       # PKCE verifier returned to keep


def test_authorize_url_none_without_client_id(monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    assert op.build_authorize_url("github", redirect_uri="https://a/cb") is None


def test_authorize_url_none_for_unknown_provider():
    assert op.build_authorize_url("nope", redirect_uri="https://a/cb") is None


def test_google_forces_offline_consent(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "g")
    url, _ = op.build_authorize_url("google", redirect_uri="https://a/cb")
    assert "access_type=offline" in url and "prompt=consent" in url


def test_make_refresher_posts_to_preset_token_url(monkeypatch):
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_ID", "cid-1")
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_SECRET", "shh")
    seen = {}

    def _fake_post(url, data):
        seen["url"] = url
        seen["data"] = data
        return {"access_token": "AT2", "expires_in": 3600}

    monkeypatch.setattr("maverick.tools.oauth_helper._post_form", _fake_post)
    refresher = op.make_refresher("slack")
    assert refresher is not None
    out = refresher({"refresh_token": "RT1"})
    assert out["access_token"] == "AT2"
    assert seen["url"] == "https://slack.com/api/oauth.v2.access"
    assert seen["data"]["grant_type"] == "refresh_token"
    assert seen["data"]["client_id"] == "cid-1"
    assert seen["data"]["client_secret"] == "shh"    # pragma: allowlist secret
    assert seen["data"]["refresh_token"] == "RT1"


def test_make_refresher_none_for_unknown_or_no_creds(monkeypatch):
    monkeypatch.delenv("SLACK_OAUTH_CLIENT_ID", raising=False)
    assert op.make_refresher("slack") is None          # no client id
    assert op.make_refresher("nope", client_id="x") is None  # unknown provider


def test_exchange_code_seals_token_in_vault(monkeypatch):
    monkeypatch.setenv("SLACK_OAUTH_CLIENT_ID", "cid-1")
    monkeypatch.setattr(
        "maverick.tools.oauth_helper._post_form",
        lambda url, data: {"access_token": "AT", "refresh_token": "RT", "expires_in": 100},
    )
    put = {}

    class _Vault:
        def put(self, provider, record):
            put["provider"] = provider
            put["record"] = record

    monkeypatch.setattr("maverick.oauth_vault.get_vault", lambda *a, **k: _Vault())
    summary = op.exchange_code("slack", code="abc", redirect_uri="https://a/cb", verifier="v")
    assert put["provider"] == "slack"
    assert put["record"]["access_token"] == "AT"
    assert summary["has_refresh_token"] is True
    assert "access_token" not in summary                # summary is redacted


def test_exchange_code_rejects_unknown_provider():
    with pytest.raises(ValueError):
        op.exchange_code("nope", code="x", redirect_uri="https://a/cb")


def test_exchange_code_requires_client_id(monkeypatch):
    monkeypatch.delenv("SLACK_OAUTH_CLIENT_ID", raising=False)
    with pytest.raises(ValueError):
        op.exchange_code("slack", code="x", redirect_uri="https://a/cb")
