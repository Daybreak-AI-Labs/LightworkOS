"""Per-tenant channel credentials and OIDC config (one-instance-per-tenant).

The supported multi-tenant deployment shape is one instance per tenant with
``MAVERICK_TENANT`` set. In that model the per-tenant config overlay
(``~/.maverick/tenants/<id>/config.toml``) must drive BOTH the channel bot
identities (``[channels.*]``) and the OIDC identity provider (``[auth.oidc]``),
so each tenant authenticates against its own IdP and replies from its own bot
account. These tests pin that resolution.

(A single shared process with ``MAVERICK_TENANT_BY_USER`` necessarily shares one
inbound bot identity and one IdP -- the listener/issuer is what identifies the
user -- which is why distinct per-tenant identities require separate instances.)
"""
from __future__ import annotations

import pytest
from maverick import config
from maverick.oidc import load_oidc_config


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # Env vars take precedence over config; clear them so the overlay is what we test.
    for v in ("MAVERICK_OIDC_ISSUER", "MAVERICK_OIDC_AUDIENCE", "MAVERICK_OIDC_JWKS_URI"):
        monkeypatch.delenv(v, raising=False)


def _write_tenant_overlay(tenant: str, body: str):
    from maverick.paths import data_dir
    d = data_dir(tenant=tenant)
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.toml").write_text(body, encoding="utf-8")


def test_channel_identity_is_per_tenant(monkeypatch):
    _write_tenant_overlay(
        "acme",
        "[channels.slack]\nenabled = true\nbot_token = \"acme-slack-bot\"\n",  # pragma: allowlist secret
    )
    # With this tenant active, channel config resolves to the tenant's bot.
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    slack = config.load_config().get("channels", {}).get("slack", {})
    assert slack.get("bot_token") == "acme-slack-bot"  # pragma: allowlist secret
    assert slack.get("enabled") is True

    # A different tenant with no overlay does NOT inherit acme's bot identity.
    monkeypatch.setenv("MAVERICK_TENANT", "globex")
    assert config.load_config().get("channels", {}).get("slack", {}).get("bot_token") is None


def test_oidc_issuer_is_per_tenant(monkeypatch):
    _write_tenant_overlay(
        "acme",
        '[auth.oidc]\nissuer = "https://acme.example.com"\n'
        'audience = "maverick-acme"\njwks_uri = "https://acme.example.com/jwks"\n',
    )
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    cfg = load_oidc_config()
    assert cfg.issuer == "https://acme.example.com"
    assert cfg.audience == "maverick-acme"

    # Another tenant without an overlay gets no issuer (not acme's).
    monkeypatch.setenv("MAVERICK_TENANT", "globex")
    assert load_oidc_config().issuer == ""
