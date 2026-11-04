"""Per-tenant BYOK provider keys (bring-your-own-key for LLM credentials).

Proves the fail-safe resolution contract for
:func:`maverick.config.tenant_provider_api_key` and the LLM wiring:

  * the ``[providers] per_tenant_keys`` knob is **off by default**;
  * with it on, tenant A runs on A's key and tenant B on B's;
  * no active tenant => the deployment-global key (resolver returns ``None``);
  * a tenant opted into BYOK but with no key configured => falls back to the
    global key without crashing;
  * the knob off, or the tenant flag off, ignores any tenant secret;
  * the key bytes are never stored on the tenant record or written to the log.

Pure/offline: a temp ``MAVERICK_HOME`` so nothing touches the real home or
registry; the "secret provider" is the default env backend, exercised through
the real tenant-scoped secret-name convention.
"""
from __future__ import annotations

import logging

import pytest
from maverick import config
from maverick.paths import reset_tenant, set_tenant
from maverick.tenant import registry


@pytest.fixture(autouse=True)
def _temp_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_PER_TENANT_KEYS", raising=False)
    # Clear the global provider key so "global" resolution is deterministic.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    tok = set_tenant(None)
    yield
    reset_tenant(tok)


def _enable_byok(monkeypatch, tenant: str, provider: str = "anthropic",
                 key: str | None = None) -> str:
    """Provision a BYOK-opted tenant and (optionally) set its secret. Returns
    the tenant-scoped secret env name."""
    registry.create_tenant(tenant)
    registry.set_byok(tenant, True)
    env_name = config.tenant_provider_key_env(tenant, provider)
    if key is not None:
        monkeypatch.setenv(env_name, key)
    return env_name


# ---- the knob ----

def test_knob_defaults_off():
    # No config, no env => the historical global-key behavior.
    assert config.providers_per_tenant_keys() is False


def test_knob_env_override_wins():
    import os
    os.environ["MAVERICK_PER_TENANT_KEYS"] = "1"
    try:
        assert config.providers_per_tenant_keys() is True
    finally:
        del os.environ["MAVERICK_PER_TENANT_KEYS"]


# ---- resolution ----

def test_no_tenant_defers_to_global(monkeypatch):
    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    # No active tenant => the resolver defers (None) so the caller uses global.
    assert config.tenant_provider_api_key("anthropic") is None


def test_active_tenant_uses_its_own_key(monkeypatch):
    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    _enable_byok(monkeypatch, "acme", key="sk-acme")  # pragma: allowlist secret
    _enable_byok(monkeypatch, "globex", key="sk-globex")  # pragma: allowlist secret

    tok = set_tenant("acme")
    try:
        assert config.tenant_provider_api_key("anthropic") == "sk-acme"  # pragma: allowlist secret
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        assert config.tenant_provider_api_key("anthropic") == "sk-globex"  # pragma: allowlist secret
    finally:
        reset_tenant(tok)


def test_byok_on_but_no_key_falls_back_to_global(monkeypatch):
    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    _enable_byok(monkeypatch, "acme")  # flag on, but no secret set
    tok = set_tenant("acme")
    try:
        # Falls back to the global key (resolver returns None) -- never crashes.
        assert config.tenant_provider_api_key("anthropic") is None
    finally:
        reset_tenant(tok)


def test_knob_off_ignores_tenant_key(monkeypatch):
    # Master switch off (default): a tenant secret + flag is inert.
    _enable_byok(monkeypatch, "acme", key="sk-acme")  # pragma: allowlist secret
    tok = set_tenant("acme")
    try:
        assert config.tenant_provider_api_key("anthropic") is None
    finally:
        reset_tenant(tok)


def test_flag_off_ignores_tenant_secret(monkeypatch):
    # Knob on, but the tenant never opted in => the stray secret is ignored
    # (explicit per-tenant opt-in required).
    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    registry.create_tenant("acme")  # byok defaults False
    monkeypatch.setenv(
        config.tenant_provider_key_env("acme", "anthropic"),
        "sk-acme",  # pragma: allowlist secret
    )
    tok = set_tenant("acme")
    try:
        assert config.tenant_provider_api_key("anthropic") is None
    finally:
        reset_tenant(tok)


def test_unknown_tenant_is_fail_soft(monkeypatch):
    # Active tenant with no registry record => defer to global, never raise.
    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    tok = set_tenant("ghost")
    try:
        assert config.tenant_provider_api_key("anthropic") is None
    finally:
        reset_tenant(tok)


# ---- LLM wiring ----

def test_llm_provider_api_key_prefers_tenant_then_global(monkeypatch):
    from maverick import llm

    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    _enable_byok(monkeypatch, "acme", key="sk-acme")  # pragma: allowlist secret

    tok = set_tenant("acme")
    try:
        assert llm._provider_api_key("anthropic", None) == "sk-acme"  # pragma: allowlist secret
    finally:
        reset_tenant(tok)

    # No tenant active => the existing global env path is byte-for-byte unchanged.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-global")  # pragma: allowlist secret
    assert llm._provider_api_key("anthropic", None) == "sk-global"  # pragma: allowlist secret


def test_get_client_constructs_with_tenant_key(monkeypatch):
    from maverick import llm as llm_mod
    from maverick import providers

    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    _enable_byok(monkeypatch, "acme", key="sk-acme")  # pragma: allowlist secret

    seen: list[str | None] = []

    def factory(_provider, *, api_key=None, base_url=None,
                default_headers=None, **_kwargs):
        seen.append(api_key)
        return object()

    monkeypatch.setattr(providers, "get_provider_client", factory)

    dispatcher = llm_mod.LLM(model="anthropic:claude-x")
    tok = set_tenant("acme")
    try:
        dispatcher._get_client("anthropic")
    finally:
        reset_tenant(tok)
    assert seen == ["sk-acme"]  # pragma: allowlist secret


# ---- secret-name convention ----

def test_key_env_name_is_collision_safe_and_shaped():
    a = config.tenant_provider_key_env("acme-1", "anthropic")
    b = config.tenant_provider_key_env("acme_1", "anthropic")
    # Distinct tenants that would share a naive uppercased slug get distinct
    # secret names (the digest is derived from the collision-safe namespace key).
    assert a != b
    assert a.startswith("MAVERICK_TENANT_")
    assert a.endswith("_ANTHROPIC_API_KEY")
    # Provider aliases canonicalize to one name.
    assert config.tenant_provider_key_env("acme", "claude") == \
        config.tenant_provider_key_env("acme", "anthropic")


def test_key_env_name_is_redacted_by_the_action_sanitizer():
    # The GitHub Action output sanitizer must treat the tenant-scoped key name
    # as a secret (it ends in _API_KEY) so it is never echoed in Action logs.
    import runpy
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    registry_mod = runpy.run_path(
        str(repo_root / "deploy" / "github-action" / "secret_env_registry.py")
    )
    name = config.tenant_provider_key_env("acme", "anthropic")
    assert registry_mod["is_secret_env_name"](name) is True


# ---- no secret leakage ----

def test_key_never_logged_or_stored_on_record(monkeypatch, caplog):
    monkeypatch.setenv("MAVERICK_PER_TENANT_KEYS", "1")
    secret = "sk-super-secret-acme-value"  # pragma: allowlist secret
    _enable_byok(monkeypatch, "acme", key=secret)

    caplog.set_level(logging.DEBUG)
    tok = set_tenant("acme")
    try:
        assert config.tenant_provider_api_key("anthropic") == secret
    finally:
        reset_tenant(tok)

    assert secret not in caplog.text
    # The tenant record holds only a flag, never the key bytes.
    rec = registry.get_tenant("acme")
    assert rec.byok is True
    assert secret not in repr(rec)
    assert secret not in str(rec.to_dict())


# ---- registry flag ----

def test_byok_flag_roundtrips_and_serializes_only_when_true():
    registry.create_tenant("acme")
    assert registry.get_tenant("acme").byok is False
    assert "byok" not in registry.get_tenant("acme").to_dict()

    registry.set_byok("acme", True)
    rec = registry.get_tenant("acme")
    assert rec.byok is True
    assert rec.to_dict()["byok"] is True

    registry.set_byok("acme", False)
    assert registry.get_tenant("acme").byok is False
    assert "byok" not in registry.get_tenant("acme").to_dict()
