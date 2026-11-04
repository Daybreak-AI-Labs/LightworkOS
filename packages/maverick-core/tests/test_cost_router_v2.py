"""Tests for cost-aware router v2: per-role routing policies
([routing.roles.<role>]). v1 behavior must be untouched when the table is absent."""
from __future__ import annotations

from maverick.cost import router as cr


def _enable(monkeypatch, providers=("anthropic", "deepseek", "openai")):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY",
                "MOONSHOT_API_KEY", "XAI_API_KEY", "GROK_API_KEY",
                "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    keys = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY", "gemini": "GEMINI_API_KEY",
            "xai": "XAI_API_KEY", "moonshot": "MOONSHOT_API_KEY",
            "openrouter": "OPENROUTER_API_KEY"}
    for p in providers:
        monkeypatch.setenv(keys[p], "k")


def _policy(monkeypatch, role_table):
    monkeypatch.setattr(
        cr, "role_policy",
        lambda role: role_table.get(role, cr.RolePolicy()),
    )


def test_empty_policy_when_table_absent(monkeypatch):
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", dict)
    assert cr.role_policy("coder").is_empty()


def test_explicit_env_false_overrides_enabled_config(monkeypatch):
    import maverick.config as config_mod

    monkeypatch.setenv("MAVERICK_COST_ROUTING", "0")
    monkeypatch.setattr(
        config_mod,
        "load_config",
        lambda: {"routing": {"cost_aware": True}},
    )
    assert cr._enabled() is False


def test_invalid_config_type_disables_with_actionable_warning(monkeypatch, caplog):
    import maverick.config as config_mod

    monkeypatch.delenv("MAVERICK_COST_ROUTING", raising=False)
    monkeypatch.setattr(
        config_mod,
        "load_config",
        lambda: {"routing": {"cost_aware": "false"}},
    )
    assert cr._enabled() is False
    assert "routing.cost_aware must be true or false" in caplog.text


def test_invalid_env_value_is_visible_and_fails_closed(monkeypatch, caplog):
    import maverick.config as config_mod

    monkeypatch.setenv("MAVERICK_COST_ROUTING", "ture")
    monkeypatch.setattr(
        config_mod,
        "load_config",
        lambda: {"routing": {"cost_aware": True}},
    )
    assert cr._enabled() is False
    assert "MAVERICK_COST_ROUTING must be one of" in caplog.text


def test_policy_load_failure_is_visible(monkeypatch, caplog):
    import maverick.config as config_mod

    monkeypatch.setattr(
        config_mod,
        "load_config",
        lambda: (_ for _ in ()).throw(RuntimeError("broken config source")),
    )
    assert cr.role_policy("coder").is_empty()
    assert "could not read policy" in caplog.text


def test_role_policy_parses_config(monkeypatch):
    import maverick.config as config_mod
    monkeypatch.setattr(config_mod, "load_config", lambda: {
        "routing": {"roles": {"summarizer": {
            "providers": ["DeepSeek"],
            "deny_providers": ["openai"],
            "max_price_per_mtok": 2.0,
            "tier": "cheap",
        }}},
    })
    pol = cr.role_policy("summarizer")
    assert pol.providers == frozenset({"deepseek"})
    assert pol.deny_providers == frozenset({"openai"})
    assert pol.max_price_per_mtok == 2.0
    assert pol.tier == cr.TIER_CHEAP
    assert cr.role_policy("coder").is_empty()


def test_provider_allowlist_restricts_pick(monkeypatch):
    _enable(monkeypatch)
    _policy(monkeypatch, {"summarizer": cr.RolePolicy(providers=frozenset({"deepseek"}))})
    out = cr.pick(cr.signal_for_role("summarizer"))
    assert out is not None and out.startswith("deepseek:")


def test_deny_providers_excludes(monkeypatch):
    _enable(monkeypatch, providers=("deepseek", "anthropic"))
    _policy(monkeypatch, {"summarizer": cr.RolePolicy(deny_providers=frozenset({"deepseek"}))})
    out = cr.pick(cr.signal_for_role("summarizer"))
    assert out is not None and out.startswith("anthropic:")


def test_price_ceiling_filters(monkeypatch):
    _enable(monkeypatch)
    # Ceiling so low nothing qualifies -> defer to default (None).
    _policy(monkeypatch, {"coder": cr.RolePolicy(max_price_per_mtok=0.000001)})
    assert cr.pick(cr.signal_for_role("coder")) is None


def test_tier_override_upgrades(monkeypatch):
    _enable(monkeypatch, providers=("anthropic",))
    # Summarizer normally routes cheap (haiku); a premium tier floor forces opus.
    _policy(monkeypatch, {"summarizer": cr.RolePolicy(tier=cr.TIER_PREMIUM)})
    out = cr.pick(cr.signal_for_role("summarizer"))
    assert out is not None and "opus" in out


def test_no_policy_means_v1_pick(monkeypatch):
    _enable(monkeypatch, providers=("anthropic",))
    _policy(monkeypatch, {})
    out = cr.pick(cr.signal_for_role("summarizer"))
    assert out is not None and "haiku" in out  # cheapest anthropic tier-0
