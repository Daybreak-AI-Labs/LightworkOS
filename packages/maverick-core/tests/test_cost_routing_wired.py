"""Cost-aware routing is wired into model_for_role (the single chokepoint
every Agent uses to resolve its model).

Before this, cost_router.pick() existed but nothing called it from the live
path -- enabling MAVERICK_COST_ROUTING did nothing. These tests pin that:
  - off by default: behaviour unchanged (ROLE_MODELS defaults win)
  - explicit user choice (env override / config) always wins over the router
  - when opted in with a cheap provider configured, cheap roles route to it
  - the router never picks below a role's tier (orchestrator stays premium)
"""
from __future__ import annotations

import pytest


@pytest.fixture
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_COST_ROUTING", raising=False)
    for prov in (
        "ANTHROPIC", "OPENAI", "DEEPSEEK", "MOONSHOT",
        "XAI", "GEMINI", "GOOGLE",
    ):
        monkeypatch.delenv(f"{prov}_API_KEY", raising=False)
    for role in ("CODER", "ORCHESTRATOR", "SUMMARIZER"):
        monkeypatch.delenv(f"MAVERICK_MODEL_OVERRIDE_{role}", raising=False)
    # Point HOME at a tmp with no config so get_role_model returns None.
    monkeypatch.setenv("HOME", "/nonexistent-cost-routing-test")


def test_off_by_default_uses_role_defaults(_clean):
    from maverick.llm import ROLE_MODELS, model_for_role
    # No routing flag -> the static ROLE_MODELS default.
    assert model_for_role("coder") == ROLE_MODELS["coder"]
    assert model_for_role("orchestrator") == ROLE_MODELS["orchestrator"]


def test_env_override_beats_router(_clean, monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    monkeypatch.setenv("MAVERICK_MODEL_OVERRIDE_CODER", "anthropic:claude-opus-4-8")
    from maverick.llm import model_for_role
    # Explicit user override wins even with routing on + a cheaper provider.
    assert model_for_role("coder") == "anthropic:claude-opus-4-8"


def test_enabled_routes_base_role_to_cheapest_provider(_clean, monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    from maverick.llm import model_for_role
    # coder is TIER_BASE; with only DeepSeek keyed, the cheapest base-tier
    # option is deepseek -> a current v4 model.
    got = model_for_role("coder")
    assert got.startswith("deepseek:"), got


def test_enabled_keeps_orchestrator_at_premium_tier(_clean, monkeypatch):
    # Even with a cheap provider configured, the orchestrator must not be
    # routed below its premium tier -- only Anthropic is keyed, so it stays
    # on the premium Anthropic model (opus 4.8).
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    from maverick.llm import model_for_role
    got = model_for_role("orchestrator")
    assert got == "anthropic:claude-opus-4-8", got


def test_router_premium_prefers_opus_4_8_over_4_7():
    from maverick.cost import router as cost_router
    # Both opus rows are premium at equal cost; 4-8 is listed first so it
    # wins the cost sort (stable). Confirms enabling routing doesn't
    # regress the flagship to the prior generation.
    rows = [r for r in cost_router._PRICING
            if r[0] == "anthropic" and r[2] == cost_router.TIER_PREMIUM]
    assert rows[0][1] == "claude-opus-4-8"


def test_signal_for_role_tiers():
    from maverick.cost import router as cost_router
    assert cost_router.signal_for_role("orchestrator").tier == cost_router.TIER_PREMIUM
    assert cost_router.signal_for_role("summarizer").tier == cost_router.TIER_CHEAP
    assert cost_router.signal_for_role("coder").tier == cost_router.TIER_BASE
    assert cost_router.signal_for_role("revisor").output_heavy is True


def test_enabled_defers_when_no_available_provider_at_required_tier(_clean, monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "x")
    from maverick.llm import ROLE_MODELS, model_for_role

    # DeepSeek has no premium-tier pricing row. The router must not fall back
    # to an unconfigured premium provider such as Gemini; it should defer to
    # the normal role default instead.
    assert model_for_role("orchestrator") == ROLE_MODELS["orchestrator"]


def test_config_provider_key_is_passed_to_provider_client(_clean, monkeypatch, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[providers.deepseek]\napi_key = " config-key "\n')
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))

    calls = []

    class DummyClient:
        pass

    def fake_get_provider_client(name, api_key=None, base_url=None, default_headers=None, environment=None):
        assert isinstance(environment, dict)
        calls.append((name, api_key))
        return DummyClient()

    import maverick.providers as providers
    from maverick.llm import LLM

    monkeypatch.setattr(providers, "get_provider_client", fake_get_provider_client)

    client = LLM("deepseek:deepseek-v4-pro")._get_client("deepseek")

    assert isinstance(client, DummyClient)
    assert calls == [("deepseek", "config-key")]
