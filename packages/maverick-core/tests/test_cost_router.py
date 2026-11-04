"""Tests for the cost router (maverick.cost.router)."""
from __future__ import annotations

# ---------- cost_router: tolerates partial health snapshot ----------

def test_cost_router_tolerates_snapshot_without_error_rate(monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k")
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    # Health snapshot rows missing 'error_rate' must not crash pick().
    import maverick.provider_health as ph
    monkeypatch.setattr(
        ph, "get",
        lambda: type("H", (), {"snapshot": staticmethod(
            lambda: [
                {"provider": "deepseek", "model": "deepseek-v4-flash"}
            ])})(),
    )
    from maverick.cost.router import CostSignal, pick
    spec = pick(CostSignal())
    assert spec is None or ":" in spec  # no KeyError


# ---------- cost router ----------

def test_cost_router_disabled_returns_none(monkeypatch):
    monkeypatch.delenv("MAVERICK_COST_ROUTING", raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    from maverick.cost.router import CostSignal, pick
    assert pick(CostSignal(role="proposer")) is None


def test_cost_router_picks_cheapest_available(monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    # Only deepseek key is set -> deepseek wins on cheapness.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds_x")
    monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)

    from maverick.cost.router import TIER_CHEAP, CostSignal, pick
    spec = pick(CostSignal(tier=TIER_CHEAP))
    assert spec is not None
    assert spec.startswith("deepseek:")


def test_cost_router_falls_back_when_no_provider_configured(monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY",
              "MOONSHOT_API_KEY", "XAI_API_KEY", "GROK_API_KEY",
              "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)

    from maverick.cost.router import CostSignal, pick
    # When no provider has usable credentials, the picker returns None so
    # model_for_role() defers to the role defaults. Picking a provider we
    # have no key for would only blow up later at client construction.
    spec = pick(CostSignal())
    assert spec is None


def test_cost_router_avoids_high_error_provider(monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k1")
    monkeypatch.setenv("OPENAI_API_KEY", "k2")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("MOONSHOT_API_KEY", raising=False)
    monkeypatch.delenv("XAI_API_KEY", raising=False)
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)

    # Poison deepseek with errors. With penalty factor (1 + 5 * 1.0) = 6x
    # cost surcharge, even DeepSeek's cheapness should be overridden.
    from maverick.provider_health import get as _h
    # Use the real singleton — reset it so we can install our pattern.
    ph = _h()
    ph.reset()
    for _ in range(10):
        ph.record("deepseek", "deepseek-v4-flash",
                  latency_ms=100, error=True)
    try:
        from maverick.cost.router import TIER_CHEAP, CostSignal, pick
        spec = pick(CostSignal(tier=TIER_CHEAP))
        assert spec is not None
        # Errored model itself should not be the pick (within-brand
        # swap to a non-errored model is acceptable).
        assert spec != "deepseek:deepseek-v4-flash"
    finally:
        ph.reset()


def test_cost_router_respects_routing_provider_allowlist(monkeypatch):
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "deepseek-key")
    for k in ("OPENAI_API_KEY", "MOONSHOT_API_KEY", "XAI_API_KEY",
              "GROK_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)

    import maverick.config as cfg
    monkeypatch.setattr(
        cfg,
        "load_config",
        lambda: {"routing": {"allowed_providers": ["anthropic"]}},
    )

    from maverick.cost.router import TIER_BASE, CostSignal, pick

    spec = pick(CostSignal(tier=TIER_BASE))
    assert spec is not None
    assert spec.startswith("anthropic:"), spec


class TestCostRouterReconciled:
    def test_deepseek_and_moonshot_match_model_prices(self):
        from maverick.cost.router import _PRICING
        from maverick.llm import MODEL_PRICES
        rates = {mid: (cin, cout) for _p, mid, _t, cin, cout in _PRICING}
        for mid in ("deepseek-v4-flash", "moonshot-v1-128k"):
            assert mid in MODEL_PRICES
            assert rates[mid] == MODEL_PRICES[mid], mid
