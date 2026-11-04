"""MiniMax M2.5 provisional OpenRouter pricing is planning-only.

These tests pin that:
  - the provisional value remains available for explicit estimates;
  - live billing and routing refuse it until its source is verified;
  - none of this changes default model selection (additive / opt-in).

Hermetic: no network, no real config. Env is scrubbed so only the keys a test
sets are visible to the router's availability heuristic.
"""
from __future__ import annotations

import pytest

# OpenRouter `vendor/model` id for MiniMax M2.5. This is the bare model_id
# _lookup_price sees after stripping the `openrouter:` prefix, so it must be
# the MODEL_PRICES key too.
MINIMAX_ID = "minimax/minimax-m2.5"
MINIMAX_SPEC = f"openrouter:{MINIMAX_ID}"


@pytest.fixture
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_COST_ROUTING", raising=False)
    for prov in (
        "ANTHROPIC", "OPENAI", "DEEPSEEK", "MOONSHOT",
        "XAI", "GEMINI", "GOOGLE", "OPENROUTER",
    ):
        monkeypatch.delenv(f"{prov}_API_KEY", raising=False)
    for role in ("CODER", "ORCHESTRATOR", "SUMMARIZER"):
        monkeypatch.delenv(f"MAVERICK_MODEL_OVERRIDE_{role}", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    # Point HOME at a tmp with no config so get_role_model returns None.
    monkeypatch.setenv("HOME", "/nonexistent-minimax-routing-test")


def test_minimax_is_priced_in_model_prices():
    from maverick.llm import MODEL_PRICES
    assert MINIMAX_ID in MODEL_PRICES
    in_rate, out_rate = MODEL_PRICES[MINIMAX_ID]
    # Cheap near-frontier: well under flagship rates, sane ordering.
    assert 0 < in_rate < out_rate < 5.0


def test_lookup_price_resolves_openrouter_spec_for_estimate_only():
    # The provider-qualified id resolves without losing the vendor/model suffix,
    # but only after the caller explicitly selects planning mode.
    from maverick.budget import UnpricedModelError, _lookup_price
    from maverick.llm import MODEL_PRICES

    with pytest.raises(UnpricedModelError, match="unverified"):
        _lookup_price(MINIMAX_SPEC)
    priced = _lookup_price(MINIMAX_SPEC, estimate_only=True)
    assert priced == MODEL_PRICES[MINIMAX_ID]


def test_minimax_in_router_cheap_tier():
    from maverick.cost import router as cost_router
    rows = [
        r for r in cost_router._PRICING
        if r[0] == "openrouter" and r[1] == MINIMAX_ID
    ]
    assert rows, "MiniMax M2.5 missing from the cost router's OpenRouter tier"
    assert rows[0][2] == cost_router.TIER_CHEAP


def test_router_requires_estimate_only_to_consider_minimax(_clean, monkeypatch):
    # With only provisional OpenRouter prices available, live role resolution
    # falls back rather than selecting an unbillable model. A planning caller
    # can still ask the router for the estimate-only candidate.
    monkeypatch.setenv("MAVERICK_COST_ROUTING", "1")
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    from maverick.cost import router
    from maverick.llm import ROLE_MODELS, model_for_role

    got = model_for_role("summarizer")
    assert got == ROLE_MODELS["summarizer"]
    estimate = router.pick(router.signal_for_role("summarizer"), estimate_only=True)
    assert estimate.startswith("openrouter:"), estimate


def test_off_by_default_does_not_select_openrouter(_clean, monkeypatch):
    # Routing disabled (default): MiniMax is registered but never selected;
    # the static ROLE_MODELS default wins. Additive change, no behaviour drift.
    monkeypatch.setenv("OPENROUTER_API_KEY", "x")
    from maverick.llm import ROLE_MODELS, model_for_role

    assert model_for_role("summarizer") == ROLE_MODELS["summarizer"]
