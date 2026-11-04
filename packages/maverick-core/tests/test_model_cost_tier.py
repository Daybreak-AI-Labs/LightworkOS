"""Model cost tiers: bands derived from real price, config-overridable."""
from __future__ import annotations

import pytest
from maverick import model_cost_tier as mct


def test_bands_track_the_real_price_table():
    # Opus is Very High, Sonnet High, Haiku Medium, a cheap open model Low.
    assert mct.band_for("claude-opus-4-8") == "very_high"
    assert mct.band_for("claude-opus-4-8-fast") == "very_high"
    assert mct.band_for("claude-sonnet-4-6") == "high"
    assert mct.band_for("claude-haiku-4-5") == "medium"
    assert mct.band_for("deepseek-v4-flash") == "low"


def test_provider_prefix_and_unknown_model():
    assert mct.band_for("anthropic:claude-opus-4-8") == "very_high"
    # An unpriced/local endpoint is cheap to run at scale -> low, never a crash.
    assert mct.band_for("local:my-finetuned-7b") == "low"
    assert mct.blended_rate("local:my-finetuned-7b") is None


def test_band_detail_and_catalog_shape():
    d = mct.band_detail("claude-haiku-4-5")
    assert d["band"] == "medium" and d["label"] == "Medium"
    assert d["overridden"] is False and d["blended_rate"] == pytest.approx(4.2)
    cat = mct.catalog()
    assert cat and all("band" in r and "label" in r for r in cat)
    # Very High sorts before Low.
    bands = [r["band"] for r in cat]
    assert bands.index("very_high") < bands.index("low")


def test_config_override_wins(monkeypatch, tmp_path):
    from maverick import config
    cfg = tmp_path / "config.toml"
    cfg.write_text('[model_cost_tiers]\n"claude-opus-4-8" = "low"\n',
                   encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    try:
        d = mct.band_detail("claude-opus-4-8")
        assert d["band"] == "low" and d["overridden"] is True
    finally:
        config.reset_config_cache()
