"""Installer coverage for the governed candidate-promotion feature gate."""

from __future__ import annotations

import pytest


def test_candidate_promotion_picker_is_explicit_and_off_by_default(monkeypatch):
    from maverick_installer import wizard

    observed = {}

    def confirm(prompt, *, default):
        observed.update(prompt=prompt, default=default)
        return False

    monkeypatch.setattr(wizard, "_q_confirm", confirm)

    assert wizard.pick_candidate_promotion() == {"enable": False}
    assert observed["default"] is False
    assert "candidate promotion" in observed["prompt"].lower()


def test_candidate_promotion_picker_writes_safe_installed_target_defaults(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *args, **kwargs: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *args, **kwargs: "installed-lightwork")

    assert wizard.pick_candidate_promotion() == {
        "enable": True,
        "allowed_targets": ["installed-lightwork"],
        "review_ttl_seconds": 3600,
        "canary_metric": "error_rate",
        "canary_comparison": "at_most",
        "canary_threshold": 0.05,
    }


def test_candidate_promotion_config_is_closed_boolean_toml():
    from maverick_installer import wizard

    enabled = {
        "enable": True,
        "allowed_targets": ["installed-lightwork"],
        "review_ttl_seconds": 3600,
        "canary_metric": "error_rate",
        "canary_comparison": "at_most",
        "canary_threshold": 0.05,
    }
    result = wizard._cfg_candidate_promotion(enabled)
    assert result[:3] == ["", "[candidate_promotion]", "enable = true"]
    assert 'allowed_targets = ["installed-lightwork"]' in result
    assert wizard._cfg_candidate_promotion({"enable": False})[-1] == "enable = false"


def test_candidate_promotion_config_rejects_ambiguous_enable_values():
    from maverick_installer import wizard

    with pytest.raises(ValueError, match="must be boolean"):
        wizard._cfg_candidate_promotion({"enable": "true"})
