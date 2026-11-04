"""Configuration contract for the production-affecting promotion surface."""

from __future__ import annotations


def test_candidate_promotion_requires_explicit_true(monkeypatch):
    from maverick import config

    monkeypatch.delenv("MAVERICK_CANDIDATE_PROMOTION", raising=False)
    assert config.candidate_promotion_enabled({}) is False
    assert config.candidate_promotion_enabled({"candidate_promotion": {"enable": True}}) is True
    assert config.candidate_promotion_enabled({"candidate_promotion": {"enable": False}}) is False
    assert config.candidate_promotion_enabled({"candidate_promotion": {"enable": "true"}}) is False
    assert config.candidate_promotion_enabled({"candidate_promotion": []}) is False


def test_candidate_promotion_environment_override_is_strict(monkeypatch):
    from maverick import config

    monkeypatch.setenv("MAVERICK_CANDIDATE_PROMOTION", "1")
    assert config.candidate_promotion_enabled({}) is True
    monkeypatch.setenv("MAVERICK_CANDIDATE_PROMOTION", "0")
    assert config.candidate_promotion_enabled({"candidate_promotion": {"enable": True}}) is False


def test_candidate_promotion_fails_closed_on_config_source_errors(monkeypatch):
    from maverick import config

    monkeypatch.delenv("MAVERICK_CANDIDATE_PROMOTION", raising=False)
    monkeypatch.setattr(config, "load_config", lambda: {"candidate_promotion": {"enable": True}})
    monkeypatch.setattr(config, "config_source_errors", lambda: ["invalid"])
    assert config.candidate_promotion_enabled() is False
