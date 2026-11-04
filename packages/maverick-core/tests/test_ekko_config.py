"""Ekko's client-controlled configuration boundary."""
from __future__ import annotations

from maverick import config
from maverick.config_lint import lint_config


def _load(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda *a, **k: value)
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)
    return config.get_ekko()


def test_ekko_is_off_by_default_independent_of_governed_learning(monkeypatch):
    cfg = _load(monkeypatch, {"self_learning": {"enable": True}})

    assert cfg["enable"] is False
    assert cfg["planning_enabled"] is False
    assert cfg["build_enabled"] is False
    assert cfg["provider_egress"] is False
    assert cfg["capture_level"] == "application_metadata"
    assert cfg["allowed_apps"] == []  # empty means deny-all, not observe-all
    assert cfg["retention_days"] == 14
    assert cfg["enrollment_days"] == 30


def test_ekko_high_authority_booleans_are_strict(monkeypatch):
    cfg = _load(monkeypatch, {
        "ekko": {"enable": "true", "provider_egress": "false", "planning_enabled": "true", "build_enabled": "true"},
    })

    assert cfg["enable"] is False
    assert cfg["provider_egress"] is False
    assert cfg["planning_enabled"] is False
    assert cfg["build_enabled"] is False


def test_ekko_env_switch_can_enable_disable_and_fails_closed(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "ekko": {"enable": True},
    })

    monkeypatch.setenv("MAVERICK_EKKO", "1")
    assert config.get_ekko()["enable"] is True
    monkeypatch.setenv("MAVERICK_EKKO", "0")
    assert config.get_ekko()["enable"] is False
    monkeypatch.setenv("MAVERICK_EKKO", "definitely")
    assert config.get_ekko()["enable"] is False


def test_ekko_numeric_policy_is_bounded_and_consistent(monkeypatch):
    cfg = _load(monkeypatch, {"ekko": {
        "retention_days": 999,
        "enrollment_days": 999,
        "min_occurrences": -1,
        "min_distinct_days": 999,
        "poll_interval_seconds": 0,
    }})

    assert cfg["retention_days"] == 30
    assert cfg["enrollment_days"] == 90
    assert cfg["min_occurrences"] == 2
    assert cfg["min_distinct_days"] == 30
    assert cfg["poll_interval_seconds"] == 1

    cfg = _load(monkeypatch, {"ekko": {
        "retention_days": 1,
        "min_distinct_days": 30,
        "poll_interval_seconds": True,
    }})
    assert cfg["retention_days"] == 2
    assert cfg["min_distinct_days"] == 2
    assert cfg["poll_interval_seconds"] == 5


def test_ekko_app_policy_is_bounded_normalized_and_block_wins(monkeypatch):
    cfg = _load(monkeypatch, {"ekko": {
        "allowed_apps": [" PowerPoint ", "POWERPOINT", "Bitwarden", 7],
        "blocked_apps": [" Slack ", "Database"],
    }})

    assert cfg["allowed_apps"] == ["powerpoint"]
    assert set(cfg["blocked_apps"]) >= {
        "email", "slack", "database", "salesforce", "sap",
    }

    empty = _load(monkeypatch, {"ekko": {
        "allowed_apps": ["email", "excel"],
        "blocked_apps": [],
    }})
    assert "email" not in empty["allowed_apps"]
    assert "email" in empty["blocked_apps"]

    malformed = _load(monkeypatch, {"ekko": {
        "allowed_apps": ["email"],
        "blocked_apps": ["slak"],
    }})
    assert "email" not in malformed["allowed_apps"]
    assert "email" in malformed["blocked_apps"]


def test_ekko_invalid_capture_level_falls_back_to_minimal(monkeypatch):
    cfg = _load(monkeypatch, {"ekko": {"capture_level": "screen_and_keys"}})
    assert cfg["capture_level"] == "application_metadata"


def test_ekko_provider_egress_is_reserved_and_cannot_be_armed(monkeypatch):
    cfg = _load(monkeypatch, {"ekko": {"provider_egress": True}})
    assert cfg["provider_egress"] is False


def test_ekko_policy_builder_enforces_configured_app_ceiling(monkeypatch):
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"ekko": {
        "enable": True,
        "allowed_apps": ["excel", "powerpoint", "chrome"],
    }})

    policy = config.get_ekko_policy(allowed_apps=["excel", "powerpoint"])
    assert policy.enabled is True
    assert policy.allowed_apps == {"excel", "powerpoint"}
    assert policy.provider_egress is False
    assert policy.allowed_actions == {"switch"}
    assert policy.allowed_object_types == {"none"}

    import pytest

    with pytest.raises(ValueError, match="exceed"):
        config.get_ekko_policy(allowed_apps=["tableau"])
    with pytest.raises(ValueError, match="unknown"):
        config.get_ekko_policy(allowed_apps=["excel.exe"])


def test_ekko_policy_builder_requires_nonempty_explicit_ceiling(monkeypatch):
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "ekko": {"enable": True, "allowed_apps": []},
    })

    import pytest

    with pytest.raises(ValueError, match="allowed_apps"):
        config.get_ekko_policy()


def test_ekko_enrolled_policy_must_stay_within_current_config(monkeypatch):
    monkeypatch.delenv("MAVERICK_EKKO", raising=False)
    current = {"ekko": {
        "enable": True,
        "allowed_apps": ["excel", "powerpoint"],
    }}
    monkeypatch.setattr(config, "load_config", lambda *a, **k: current)
    enrolled = config.get_ekko_policy(allowed_apps=["excel"])
    config.validate_ekko_policy_ceiling(enrolled)

    current["ekko"]["retention_days"] = 7
    import pytest

    with pytest.raises(ValueError, match="re-enrollment"):
        config.validate_ekko_policy_ceiling(enrolled)


def test_ekko_schema_flags_unknown_and_bad_authority_types():
    findings = lint_config({"ekko": {
        "retension_days": 14,
        "enable": "yes",
        "provider_egress": 1,
        "planning_enabled": "yes",
        "build_enabled": "yes",
    }})

    assert {(f.key, f.severity) for f in findings} >= {
        ("retension_days", "warning"),
        ("enable", "error"),
        ("provider_egress", "error"),
        ("planning_enabled", "error"),
        ("build_enabled", "error"),
    }

    unsupported = lint_config({"ekko": {"provider_egress": True}})
    assert [(f.key, f.severity) for f in unsupported] == [
        ("provider_egress", "error"),
    ]
