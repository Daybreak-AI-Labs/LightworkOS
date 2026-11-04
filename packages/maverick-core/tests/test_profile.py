"""Deployment profile resolver: one named knob (standard | enterprise)."""
from __future__ import annotations

import pytest
from maverick.enterprise import enterprise_enabled
from maverick.profile import (
    ENTERPRISE,
    STANDARD,
    active_profile,
    is_enterprise_profile,
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Known-off start: no profile env, empty config."""
    monkeypatch.delenv("MAVERICK_PROFILE", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_default_is_standard():
    assert active_profile() == STANDARD
    assert is_enterprise_profile() is False


def test_env_selects_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    assert active_profile() == ENTERPRISE
    assert is_enterprise_profile() is True


@pytest.mark.parametrize("alias", ["enterprise", "regulated", "hardened", "prod",
                                   "production", "ENTERPRISE", " Enterprise "])
def test_enterprise_aliases(monkeypatch, alias):
    monkeypatch.setenv("MAVERICK_PROFILE", alias)
    assert active_profile() == ENTERPRISE


@pytest.mark.parametrize("alias", ["standard", "dev", "local", "personal", "default"])
def test_standard_aliases(monkeypatch, alias):
    monkeypatch.setenv("MAVERICK_PROFILE", alias)
    assert active_profile() == STANDARD


def test_config_selects_enterprise(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"profile": {"name": "enterprise"}},
    )
    assert active_profile() == ENTERPRISE


def test_env_wins_over_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"profile": {"name": "enterprise"}},
    )
    monkeypatch.setenv("MAVERICK_PROFILE", "standard")
    assert active_profile() == STANDARD


def test_unrecognized_value_falls_back_to_standard(monkeypatch):
    # Must not raise and must not silently pick a posture the operator didn't name.
    monkeypatch.setenv("MAVERICK_PROFILE", "ultra-mega-secure")
    assert active_profile() == STANDARD


def test_enterprise_profile_turns_on_the_boundary(monkeypatch):
    """profile=enterprise enables enterprise mode when no explicit knob is set."""
    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    assert enterprise_enabled() is True


def test_explicit_disable_wins_over_enterprise_profile(monkeypatch):
    """An explicit [enterprise] mode=false beats profile=enterprise (knob wins)."""
    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"enterprise": {"mode": False}},
    )
    assert enterprise_enabled() is False


def test_env_enterprise_off_wins_over_enterprise_profile(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    assert enterprise_enabled() is False


def test_standard_profile_leaves_boundary_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROFILE", "standard")
    assert enterprise_enabled() is False
