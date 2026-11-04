"""Governance levels: the installer's level-to-settings expansion as a kernel function."""
from __future__ import annotations

import builtins

import pytest
from maverick import governance_levels as levels


def test_each_level_expands_to_the_installers_own_settings():
    pytest.importorskip("maverick_installer")
    essentials = levels.level_settings("essentials")
    regulated = levels.level_settings("regulated")
    assert essentials[("governance", "profile")] == "essentials"
    assert regulated[("governance", "profile")] == "regulated"
    assert regulated[("retention", "audit_days")] == 365
    assert essentials[("retention", "audit_days")] == 30
    # Levels only add protections: whatever essentials turns on, regulated does too.
    for path, value in essentials.items():
        if value is True:
            assert regulated.get(path) is True, path
    assert set(essentials) < set(regulated)


def test_an_unknown_level_is_refused():
    with pytest.raises(ValueError):
        levels.level_settings("paranoid")


def test_without_the_installer_the_level_cannot_be_expanded(monkeypatch):
    real_import = builtins.__import__

    def no_installer(name, *args, **kwargs):
        if name.startswith("maverick_installer"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_installer)
    with pytest.raises(levels.GovernanceLevelUnavailable):
        levels.level_settings("standard")


def test_the_current_level_is_read_from_the_settings(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"governance": {"profile": "standard"}})
    assert levels.current_level() == "standard"
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"governance": {"profile": "custom"}})
    assert levels.current_level() == ""
