"""Plugin security defaults follow the deployment profile.

Under enterprise mode third-party plugins should not run in-process by default,
and the version/content lockfile should be enforced. Explicit config/env always
wins, and dev (non-enterprise) keeps today's behavior.
"""
from __future__ import annotations

import pytest
from maverick.plugin_isolation import isolation_mode
from maverick.plugin_lock import lock_policy


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("MAVERICK_PLUGIN_ISOLATION", raising=False)
    monkeypatch.delenv("MAVERICK_PLUGIN_LOCK_POLICY", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.delenv("MAVERICK_PROFILE", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def test_isolation_defaults_none_in_dev():
    assert isolation_mode() == "none"


def test_isolation_defaults_subprocess_under_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert isolation_mode() == "subprocess"


def test_isolation_via_enterprise_profile(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROFILE", "enterprise")
    assert isolation_mode() == "subprocess"


def test_explicit_isolation_wins_over_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"plugins": {"isolation": "none"}},
    )
    assert isolation_mode() == "none"


def test_lock_policy_defaults_off_in_dev():
    assert lock_policy() == "off"


def test_lock_policy_defaults_enforce_under_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert lock_policy() == "enforce"


def test_explicit_lock_policy_wins_over_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"plugins": {"lock_policy": "warn"}},
    )
    assert lock_policy() == "warn"
