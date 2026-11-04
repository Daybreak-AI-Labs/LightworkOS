"""Enterprise preflight gate: opt-in, fail-open by default.

The hardening preflight must stay a NO-OP unless an operator explicitly requires
it (``MAVERICK_REQUIRE_ENTERPRISE`` / ``[enterprise] require``), and when required
it must BLOCK (raise / non-zero) if any data-boundary guarantee fails. These tests
force ``verify_deployment`` results via monkeypatch so they are hermetic and do not
depend on crypto, network, or the host config.
"""
from __future__ import annotations

import pytest
from maverick.deployment import (
    EnterpriseRequiredError,
    GuaranteeCheck,
    enterprise_required,
    preflight_enterprise,
    require_enterprise_or_die,
)

_PASS = [
    GuaranteeCheck("Egress lock", True, "ok"),
    GuaranteeCheck("At-rest encryption", True, "ok"),
]
_FAIL = [
    GuaranteeCheck("Egress lock", False, "enable [enterprise] mode = true"),
    GuaranteeCheck("At-rest encryption", True, "ok"),
]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    # No env flag, no config, isolated HOME -> "required" must read False so the
    # default posture is genuinely fail-open.
    monkeypatch.delenv("MAVERICK_REQUIRE_ENTERPRISE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def _force_verify(monkeypatch, checks):
    """Make verify_deployment() return a fixed result without exercising probes."""
    monkeypatch.setattr("maverick.deployment.verify_deployment", lambda: checks)


# ----- detection: enterprise_required() -------------------------------------

def test_required_false_by_default():
    assert enterprise_required() is False


@pytest.mark.parametrize("val", ["1", "true", "yes", "on", "enabled", "TRUE"])
def test_required_true_from_env(monkeypatch, val):
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", val)
    assert enterprise_required() is True


@pytest.mark.parametrize("val", ["0", "false", "no", "off", "", "  "])
def test_required_false_from_falsey_env(monkeypatch, val):
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", val)
    assert enterprise_required() is False


def test_required_from_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"enterprise": {"require": True}}
    )
    assert enterprise_required() is True


def test_env_wins_over_config(monkeypatch):
    # Operator can force-disable the gate at the env even if config requires it.
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", "0")
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"enterprise": {"require": True}}
    )
    assert enterprise_required() is False


# ----- not required => no-op, even when verify would fail --------------------

def test_not_required_is_noop_even_when_verify_fails(monkeypatch):
    _force_verify(monkeypatch, _FAIL)
    # Must not raise: the gate is off, so a failing boundary is allowed (fail-open).
    require_enterprise_or_die()
    ok, report = preflight_enterprise()
    assert ok is True
    assert report is None


# ----- required + passing => ok ---------------------------------------------

def test_required_and_passing_is_ok(monkeypatch):
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", "1")
    _force_verify(monkeypatch, _PASS)
    require_enterprise_or_die()  # does not raise
    ok, report = preflight_enterprise()
    assert ok is True
    assert "guarantees hold" in report


# ----- required + failing => raises / non-zero ------------------------------

def test_required_and_failing_raises(monkeypatch):
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", "1")
    _force_verify(monkeypatch, _FAIL)
    with pytest.raises(EnterpriseRequiredError) as exc:
        require_enterprise_or_die()
    # The exception names the failing guarantee and carries the checks for callers.
    assert "Egress lock" in exc.value.summary
    assert "refusing to start" in exc.value.summary
    assert any(not c.passed for c in exc.value.checks)


def test_required_and_failing_reports_not_ok(monkeypatch):
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", "1")
    _force_verify(monkeypatch, _FAIL)
    ok, report = preflight_enterprise()
    assert ok is False
    assert "Egress lock" in report


# ----- force= overrides env/config detection (the --require CLI flag path) ---

def test_force_true_requires_even_without_env(monkeypatch):
    _force_verify(monkeypatch, _FAIL)
    with pytest.raises(EnterpriseRequiredError):
        require_enterprise_or_die(force=True)
    ok, _ = preflight_enterprise(force=True)
    assert ok is False


def test_force_false_skips_even_when_env_requires(monkeypatch):
    monkeypatch.setenv("MAVERICK_REQUIRE_ENTERPRISE", "1")
    _force_verify(monkeypatch, _FAIL)
    require_enterprise_or_die(force=False)  # does not raise
    ok, report = preflight_enterprise(force=False)
    assert ok is True
    assert report is None
