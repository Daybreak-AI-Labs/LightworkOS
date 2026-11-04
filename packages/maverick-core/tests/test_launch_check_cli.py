"""`maverick launch-check` — the go-live readiness gate.

Unlike ``maverick doctor`` (does the install WORK?), launch-check asserts the
deliberate production switches are ON and exits non-zero if any is off, so a
deploy pipeline can gate on it. Every switch reads real config/env; these tests
drive each one through env vars (which win over config in the kernel) and the
single provider probe through a monkeypatch.
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    for var in (
        "MAVERICK_TENANT",
        "MAVERICK_QUOTA_ENFORCE",
        "MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY",
        "MAVERICK_QUOTA_MAX_TOKENS_PER_DAY",
        "MAVERICK_TENANT_BY_USER",
        "MAVERICK_ENCRYPT_AT_REST",
    ):
        monkeypatch.delenv(var, raising=False)


def _configure_go_live(monkeypatch):
    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    monkeypatch.setenv("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY", "50")
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    # The provider probe reads config/env; pin it so the test is hermetic.
    monkeypatch.setattr("maverick.config.any_provider_configured", lambda: True)


def _run():
    return CliRunner().invoke(main, ["launch-check"])


def test_passes_when_every_switch_is_on(monkeypatch):
    _configure_go_live(monkeypatch)
    res = _run()
    assert res.exit_code == 0, res.output
    assert "FAIL" not in res.output
    assert res.output.count("PASS") == 4
    assert "clear for go-live" in res.output.lower()


def test_fails_nonzero_when_switches_are_off(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr("maverick.config.any_provider_configured", lambda: False)
    res = _run()
    assert res.exit_code != 0, res.output
    # Each off switch is named as a FAIL with actionable remediation.
    assert "[FAIL]" in res.output or "FAIL" in res.output
    assert "cost caps" in res.output
    assert "per-user tenancy" in res.output
    assert "encryption at rest" in res.output
    assert "provider credential" in res.output


def test_enforcement_on_but_no_cap_is_a_fail(monkeypatch):
    # Caps enforced but every cap 0 (unlimited) is not go-live ready.
    _configure_go_live(monkeypatch)
    monkeypatch.delenv("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY", raising=False)
    monkeypatch.delenv("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY", raising=False)
    res = _run()
    assert res.exit_code != 0, res.output
    assert "cost caps" in res.output
    assert "every cap is 0" in res.output


def test_a_dashboard_spending_limit_satisfies_cost_caps(monkeypatch):
    # Spending limits set in Admin > Spending limits count as cost governance
    # without turning on the older [quotas] switch.
    _configure_go_live(monkeypatch)
    monkeypatch.delenv("MAVERICK_QUOTA_ENFORCE", raising=False)
    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "0")
    res = _run()
    assert res.exit_code != 0, res.output
    assert "no spending limit is set" in res.output
    from maverick import spending_limits
    spending_limits.set_workspace_limit("500", "month", actor="user:admin")
    res = _run()
    assert res.exit_code == 0, res.output
    assert "spending limits: workspace $500 per month" in res.output
