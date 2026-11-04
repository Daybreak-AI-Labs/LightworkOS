"""`maverick billing stripe-*` operator surface (offline)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    for var in ("MAVERICK_STRIPE_ENABLE", "MAVERICK_STRIPE_SECRET_KEY",
                "MAVERICK_STRIPE_BILL_METERED"):
        monkeypatch.delenv(var, raising=False)


def _run(*args):
    return CliRunner().invoke(main, ["billing", *args])


def test_stripe_status_reports_disabled_by_default():
    res = _run("stripe-status")
    assert res.exit_code == 0, res.output
    assert "disabled" in res.output.lower()


def test_stripe_status_json():
    res = _run("stripe-status", "--json")
    assert res.exit_code == 0, res.output
    payload = json.loads(res.output)
    assert payload["enabled"] is False
    assert payload["bill_metered_usage"] is False


def test_stripe_sync_refuses_when_disabled():
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", plan="pro")
    res = _run("stripe-sync", "acme")
    assert res.exit_code == 2, res.output
    assert "off" in res.output.lower()


def test_stripe_preview_shows_unbilled_usage_offline():
    from maverick.billing import ledger_for_tenant
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", plan="pro")
    ledger_for_tenant("acme").record("user:alice", 1.00, 10_000, 2_000, day="2026-06-01")
    res = _run("stripe-preview", "acme", "--since", "2026-06-01",
               "--until", "2026-06-01", "--markup-pct", "20")
    assert res.exit_code == 0, res.output
    assert "not billed" in res.output.lower()
    assert "pro" in res.output


def test_stripe_preview_rejects_bad_date():
    from maverick.tenant import registry as tr
    tr.create_tenant("acme", plan="pro")
    res = _run("stripe-preview", "acme", "--since", "june")
    assert res.exit_code == 2, res.output
    assert "valid YYYY-MM-DD" in res.output
