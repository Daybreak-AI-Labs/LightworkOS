"""Settings > All settings > Finance: the operating profile rows change what the
kernel does once saved.

The generic save / refuse / confirm / audit contract for these rows is in
test_settings_catalog_integrations.py; this module shows each saved value
reaching maverick.finance.profile and governance, the hard-floor refusal, and
that the page offers the installer's values.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import settings_catalog as catalog
from maverick_dashboard.app import app

from test_support.settings_pages import every_group, save_catalog

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/settings/catalog"


@pytest.fixture(autouse=True)
def _finance_on(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    path = config.config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[finance_operations]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


@pytest.fixture()
def audit_rows(monkeypatch):
    import maverick.audit as audit

    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    return rows


def _save(changes, confirm=False):
    from maverick import config

    response = save_catalog(client, API, json={"changes": changes, "confirm": confirm})
    config.reset_config_cache()
    return response


def _decision(action: str, **kw):
    from maverick.governance import Policy, evaluate

    return evaluate(action, policy=Policy.from_config(), **kw).decision


def test_saved_levels_gate_finance_actions(audit_rows):
    from maverick.governance import Decision

    assert _decision("approve_expense") is Decision.ALLOW
    assert _save([{"id": "finance.automation.default", "value": "draft"}]).status_code == 200
    assert _decision("approve_expense") is Decision.DENY
    r = _save([{"id": "finance.automation.*",
                "value": [{"name": "send_invoice", "level": "straight_through"}]}],
              confirm=True)
    assert r.status_code == 200, r.text
    assert _decision("send_invoice") is Decision.ALLOW
    assert _decision("approve_expense") is Decision.DENY
    # Loosening the default is confirmed first; the payment floor still holds.
    r = _save([{"id": "finance.automation.default", "value": "straight_through"}])
    assert r.status_code == 409
    assert _save([{"id": "finance.automation.default", "value": "straight_through"}],
                 confirm=True).status_code == 200
    assert _decision("approve_expense") is Decision.ALLOW
    assert _decision("release_payment") is Decision.REQUIRE_HUMAN


def test_a_payment_can_be_tightened_but_never_loosened(audit_rows):
    from maverick.governance import Decision

    r = _save([{"id": "finance.automation.*",
                "value": [{"name": "release_payment", "level": "auto_threshold"}]}],
              confirm=True)
    assert r.status_code == 400
    assert "always waits for a person" in r.json()["message"]
    assert audit_rows == []
    r = _save([{"id": "finance.automation.*",
                "value": [{"name": "release_payment", "level": "draft"}]}], confirm=True)
    assert r.status_code == 200, r.text
    assert _decision("release_payment") is Decision.DENY


def test_saved_framework_selects_its_rules(audit_rows):
    from maverick.governance import Decision

    assert _decision("apply_lifo_inventory") is Decision.ALLOW
    assert _save([{"id": "finance.framework", "value": "ifrs"}], confirm=True).status_code == 200
    assert _decision("apply_lifo_inventory") is Decision.DENY
    assert _save([{"id": "finance.framework", "value": "us_gaap"}],
                 confirm=True).status_code == 200
    assert _decision("reverse_impairment_loss") is Decision.DENY
    assert _decision("apply_lifo_inventory") is Decision.ALLOW


def test_saved_materiality_reaches_anomaly_review(audit_rows):
    from decimal import Decimal

    from maverick.finance.anomaly_engine import (
        FinanceAnomalyConfig,
        with_configured_materiality,
    )

    assert with_configured_materiality(FinanceAnomalyConfig()).materiality is None
    assert _save([{"id": "finance.materiality", "value": 25000}]).status_code == 200
    assert with_configured_materiality(FinanceAnomalyConfig()).materiality == Decimal("25000.0")
    assert _save([{"id": "finance.materiality", "value": 90000}]).status_code == 409


def test_saved_sod_mode_blocks_or_asks(audit_rows):
    from maverick.finance import profile

    assert profile.check_action_sod("approve_expense") is None
    assert _save([{"id": "finance.sod.mode", "value": "enforce"}]).status_code == 200
    assert profile.check_action_sod("approve_expense").blocks
    assert _save([{"id": "finance.sod.mode", "value": "warn"}]).status_code == 409
    assert _save([{"id": "finance.sod.mode", "value": "warn"}], confirm=True).status_code == 200
    assert not profile.check_action_sod("approve_expense").blocks


def test_saved_timeout_makes_finance_approvals_fail_closed(audit_rows):
    from maverick.finance import profile

    assert not profile.approval_fail_closed("release_payment")
    assert _save([{"id": "finance.approvals.timeout", "value": "fail_closed"}]).status_code == 200
    assert profile.approval_fail_closed("release_payment")
    r = _save([{"id": "finance.approvals.timeout", "value": ""}])
    assert r.status_code == 409  # going back to the general rules is confirmed
    assert audit_rows[-1]["key"] == "timeout"


def test_saved_values_do_nothing_while_finance_operations_are_off(audit_rows):
    from maverick import config
    from maverick.finance import profile
    from maverick.governance import Decision

    assert _save([{"id": "finance.automation.default", "value": "draft"},
                  {"id": "finance.sod.mode", "value": "enforce"}]).status_code == 200
    config.config_path().write_text("[finance_operations]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    assert profile.configured_profile() is None
    assert _decision("approve_expense") is Decision.ALLOW


def test_page_offers_the_installer_values():
    from maverick.finance import profile
    from maverick.governance import AUTOMATION_LEVELS
    from maverick_installer import wizard

    def values(setting_id):
        return tuple(v for v, _ in catalog.BY_ID[setting_id].choices if v)

    assert values("finance.framework") == wizard.FINANCE_FRAMEWORKS == profile.FRAMEWORK_KEYS
    assert values("finance.automation.default") == wizard.FINANCE_AUTOMATION_LEVELS \
        == AUTOMATION_LEVELS
    assert values("finance.sod.mode") == wizard.FINANCE_SOD_MODES == profile.SOD_MODES
    assert values("finance.approvals.timeout") == profile.APPROVAL_TIMEOUTS
    table = catalog.BY_ID["finance.automation.*"]
    assert {v for v, _ in table.choices} == set(profile.FINANCE_ACTIONS)
    page = every_group(client)
    for setting_id in ("finance.framework", "finance.materiality", "finance.automation.default",
                       "finance.automation.*", "finance.sod.mode", "finance.approvals.timeout"):
        assert catalog.BY_ID[setting_id].label in page, setting_id
