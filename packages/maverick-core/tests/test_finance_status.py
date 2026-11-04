"""Finance posture report (finance-agent-suite §5)."""
from __future__ import annotations

import json

import pytest
from maverick.finance import operations_health
from maverick.finance import status as status_module
from maverick.finance.status import (
    finance_status,
    render_status_json,
    render_status_text,
)


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    # No config / no sanctions list / no signing -> a clean "fresh deploy" view.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for var in ("MAVERICK_AUDIT_SIGN", "MAVERICK_ENTERPRISE",
                "MAVERICK_ENCRYPTION_KEY"):
        monkeypatch.delenv(var, raising=False)
    from maverick import config

    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _operations_config(tmp_path):
    (tmp_path / "config.toml").write_text(
        """[finance_operations]
enable = true
federal_register_enable = true
regulatory_poll_seconds = 300
control_test_interval_seconds = 300

[security_ops]
enable = true
""",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()


def _by_control():
    return {c.control: c for c in finance_status()}


def test_sod_is_active_out_of_the_box():
    # The shipped roster is SoD-clean regardless of config.
    sod = _by_control()["Segregation of duties (roster)"]
    assert sod.status == "active"
    assert "clean" in sod.detail


def test_money_gate_needs_action_without_policy():
    checks = _by_control()
    assert checks["Maker-checker on money movement"].status == "action_needed"
    assert checks["Amount-aware authorization (DoA tiers)"].status == "action_needed"


def test_sanctions_needs_list():
    assert _by_control()["Sanctions screening"].status == "action_needed"


def test_governed_sanctions_status_never_falls_back_to_legacy_list(tmp_path, monkeypatch):
    _operations_config(tmp_path)
    from maverick.tools import sanctions_screen

    monkeypatch.setattr(sanctions_screen, "load_list", lambda _path: ["Legacy Example"])

    ok, detail = status_module._sanctions_active()

    assert ok is False
    assert "governed sanctions list" in detail


def test_unverified_licensing_source_packs_need_legal_review():
    licensing = _by_control()["State licensing source packs"]
    assert licensing.status == "action_needed"
    assert "source_check_required" in licensing.detail


def test_all_controls_present():
    controls = set(_by_control())
    assert {
        "Segregation of duties (roster)",
        "Maker-checker on money movement",
        "Amount-aware authorization (DoA tiers)",
        "Tamper-evident book of record",
        "Sanctions screening",
        "Regulatory-change monitoring",
        "State licensing source packs",
        "Deterministic finance anomaly rules",
        "Finance-to-GRC control testing",
        "Encryption at rest",
        "Data-egress lock",
        "Compliance regimes enabled",
    } <= controls


def test_scheduler_controls_require_fresh_success_receipts(tmp_path):
    _operations_config(tmp_path)
    regulatory_ok, regulatory_detail = status_module._regulatory_monitor_active()
    grc_ok, grc_detail = status_module._grc_control_loop_active()
    assert regulatory_ok is False
    assert "no successful" in regulatory_detail or "lack a fresh" in regulatory_detail
    assert grc_ok is False
    assert "no successful" in grc_detail

    operations_health.record_success("regulatory_poll", "federal-register")
    operations_health.record_success("grc_control_cycle", "FCT-test")
    assert status_module._regulatory_monitor_active()[0] is True
    assert status_module._grc_control_loop_active()[0] is True


def test_regulatory_status_tracks_opt_in_texas_register_receipt(tmp_path):
    (tmp_path / "config.toml").write_text(
        """[finance_operations]
enable = true
federal_register_enable = false
texas_register_enable = true
regulatory_poll_seconds = 300
""",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    assert status_module._regulatory_monitor_active()[0] is False
    operations_health.record_success("regulatory_poll", "texas-register")
    ok, detail = status_module._regulatory_monitor_active()
    assert ok is True
    assert "1 configured official feed" in detail


def test_render_text_and_json():
    checks = finance_status()
    text = render_status_text(checks)
    assert "Finance control coverage" in text
    assert "not an audit opinion" in text
    parsed = json.loads(render_status_json(checks))
    assert parsed["summary"]["total"] == len(checks)
    assert parsed["controls"]
