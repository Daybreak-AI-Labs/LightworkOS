"""`maverick soc2` -- print and gate the SOC 2 evidence snapshot as JSON."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick import soc2 as soc2_module
from maverick.cli import main


def _passing_evidence() -> dict:
    return {
        "version": "test",
        "collected_at": 0.0,
        "controls": {
            "capability_enforcement": {"status": "enabled", "enabled": True},
            "tenant_isolation": {"status": "enabled", "enabled": True},
            "usage_quotas": {"status": "enabled", "enabled": True},
            "oidc_auth": {"status": "enabled", "enabled": True},
            "encryption_at_rest": {"status": "enabled", "enabled": True},
        },
        "audit_log": {"status": "ok"},
        "audit_signing_key": {"status": "enabled", "present": True},
    }


def test_soc2_prints_valid_json_and_fails_insecure_default():
    result = CliRunner().invoke(main, ["soc2"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    # Top-level shape of collect_soc2_evidence() (see maverick/soc2.py).
    assert "controls" in payload
    assert "audit_log" in payload
    assert "version" in payload
    assert "collected_at" in payload
    assert "audit_signing_key" in payload
    # Each control probe carries a status.
    assert "capability_enforcement" in payload["controls"]
    assert "status" in payload["controls"]["capability_enforcement"]
    assert "status" in payload["audit_log"]


def test_soc2_exits_zero_for_ready_posture(monkeypatch):
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", _passing_evidence)

    result = CliRunner().invoke(main, ["soc2"])

    assert result.exit_code == 0
    assert json.loads(result.output) == _passing_evidence()


def test_soc2_default_is_pretty_printed(monkeypatch):
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", _passing_evidence)

    result = CliRunner().invoke(main, ["soc2"])

    assert result.exit_code == 0
    # indent=2 output spans multiple lines and indents nested keys.
    assert "\n  " in result.output


def test_soc2_json_flag_is_compact_single_line(monkeypatch):
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", _passing_evidence)

    result = CliRunner().invoke(main, ["soc2", "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert "controls" in payload
    assert "audit_log" in payload
    # Compact form: a single JSON line (click.echo adds one trailing newline).
    assert result.output.strip().count("\n") == 0


def test_soc2_fails_when_any_required_control_is_not_enabled(monkeypatch):
    evidence = _passing_evidence()
    evidence["controls"]["usage_quotas"] = {"status": "disabled", "enabled": False}
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", lambda: evidence)

    result = CliRunner().invoke(main, ["soc2", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.output)["controls"]["usage_quotas"]["status"] == "disabled"


def test_soc2_fails_when_encryption_at_rest_is_not_enabled(monkeypatch):
    evidence = _passing_evidence()
    evidence["controls"]["encryption_at_rest"] = {
        "status": "disabled",
        "enabled": False,
    }
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", lambda: evidence)

    result = CliRunner().invoke(main, ["soc2", "--json"])

    assert result.exit_code == 1
    assert (
        json.loads(result.output)["controls"]["encryption_at_rest"]["status"]
        == "disabled"
    )


def test_soc2_fails_when_audit_log_is_not_ok(monkeypatch):
    evidence = _passing_evidence()
    evidence["audit_log"] = {"status": "unsigned"}
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", lambda: evidence)

    result = CliRunner().invoke(main, ["soc2", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.output)["audit_log"]["status"] == "unsigned"


def test_soc2_fails_when_signing_key_is_absent(monkeypatch):
    evidence = _passing_evidence()
    evidence["audit_signing_key"] = {"status": "absent", "present": False}
    monkeypatch.setattr(soc2_module, "collect_soc2_evidence", lambda: evidence)

    result = CliRunner().invoke(main, ["soc2", "--json"])

    assert result.exit_code == 1
    assert json.loads(result.output)["audit_signing_key"]["status"] == "absent"
