"""Security remediation: posture plan + bounded, guarded auto-fix."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.file_lock import private_path_is_restricted
from maverick.remediation import (
    RemediationItem,
    apply_remediation,
    auto_fix_enabled,
    plan,
)
from maverick.threat_hunt import ThreatReport


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for v in ("MAVERICK_ENTERPRISE", "MAVERICK_SECURITY_AUTOFIX",
              "MAVERICK_AUDIT_SIGN", "MAVERICK_ENCRYPT_AT_REST"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    # Don't scan the real audit log during planning.
    monkeypatch.setattr("maverick.threat_hunt.hunt",
                        lambda **k: ThreatReport([], 0, "clear"))


def _auto_item():
    return RemediationItem("Tamper-evident audit", "Enable audit signing", True,
                           "audit", {"sign": True}, "reversible", "detail")


def test_auto_fix_off_by_default_and_needs_enterprise_plus_optin(monkeypatch):
    assert auto_fix_enabled() is False                 # nothing on
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    assert auto_fix_enabled() is False                 # opt-in but no enterprise
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert auto_fix_enabled() is True                  # both -> enabled


def test_plan_separates_auto_fixable_from_gated(monkeypatch):
    # The plan only lists CLOSED gaps as gaps: under the secure default,
    # signing and sealing are already on and would drop off the list. Pin an
    # explicitly-hardened-off deployment so the classification stays testable.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    gaps = {g.control: g for g in plan().gaps}
    # reversible, in-boundary flips -> auto
    assert gaps["Tamper-evident audit"].auto is True
    assert gaps["Storage limitation (retention)"].auto is True
    # behaviour-changing -> gated (proposed, never auto-applied)
    assert gaps["Data-egress control"].auto is False
    assert gaps["Encryption at rest"].auto is False


def test_apply_refuses_gated_items():
    gated = RemediationItem("Data-egress control", "Enterprise mode", False,
                            "enterprise", {"mode": True}, "r", "d")
    res = apply_remediation(gated, dry_run=False)
    assert res.applied is False and "gated" in res.reason


def test_apply_refuses_when_auto_fix_disabled():
    res = apply_remediation(_auto_item(), dry_run=False)   # no enterprise/opt-in
    assert res.applied is False and "disabled" in res.reason


def test_apply_dry_run_writes_nothing(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    cfg = tmp_path / "config.toml"
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg)

    res = apply_remediation(_auto_item(), dry_run=True)
    assert res.dry_run and res.applied is False
    assert "[audit]" in res.block and "sign = true" in res.block
    assert not cfg.exists()


def test_apply_appends_block_without_clobbering_and_audits(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    cfg = tmp_path / "config.toml"
    cfg.write_text('[providers]\ndefault = "ollama"\n')
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg)

    recorded = []
    import maverick.audit as audit
    monkeypatch.setattr(audit, "record", lambda kind, **p: recorded.append((kind, p)) or True)

    res = apply_remediation(_auto_item(), dry_run=False)
    assert res.applied is True
    text = cfg.read_text()
    assert "[providers]" in text and "[audit]" in text and "sign = true" in text
    assert recorded and recorded[0][1]["section"] == "audit"
    # Hardening: the secret-bearing config is written private (0600), the prior
    # contents are backed up, and undo points at the backup.
    assert private_path_is_restricted(cfg, 0o600)
    bak = tmp_path / "config.toml.bak"
    assert bak.exists() and bak.read_text() == '[providers]\ndefault = "ollama"\n'
    assert private_path_is_restricted(bak, 0o600)
    assert private_path_is_restricted(tmp_path, 0o700)
    assert "restore" in res.undo


@pytest.mark.parametrize("audit_result", [False, OSError("audit log unwritable")])
def test_apply_refuses_unloggable_change_and_rolls_back(monkeypatch, tmp_path,
                                                        audit_result):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    cfg = tmp_path / "config.toml"
    cfg.write_text('[providers]\ndefault = "ollama"\n')
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg)

    import maverick.audit as audit

    def _record(kind, **p):
        if isinstance(audit_result, Exception):
            raise audit_result
        return audit_result
    monkeypatch.setattr(audit, "record", _record)

    res = apply_remediation(_auto_item(), dry_run=False)
    assert res.applied is False and "audit record" in res.reason
    assert cfg.read_text() == '[providers]\ndefault = "ollama"\n'


def test_apply_does_not_audit_when_config_write_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    cfg = tmp_path / "config.toml"
    cfg.write_text('[providers]\ndefault = "ollama"\n')
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg)

    recorded = []
    import maverick.audit as audit
    import maverick.remediation as remediation

    monkeypatch.setattr(audit, "record", lambda kind, **p: recorded.append((kind, p)) or True)

    def _write_fails(path, text, *, prior):
        raise OSError("disk full")
    monkeypatch.setattr(remediation, "_write_config_atomic", _write_fails)

    res = apply_remediation(_auto_item(), dry_run=False)
    assert res.applied is False and "could not write config" in res.reason
    assert recorded == []
    assert cfg.read_text() == '[providers]\ndefault = "ollama"\n'


def test_apply_refuses_when_result_would_be_invalid_toml(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    cfg = tmp_path / "config.toml"
    cfg.write_text("this is = = not valid toml [[[\n")    # already malformed
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg)

    res = apply_remediation(_auto_item(), dry_run=False)
    assert res.applied is False and "invalid" in res.reason
    assert cfg.read_text() == "this is = = not valid toml [[[\n"   # left untouched


def test_apply_refuses_when_section_already_present(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    monkeypatch.setattr("maverick.config.load_config",
                        lambda *a, **k: {"audit": {"other": 1}})
    monkeypatch.setattr("maverick.config.config_path", lambda: tmp_path / "config.toml")

    res = apply_remediation(_auto_item(), dry_run=False)
    assert res.applied is False and "already present" in res.reason


def test_cli_remediate_reports_and_apply_is_gated_by_optin():
    runner = CliRunner()
    out = runner.invoke(main, ["remediate"])
    assert out.exit_code == 0 and "Security remediation plan" in out.output

    applied = runner.invoke(main, ["remediate", "--apply"])
    assert applied.exit_code == 0
    assert "auto-fix disabled" in applied.output   # off by default


def test_concurrent_applies_do_not_clobber_each_other(monkeypatch, tmp_path):
    """apply_remediation reads config.toml, appends its section, and writes it
    back. Without the cross-process lock two concurrent auto-fixes both read the
    same base and the second write drops the first's appended section. Both must
    survive."""
    import threading

    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    monkeypatch.setenv("MAVERICK_SECURITY_AUTOFIX", "1")
    cfg = tmp_path / "config.toml"
    cfg.write_text('[providers]\ndefault = "ollama"\n')
    monkeypatch.setattr("maverick.config.config_path", lambda: cfg)

    import maverick.audit as audit
    monkeypatch.setattr(audit, "record", lambda kind, **p: True)

    items = [
        RemediationItem("c1", "a1", True, "audit", {"sign": True}, "r", "d"),
        RemediationItem("c2", "a2", True, "budget", {"max_dollars": 5}, "r", "d"),
    ]
    barrier = threading.Barrier(len(items))
    results = []
    lock = threading.Lock()

    def apply(it):
        barrier.wait()
        r = apply_remediation(it, dry_run=False)
        with lock:
            results.append(r)

    threads = [threading.Thread(target=apply, args=(it,)) for it in items]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(r.applied for r in results), [r.reason for r in results]
    text = cfg.read_text()
    # Both appended sections survive -- neither write clobbered the other.
    assert "[audit]" in text and "[budget]" in text
    assert '[providers]' in text  # and the pre-existing content is intact
