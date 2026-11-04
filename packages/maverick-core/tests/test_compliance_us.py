"""US-framework coverage in the compliance posture report.

The enterprise audience must satisfy the US patchwork as well as the EU AI Act,
so the report maps the same live controls onto NIST AI RMF + enforceable
state/sector law alongside the EU/GDPR rows, with a ``--framework`` filter.
"""
from __future__ import annotations

from click.testing import CliRunner
from maverick.compliance import compliance_report


def _regs(checks) -> str:
    return " ".join(c.regulation for c in checks)


def test_report_includes_us_frameworks(monkeypatch):
    monkeypatch.setattr("maverick.compliance._report_cfg", dict)
    checks = compliance_report()
    assert "us" in {c.framework for c in checks}
    regs = _regs(checks)
    assert "NIST AI RMF" in regs
    assert "NYC Local Law 144" in regs
    assert "Colorado AI Act" in regs
    assert "CCPA" in regs


def test_eu_rows_still_present(monkeypatch):
    monkeypatch.setattr("maverick.compliance._report_cfg", dict)
    checks = compliance_report()
    assert "eu" in {c.framework for c in checks}
    assert "EU AI Act Art. 12" in _regs(checks)


def test_us_consumer_notice_tracks_disclosure(monkeypatch):
    monkeypatch.setattr("maverick.compliance._report_cfg", dict)
    monkeypatch.delenv("MAVERICK_AI_DISCLOSURE", raising=False)
    by = {c.control: c for c in compliance_report() if c.framework == "us"}
    assert by["Consumer notice of AI"].status == "active"

    monkeypatch.setenv("MAVERICK_AI_DISCLOSURE", "")  # operator opt-out
    by = {c.control: c for c in compliance_report() if c.framework == "us"}
    assert by["Consumer notice of AI"].status == "action_needed"


def test_cli_framework_filter_us_only():
    from maverick.cli import main
    res = CliRunner().invoke(main, ["compliance", "--framework", "us"])
    assert res.exit_code == 0, res.output
    assert "NIST AI RMF" in res.output
    # An EU-only article row must be filtered out (the header keeps "EU AI Act").
    assert "EU AI Act Art. 12" not in res.output


def test_cli_framework_filter_eu_only():
    from maverick.cli import main
    res = CliRunner().invoke(main, ["compliance", "--framework", "eu"])
    assert res.exit_code == 0, res.output
    assert "NIST AI RMF" not in res.output


def test_cli_default_shows_both():
    from maverick.cli import main
    res = CliRunner().invoke(main, ["compliance"])
    assert res.exit_code == 0, res.output
    assert "EU AI Act" in res.output and "NIST AI RMF" in res.output
