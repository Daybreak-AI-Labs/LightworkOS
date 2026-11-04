"""CLI: maverick finance status / lint-sod (finance-agent-suite §5)."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))


def test_finance_lint_sod_clean():
    res = CliRunner().invoke(main, ["finance", "lint-sod"])
    assert res.exit_code == 0
    assert "segregation-of-duties clean" in res.output


def test_finance_status_text():
    res = CliRunner().invoke(main, ["finance", "status"])
    assert res.exit_code == 0
    assert "Finance control coverage" in res.output
    assert "Segregation of duties" in res.output


def test_finance_status_json():
    import json
    res = CliRunner().invoke(main, ["finance", "status", "--format", "json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "controls" in data and data["summary"]["total"] >= 7


def test_finance_status_strict_exits_nonzero_on_fresh_deploy():
    # A fresh deploy has action-needed controls (no governance/sanctions yet).
    res = CliRunner().invoke(main, ["finance", "status", "--strict"])
    assert res.exit_code != 0
    assert "need action" in res.output.lower() or "need action" in str(res.exception or "")
