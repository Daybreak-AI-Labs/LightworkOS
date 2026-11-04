"""`maverick audit worm push|verify` CLI wiring (orchestration tested in test_audit_worm)."""
from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.audit import worm
from maverick.cli import main


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))


def test_push_reports_and_unconfigured_errors(monkeypatch):
    def _raise(**k):
        raise worm.WormUnavailable("no WORM target configured")
    monkeypatch.setattr(worm, "push_closed_dayfiles", _raise)
    res = CliRunner().invoke(main, ["audit", "worm", "push"])
    assert res.exit_code != 0
    assert "no WORM target configured" in res.output


def test_push_shows_shipped_count(monkeypatch):
    monkeypatch.setattr(worm, "push_closed_dayfiles",
                        lambda **k: {"2020-01-01.ndjson": "pushed",
                                     "2020-01-02.ndjson": "already pushed"})
    res = CliRunner().invoke(main, ["audit", "worm", "push"])
    assert res.exit_code == 0, res.output
    assert "Shipped 1 day-file(s)." in res.output


def test_push_refusal_exits_nonzero(monkeypatch):
    monkeypatch.setattr(
        worm, "push_closed_dayfiles",
        lambda **k: {"2020-01-01.ndjson": "error (retention proof unavailable)"},
    )
    res = CliRunner().invoke(main, ["audit", "worm", "push"])
    assert res.exit_code != 0
    assert "not safely shipped" in res.output


def test_verify_ok_exits_zero(monkeypatch):
    monkeypatch.setattr(worm, "verify", lambda **k: {"2020-01-01.ndjson": "ok"})
    res = CliRunner().invoke(main, ["audit", "worm", "verify"])
    assert res.exit_code == 0, res.output
    assert "verified in WORM store" in res.output


def test_verify_divergence_exits_nonzero(monkeypatch):
    monkeypatch.setattr(worm, "verify",
                        lambda **k: {"2020-01-01.ndjson": "NOT pushed"})
    res = CliRunner().invoke(main, ["audit", "worm", "verify"])
    assert res.exit_code == 1
    assert "not durably shipped" in res.output
