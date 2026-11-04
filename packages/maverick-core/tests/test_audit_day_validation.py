"""Audit ``--day`` path-traversal validation.

An audit ``day`` is resolved to ``<audit_dir>/<day>.ndjson``; an unvalidated
value like ``../../../etc/passwd`` would escape the audit dir. The day is now
gated to a literal ``YYYY-MM-DD`` at two layers:

* the library chokepoints (``AuditLog._path_for`` and
  ``audit.export.audit_event_paths``) raise ``ValueError`` -- a backstop for
  *any* caller, not just the CLI;
* the CLI commands that take ``--day`` (``audit tail|grep|verify|export`` and
  ``logs``) reject it up front with a friendly message and exit 2.

(The dashboard already neutralizes ``?day=`` at its own HTTP boundary via
``safe_audit_day``; this closes the same hole for the CLI / programmatic paths.)
"""
from __future__ import annotations

import pytest
from click.testing import CliRunner

# --- the shared predicate ---------------------------------------------------

def test_is_valid_day():
    from maverick.audit.events import is_valid_day
    assert is_valid_day("2026-05-28")
    # traversal / separators / absolute / NUL / unpadded / empty / non-str
    assert not is_valid_day("../../etc/passwd")
    assert not is_valid_day("../secret")
    assert not is_valid_day("2026-05-28/../../x")
    assert not is_valid_day("/etc/passwd")
    assert not is_valid_day("2026-05-28\x00")
    assert not is_valid_day("2026-5-1")
    assert not is_valid_day("")
    assert not is_valid_day(None)  # type: ignore[arg-type]


# --- library backstop: writer ----------------------------------------------

def test_path_for_accepts_valid_day(tmp_path):
    from maverick.audit.writer import AuditLog
    log = AuditLog(tmp_path / "audit")
    assert log._path_for("2026-05-28") == (tmp_path / "audit" / "2026-05-28.ndjson")


def test_path_for_rejects_traversal(tmp_path):
    from maverick.audit.writer import AuditLog
    log = AuditLog(tmp_path / "audit")
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        log._path_for("../secret")


def test_tail_and_grep_refuse_traversal_instead_of_reading_outside(tmp_path):
    # A sentinel file one level above the audit dir: a traversal day would
    # resolve onto it. The guard must raise rather than read it.
    from maverick.audit.writer import AuditLog
    (tmp_path / "secret.ndjson").write_text(
        '{"kind":"tool_call","name":"LEAK"}\n', encoding="utf-8"
    )
    log = AuditLog(tmp_path / "audit")
    with pytest.raises(ValueError):
        log.tail(50, day="../secret")
    with pytest.raises(ValueError):
        log.grep("LEAK", day="../secret")


def test_tail_with_valid_or_default_day_still_works(tmp_path):
    # Regression: the guard must not disturb the normal None/today path.
    import time

    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog
    log = AuditLog(tmp_path / "audit")
    assert log.record(AuditEvent(ts=time.time(), kind="tool_call", payload={"i": 1}))
    assert log.tail(50) != []                 # default (today) unaffected
    assert log.tail(50, day=None) != []       # explicit None unaffected


# --- library backstop: export ----------------------------------------------

def test_audit_event_paths_rejects_traversal(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit.export import audit_event_paths
    with pytest.raises(ValueError, match="YYYY-MM-DD"):
        audit_event_paths(day="../../etc/passwd")


def test_iter_audit_events_rejects_traversal_when_consumed(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit.export import iter_audit_events
    with pytest.raises(ValueError):
        list(iter_audit_events(day="../../etc/passwd"))


# --- CLI: every --day surface rejects traversal with exit 2 -----------------

_BAD = "../../../etc/passwd"


@pytest.fixture()
def _home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    return tmp_path


@pytest.mark.parametrize(
    "argv",
    [
        ["audit", "tail", "--day", _BAD],
        ["audit", "grep", "x", "--day", _BAD],
        ["audit", "verify", "--day", _BAD],
        ["audit", "export", "--day", _BAD],
        ["logs", "--day", _BAD],
    ],
)
def test_cli_day_traversal_is_rejected(_home, argv):
    from maverick.cli import main
    res = CliRunner().invoke(main, argv)
    assert res.exit_code == 2, res.output
    assert "YYYY-MM-DD" in res.output
    assert "etc/passwd" not in res.output  # never echoed back / used as a path


def test_cli_audit_tail_accepts_valid_day(_home):
    # Regression: a well-formed day is accepted (exit 0), even with no events.
    from maverick.cli import main
    res = CliRunner().invoke(main, ["audit", "tail", "--day", "2020-01-01"])
    assert res.exit_code == 0, res.output


def test_is_valid_day_rejects_impossible_calendar_dates():
    # Shape-valid but not a real date: a typo'd --day must not pass and report a
    # misleading "OK / no entries" instead of a friendly error.
    from maverick.audit.events import is_valid_day
    assert not is_valid_day("2026-13-99")  # month 13, day 99
    assert not is_valid_day("2026-00-00")
    assert not is_valid_day("2026-02-30")  # Feb 30
    assert not is_valid_day("9999-99-99")
    assert not is_valid_day("2026-02-29")  # 2026 is not a leap year
    # Real dates still pass, including a genuine leap day.
    assert is_valid_day("2024-02-29")
    assert is_valid_day("2026-12-31")


def test_audit_verify_rejects_typo_date(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    monkeypatch.setenv("HOME", str(tmp_path))
    res = CliRunner().invoke(main, ["audit", "verify", "--day", "2026-13-99"])
    assert res.exit_code == 2, res.output
    assert "YYYY-MM-DD" in res.output
