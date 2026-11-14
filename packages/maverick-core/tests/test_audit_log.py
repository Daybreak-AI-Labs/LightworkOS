"""Tests for the audit log writer (maverick.audit.writer): event shape,
redaction depth and tail/grep robustness.
"""
from __future__ import annotations

import json
import stat


def test_audit_log_unsigned_by_default(tmp_path):
    import json

    from maverick.audit.events import AuditEvent
    from maverick.audit.writer import AuditLog

    adir = tmp_path / "audit"
    alog = AuditLog(adir, sign=False)
    alog.record(AuditEvent(ts=1.0, kind="x", agent="a", payload={}))
    row = json.loads(list(adir.glob("*.ndjson"))[0].read_text().splitlines()[0])
    assert "sig" not in row and "hash" not in row


# ---------- audit log ----------

def test_audit_log_writes_ndjson(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.audit import AuditEvent, AuditLog, EventKind

    al = AuditLog(audit_dir=tmp_path / ".maverick" / "audit")
    import time
    ok = al.record(AuditEvent(
        ts=time.time(), kind=EventKind.GOAL_START,
        agent="orchestrator", goal_id=1,
        payload={"title": "test", "description": None},
    ))
    assert ok
    # File exists with mode 0600.
    files = list((tmp_path / ".maverick" / "audit").glob("*.ndjson"))
    assert len(files) == 1
    import os
    if os.name != "nt":  # NTFS reports 0o666 regardless of chmod
        assert stat.S_IMODE(files[0].stat().st_mode) == 0o600


def test_audit_log_tail_and_grep(tmp_path):
    from maverick.audit import AuditEvent, AuditLog, EventKind
    al = AuditLog(audit_dir=tmp_path / "audit")
    import time
    for i in range(10):
        al.record(AuditEvent(
            ts=time.time() + i * 0.001,
            kind=EventKind.TOOL_CALL if i % 2 == 0 else EventKind.TOOL_RESULT,
            agent="coder", goal_id=1,
            payload={"name": f"tool{i}"},
        ))
    last5 = al.tail(5)
    assert len(last5) == 5
    # Only TOOL_CALL events should match the grep.
    hits = al.grep('"kind": "tool_call"')
    assert len(hits) == 5
    assert all(h["kind"] == "tool_call" for h in hits)


def test_audit_log_failsafe_on_bad_dir(tmp_path):
    """If audit_dir can't be created, record() returns False, doesn't raise."""
    from maverick.audit import AuditEvent, AuditLog, EventKind
    # Point to a path under a file (cannot create a subdir of a file).
    bad_parent = tmp_path / "blocking_file"
    bad_parent.write_text("x")
    al = AuditLog(audit_dir=bad_parent / "audit")
    import time
    ok = al.record(AuditEvent(ts=time.time(), kind=EventKind.HALT))
    assert ok is False  # graceful


def test_audit_record_module_helper(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # Force re-resolution of the default audit log.
    import maverick.audit.writer as w
    w._default = None
    from maverick.audit import EventKind, record
    ok = record(EventKind.GOAL_START, goal_id=42, title="test goal")
    assert ok


# ---- audit redaction: depth-64 guard ---------------------------------------

def test_redaction_does_not_leak_secret_past_depth_64():
    from maverick.audit.writer import _redact_event
    v: object = {"k": "sk-ant-api03-SECRETKEYBODY1234567890abcdef"}  # pragma: allowlist secret
    for _ in range(70):
        v = {"n": v}
    out = json.dumps(_redact_event({"kind": "tool_result", "payload": v}))
    assert "SECRETKEYBODY" not in out


# ---- audit tail/grep: RecursionError on deep JSON --------------------------

def test_audit_tail_survives_deeply_nested_line(tmp_path):
    from datetime import datetime, timezone

    from maverick.audit.writer import AuditLog
    # tail()/grep() default to today's UTC day-file, so name the fixture for
    # today rather than a fixed date (a hard-coded date only passes on that day).
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    f = tmp_path / f"{day}.ndjson"
    # Deep enough to exhaust json's recursion-descent parser on every CPython
    # (3.11 trips near the 1000 default; 3.12+ near its C-recursion cap, which
    # let a 2000-deep line parse fine and broke an exact-equality assert here).
    depth = 100_000
    f.write_text('{"v":1,"kind":"goal_start"}\n' + ("[" * depth) + ("]" * depth) + "\n")
    log = AuditLog(tmp_path)
    rows = log.tail(10)            # must not raise RecursionError
    # The valid row survives; where exactly the interpreter gives up on the
    # deep line is version-dependent, so assert no-crash + presence, not shape.
    assert {"v": 1, "kind": "goal_start"} in rows
    assert log.grep("goal_start")  # grep also survives


def test_unreadable_earlier_day_fails_governed_record_instead_of_raising(tmp_path, monkeypatch):
    # record() promises True/False; an undecryptable old day-file scanned for
    # a governed identity must surface as False, not a RuntimeError.
    from maverick.audit import sealing
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.segments import SegmentReadError
    from maverick.audit.writer import AuditLog

    adir = tmp_path / "audit"
    adir.mkdir()
    (adir / "2020-01-01.ndjson").write_text("{}\n")

    def _unreadable(path, *, fail_soft=True):
        raise SegmentReadError(f"cannot decrypt {path}")

    monkeypatch.setattr(sealing, "segment_text", _unreadable)
    alog = AuditLog(adir, sign=False)
    event = AuditEvent(ts=1.0, kind=EventKind.PRIVACY_RECORD_CHANGED, agent="a",
                       payload={"event_id": "evt-1"})
    assert alog.record(event) is False


def test_signing_stays_on_when_audit_section_is_not_a_table(monkeypatch):
    import maverick.config as config
    from maverick.audit.writer import _resolve_signing

    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    monkeypatch.setattr("maverick.security_defaults.secure_by_default", lambda: True)
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"audit": "oops"})
    assert _resolve_signing(None) is True
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"audit": {"sign": "false"}})
    assert _resolve_signing(None) is False
