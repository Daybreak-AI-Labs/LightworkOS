"""Unsigned audit rows are fsync'd so a crash can't lose them.

The signed path (signing.py) already fsyncs every committed row; this pins the
unsigned path to the same durability so an audit log is just as crash-safe
whether or not signing is enabled.
"""
from __future__ import annotations

from maverick.audit import writer as W
from maverick.audit.events import AuditEvent
from maverick.audit.writer import AuditLog


def test_unsigned_record_fsyncs_the_row(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    fsynced: list[int] = []
    monkeypatch.setattr(W.os, "fsync", lambda fd: fsynced.append(fd))

    log = AuditLog(audit_dir=tmp_path, sign=False)
    ok = log.record(AuditEvent(ts=1.0, kind="tool_call", agent="a", payload={}))

    assert ok is True
    assert fsynced, "unsigned audit write must fsync the row (durability)"
    # The row is also actually on disk.
    files = list(tmp_path.glob("*.ndjson"))
    assert files and files[0].read_text().strip()
