"""Reading the active audit segment while the writer appends to it."""
from __future__ import annotations

import json
import os

from maverick.audit import reader, segments


def _segment(tmp_path):
    path = tmp_path / "2026-09-27.jsonl"
    path.write_text("".join(json.dumps({"i": i}) + "\n" for i in range(1000)))
    os.chmod(path, 0o600)
    return path


def test_a_concurrent_append_does_not_empty_a_tail(tmp_path, monkeypatch):
    path = _segment(tmp_path)
    real = segments.SegmentSnapshot.validate

    def appending(self, **kw):
        with open(path, "a") as fh:                      # the live writer
            fh.write(json.dumps({"i": "new"}) + "\n")
        return real(self, **kw)
    monkeypatch.setattr(segments.SegmentSnapshot, "validate", appending)
    report = segments.ReadReport()
    rows = reader.tail_events(path, 10, report=report)
    assert len(rows) == 10 and report.as_dict()["state"] != "unreadable"


def test_a_rewrite_or_truncation_during_the_read_still_fails(tmp_path, monkeypatch):
    path = _segment(tmp_path)
    real = segments.SegmentSnapshot.validate

    def truncating(self, **kw):
        with open(path, "r+") as fh:
            fh.truncate(10)
        return real(self, **kw)
    monkeypatch.setattr(segments.SegmentSnapshot, "validate", truncating)
    report = segments.ReadReport()
    assert reader.tail_events(path, 10, report=report) == []
    assert report.as_dict()["state"] == "unreadable"
