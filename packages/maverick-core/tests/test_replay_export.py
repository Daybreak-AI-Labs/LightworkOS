"""Tests for trajectory replay export (maverick.replay.export)."""
from __future__ import annotations

import json

# ---------- replay_export: non-numeric goal_id skips, not crashes ----

def test_replay_export_skips_bad_goal_id(tmp_path, monkeypatch):
    import json as _json

    import maverick.replay.export as rex
    audit = tmp_path / "audit"
    audit.mkdir()
    f = audit / "2026-05-28.ndjson"
    rows = [
        {"goal_id": 7, "kind": "goal_start"},
        {"goal_id": "not-a-number", "kind": "junk"},  # must not abort
        {"goal_id": 7, "kind": "goal_end"},
    ]
    f.write_text("\n".join(_json.dumps(r) for r in rows) + "\n")
    monkeypatch.setattr(rex, "_AUDIT_DIR", audit)
    out_file = tmp_path / "r.json"
    n = rex.export_json(7, out_file)
    assert n == 2  # both goal-7 rows survived; the bad row was skipped


# ---------- Replay export ----------

def _seed_audit(dir_path, goal_id, events):
    dir_path.mkdir(parents=True, exist_ok=True)
    f = dir_path / "2026-05-28.ndjson"
    with open(f, "w", encoding="utf-8") as out:
        for ev in events:
            line = dict(ev)
            line.setdefault("goal_id", goal_id)
            out.write(json.dumps(line) + "\n")
    return f


def test_replay_export_html(tmp_path, monkeypatch):
    audit = tmp_path / "audit"
    _seed_audit(audit, 42, [
        {"kind": "goal_start", "ts": 1700000000, "title": "do thing"},
        {"kind": "tool_call", "ts": 1700000010, "tool": "shell", "args": "ls"},
        {"kind": "goal_end", "ts": 1700000020, "status": "done"},
        # An event from a different goal should be excluded.
        {"kind": "goal_start", "ts": 1700000030, "goal_id": 99, "title": "other"},
    ])
    import maverick.replay.export as rex
    monkeypatch.setattr(rex, "_AUDIT_DIR", audit)
    out_file = tmp_path / "replay.html"
    n = rex.export_html(42, out_file)
    assert n == 3
    html = out_file.read_text(encoding="utf-8")
    assert "goal 42" in html
    assert "3 event" in html
    assert "tool_call" in html
    assert "other" not in html


def test_replay_export_json(tmp_path, monkeypatch):
    audit = tmp_path / "audit"
    _seed_audit(audit, 7, [
        {"kind": "goal_start", "ts": 0},
        {"kind": "tool_call", "ts": 1, "tool": "shell"},
    ])
    import maverick.replay.export as rex
    monkeypatch.setattr(rex, "_AUDIT_DIR", audit)
    out_file = tmp_path / "replay.json"
    n = rex.export_json(7, out_file)
    assert n == 2
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["goal_id"] == 7
    assert len(data["events"]) == 2


def test_replay_export_empty_goal(tmp_path, monkeypatch):
    audit = tmp_path / "audit"
    audit.mkdir()
    import maverick.replay.export as rex
    monkeypatch.setattr(rex, "_AUDIT_DIR", audit)
    out_file = tmp_path / "replay.html"
    n = rex.export_html(123, out_file)
    assert n == 0
    assert "No events recorded" in out_file.read_text(encoding="utf-8")


class TestReplayExportSanitize:
    def test_pii_and_secrets_redacted(self):
        from maverick.replay.export import _sanitize
        text = 'contact john@example.com key=sk-ant-abcdefghij0123456789XYZ'
        out = _sanitize(text)
        assert "john@example.com" not in out
        assert "sk-ant-abcdefghij0123456789XYZ" not in out
