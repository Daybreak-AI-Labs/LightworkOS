"""Exported replay bundles must not leak secrets.

Regression: export_html / export_json wrote raw audit events to a file
the user shares with support/reviewers, with no scrubbing -- so an API
key captured in a tool arg/result/prompt landed in the export verbatim.
Both paths now run through secrets.scrub().
"""
import json

import maverick.replay.export as rx

# sk-ant- + 30 chars -> matches the anthropic_key pattern in secrets.scrub
_SECRET = "sk-ant-api03-" + "A" * 30


def _one_event_with_secret(monkeypatch):
    events = [{
        "kind": "observation", "ts": "2026-05-30T00:00:00", "goal_id": 1,
        "content": f"calling the API with key={_SECRET}",
    }]
    monkeypatch.setattr(
        rx,
        "load_goal_events",
        lambda gid, files=None: (
            events,
            {"status": "unsigned", "anchors": "unavailable_unsigned", "files": []},
        ),
    )


def test_export_html_scrubs_secret(tmp_path, monkeypatch):
    _one_event_with_secret(monkeypatch)
    out = tmp_path / "replay.html"
    rx.export_html(1, out)
    text = out.read_text(encoding="utf-8")
    assert _SECRET not in text
    assert "REDACTED" in text


def test_export_json_scrubs_secret_and_stays_valid(tmp_path, monkeypatch):
    _one_event_with_secret(monkeypatch)
    out = tmp_path / "replay.json"
    rx.export_json(1, out)
    text = out.read_text(encoding="utf-8")
    assert _SECRET not in text
    assert "REDACTED" in text
    json.loads(text)  # still valid JSON after scrubbing
