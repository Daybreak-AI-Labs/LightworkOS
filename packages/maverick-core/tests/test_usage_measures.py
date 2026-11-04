"""Name-free usage measures for the research kit: first result in the first
session and AI suggestions shown, used or dismissed."""
from __future__ import annotations

import json

import pytest


@pytest.fixture
def measures(tmp_path, monkeypatch):
    from maverick import config, usage_measures

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("[analytics]\nusage_measures = true\n", encoding="utf-8")
    config.reset_config_cache()
    yield usage_measures
    config.reset_config_cache()


def test_off_by_default_counts_nothing(tmp_path, monkeypatch):
    from maverick import config, usage_measures

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    try:
        assert usage_measures.enabled() is False
        usage_measures.note_seen("user:pat@example.com", "operator")
        usage_measures.record_suggestion("user:pat@example.com", "copilot-question", "How do I invite?", "shown")
        assert not usage_measures.store_path().exists()
    finally:
        config.reset_config_cache()


def test_first_result_in_the_first_session_by_role(measures):
    measures.note_seen("user:ana@example.com", "operator", now=1000.0)
    measures.note_seen("user:ben@example.com", "operator", now=1000.0)
    measures.note_seen("user:cy@example.com", "admin", now=1000.0)
    measures.note_seen("user:ana@example.com", "admin", now=5000.0)  # first sighting wins
    assert measures.note_first_result("user:ana@example.com", now=1000.0 + 600) is True
    assert measures.note_first_result("user:ben@example.com", now=1000.0 + 5 * 3600) is True  # a later session
    assert measures.note_first_result("user:nobody@example.com") is False  # never seen
    report = {row["role"]: row for row in measures.first_session_report()}
    assert report["operator"] == {"role": "operator", "people": 2, "first_session": 1, "share": 50,
                                  "median_minutes": 10.0}
    assert report["admin"]["first_session"] == 0 and report["admin"]["median_minutes"] is None
    stored = measures.store_path().read_text(encoding="utf-8")
    assert "ana@example.com" not in stored and "ben" not in stored  # names are never kept


def test_suggestions_count_use_dismissal_and_reshowing_after_dismissal(measures):
    for _ in range(3):
        measures.record_suggestion("user:ana@example.com", "copilot-question", "How do I invite?", "shown")
    measures.record_suggestion("user:ana@example.com", "copilot-question", "How do I invite?", "dismissed")
    measures.record_suggestion("user:ana@example.com", "copilot-question", "How do I invite?", "shown", typing=True)
    measures.record_suggestion("user:ben@example.com", "copilot-question", "How do I invite?", "shown")
    measures.record_suggestion("user:ben@example.com", "copilot-question", "How do I invite?", "accepted")
    measures.record_suggestion("user:ben@example.com", "chat-example", "Draft a reminder.", "dismissed")
    report = {row["kind"]: row for row in measures.suggestion_report()}
    question = report["copilot-question"]
    assert (question["shown"], question["accepted"], question["dismissed"]) == (5, 1, 1)
    assert question["reshown"] == 1 and question["while_typing"] == 1 and question["review"] is False
    assert report["chat-example"]["review"] is False  # never shown: nothing to review
    for _ in range(2):
        measures.record_suggestion("user:cy@example.com", "next-step", "Connect Slack", "shown")
        measures.record_suggestion("user:cy@example.com", "next-step", "Connect Slack", "dismissed")
    assert {row["kind"]: row for row in measures.suggestion_report()}["next-step"]["review"] is True
    assert "How do I invite" not in json.dumps(json.loads(measures.store_path().read_text(encoding="utf-8")))
