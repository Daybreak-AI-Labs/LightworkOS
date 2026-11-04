"""Reviewer follow-ups on saved assessments: ask, answer, status round-trip."""
from __future__ import annotations

import pytest
from maverick.assessment import (
    AssessmentSession,
    add_followups,
    answer_followup,
    list_saved,
    load_saved,
    save_session,
)


@pytest.fixture(autouse=True)
def _fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))


def _saved() -> AssessmentSession:
    s = AssessmentSession(type="pia", subject="Acme CRM")
    s.record("pia_necessity", "yes")
    save_session(s)
    return s


def test_add_followups_flips_status_to_needs_more():
    s = _saved()
    rec = add_followups(s.id, ["Which sub-processors receive data?",
                               "  Is the DPA countersigned?  "], asked_by="lena")
    assert rec is not None
    assert rec["status"] == "needs_more"
    fups = rec["followups"]
    assert [f["id"] for f in fups] == ["fu-1", "fu-2"]
    assert fups[1]["question"] == "Is the DPA countersigned?"
    assert fups[0]["asked_by"] == "lena"
    # The summary listing surfaces the open count for worklists.
    row = next(r for r in list_saved() if r["id"] == s.id)
    assert row["status"] == "needs_more"
    assert row["open_followups"] == 2


def test_answering_last_followup_returns_to_pending_review():
    s = _saved()
    add_followups(s.id, ["Q1?", "Q2?"])
    rec = answer_followup(s.id, "fu-1", "Only Acme's EU subsidiary.", "jordan")
    assert rec["status"] == "needs_more"
    rec = answer_followup(s.id, "fu-2", "Yes, countersigned in May.")
    assert rec["status"] == "pending_review"
    persisted = load_saved(s.id)
    assert persisted["followups"][0]["answered_by"] == "jordan"
    assert persisted["followups"][1]["answer"] == "Yes, countersigned in May."


def test_second_round_of_followups_appends():
    s = _saved()
    add_followups(s.id, ["Q1?"])
    answer_followup(s.id, "fu-1", "answered")
    rec = add_followups(s.id, ["Round two?"])
    assert [f["id"] for f in rec["followups"]] == ["fu-1", "fu-2"]
    assert rec["status"] == "needs_more"


def test_bad_ids_and_empty_input_are_none():
    s = _saved()
    assert add_followups("no-such-id", ["Q?"]) is None
    assert add_followups(s.id, ["   ", ""]) is None
    assert answer_followup(s.id, "fu-99", "hello") is None
    add_followups(s.id, ["Q1?"])
    assert answer_followup(s.id, "fu-1", "   ") is None
    # Path traversal in the id is refused by the load_saved guard.
    assert add_followups("../../etc/passwd", ["Q?"]) is None
