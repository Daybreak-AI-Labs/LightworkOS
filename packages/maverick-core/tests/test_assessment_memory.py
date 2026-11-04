"""Assessment memory: the flow learns from the org's own past assessments."""
from __future__ import annotations

import pytest
from maverick import assessment_memory
from maverick.assessment import AssessmentSession, save_session
from maverick.config import get_assessments, reset_config_cache


@pytest.fixture(autouse=True)
def _fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_ASSESS_LEARN", raising=False)
    monkeypatch.delenv("MAVERICK_ASSESS_DISCOVERY", raising=False)
    reset_config_cache()
    yield
    reset_config_cache()


def _saved_pia(subject: str, answers: dict[str, str]) -> AssessmentSession:
    s = AssessmentSession(type="pia", subject=subject)
    for qid, ans in answers.items():
        s.record(qid, ans)
    save_session(s)
    return s


class TestSimilar:
    def test_ranks_by_subject_overlap(self):
        _saved_pia("Acme CRM", {"pia_necessity": "yes"})
        _saved_pia("Globex payroll", {"pia_necessity": "no"})
        rows = assessment_memory.similar("Acme CRM rollout",
                                         assessment_type="pia")
        assert rows
        assert rows[0]["subject"] == "Acme CRM"
        assert rows[0]["similarity"] > 0.5
        assert all("risk_rating" in r for r in rows)

    def test_no_history_is_empty(self):
        assert assessment_memory.similar("anything") == []

    def test_exclude_id_skips_self(self):
        s = _saved_pia("Acme CRM", {"pia_necessity": "yes"})
        assert assessment_memory.similar("Acme CRM", exclude_id=s.id) == []

    def test_learn_kill_switch(self, monkeypatch):
        _saved_pia("Acme CRM", {"pia_necessity": "yes"})
        monkeypatch.setenv("MAVERICK_ASSESS_LEARN", "0")
        reset_config_cache()
        assert assessment_memory.similar("Acme CRM") == []


class TestSuggestAnswers:
    def test_majority_vote_with_confidence_and_provenance(self):
        a = _saved_pia("Acme CRM east", {"pia_necessity": "yes",
                                         "pia_retention": "no"})
        b = _saved_pia("Acme CRM west", {"pia_necessity": "yes",
                                         "pia_retention": "yes"})
        sugg = assessment_memory.suggest_answers("pia", "Acme CRM", k=2)
        assert sugg["pia_necessity"]["answer"] == "yes"
        assert sugg["pia_necessity"]["confidence"] == 1.0
        assert set(sugg["pia_necessity"]["based_on"]) == {a.id, b.id}
        # A 50/50 split fails the default min_confidence and is dropped...
        assert "pia_retention" not in sugg
        # ...but survives a permissive threshold.
        loose = assessment_memory.suggest_answers("pia", "Acme CRM", k=2,
                                                  min_confidence=0.0)
        assert "pia_retention" in loose

    def test_other_templates_never_leak_in(self):
        s = AssessmentSession(type="vendor_risk", subject="Acme CRM")
        s.record("vr_dpa", "yes")
        save_session(s)
        assert assessment_memory.suggest_answers("pia", "Acme CRM") == {}


class TestRecordSession:
    def test_fail_open_without_knowledge_plane(self):
        # Knowledge RAG is off in a bare env: recording is a no-op, not a crash.
        assert assessment_memory.record_session(
            {"id": "x", "subject": "s", "result": {}}) is False

    def test_save_session_hook_never_breaks_save(self, monkeypatch):
        import maverick.assessment_memory as mem

        def boom(_payload):
            raise RuntimeError("knowledge exploded")

        monkeypatch.setattr(mem, "record_session", boom)
        s = _saved_pia("Acme CRM", {"pia_necessity": "yes"})  # must not raise
        assert s.id

    def test_distill_mentions_rating_and_findings(self):
        text = assessment_memory._distill({
            "id": "A1", "type": "pia", "subject": "Acme CRM",
            "result": {"risk_rating": "high", "answered": 9, "total": 10,
                       "findings": [{"severity": "high", "section": "Transfers",
                                     "question": "SCCs in place?",
                                     "answer": "no"}]},
        })
        assert "risk high" in text
        assert "Transfers" in text


class TestLessons:
    def test_semantic_lessons_require_a_governed_reader(self, monkeypatch):
        from maverick import knowledge_admin

        monkeypatch.setattr(
            knowledge_admin,
            "open_knowledge_base",
            lambda **_kwargs: pytest.fail("raw knowledge store must not be opened"),
        )
        assert assessment_memory.lessons("Acme CRM") == []

    def test_governed_reader_is_bounded_and_malformed_results_fail_closed(self):
        seen = []

        def governed(query, limit):
            seen.append((query, limit))
            return ["  current approved lesson  "]

        assert assessment_memory.lessons("Acme CRM", k=2, reader=governed) == [
            "current approved lesson"
        ]
        assert seen == [("Acme CRM", 2)]
        assert assessment_memory.lessons(
            "Acme CRM",
            k=1,
            reader=lambda *_: ["one", "two"],
        ) == []


class TestConfig:
    def test_defaults(self):
        cfg = get_assessments()
        assert cfg == {"doc_discovery": True,
                       "sources": ["msgraph", "slack", "gdrive"],
                       "learn": True}

    def test_section_overrides(self, tmp_path, monkeypatch):
        cfg_file = tmp_path / "config.toml"
        cfg_file.write_text(
            '[assessments]\ndoc_discovery = false\nsources = ["slack"]\n',
            encoding="utf-8")
        monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_file))
        reset_config_cache()
        cfg = get_assessments()
        assert cfg["doc_discovery"] is False
        assert cfg["sources"] == ["slack"]
        assert cfg["learn"] is True


def test_winning_answer_note_and_sources_do_not_come_from_dissent(monkeypatch):
    from maverick import assessment
    losing = _saved_pia("Acme CRM", {"pia_necessity": "no"})
    winning = [_saved_pia("Acme CRM", {"pia_necessity": "yes"}) for _ in range(2)]
    records = {}
    for session, note in [(losing, "Dissenting rationale"), (winning[0], "Winning rationale"), (winning[1], "")]:
        record = assessment.load_saved(session.id)
        record["answers"]["pia_necessity"]["note"] = note
        records[session.id] = record
    monkeypatch.setattr(assessment_memory, "similar", lambda *args, **kwargs: [{"id": session.id} for session in [losing, *winning]])
    monkeypatch.setattr(assessment, "load_saved", lambda identifier: records[identifier])
    value = assessment_memory.suggest_answers("pia", "Acme CRM")["pia_necessity"]
    assert value["note"] == "Winning rationale"
    assert value["based_on"] == [session.id for session in winning]
    assert value["conflicts"][0]["assessment_id"] == losing.id
    assert value["state"] == "unreviewed_precedent"
    assert "not factual certainty" in value["confidence_meaning"]


def test_approved_source_becomes_stale_when_policy_or_review_expiry_changes(monkeypatch):
    from maverick import assessment
    session = _saved_pia("Acme CRM", {"pia_necessity": "yes"})
    record = assessment.decide_assessment(session.id, "approved", decided_by="user:reviewer", expected_revision=1)
    value = assessment_memory.source_evidence(record, "pia_necessity")
    assert value["state"] == "current_approved" and value["approval_owner"] == "user:reviewer"
    assert value["policy_digest"] == record["template_digest"]
    record["next_review_at"] = 1
    assert assessment_memory.source_evidence(record, "pia_necessity")["state"] == "stale_precedent"
    record["next_review_at"] = None
    monkeypatch.setattr(assessment, "template_state", lambda kind: {"digest": "a"*64,"revision": 7})
    value = assessment_memory.source_evidence(record, "pia_necessity")
    assert value["state"] == "stale_precedent" and value["current_policy_version"] == 7


def test_department_filter_and_exclude_current_before_ranking():
    session = _saved_pia("Acme CRM", {"pia_necessity": "yes"})
    assert assessment_memory.similar("Acme CRM", allowed_types={"vendor_risk"}) == []
    assert assessment_memory.suggest_answers("pia", "Acme CRM", allowed_types={"vendor_risk"}) == {}
    assert assessment_memory.suggest_answers("pia", "Acme CRM", exclude_id=session.id) == {}
