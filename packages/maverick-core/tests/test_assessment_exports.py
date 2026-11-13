"""OSCAL and SoA exports: faithful projections, nothing invented.

The assertions that matter: every answered question becomes one OSCAL
observation, findings carry satisfied/not-satisfied honestly, the SoA
treats ``na`` as a justified exclusion, and both exports are
deterministic for an unchanged record.
"""
from __future__ import annotations

import pytest
from maverick import assessment_exports, config
from maverick.assessment import AssessmentSession, save_session


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _saved_iso42001_session() -> str:
    session = AssessmentSession()
    session.restart("iso42001", "ai-platform")
    questions = session.template().questions
    # First control implemented, second excluded with a justification,
    # third answered with the risky answer; the rest implemented.
    for index, question in enumerate(questions):
        risky = str(question.risk_answer).strip().lower()
        safe = "no" if risky == "yes" else "yes"
        if index == 1:
            session.record(question.id, "na", "Out of scope: no in-house training.")
        elif index == 2:
            session.record(question.id, risky)
        else:
            session.record(question.id, safe)
    save_session(session)
    return session.id


def test_oscal_export_mirrors_the_record():
    session_id = _saved_iso42001_session()
    document = assessment_exports.render_oscal_assessment_results(session_id)
    results = document["assessment-results"]["results"][0]
    assert (
        document["assessment-results"]["metadata"]["oscal-version"]
        == assessment_exports.OSCAL_VERSION
    )
    # Every answered question observed; na answers observed but not judged.
    assert len(results["observations"]) == 22
    states = [
        finding["target"]["status"]["state"] for finding in results["findings"]
    ]
    assert states.count("not-satisfied") == 1
    assert states.count("satisfied") == 20
    # An unreviewed record is self-reported, never "attested".
    metadata = document["assessment-results"]["metadata"]
    assert {"name": "review-status", "value": "pending_review"} in metadata["props"]
    assert "not a certification audit" in metadata["remarks"]
    satisfied = [
        finding for finding in results["findings"]
        if finding["target"]["status"]["state"] == "satisfied"
    ]
    assert all("self-reported" in finding["description"] for finding in satisfied)
    # Deterministic: an unchanged record re-exports identically.
    again = assessment_exports.render_oscal_assessment_results(session_id)
    assert again == document
    with pytest.raises(KeyError):
        assessment_exports.render_oscal_assessment_results("AS-nope")


def test_soa_treats_na_as_justified_exclusion():
    session_id = _saved_iso42001_session()
    soa = assessment_exports.render_statement_of_applicability(session_id)
    assert soa["counts"] == {
        "implemented": 20, "not_implemented": 1,
        "excluded": 1, "unanswered": 0,
    }
    excluded = [row for row in soa["rows"] if row["status"] == "excluded"]
    assert excluded[0]["applicable"] is False
    assert "Out of scope" in excluded[0]["justification"]

    rendered = assessment_exports.soa_markdown(soa)
    assert "Statement of Applicability" in rendered
    assert "ISO/IEC 42001" in rendered
    assert "Implemented: 20" in rendered
