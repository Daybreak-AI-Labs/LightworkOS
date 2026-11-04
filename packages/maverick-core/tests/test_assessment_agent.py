"""The compliance assessor agent's tools driving a session to scored findings.
Imports maverick.tools, so it runs in CI (full deps)."""
from __future__ import annotations

import asyncio

import pytest
from maverick.assessment import AssessmentSession, list_saved
from maverick.tools.assessment_tools import assessment_tools


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    from maverick import paths
    monkeypatch.setattr(paths, "maverick_home", lambda: tmp_path / "home")


def _session_and_tools():
    session = AssessmentSession()
    return session, {t.name: t for t in assessment_tools(session)}


def test_tool_set_is_the_five_assessor_actions():
    _, tools = _session_and_tools()
    assert set(tools) == {
        "list_assessments", "start_assessment", "answer_question",
        "similar_assessments", "finalize_assessment",
    }


def test_answer_and_finalize_refuse_before_start():
    _, tools = _session_and_tools()
    assert "start_assessment first" in asyncio.run(
        tools["answer_question"].fn({"question_id": "vr_dpa", "answer": "no"}))
    assert "start_assessment first" in asyncio.run(
        tools["finalize_assessment"].fn({}))


def test_tools_drive_a_vendor_assessment_to_a_scored_draft():
    session, tools = _session_and_tools()

    started = asyncio.run(tools["start_assessment"].fn(
        {"type": "vendor_risk", "subject": "Acme Corp"}))
    assert "Vendor Risk Assessment" in started and "vr_dpa" in started

    asyncio.run(tools["answer_question"].fn(
        {"question_id": "vr_dpa", "answer": "no"}))                  # high finding
    asyncio.run(tools["answer_question"].fn(
        {"question_id": "vr_soc2", "answer": "yes"}))                # safe -> none
    asyncio.run(tools["answer_question"].fn(
        {"question_id": "vr_subprocessors", "answer": "unknown"}))   # unverified
    assert session.answers["vr_dpa"]["answer"] == "no"

    out = asyncio.run(tools["finalize_assessment"].fn({}))
    assert "risk HIGH" in out and "DRAFT" in out
    # The agent's draft was persisted for human review.
    assert list_saved()[0]["subject"] == "Acme Corp"


def test_starting_another_assessment_persists_a_distinct_draft():
    session, tools = _session_and_tools()

    asyncio.run(tools["start_assessment"].fn(
        {"type": "vendor_risk", "subject": "Acme Corp"}))
    first_id = session.id
    first_created_at = session.created_at
    asyncio.run(tools["answer_question"].fn(
        {"question_id": "vr_dpa", "answer": "no"}))
    asyncio.run(tools["finalize_assessment"].fn({}))

    asyncio.run(tools["start_assessment"].fn(
        {"type": "vendor_risk", "subject": "Beta LLC"}))
    assert session.id != first_id
    assert session.created_at >= first_created_at
    asyncio.run(tools["finalize_assessment"].fn({}))

    saved = {item["subject"]: item for item in list_saved()}
    assert set(saved) == {"Acme Corp", "Beta LLC"}
    assert saved["Acme Corp"]["risk_rating"] == "high"
    assert saved["Beta LLC"]["risk_rating"] == "minimal"


def test_bad_answers_are_surfaced_as_errors_not_raised():
    _, tools = _session_and_tools()
    asyncio.run(tools["start_assessment"].fn({"type": "aira", "subject": "Screener"}))
    assert asyncio.run(tools["answer_question"].fn(
        {"question_id": "aira_purpose", "answer": "maybe"})).startswith("ERROR")
    assert asyncio.run(tools["answer_question"].fn(
        {"question_id": "nope", "answer": "yes"})).startswith("ERROR")


def test_build_assessment_agent_is_importable_with_persona():
    from maverick.assessment import ASSESSMENT_PERSONA, build_assessment_agent
    assert callable(build_assessment_agent)
    # The persona instructs the honest-'unknown' + human-sign-off behaviour.
    assert "unknown" in ASSESSMENT_PERSONA and "never approve" in ASSESSMENT_PERSONA
