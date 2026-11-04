"""The first-round privacy analyst: research + find_controls + the assessment
engine curated into one agent's toolset."""
from __future__ import annotations

from maverick.assessment import (
    PRIVACY_ANALYST_PERSONA,
    AssessmentSession,
    _privacy_analyst_tools,
    build_privacy_analyst_agent,
)
from maverick.tools import Tool, ToolRegistry


async def _noop(args):
    return "ok"


def _tool(name):
    return Tool(name=name, description=name,
                input_schema={"type": "object", "properties": {}}, fn=_noop)


def test_registry_keeps_research_and_controls_drops_mutating_adds_assessment():
    base = ToolRegistry()
    for n in ("read_file", "web_search", "knowledge_search", "find_controls",
              "http_fetch", "shell", "write_file", "apply_patch"):
        base.register(_tool(n))

    reg = _privacy_analyst_tools(base, AssessmentSession())
    names = {t.name for t in reg.all()}

    # read-only research + the control catalog are kept
    assert {"read_file", "web_search", "knowledge_search", "find_controls"} <= names
    # mutating / outward tools are excluded from the analyst envelope
    assert names.isdisjoint({"http_fetch", "shell", "write_file", "apply_patch"})
    # the assessment engine is wired in
    assert {"list_assessments", "start_assessment", "answer_question",
            "finalize_assessment"} <= names


def test_missing_optional_tools_are_skipped_not_fatal():
    base = ToolRegistry()
    base.register(_tool("find_controls"))  # web_search/knowledge_search absent
    reg = _privacy_analyst_tools(base, AssessmentSession())
    names = {t.name for t in reg.all()}
    assert "find_controls" in names
    assert {"start_assessment", "finalize_assessment"} <= names


def test_persona_orchestrates_research_assess_and_controls():
    p = PRIVACY_ANALYST_PERSONA.lower()
    assert "research" in p
    assert "find_controls" in p and "start_assessment" in p
    # the trust guarantees: honest unknown + human sign-off
    assert "never guess" in p and "never approve" in p


def test_builder_is_callable():
    assert callable(build_privacy_analyst_agent)


def test_http_fetch_is_excluded_from_the_analyst_envelope():
    # http_fetch can POST an arbitrary body to any URL -> a data-exfiltration
    # channel; it must NOT be in the analyst's curated tools (the analyst ingests
    # untrusted subject material, so it's the prompt-injection surface).
    base = ToolRegistry()
    for n in ("read_file", "web_search", "http_fetch", "find_controls"):
        base.register(_tool(n))
    names = {t.name for t in _privacy_analyst_tools(base, AssessmentSession()).all()}
    assert "http_fetch" not in names
    assert {"read_file", "web_search", "find_controls"} <= names
