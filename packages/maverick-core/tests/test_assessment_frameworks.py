"""HIPAA / SOC 2 / PCI DSS assessment frameworks (multi-vertical coverage)."""
from __future__ import annotations

import asyncio

import pytest
from maverick.assessment import AssessmentSession, get_template
from maverick.tools.assessment_tools import assessment_tools

NEW = ["hipaa", "soc2", "pci_dss"]


@pytest.mark.parametrize("atype", NEW)
def test_framework_registered_and_well_formed(atype):
    tpl = get_template(atype)
    assert tpl is not None
    assert len(tpl.questions) >= 8
    ids = [q.id for q in tpl.questions]
    assert len(ids) == len(set(ids))                # unique question ids
    for q in tpl.questions:
        assert q.risk_answer in ("yes", "no")
        assert q.severity in ("low", "medium", "high")
        assert q.guidance                            # every question has remediation


@pytest.mark.parametrize("atype", NEW)
def test_all_risk_answers_roll_up_high(atype):
    tpl = get_template(atype)
    s = AssessmentSession(type=atype, subject="Acme")
    for q in tpl.questions:
        s.record(q.id, q.risk_answer)
    r = s.evaluate()
    assert r.risk_rating == "high"
    assert len(r.findings) == len(tpl.questions)


@pytest.mark.parametrize("atype", NEW)
def test_all_safe_answers_clear(atype):
    tpl = get_template(atype)
    s = AssessmentSession(type=atype, subject="Acme")
    for q in tpl.questions:
        s.record(q.id, "no" if q.risk_answer == "yes" else "yes")
    r = s.evaluate()
    assert r.findings == []
    assert r.risk_rating == "minimal"


def test_unknown_answers_are_unverified_findings():
    tpl = get_template("hipaa")
    s = AssessmentSession(type="hipaa", subject="Acme")
    for q in tpl.questions:
        s.record(q.id, "unknown")
    r = s.evaluate()
    assert len(r.findings) == len(tpl.questions)
    assert all(f.kind == "unverified" for f in r.findings)   # honest diligence gaps


def test_agent_tool_lists_the_new_frameworks():
    tools = {t.name: t for t in assessment_tools(AssessmentSession())}
    out = asyncio.run(tools["list_assessments"].fn({}))
    for atype in NEW:
        assert atype in out


def test_tia_template_scores_transfer_posture(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick.assessment import TEMPLATES, AssessmentSession
    tpl = TEMPLATES["tia"]
    assert tpl.framework.startswith("Schrems II")
    assert len(tpl.questions) == 10
    s = AssessmentSession(type="tia", subject="EU→US telemetry flow")
    s.record("tia_mechanism", "yes")
    s.record("tia_mapping", "yes")
    s.record("tia_local_law", "no", "FISA 702 exposure not yet analysed")
    s.record("tia_encryption_transit", "yes")
    s.record("tia_encryption_rest", "unknown")
    r = s.evaluate()
    assert r.inherent_risk == "high"
    assert r.residual_risk == "high"  # unanalysed regime + unverified crypto
    ids = {f.question_id for f in r.findings}
    assert {"tia_local_law", "tia_encryption_rest"} <= ids
