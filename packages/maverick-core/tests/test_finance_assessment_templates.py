"""Finance assessment templates (finance-agent-suite §6)."""
from __future__ import annotations

import pytest
from maverick.assessment import AssessmentSession, get_template

_FINANCE_TYPES = ("sox_control", "fraud_risk", "itgc", "credit_risk", "close_readiness")


@pytest.mark.parametrize("atype", _FINANCE_TYPES)
def test_template_exists_and_well_formed(atype):
    tpl = get_template(atype)
    assert tpl is not None
    assert tpl.questions
    for q in tpl.questions:
        assert q.risk_answer in ("yes", "no")
        assert q.severity in ("low", "medium", "high")


def test_sox_control_scores_high_on_no_evidence():
    s = AssessmentSession()
    s.restart("sox_control", "Revenue cutoff control")
    s.record("sox_evidence", "no")     # no evidence -> high finding
    s.record("sox_sod", "no")          # no SoD conflict -> clears
    result = s.evaluate()
    assert result.risk_rating == "high"
    assert any(f.question_id == "sox_evidence" and f.kind == "risk"
               for f in result.findings)


def test_fraud_risk_flags_create_and_approve():
    s = AssessmentSession()
    s.restart("fraud_risk", "Vendor onboarding")
    s.record("fraud_vendor_create_approve", "yes")  # one person both -> high
    result = s.evaluate()
    assert result.risk_rating == "high"


def test_credit_risk_past_due():
    s = AssessmentSession()
    s.restart("credit_risk", "Acme Co")
    s.record("credit_past_due", "yes")
    assert s.evaluate().risk_rating == "high"


def test_unknown_answer_is_unverified_finding():
    s = AssessmentSession()
    s.restart("close_readiness", "Q3 close")
    s.record("close_bs_recon", "unknown")
    result = s.evaluate()
    assert any(f.kind == "unverified" for f in result.findings)
