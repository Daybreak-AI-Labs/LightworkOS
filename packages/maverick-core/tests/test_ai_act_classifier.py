"""ai_act_classifier: EU AI Act risk-tier screening."""
from __future__ import annotations

from maverick.tools.ai_act_classifier import ai_act_classifier


def _classify(text):
    return ai_act_classifier().fn({"op": "classify", "description": text})


def test_prohibited():
    out = _classify("A government social scoring system that ranks citizens.")
    assert "tier: PROHIBITED" in out and "social scoring" in out
    assert "not legal advice" in out


def test_high_risk_employment():
    out = _classify("An AI that screens resumes and ranks job candidates for hiring.")
    assert "tier: HIGH-RISK" in out
    assert "employment" in out
    assert "conformity assessment" in out


def test_high_risk_credit():
    out = _classify("A model that decides loan approval based on creditworthiness.")
    assert "tier: HIGH-RISK" in out and "creditworthiness" in out


def test_limited_risk_chatbot():
    out = _classify("A customer support chatbot that answers product questions.")
    assert "tier: LIMITED-RISK" in out
    assert "transparency" in out


def test_minimal():
    out = _classify("A spam filter for an internal mailing list.")
    assert "tier: MINIMAL" in out


def test_severity_ordering_prohibited_beats_high():
    # mentions both biometric (high) and social scoring (prohibited) -> prohibited wins
    out = _classify("Biometric system used for social scoring of individuals.")
    assert "tier: PROHIBITED" in out


def test_errors():
    t = ai_act_classifier()
    assert t.fn({"op": "classify", "description": ""}).startswith("ERROR")
    assert t.fn({"op": "nope", "description": "x"}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "ai_act_classifier" in names
