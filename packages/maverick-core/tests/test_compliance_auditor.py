"""The compliance-auditor agent: audit envelope (research + controls + assessment
+ live-posture evidence) and the never-certify persona."""
from __future__ import annotations

import asyncio

from maverick import assessment
from maverick.assessment import (
    AssessmentSession,
    _compliance_auditor_tools,
    build_compliance_auditor_agent,
)
from maverick.tools import Tool, ToolRegistry


async def _noop(args):
    return "ok"


def _tool(name):
    return Tool(name=name, description=name,
                input_schema={"type": "object", "properties": {}}, fn=_noop)


def test_auditor_envelope_keeps_evidence_drops_mutating():
    base = ToolRegistry()
    for n in ("read_file", "web_search", "knowledge_search", "find_controls",
              "http_fetch", "shell", "write_file"):
        base.register(_tool(n))
    names = {t.name for t in _compliance_auditor_tools(base, AssessmentSession()).all()}
    # research + control catalog + assessment engine + the live-posture evidence tool
    assert {"read_file", "web_search", "knowledge_search", "find_controls",
            "start_assessment", "finalize_assessment", "deployment_posture"} <= names
    # mutating / outward (incl. the exfil-capable http_fetch) excluded
    assert names.isdisjoint({"shell", "write_file", "http_fetch"})


def test_deployment_posture_reports_live_control_state(monkeypatch):
    from dataclasses import dataclass

    from maverick.tools.posture_tools import posture_tools

    @dataclass
    class _C:
        control: str
        regulation: str
        status: str
        detail: str
        framework: str = "eu"

    monkeypatch.setattr(
        "maverick.compliance.compliance_report",
        lambda: [_C("Encryption at rest", "GDPR Art. 32", "active", "AES-256-GCM")],
    )
    out = asyncio.run(posture_tools()[0].fn({}))
    assert "Encryption at rest" in out and "[active]" in out


def test_persona_audits_and_never_certifies():
    p = assessment.COMPLIANCE_AUDITOR_PERSONA.lower()
    assert "deployment_posture" in p and "audit-readiness" in p
    assert "unknown" in p                         # honest gaps, not guessed passes
    assert "never declare" in p and "certified" in p
    assert callable(build_compliance_auditor_agent)


def test_pii_redaction_control_reflects_real_posture(monkeypatch):
    # The report must not claim "Secret/PII redaction" is active by default:
    # PII (email/SSN/phone) is redacted only under anon mode. At-rest
    # encryption is reported separately and must not satisfy live log redaction.
    from maverick.compliance import compliance_report

    def _status(anon, enc):
        monkeypatch.setattr("maverick.privacy.anon_enabled", lambda: anon)
        monkeypatch.setattr("maverick.crypto_at_rest.at_rest_enabled", lambda: enc)
        checks = {c.control: c for c in compliance_report()}
        assert checks["Secret redaction in logs"].status == "active"
        return checks["PII redaction in logs"].status

    # Neither anon nor encryption -> PII in plaintext logs -> action_needed.
    assert _status(anon=False, enc=False) == "action_needed"
    # Anon redacts it -> active; at-rest encryption alone does not redact live logs.
    assert _status(anon=True, enc=False) == "active"
    assert _status(anon=False, enc=True) == "action_needed"
