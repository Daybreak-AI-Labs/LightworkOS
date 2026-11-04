"""GDPR + EU AI Act compliance posture report."""
from __future__ import annotations

import json

import pytest
from maverick.compliance import (
    compliance_report,
    render_report_json,
    render_report_text,
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in (
        "MAVERICK_ENTERPRISE", "MAVERICK_CONSENT_MODE", "MAVERICK_AUDIT_SIGN",
        "MAVERICK_ANON", "MAVERICK_AI_DISCLOSURE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


def _by_control(checks):
    return {c.control: c for c in checks}


def test_report_covers_core_articles():
    regs = " ".join(c.regulation for c in compliance_report())
    for article in ("Art. 50", "Art. 12", "Art. 14", "Art. 15", "Art. 17",
                    "Art. 5(1)(e)", "Art. 32"):
        assert article in regs


def test_disclosure_active_by_default():
    assert _by_control(compliance_report())["AI transparency disclosure"].status == "active"


def test_disclosure_off_when_opted_out(monkeypatch):
    monkeypatch.setenv("MAVERICK_AI_DISCLOSURE", "")  # explicit opt-out
    assert _by_control(compliance_report())["AI transparency disclosure"].status == "action_needed"


def test_egress_control_reflects_enterprise(monkeypatch):
    assert _by_control(compliance_report())["Data-egress control"].status == "action_needed"
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert _by_control(compliance_report())["Data-egress control"].status == "active"


def test_audit_signing_requires_crypto_backend(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr("maverick.audit.signing._have_crypto", lambda: False)

    check = _by_control(compliance_report())["Tamper-evident audit"]

    assert check.status == "action_needed"
    # Now reflects the active probe, which names the missing crypto backend.
    assert "cryptography" in check.detail


def test_audit_signing_active_when_requested_and_crypto_available(monkeypatch):
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setattr("maverick.audit.signing._have_crypto", lambda: True)

    check = _by_control(compliance_report())["Tamper-evident audit"]

    assert check.status == "active"
    # Detail now comes from the real signed-probe verification, not an inference.
    assert "Ed25519 hash-chain" in check.detail


def test_audit_signing_not_active_when_the_signed_write_fails(monkeypatch):
    # The old import-only inference (requested AND cryptography importable) would
    # read "active" here; the probe-backed check reports the real state -- a
    # signer that can't actually produce a verifiable signed row is NOT
    # tamper-evident, so this must be action_needed, not a false PASS.
    from maverick.deployment import GuaranteeCheck
    monkeypatch.setattr(
        "maverick.deployment._verify_audit_signing",
        lambda: GuaranteeCheck("Tamper-evident audit", False,
                               "audit signing probe failed to write or verify"),
    )
    check = _by_control(compliance_report())["Tamper-evident audit"]
    assert check.status == "action_needed"
    assert "failed" in check.detail


def test_oversight_reflects_consent_mode(monkeypatch):
    assert _by_control(compliance_report())["Human oversight (consent gating)"].status == "action_needed"
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "ask")
    assert _by_control(compliance_report())["Human oversight (consent gating)"].status == "active"


def test_retention_reflects_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"retention": {"audit_days": 90}}
    )
    assert _by_control(compliance_report())["Storage limitation (retention)"].status == "active"


def test_renderers_and_disclaimer():
    checks = compliance_report()
    text = render_report_text(checks)
    assert "control coverage" in text.lower()
    assert "not legal advice" in text.lower()
    data = json.loads(render_report_json(checks))
    assert data["summary"]["total"] == len(checks)
    assert data["disclaimer"]
