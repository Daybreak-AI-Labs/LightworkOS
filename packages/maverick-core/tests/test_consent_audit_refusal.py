"""An unavailable required audit must not release a destructive-action approval."""
from __future__ import annotations

import logging

import pytest
from maverick.audit import AuditWriteRefused
from maverick.audit.signing import OffHostSigningRequiredError


@pytest.mark.parametrize("refusal", [AuditWriteRefused, OffHostSigningRequiredError])
@pytest.mark.parametrize("failed_kind", ["consent_prompt", "consent_result"])
@pytest.mark.parametrize("source", ["auto", "ledger", "dashboard"])
def test_required_audit_refusal_does_not_return_approval(
    monkeypatch, refusal, failed_kind, source,
):
    from maverick import audit
    from maverick.safety import consent

    monkeypatch.setattr(consent, "_check_ledger", lambda *_args: source == "ledger")
    monkeypatch.setattr(
        consent, "_resolve_mode",
        lambda _risk: "dashboard" if source == "dashboard" else "auto-approve",
    )
    monkeypatch.setattr(
        consent, "_decide_via_dashboard",
        lambda *_args: consent.ConsentDecision(True, "dashboard", "high", 1.0),
    )
    recorded = []

    def record(kind, **_payload):
        recorded.append(str(kind))
        if kind == failed_kind:
            raise refusal("required audit cannot accept this event")
        return True

    monkeypatch.setattr(audit, "record", record)

    with pytest.raises(refusal, match="required audit cannot accept"):
        consent.require_consent("delete-record", risk="high", scope="example-record")

    assert len(recorded) == (1 if failed_kind == "consent_prompt" else 2)


def test_incidental_consent_audit_outage_is_visible_and_remains_best_effort(
    monkeypatch, caplog,
):
    from maverick import audit
    from maverick.safety import consent

    monkeypatch.setattr(consent, "_resolve_mode", lambda _risk: "auto-approve")

    def unavailable(*_args, **_kwargs):
        raise OSError("audit sink unavailable")

    monkeypatch.setattr(audit, "record", unavailable)
    with caplog.at_level(logging.WARNING):
        decision = consent.require_consent("example-action", consult_ledger=False)

    assert decision.granted
    assert any("audit: write failed" in record.message and record.exc_info
               for record in caplog.records)


@pytest.mark.parametrize("failed_kind", ["consent_prompt", "consent_result"])
def test_browser_gate_cannot_issue_permit_after_required_audit_refusal(
    monkeypatch, failed_kind,
):
    from maverick import audit
    from maverick.safety import action_gate, consent

    monkeypatch.setattr(consent, "_resolve_mode", lambda _risk: "dashboard")
    monkeypatch.setattr(
        consent, "_runtime_approval_authority",
        lambda **_kwargs: (
            {
                "actor": "user:reviewer", "workspace": "tenant-a", "role": "operator",
                "versions": {
                    "principal_sha256": "a" * 64,
                    "role_permissions_sha256": "b" * 64,
                    "budget_authority_sha256": "c" * 64,
                },
            },
            {"currency": "USD", "external_effect_cost": "unmeasured",
             "authority_sha256": "c" * 64},
            True,
        ),
    )
    monkeypatch.setattr(
        consent, "_decide_via_dashboard",
        lambda *_args: consent.ConsentDecision(
            True, "dashboard", "high", 1.0, actor="user:reviewer",
        ),
    )

    def record(kind, **_payload):
        if kind == failed_kind:
            raise AuditWriteRefused("required audit unavailable before browser dispatch")
        return True

    monkeypatch.setattr(audit, "record", record)

    with pytest.raises(AuditWriteRefused, match="before browser dispatch"):
        action_gate.gate_browser_action("click", {"selector": "#submit"})
