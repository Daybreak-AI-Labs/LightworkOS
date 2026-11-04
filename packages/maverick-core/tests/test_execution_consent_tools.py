"""The code-capable tools share one fresh, exact-operation approval policy."""
from __future__ import annotations

import pytest
from maverick.approval_cards import ApprovalCardError
from maverick.safety import ConsentDenied, consume_operation_consent
from maverick.tools import execution_consent


def test_execution_policy_disallows_silent_or_standing_approval(monkeypatch, tmp_path):
    captured = {}

    def fake_require(action, **kwargs):
        captured.update(action=action, **kwargs)
        return object()

    monkeypatch.setattr(execution_consent, "require_operation_consent", fake_require)

    class _Sandbox:
        workdir = str(tmp_path)

    def target():
        return execution_consent.execution_target(_Sandbox())
    permit = execution_consent.request_execution_consent(
        "code_exec", target_provider=target,
        parameters={"code": "print(1)"}, detail="Run Python code.",
        effect="Runs the reviewed code.", review_items=["Python code"], timeout=10,
    )
    assert permit is not None
    assert captured["action"] == "code_exec"
    assert captured["allow_auto_approve"] is False
    assert captured["consult_ledger"] is False
    assert captured["target"]["workdir"] == str(tmp_path)
    assert captured["parameters"] == {"code": "print(1)"}
    assert captured["irreversible"] is True


@pytest.mark.parametrize("mode", ["auto-deny", "auto-approve"])
def test_real_execution_policy_requires_person_even_in_automatic_modes(
    monkeypatch, tmp_path, mode,
):
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", mode)
    with pytest.raises(ConsentDenied):
        execution_consent.request_execution_consent(
            "code_exec",
            target_provider=lambda: {"workdir": str(tmp_path), "isolation": "host"},
            parameters={"code": "print('must not run')"},
            detail="Run Python code.", effect="Runs Python code.",
            review_items=["Python code"], timeout=10,
        )


def test_approved_execution_permit_is_one_use(monkeypatch, tmp_path):
    from types import SimpleNamespace

    import maverick.safety.consent as consent

    monkeypatch.setattr(consent, "require_consent", lambda *a, **kw: SimpleNamespace(
        granted=True, source="dashboard", actor="user:reviewer"))
    permit = execution_consent.request_execution_consent(
        "code_exec",
        target_provider=lambda: {"workdir": str(tmp_path), "isolation": "host"},
        parameters={"code": "print(1)"},
        detail="Run Python code.", effect="Runs Python code.",
        review_items=["Python code"], timeout=10,
    )
    with consume_operation_consent(permit):
        pass
    with pytest.raises(ApprovalCardError), consume_operation_consent(permit):
        pass
