"""After a regulated-posture setup, the wizard surfaces the compliance and
GDPR/EU AI Act documentation commands so a non-technical operator can find them
(the rule-6 integrity check: a capability the operator turned on must be
reachable from the wizard)."""
from __future__ import annotations

from maverick_installer import wizard


def test_regulated_deployment_detects_each_sensitive_control():
    assert wizard._regulated_deployment({"enterprise": True})
    assert wizard._regulated_deployment({"compliance_profiles": ["gdpr"]})
    assert wizard._regulated_deployment({"encrypt_at_rest": True})
    assert wizard._regulated_deployment({"audit_sign": True})
    assert wizard._regulated_deployment({"security_autofix": True})
    # A non-sensitive toggle (or nothing) does not trigger the panel.
    assert not wizard._regulated_deployment({"tenant_by_user": True})
    assert not wizard._regulated_deployment({})
    assert not wizard._regulated_deployment(None)


def test_compliance_command_set_is_the_full_surface():
    assert [cmd for cmd, _ in wizard._COMPLIANCE_COMMANDS] == [
        "maverick enterprise verify",
        "maverick compliance",
        "maverick ropa",
        "maverick dpia",
        "maverick ai-act",
        "maverick assess",
        "maverick hunt",
        "maverick remediate",
        "maverick regulatory verify",
        "maverick attest receipt mint",
    ]


def test_compliance_guidance_does_not_overclaim_runtime_proof():
    descriptions = " ".join(description for _, description in wizard._COMPLIANCE_COMMANDS)
    assert "prove" not in descriptions.lower()
    assert "configured application-layer boundary controls" in descriptions
    assert "non-vacuous gates" in descriptions


def test_panel_prints_only_for_a_regulated_deployment(capsys):
    # Not regulated -> silent (no noise for a personal install).
    wizard.show_compliance_commands({})
    assert capsys.readouterr().out == ""

    # Regulated -> the documentation commands are shown.
    wizard.show_compliance_commands({"enterprise": True})
    out = capsys.readouterr().out
    assert "maverick ropa" in out
    assert "maverick ai-act" in out
    assert "Compliance" in out
    assert "Verify" in out
    assert "prepare" in out
    assert "Prove" not in out

    wizard.show_compliance_commands({"compliance_profiles": ["eu_ai_act"]})
    assert "maverick regulatory verify" in capsys.readouterr().out
