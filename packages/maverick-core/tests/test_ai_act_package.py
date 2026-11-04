"""AI Act conformance package: honest assembly from recorded posture."""
from __future__ import annotations

import json

import pytest
from maverick import ai_act_package as pkg


def test_build_package_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    p = pkg.build_package()
    assert p["kind"] == "ai-act-technical-documentation"
    assert "classification" in p and "human_oversight" in p
    assert "logging" in p and "evidence" in p
    # nothing recorded in a fresh home -> evidence sections are None
    assert p["evidence"]["redteam"] is None
    assert p["evidence"]["reliability_cert"] is None


def test_render_says_no_evidence_when_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    md = pkg.render_markdown(pkg.build_package())
    assert "no evidence recorded" in md
    assert "Annex III" in md and "Art. 14" in md and "Art. 12" in md
    assert "Completed by the provider" in md  # honest scope split


def test_render_embeds_present_evidence(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    from maverick.paths import data_dir
    cert = data_dir("reliability_cert.json")
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_text(json.dumps({"passed": True, "checks": {}}), encoding="utf-8")
    md = pkg.render_markdown(pkg.build_package())
    assert "reliability certificate: present" in md
    assert '"passed": true' in md


def test_oversight_reflects_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    p = pkg.build_package()
    assert p["human_oversight"]["consent_mode"] == "dashboard"
    assert "HALT" in p["human_oversight"]["killswitch_path"]


def test_oversight_consent_mode_matches_real_resolver(monkeypatch, tmp_path):
    """The reported default must mirror the actual resolver, not a guess.

    Regression: _oversight() used to hardcode 'ask (default)' when no consent
    mode was configured, telling an auditor human oversight was in place while
    the real default (consent._resolve_mode) is 'auto-approve'.
    """
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_CONSENT_MODE", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    from maverick.safety import consent

    resolved = consent._resolve_mode()
    p = pkg.build_package()
    mode = p["human_oversight"]["consent_mode"]
    assert mode.startswith(resolved), (resolved, mode)
    # The fabricated posture must be gone.
    assert mode != "ask (default)"
    assert resolved == "auto-approve"


def test_logging_audit_signing_matches_compliance_report(monkeypatch, tmp_path):
    """Two compliance artifacts must not disagree about one control.

    Regression: _logging_posture() read only the ``[audit] sign`` config key,
    which is one of five inputs writer._resolve_signing consults (compliance
    floor > explicit arg > MAVERICK_AUDIT_SIGN > [audit] sign > secure-by-
    default). On a default install with no config and no env vars, signing is ON
    and compliance_report() reported "Tamper-evident audit | active" -- while
    this package rendered "audit chain signing: no" from the same deployment at
    the same moment. An auditor handed both would be entitled to conclude we do
    not know our own control state.

    Both surfaces must now resolve through the same probe. This asserts they
    agree, not that either says yes: the point is consistency, so the test still
    holds if the default ever flips.
    """
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_AUDIT_SIGN", raising=False)
    from maverick.deployment import _verify_audit_signing

    probe = _verify_audit_signing()
    posture = pkg.build_package()["logging"]["audit_signing"]
    assert posture == probe.passed, (posture, probe.passed, probe.detail)


def test_logging_audit_signing_is_probed_not_read_from_config(monkeypatch, tmp_path):
    """A config key alone must not be able to fake the posture either way.

    A single config lookup could be flipped by writing a key regardless of
    whether signing actually worked. Setting the env
    var that the real resolver honours must move the reported posture; that is
    only true if we are probing the resolver rather than reading one key.
    """
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    from maverick.deployment import _verify_audit_signing

    assert pkg.build_package()["logging"]["audit_signing"] is _verify_audit_signing().passed


def test_package_is_json_serializable(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    json.dumps(pkg.build_package(), default=str)


@pytest.mark.parametrize(
    ("environment", "saved", "enabled"),
    [
        (None, None, True),
        (None, "", False),
        ("", "Visible saved message", False),
        ("  ", None, False),
        ("Visible environment message", "", True),
    ],
)
def test_transparency_matches_effective_disclosure_and_compliance_report(
    tmp_path, monkeypatch, environment, saved, enabled,
):
    """An explicit opt-out cannot be described as a wired Art. 50 control."""
    from maverick import compliance, config

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    if environment is None:
        monkeypatch.delenv("MAVERICK_AI_DISCLOSURE", raising=False)
    else:
        monkeypatch.setenv("MAVERICK_AI_DISCLOSURE", environment)
    saved_config = {} if saved is None else {"compliance": {"disclosure_text": saved}}
    monkeypatch.setattr(config, "load_config", lambda: saved_config)

    built = pkg.build_package()
    transparency = built["transparency"]
    control = next(check for check in compliance.compliance_report()
                   if check.regulation == "EU AI Act Art. 50")
    assert transparency["first_turn_disclosure_enabled"] is enabled
    assert control.status == ("active" if enabled else "action_needed")
    markdown = pkg.render_markdown(built)
    assert ("first-turn AI disclosure: enabled" if enabled
            else "first-turn AI disclosure: disabled by operator") in markdown
    assert "wired" not in transparency["first_turn_disclosure"]
