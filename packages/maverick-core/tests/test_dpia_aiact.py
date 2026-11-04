"""maverick dpia / ai-act: GDPR Art. 35 DPIA + EU AI Act classification."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick.cli import main


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for var in (
        "MAVERICK_ENTERPRISE", "MAVERICK_ENCRYPT_AT_REST", "MAVERICK_AUDIT_SIGN",
        "MAVERICK_CONSENT_MODE", "MAVERICK_AI_DISCLOSURE",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})


# --- DPIA -----------------------------------------------------------------

def test_dpia_shape_and_open_risks_on_bare_deployment():
    from maverick.dpia import generate_dpia

    dpia = generate_dpia()
    assert dpia["assessment_type"].startswith("GDPR Article 35")
    assert dpia["risk_register"], "expected a non-empty risk register"
    # A bare deployment has opt-in mitigations off -> open risks.
    assert dpia["open_risk_count"] >= 1
    egress = next(r for r in dpia["risk_register"] if "third-party LLM" in r["risk"])
    assert egress["treatment"].startswith("OPEN")


def test_dpia_enterprise_mitigates_egress_and_encryption(monkeypatch):
    from maverick.dpia import generate_dpia

    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")  # egress + consent + encryption
    dpia = generate_dpia()
    treatments = {r["risk"][:24]: r["treatment"] for r in dpia["risk_register"]}
    egress = next(r for r in dpia["risk_register"] if "third-party LLM" in r["risk"])
    enc = next(r for r in dpia["risk_register"] if "on disk" in r["risk"])
    assert egress["treatment"] == "mitigated"
    assert enc["treatment"] == "mitigated"
    assert treatments  # sanity


def test_dpia_cli_text_json_and_file(tmp_path):
    runner = CliRunner()
    text = runner.invoke(main, ["dpia"])
    assert text.exit_code == 0
    assert "Data Protection Impact Assessment" in text.output

    out = tmp_path / "dpia.json"
    written = runner.invoke(main, ["dpia", "--format", "json", "-o", str(out)])
    assert written.exit_code == 0
    assert json.loads(out.read_text())["assessment_type"].startswith("GDPR Article 35")


# --- AI Act ---------------------------------------------------------------

def test_ai_act_reports_default_limited_risk_and_checklists():
    from maverick.ai_act import assess_ai_act

    rep = assess_ai_act()
    assert "Limited risk" in rep["default_classification"]
    # Default deployment discloses it is AI -> Art. 50 obligation met.
    assert rep["transparency_obligation_art50"]["disclosure_active"] is True
    assert rep["self_assessment"]["prohibited_art5"]
    assert rep["self_assessment"]["high_risk_annex_iii"]


def test_ai_act_transparency_not_met_when_disclosure_disabled(monkeypatch):
    from maverick.ai_act import assess_ai_act

    monkeypatch.setenv("MAVERICK_AI_DISCLOSURE", "")  # operator opted out
    rep = assess_ai_act()
    assert rep["transparency_obligation_art50"]["disclosure_active"] is False


def test_ai_act_cli_text_and_json():
    runner = CliRunner()
    text = runner.invoke(main, ["ai-act"])
    assert text.exit_code == 0
    assert "EU AI Act" in text.output and "PROHIBITED" in text.output

    js = runner.invoke(main, ["ai-act", "--format", "json"])
    assert js.exit_code == 0
    assert json.loads(js.output)["framework"].startswith("EU AI Act")
