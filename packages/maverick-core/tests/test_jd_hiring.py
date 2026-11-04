"""Tests for maverick.jd_hiring — JD → roster matching, drafting, fleet add."""
from __future__ import annotations

import json

import pytest
from maverick.domain import DomainProfile, available_domains
from maverick.jd_hiring import (
    JDMatch,
    add_pack_to_fleet,
    draft_from_jd,
    jd_hiring_enabled,
    match_jd,
)

FINANCE_JD = """Senior Accounts Payable Specialist

We are hiring an accounts payable specialist to own vendor invoices and payments.

- Process vendor invoices and three-way match against purchase orders
- Reconcile supplier statements and resolve payment discrepancies
- Prepare weekly payment runs for approval
- Maintain vendor master data and W-9 records
- Support the monthly close with AP accruals
"""

PRIVACY_JD = """Privacy Analyst

Own data subject access requests and GDPR compliance operations.

- Fulfill data subject access requests within statutory deadlines
- Maintain the record of processing activities
- Run privacy impact assessments for new vendors
"""


# ---- match_jd ---------------------------------------------------------------

def test_match_returns_ranked_relevant_packs():
    matches = match_jd(FINANCE_JD, k=5)
    assert matches, "a finance JD must match the shipped roster"
    assert all(isinstance(m, JDMatch) for m in matches)
    # Relative fit: best hit is 1.0, rest are descending in (0, 1].
    assert matches[0].fit == 1.0
    fits = [m.fit for m in matches]
    assert fits == sorted(fits, reverse=True)
    # The top hits for an AP JD should come from the finance suite.
    assert any((m.suite or "").startswith("finance") for m in matches[:3]), \
        [m.name for m in matches]
    # Explanability: matched terms are real JD words.
    assert any("invoices" in m.matched_terms or "vendor" in m.matched_terms
               for m in matches[:3])
    assert not {"specialist", "match", "process", "prepare"} & {
        term for match in matches for term in match.matched_terms
    }


def test_match_domain_specificity():
    privacy = match_jd(PRIVACY_JD, k=3)
    assert privacy
    names = " ".join(m.name for m in privacy)
    assert "dsar" in names or "privacy" in names or "ropa" in names, names


def test_match_includes_custom_tenant_packs(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path))
    (tmp_path / "acme_llama_groomer.toml").write_text(
        'name = "acme_llama_groomer"\n'
        'compartment = "acme_llama_groomer"\n'
        'description = "Grooms llamas and maintains llama grooming schedules"\n'
        'persona = "You are the llama grooming specialist."\n'
        'allow_tools = ["read_file"]\n'
        'max_risk = "low"\n',
        encoding="utf-8",
    )
    domains = available_domains()
    assert "acme_llama_groomer" in domains
    matches = match_jd("We need someone to groom llamas on a schedule",
                       k=3, domains=domains)
    assert matches and matches[0].name == "acme_llama_groomer"


def test_match_empty_and_oversized_input():
    assert match_jd("") == []
    assert match_jd("   \n  ") == []
    # Oversized input is truncated, not an error.
    assert isinstance(match_jd("invoice " * 10_000, k=2), list)


# ---- draft_from_jd ----------------------------------------------------------

def test_draft_deterministic_is_clamped():
    prof = draft_from_jd("Accounts Payable Specialist", FINANCE_JD)
    assert isinstance(prof, DomainProfile)
    assert prof.authoring == "generated"
    # The generated deny-floor always applies (intake._GENERATED_DENY).
    for tool in ("shell", "write_file", "code_exec", "browser"):
        assert tool in prof.deny_tools
        assert tool not in prof.allow_tools
    assert prof.max_risk in ("low", "medium")
    assert prof.compartment  # seal boundary set


def test_draft_derives_workflow_from_jd_bullets():
    prof = draft_from_jd("AP Specialist", FINANCE_JD)
    names = [s.name for s in prof.workflow]
    assert any("invoice" in n.lower() for n in names), names
    # Human handoff on the final step.
    assert prof.workflow[-1].gate in ("review", "approval")


def test_draft_without_bullets_falls_back_to_default_workflow():
    prof = draft_from_jd("Generalist", "A role with no bullet structure at all.")
    assert prof.workflow, "default workflow must be present"


def test_unusable_ai_draft_uses_bullets_and_reports_the_source():
    class UnusableLLM:
        def complete(self, **_kwargs):
            return type("Reply", (), {"text": "Here is my draft in prose, not JSON."})()

    prof, source = draft_from_jd(
        "Accounts Payable Specialist", FINANCE_JD, llm=UnusableLLM(),
        return_source=True,
    )
    assert source == "bullet_points"
    assert prof.description == "Accounts Payable Specialist"
    assert "Process vendor invoices" in [s.name for s in prof.workflow][0]
    assert "configured work steps" in prof.persona


def test_ai_draft_keeps_role_title_as_the_short_display_name():
    class UsefulLLM:
        def complete(self, **_kwargs):
            return type("Reply", (), {"text": json.dumps({
                "description": "A paragraph that should never replace the role title " * 8,
                "persona": "You review accounts payable records against source documents.",
                "workflow": [
                    {"name": "Check invoices", "instruction": "Compare invoices with purchase orders."},
                    {"name": "Reconcile records", "instruction": "Identify and flag discrepancies."},
                    {"name": "Hand off payment run", "instruction": "Prepare an approval-ready report.", "gate": "review"},
                ],
            })})()

    prof, source = draft_from_jd(
        "Accounts Payable Specialist", FINANCE_JD, llm=UsefulLLM(),
        return_source=True,
    )
    assert source == "ai"
    assert prof.description == "Accounts Payable Specialist"
    assert prof.workflow[0].name == "Check invoices"


@pytest.mark.parametrize("field", ["role_title", "jd_text", "industry"])
def test_llm_draft_rejects_credentials_before_provider_call(field):
    values = {
        "role_title": "Accounts Payable Specialist",
        "jd_text": FINANCE_JD,
        "industry": "manufacturing",
    }
    values[field] = "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456"  # pragma: allowlist secret

    with pytest.raises(ValueError, match="contains a credential"):
        draft_from_jd(
            values["role_title"], values["jd_text"],
            industry=values["industry"], llm=object(),
        )


def test_llm_draft_fails_closed_when_dlp_scanner_fails(monkeypatch):
    from maverick.safety import secret_detector

    def scanner_failure(_text):
        raise RuntimeError("scanner unavailable")

    monkeypatch.setattr(secret_detector, "scan", scanner_failure)
    with pytest.raises(ValueError, match="could not be safely screened"):
        draft_from_jd("AP Specialist", FINANCE_JD, llm=object())


# ---- add_pack_to_fleet -------------------------------------------------------

def test_add_pack_to_fleet_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    fleet = add_pack_to_fleet("finance_ap", "finance-team", "hr.lead@company.com")
    assert fleet.name == "finance-team"
    assert any(a.domain == "finance_ap" for a in fleet.agents)
    # Idempotent.
    again = add_pack_to_fleet("finance_ap", "finance-team", "hr.lead@company.com")
    assert sum(1 for a in again.agents if a.domain == "finance_ap") == 1
    # Persisted as the standard fleet JSON.
    saved = json.loads(
        (tmp_path / "fleets" / "finance-team.json").read_text(encoding="utf-8"))
    assert saved["agents"][0]["domain"] == "finance_ap"
    # Role defaults to the pack's suite (department key).
    assert saved["agents"][0]["role"] == "finance"


def test_add_unknown_pack_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    try:
        add_pack_to_fleet("no_such_pack_xyz", "team", "owner")
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "no such specialist pack" in str(e)


# ---- config knob -------------------------------------------------------------

def test_jd_hiring_enabled_default_and_off(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    assert jd_hiring_enabled() is True  # no config -> default on
    cfg.write_text("[agent_factory]\njd_hiring = false\n", encoding="utf-8")
    assert jd_hiring_enabled() is False


@pytest.mark.parametrize(
    "content",
    [
        'agent_factory = "yes"\n',
        '[agent_factory]\njd_hiring = "yes"\n',
        '[agent_factory\njd_hiring = true\n',
    ],
)
def test_jd_hiring_gate_fails_closed_on_invalid_config(tmp_path, monkeypatch, content):
    import maverick.config as config

    cfg = tmp_path / "config.toml"
    cfg.write_text(content, encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    try:
        assert jd_hiring_enabled() is False
    finally:
        config.reset_config_cache()
