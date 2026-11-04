"""Read-seat rollout across the non-finance suites.

The connector seats remain registered so high-trust workflows can still opt into
suite data; lower-risk packs explicitly require approved exports instead of
declaring tools their capability cannot use. GET-only enterprise API access is not treated
as low confidentiality risk by default. Identity, HR, security, CI/CD, legal,
customer, and BI systems fail closed as high risk unless an operator deliberately
adds an exact risk override.
"""
from __future__ import annotations

from maverick.capability import Capability
from maverick.domain import builtin_dir, domain_capability, load_domains
from maverick.safety.tool_risk import tool_risk
from maverick.tools.enterprise_connectors import READ_CONNECTOR_NAMES, READ_CONNECTOR_RISKS

# one representative (pack -> read seat) per suite
_SAMPLES = {
    "gtm_outbound_sdr": "salesloft_read",
    "legal_contract_drafting": "ironclad_read",
    "ops_transportation": "flexport_read",
    "hr_recruiting_ops": "greenhouse_read",
    "itgrc_vuln_mgmt": "qualys_read",
    "pe_cicd": "jenkins_read",
    "strat_competitive_intel": "crunchbase_read",
}

_SENSITIVE_EXAMPLES = {
    "bamboohr_read",
    "cyberark_read",
    "okta_read",
    "splunk_read",
    "crowdstrike_read",
    "jenkins_read",
}


def test_each_suite_pack_uses_a_permitted_seat_or_explicit_export_prerequisite():
    d = load_domains(builtin_dir())
    low_parent = Capability(principal="agent:low-risk-channel-0", max_risk="low")
    for pack, seat in _SAMPLES.items():
        profile = d[pack]
        if profile.max_risk == 'high':
            assert seat in profile.allow_tools
        else:
            assert seat not in profile.allow_tools
            assert seat in profile.persona
            assert 'operator-approved export' in profile.persona
            assert 'read_file' in profile.allow_tools
            assert all(seat not in step.tools for step in profile.workflow)
        cap = domain_capability(profile, low_parent, f"agent:{pack}-1")
        assert cap.permits('read_file')
        assert not cap.permits(seat), f"{pack} must not reach high-risk read seat {seat}"
        assert tool_risk(seat) == "high", f"{seat} must not bypass low-risk ceilings"


def test_pam_domain_does_not_grant_cyberark_read_under_low_risk_ceiling():
    d = load_domains(builtin_dir())
    parent = Capability(principal="agent:supervisor-0", max_risk="high")
    cap = domain_capability(d["itgrc_pam"], parent, "agent:itgrc_pam-1")
    assert "cyberark_read" not in d["itgrc_pam"].allow_tools
    assert "cyberark_read" in d["itgrc_pam"].persona
    assert 'operator-approved export' in d['itgrc_pam'].persona
    assert cap.permits('read_file')
    assert tool_risk("cyberark_read") == "high"
    assert not cap.permits("cyberark_read")


def test_sensitive_read_seats_are_high_while_write_seats_stay_high():
    for seat in _SENSITIVE_EXAMPLES:
        assert seat in READ_CONNECTOR_NAMES
        assert READ_CONNECTOR_RISKS[seat] == "high"
        assert tool_risk(seat) == "high"
        assert tool_risk(seat[: -len("_read")]) == "high"


def test_rollout_covers_all_seven_non_finance_suites_without_low_risk_bypass():
    d = load_domains(builtin_dir())
    reads = set(READ_CONNECTOR_NAMES)
    sensitive_reads = {seat for seat in reads if tool_risk(seat, overrides={}) == 'high'}
    suites: dict[str, int] = {}
    for name, prof in d.items():
        if name.startswith("finance"):
            continue
        live = reads & set(prof.allow_tools)
        export = 'operator-approved export' in prof.persona and any(seat in prof.persona for seat in reads)
        if live or export:
            low = domain_capability(prof, Capability(principal='agent:low', max_risk='low'), 'agent:child')
            assert not any(low.permits(seat) for seat in sensitive_reads)
            if export:
                assert low.permits('read_file')
            suites[name.split("_")[0]] = suites.get(name.split("_")[0], 0) + 1
    assert set(suites) >= {"gtm", "legal", "ops", "hr", "itgrc", "pe", "strat"}, suites
    assert sum(suites.values()) >= 100, suites  # the rollout still reaches breadth
