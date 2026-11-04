"""Finance compliance-regime packs (finance-agent-suite §5)."""
from __future__ import annotations

import pytest
from maverick.finance.regimes import (
    REGIMES,
    compile_policy,
    list_regimes,
    union_policies,
)
from maverick.governance import Decision, GovernancePolicyError, Policy, evaluate


def test_all_regimes_present():
    assert set(REGIMES) == {
        "sox", "coso", "gaap", "pci", "glba", "aml", "sec", "irs",
        "dora", "basel_iii", "ifrs_17",
    }
    assert len(list_regimes()) == 11


def test_sox_gates_money_movement():
    pol = compile_policy(["sox"])
    assert "post_journal_entry" in pol.require_human_actions
    assert "release_payment" in pol.require_human_actions
    assert pol.require_human_min_risk == "high"
    assert evaluate("release_payment", policy=pol).decision is Decision.REQUIRE_HUMAN


def test_compile_policy_normalizes_regime_key_case():
    # A mis-cased KNOWN regime key must not silently compile to no enforcement.
    caps = compile_policy(["SOX", "AML"])
    low = compile_policy(["sox", "aml"])
    assert caps.require_human_actions == low.require_human_actions
    assert "release_payment" in caps.require_human_actions
    assert compile_policy([" Sox "]).require_human_actions \
        == compile_policy(["sox"]).require_human_actions


def test_sec_and_irs_gate_filing():
    assert "file_with_sec" in compile_policy(["sec"]).require_human_actions
    irs = compile_policy(["irs"])
    assert {"file_return", "remit_tax"} <= set(irs.require_human_actions)


def test_union_is_strictest_wins_thresholds():
    a = Policy(deny_above={"pay": 100}, require_human_min_risk="high")
    b = Policy(deny_above={"pay": 50}, require_human_min_risk="medium")
    u = union_policies([a, b])
    assert u.deny_above["pay"] == 50              # lowest threshold wins
    assert u.require_human_min_risk == "medium"   # stricter floor wins


def test_union_preserves_strictest_fresh_human_approval_requirement():
    ordinary = Policy(require_human_actions=frozenset({"pay"}))
    fresh = Policy(require_fresh_human_approval=True)

    combined = union_policies([ordinary, fresh])

    assert combined.require_fresh_human_approval is True
    assert combined.is_empty() is False


def test_deny_beats_require_human_in_union():
    a = Policy(deny_actions=frozenset({"x"}))
    b = Policy(require_human_actions=frozenset({"x"}))
    u = union_policies([a, b])
    assert "x" in u.deny_actions
    assert "x" not in u.require_human_actions


def test_multi_regime_union_covers_all():
    pol = compile_policy(["sox", "aml", "sec", "irs"])
    for action in ("release_payment", "wire_transfer", "file_with_sec", "remit_tax"):
        v = evaluate(action, policy=pol)
        assert v.decision is Decision.REQUIRE_HUMAN, action


def test_expanded_regimes_compile_as_strictest_wins_union():
    pol = compile_policy(["DORA", "BASEL_III", "IFRS_17", "PCI"])
    expected = {
        "report_ict_incident",
        "change_critical_ict_provider",
        "approve_ict_third_party",
        "file_regulatory_capital_report",
        "approve_risk_weight",
        "change_regulatory_capital_model",
        "post_journal_entry",
        "close_period",
        "publish_insurance_financials",
    }
    assert expected <= set(pol.require_human_actions)
    for action in expected:
        assert evaluate(action, policy=pol).decision is Decision.REQUIRE_HUMAN


def test_expanded_regime_union_preserves_deny_precedence():
    dora = REGIMES["dora"].policy
    override = Policy(deny_actions=frozenset({"report_ict_incident"}))
    pol = union_policies([dora, override])
    assert "report_ict_incident" in pol.deny_actions
    assert "report_ict_incident" not in pol.require_human_actions
    assert evaluate("report_ict_incident", policy=pol).decision is Decision.DENY


def test_expanded_regimes_carry_primary_source_provenance():
    expected_hosts = {
        "dora": "eur-lex.europa.eu",
        "basel_iii": "www.bis.org",
        "ifrs_17": "www.ifrs.org",
        "pci": "www.pcisecuritystandards.org",
    }
    for key, host in expected_hosts.items():
        regime = REGIMES[key]
        assert regime.source_urls
        assert all(url.startswith(f"https://{host}/") for url in regime.source_urls)


def test_configured_finance_regimes_are_live_in_policy_from_config(monkeypatch):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *args, **kwargs: {
            "finance": {"regimes": ["DORA", "BASEL_III", "IFRS_17"]},
            "governance": {"require_fresh_human_approval": True},
        },
    )

    policy = Policy.from_config()

    assert policy.require_fresh_human_approval is True
    for action in (
        "report_ict_incident",
        "file_regulatory_capital_report",
        "publish_insurance_financials",
    ):
        assert evaluate(action).decision is Decision.REQUIRE_HUMAN


def test_malformed_finance_regime_overlay_fails_closed(monkeypatch):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *args, **kwargs: {"finance": {"regimes": "DORA"}},
    )

    with pytest.raises(GovernancePolicyError, match="finance-regime"):
        Policy.from_config()


def test_unknown_live_finance_regime_fails_closed(monkeypatch):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *args, **kwargs: {"finance": {"regimes": ["DORA", "DORAA"]}},
    )

    with pytest.raises(GovernancePolicyError, match="finance-regime"):
        Policy.from_config()


def test_unknown_key_ignored_and_empty():
    assert compile_policy(["bogus"]).is_empty()
    assert compile_policy([]).is_empty()


def test_evidence_only_regimes_have_empty_policy():
    # COSO / PCI / GLBA are evidence frameworks; enforcement is elsewhere.
    for k in ("coso", "pci", "glba"):
        assert REGIMES[k].policy.is_empty()
        assert REGIMES[k].asserts  # but they describe what they cover
