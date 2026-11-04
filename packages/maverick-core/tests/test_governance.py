"""Oversight control plane policy engine: ALLOW / DENY / REQUIRE_HUMAN.

Pure decision logic (no I/O), so every clause + the strictest-wins precedence is
unit-tested directly. Risk facts used: ``shell`` is high-risk, ``read_file`` is
low-risk (see ``safety.tool_risk``).
"""
from __future__ import annotations

import pytest
from maverick.governance import (
    Decision,
    GovernancePolicyError,
    Policy,
    Verdict,
    evaluate,
)


def test_empty_policy_allows():
    v = evaluate("read_file", policy=Policy())
    assert v.decision is Decision.ALLOW and v.allowed and v.rule == "default"
    assert v.compliance_profiles == ()


def test_unavailable_verdict_provenance_is_distinct_from_no_active_profiles():
    unavailable = Verdict(Decision.DENY, "policy unavailable", "policy_unavailable")
    assert unavailable.compliance_profiles is None


def test_deny_actions():
    v = evaluate("delete_file", policy=Policy(deny_actions=frozenset({"delete_file"})))
    assert v.decision is Decision.DENY and v.rule == "deny_actions"


def test_deny_min_risk_floor():
    pol = Policy(deny_min_risk="high")
    assert evaluate("shell", policy=pol).decision is Decision.DENY        # high
    assert evaluate("read_file", policy=pol).decision is Decision.ALLOW   # low


def test_require_human_actions():
    v = evaluate("send_email",
                 policy=Policy(require_human_actions=frozenset({"send_email"})))
    assert v.decision is Decision.REQUIRE_HUMAN and v.needs_human


def test_require_human_min_risk_floor():
    pol = Policy(require_human_min_risk="high")
    assert evaluate("shell", policy=pol).decision is Decision.REQUIRE_HUMAN
    assert evaluate("read_file", policy=pol).decision is Decision.ALLOW


def test_risk_override_param():
    # An action classified low can be forced high by the caller.
    pol = Policy(require_human_min_risk="high")
    assert evaluate("read_file", risk="high", policy=pol).decision is Decision.REQUIRE_HUMAN


def test_capability_denial_takes_precedence():
    from maverick.capability import Capability
    cap = Capability(principal="p", deny_tools=frozenset({"shell"}))
    v = evaluate("shell", capability=cap,
                 policy=Policy(require_human_actions=frozenset({"shell"})))
    assert v.decision is Decision.DENY and v.rule == "capability"


def test_deny_beats_require_human():
    pol = Policy(deny_actions=frozenset({"x"}),
                 require_human_actions=frozenset({"x"}))
    assert evaluate("x", policy=pol).decision is Decision.DENY


def test_from_config(monkeypatch):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {
        "governance": {
            "deny_actions": ["delete_file"],
            "require_human_actions": ["send_email"],
            "require_human_min_risk": "high",
        },
    })
    pol = Policy.from_config()
    assert "delete_file" in pol.deny_actions
    assert "send_email" in pol.require_human_actions
    assert pol.require_human_min_risk == "high"
    assert not pol.is_empty()


def test_from_config_empty_is_default_allow(monkeypatch):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    pol = Policy.from_config()
    assert pol.is_empty()
    assert evaluate("shell", policy=pol).decision is Decision.ALLOW


def test_from_config_refuses_untrusted_policy_source(monkeypatch):
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setattr(
        "maverick.config.config_source_errors",
        lambda: {"config.toml": "invalid TOML"},
    )

    with pytest.raises(GovernancePolicyError, match="source is invalid"):
        Policy.from_config()


@pytest.mark.parametrize(
    "governance",
    [
        {"deny_actions": "delete_file"},
        {"require_human_actions": ["send_email", 7]},
        {"deny_min_risk": 3},
        {"deny_above": {"*": "5000"}},
        {"require_human_above": {"wire_transfer": float("nan")}},
        {"require_human_above": {"wire_transfer": float("inf")}},
        {"require_fresh_human_approval": "false"},
    ],
)
def test_from_config_refuses_malformed_security_fields(monkeypatch, governance):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"governance": governance},
    )

    with pytest.raises(GovernancePolicyError):
        Policy.from_config()


def test_from_config_refuses_non_table_governance_section(monkeypatch):
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"governance": "disabled"},
    )

    with pytest.raises(GovernancePolicyError, match="configuration table"):
        Policy.from_config()


def test_from_config_refuses_lost_compliance_overlay(monkeypatch):
    from maverick import compliance_profiles

    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr("maverick.config.load_config", dict)
    monkeypatch.setattr(
        compliance_profiles,
        "configured_profiles",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("profile store unavailable")),
    )

    with pytest.raises(GovernancePolicyError, match="compliance governance"):
        Policy.from_config()


@pytest.mark.parametrize(
    "config",
    [
        {"compliance": "hipaa"},
        {"compliance": {"profiles": "hipaa"}},
        {"compliance": {"profiles": ["unknown"]}},
    ],
)
def test_from_config_refuses_malformed_or_unknown_compliance_profiles(
    monkeypatch, config
):
    monkeypatch.delenv("MAVERICK_COMPLIANCE_PROFILES", raising=False)
    monkeypatch.setattr("maverick.config.config_source_errors", dict)
    monkeypatch.setattr("maverick.config.load_config", lambda: config)

    with pytest.raises(GovernancePolicyError, match="compliance governance"):
        Policy.from_config()


# --- governance risk floor never silently disabled ------------------

def test_critical_risk_floor_denies_high_risk_action():
    from maverick.governance import _risk_floor
    # "critical" used to resolve to None -> no deny floor at all. As a config
    # value it must now behave as the top tier and deny a high-risk tool. This
    # is exactly what Policy.from_config does with cfg["deny_min_risk"].
    pol = Policy(deny_min_risk=_risk_floor("critical"))
    assert pol.deny_min_risk == "high"
    assert evaluate("shell", policy=pol).decision is Decision.DENY  # shell=high
    # Sanity: a low-risk tool is still allowed under that floor.
    assert evaluate("read_file", policy=pol).decision is Decision.ALLOW


def test_unknown_risk_floor_clamps_high_not_disabled():
    from maverick.governance import _risk_floor
    assert _risk_floor("critical") == "high"
    assert _risk_floor("severe") == "high"
    assert _risk_floor("bogus-typo") == "high"   # fail-closed, not None
    assert _risk_floor("HIGH") == "high"          # case/space tolerant
    assert _risk_floor("  medium ") == "medium"


def test_explicit_disable_sentinel_clears_floor():
    from maverick.governance import _risk_floor
    # An operator can still intentionally clear a floor.
    assert _risk_floor("none") is None
    assert _risk_floor("off") is None
    assert _risk_floor(None) is None
    assert _risk_floor("") is None


def test_risk_override_still_falls_through_to_classifier():
    # The caller-supplied risk= override keeps its strict semantics: an
    # unrecognized value falls back to the tool classifier, NOT clamped to high.
    from maverick.governance import _risk_level
    assert _risk_level("bogus") is None
    assert _risk_level("critical") is None  # not a known level; override path
