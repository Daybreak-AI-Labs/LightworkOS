"""Approval delegation rules (re-triage build)."""
from __future__ import annotations

from maverick.approval_delegation import DelegationRule, parse_rules, route


def test_parse_skips_malformed():
    rules = parse_rules([
        {"delegate_to": "lead", "min_risk": "high"},
        {"min_risk": "high"},               # no delegate_to -> skipped
        {"delegate_to": "x", "min_risk": "bogus"},  # bad risk -> skipped
        "not a dict",                       # skipped
    ])
    assert len(rules) == 1
    assert rules[0].delegate_to == "lead"


def test_route_by_min_risk():
    rules = [DelegationRule(delegate_to="senior", min_risk="high")]
    assert route({"risk": "high", "tool": "shell"}, rules) == "senior"
    assert route({"risk": "critical", "tool": "x"}, rules) == "senior"
    assert route({"risk": "low", "tool": "x"}, rules) is None


def test_route_by_tool_glob():
    rules = [DelegationRule(delegate_to="payments", tool_glob="stripe_*")]
    assert route({"risk": "low", "tool": "stripe_refund"}, rules) == "payments"
    assert route({"risk": "low", "tool": "read_file"}, rules) is None


def test_first_matching_rule_wins():
    rules = [
        DelegationRule(delegate_to="payments", tool_glob="stripe_*"),
        DelegationRule(delegate_to="catchall", min_risk="low"),
    ]
    assert route({"risk": "high", "tool": "stripe_refund"}, rules) == "payments"
    assert route({"risk": "high", "tool": "shell"}, rules) == "catchall"


def test_no_rules_returns_none():
    assert route({"risk": "critical", "tool": "shell"}, []) is None


def test_unknown_risk_treated_as_low():
    rules = [DelegationRule(delegate_to="x", min_risk="medium")]
    assert route({"risk": "garbage", "tool": "t"}, rules) is None
