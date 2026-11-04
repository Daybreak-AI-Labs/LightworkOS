"""A "*" DoA dollar threshold is a FLOOR (strictest-wins).

_threshold_for compares an exact per-action entry against a stricter "*"
catch-all, so an org-wide ``require_human_above = {"*": 5000}`` (or a
``deny_above`` ceiling) is not defeated for an action carrying its own higher
threshold, and a money-movement action cannot slip its human-approval / deny
tier. The catch-all is a floor: a per-action key can only tighten it. This holds for a single policy AND for a
composed (union) policy, matching the documented "lowest threshold wins" rule.
"""
from __future__ import annotations

from maverick.governance import Decision, Policy, evaluate


def test_wildcard_deny_ceiling_binds_below_higher_per_action():
    # deny_above {"*": 50000, "wire_transfer": 1_000_000}: a $100k wire must be
    # DENIED by the $50k catch-all, not allowed under the higher per-action key.
    pol = Policy(deny_above={"*": 50_000, "wire_transfer": 1_000_000})
    assert evaluate("wire_transfer", amount=100_000, policy=pol).decision is Decision.DENY
    # Under the floor: allowed.
    assert evaluate("wire_transfer", amount=10_000, policy=pol).decision is Decision.ALLOW


def test_union_preserves_the_wildcard_floor():
    # A base org floor composed with a regime that sets a HIGHER per-action
    # threshold must not open a hole: the $5k floor still gates a $20k wire.
    from maverick.finance.regimes import union_policies

    base = Policy(require_human_above={"*": 5_000})
    regime = Policy(require_human_above={"wire_transfer": 50_000})
    merged = union_policies([base, regime])
    assert evaluate("wire_transfer", amount=20_000, policy=merged).decision is Decision.REQUIRE_HUMAN
    # Order-independent.
    merged2 = union_policies([regime, base])
    assert evaluate("wire_transfer", amount=20_000, policy=merged2).decision is Decision.REQUIRE_HUMAN


def test_no_wildcard_uses_exact_only():
    # With no "*" entry, the exact per-action threshold is used unchanged.
    pol = Policy(require_human_above={"wire_transfer": 50_000})
    assert evaluate("wire_transfer", amount=20_000, policy=pol).decision is Decision.ALLOW
    assert evaluate("wire_transfer", amount=60_000, policy=pol).decision is Decision.REQUIRE_HUMAN
    # An action with neither an exact nor "*" entry is unconstrained by amount.
    assert evaluate("post_note", amount=10_000_000, policy=pol).decision is Decision.ALLOW
