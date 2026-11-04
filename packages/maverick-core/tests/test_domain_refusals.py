"""Hard refusals: the prohibited-use list rendered into a specialist's prompt.

Unlike operating discipline, refusals are always on (no operator opt-out) and
have no approval path -- the agent declines and escalates. These tests pin the
EU AI Act Art. 5 coverage for HR and the safety-critical refusals for the
physical-world suites, so a future edit can't quietly drop a prohibition.
"""
from __future__ import annotations

from maverick.domain_refusals import (
    SUITE_REFUSALS,
    UNIVERSAL,
    refusals_for,
    render_refusals,
)


def test_universal_refusals_apply_to_every_pack():
    # Even a suite with no prohibited-use list carries the universal refusals.
    items = refusals_for("mkt_social")
    assert list(UNIVERSAL) == items
    assert any("safety controls" in r for r in items)
    assert any("impersonate" in r for r in items)


def test_hr_carries_eu_ai_act_art5_refusals():
    items = refusals_for("hr_screening")
    assert any("emotion" in r for r in items), "missing workplace emotion-inference refusal"
    assert any("biometric" in r for r in items)
    assert any("social score" in r for r in items)
    # ...and the consequential-decision refusal (a human decides).
    assert any("hire, fire" in r for r in items)


def test_physical_suites_refuse_safety_critical_actuation():
    for name in ("ops_shopfloor", "mfg_lockout", "util_outage_coord"):
        items = refusals_for(name)
        assert any("interlock" in r or "safety-critical" in r for r in items), name


def test_pack_specific_refusals_append_and_dedupe():
    items = refusals_for("hr_screening",
                         ["never use a credit score in screening",
                          # a duplicate of a universal entry must not repeat
                          UNIVERSAL[0]])
    assert any("credit score" in r for r in items)
    assert items.count(UNIVERSAL[0]) == 1


def test_render_is_a_non_negotiable_block_or_empty():
    block = render_refusals("hr_screening")
    assert "Hard refusals" in block and "no approval path" in block
    for r in refusals_for("hr_screening"):
        assert r in block
    # render is never empty in practice (universal always applies), but a blank
    # name still yields the universal block, not a crash.
    assert "Hard refusals" in render_refusals("")


def test_covered_suites_are_the_refuse_not_gate_ones():
    # Sanity: the suites with prohibited uses are the physical / adjudication /
    # MNPI ones -- not the suites whose controls are all human-approval gates.
    assert {"hr", "operations", "healthcare", "banking", "capital_markets",
            "legal"} <= set(SUITE_REFUSALS)
    assert "marketing" not in SUITE_REFUSALS
    assert "procurement" not in SUITE_REFUSALS
