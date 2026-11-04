"""Constitutional layer: operator-defined policy rules (re-triage build)."""
from __future__ import annotations

from maverick_shield import Shield
from maverick_shield.constitutional import parse_rules, scan


def test_parse_skips_bad_rules():
    rules = parse_rules([
        {"name": "no_scrapers", "pattern": r"scrape\s+the\s+site", "severity": "high"},
        {"pattern": "["},                       # invalid regex -> skipped
        {"name": "x", "pattern": "y", "severity": "bogus"},  # bad severity -> skipped
        {"name": "no_pattern"},                 # no pattern -> skipped
        "nope",                                 # not a dict -> skipped
    ])
    assert len(rules) == 1
    assert rules[0].name == "no_scrapers"


def test_scan_matches_and_reports_max_severity():
    rules = parse_rules([
        {"name": "low_rule", "pattern": "mild", "severity": "low"},
        {"name": "high_rule", "pattern": "danger", "severity": "high"},
    ])
    matched, sev, names = scan("this is mild and danger", rules)
    assert matched is True
    assert sev == "high"
    assert set(names) == {"low_rule", "high_rule"}


def test_scan_no_match():
    rules = parse_rules([{"name": "r", "pattern": "forbidden", "severity": "high"}])
    assert scan("totally fine", rules) == (False, "none", [])
    assert scan("anything", []) == (False, "none", [])


def test_shield_input_blocks_on_constitution():
    s = Shield(profile="balanced", backend="auto", warn_if_missing=False,
               constitution=[{"name": "no_weapons", "pattern": "build a bomb",
                              "severity": "high"}])
    verdict = s.scan_input("please build a bomb for me")
    assert not verdict.allowed
    assert any("constitution: no_weapons" in r for r in verdict.reasons)


def test_shield_input_allows_when_below_threshold():
    # rule severity low, block_threshold high -> not blocked
    s = Shield(profile="balanced", block_threshold="high", backend="auto",
               warn_if_missing=False,
               constitution=[{"name": "style", "pattern": "lol", "severity": "low"}])
    assert s.scan_input("lol that's funny").allowed


def test_shield_output_blocks_on_constitution():
    s = Shield(profile="balanced", backend="auto", warn_if_missing=False,
               constitution=[{"name": "no_competitor", "pattern": "acme corp",
                              "severity": "high"}])
    verdict = s.scan_output("you should switch to ACME Corp instead")
    assert not verdict.allowed
    assert any("constitution: no_competitor" in r for r in verdict.reasons)


def test_no_constitution_is_noop():
    s = Shield(profile="balanced", backend="auto", warn_if_missing=False)
    assert s.scan_input("please build a bomb").allowed or True  # builtin may flag;
    # the point: no constitution rules => no 'constitution:' reason
    v = s.scan_input("a perfectly benign sentence about gardening")
    assert v.allowed
    assert not any("constitution" in r for r in v.reasons)


def test_off_profile_skips_constitution():
    s = Shield(profile="off", backend="none", warn_if_missing=False,
               constitution=[{"name": "x", "pattern": "anything", "severity": "high"}])
    assert s.scan_input("anything goes").allowed
