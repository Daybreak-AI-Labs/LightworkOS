"""Tests for the what_changed_digest tool (maverick.tools.what_changed_digest)."""
from __future__ import annotations

from maverick.tools.what_changed_digest import what_changed_digest

# ---- what_changed_digest ----

def test_digest_added_removed_changed():
    t = what_changed_digest()
    out = t.fn({"before": {"a": 1, "b": 2, "c": 3}, "after": {"a": 1, "b": 5, "d": 9}})
    assert "1 added, 1 removed, 1 changed" in out
    assert "+ d = 9" in out and "- c (was 3)" in out and "~ b: 2 -> 5" in out


def test_digest_numeric_delta_and_nochange():
    t = what_changed_digest()
    out = t.fn({"before": {"cost": 10.0}, "after": {"cost": 12.5}, "numeric_delta": True})
    assert "~ cost: 10 -> 12.5  (+2.5)" in out
    assert t.fn({"before": {"a": 1}, "after": {"a": 1}}) == "no changes"


def test_digest_validation():
    t = what_changed_digest()
    assert t.fn({"before": [], "after": {}}).startswith("ERROR")
