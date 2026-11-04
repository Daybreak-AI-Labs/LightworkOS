"""Regression tests for two robustness defects found by the 1M stress sweep.

Both were "wrong exception type / crash on malformed input": a function that
should return a value or raise a documented error type instead leaked an
AttributeError on adversarial/None input.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.money_format import format_money
from maverick.skills import Skill

# --- Skill.parse: a list item under a scalar key must raise ValueError, not
#     AttributeError (skill markdown can be untrusted; callers guard with
#     ``except ValueError``). -------------------------------------------------

@pytest.mark.parametrize("text", [
    "---\nname: foo\n  - bar\n---\nbody",
    "---\ntriggers: scalar\n  - item\n---\nbody",
    "---\ndescription: a\n  - b\n  - c\n---\nbody",
])
def test_skill_parse_list_under_scalar_raises_valueerror(text):
    with pytest.raises(ValueError):
        Skill.parse(text, Path("x.md"))


def test_skill_parse_valid_list_frontmatter_still_works():
    s = Skill.parse(
        "---\nname: ok\ntriggers:\n  - a\n  - b\ntools_needed:\n  - read_file\n---\nbody",
        Path("ok.md"))
    assert s.name == "ok"
    assert s.triggers == ["a", "b"]
    assert s.tools_needed == ["read_file"]


def test_all_builtin_skills_still_validate():
    from maverick.skills import BUILTIN_SKILLS_DIR, validate_skill_file
    bad = [p.name for p in BUILTIN_SKILLS_DIR.glob("*.md")
           if not validate_skill_file(p).ok]
    assert not bad, f"the parse hardening must not reject real skills: {bad[:10]}"


# --- format_money: a None/empty currency degrades like an unknown one
#     (matching the locale path), never crashes on None.upper(). -------------

def test_format_money_none_currency_degrades_not_crashes():
    assert format_money(100, currency=None) == "$100.00"
    assert format_money(100, currency="") == "$100.00"


def test_format_money_known_and_unknown_currencies_unchanged():
    assert format_money(100, currency="USD") == "$100.00"
    assert format_money(100, currency="EUR") == "€100.00"
    # an unknown code degrades to a generic "CODE " prefix
    assert format_money(100, currency="XyZ").startswith("XYZ ")


def test_format_money_none_locale_already_graceful():
    # the sibling behavior the currency fix now matches
    assert format_money(100, locale=None) == "$100.00"
