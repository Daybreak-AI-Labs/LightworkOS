"""Tests for the constrained_output tool (maverick.tools.constrained_output)."""
from __future__ import annotations

from maverick.tools.constrained_output import constrained_output

# ---- constrained_output ----

def test_constrained_type_coercion_and_range():
    t = constrained_output()
    assert t.fn({"value": "42", "schema": {"type": "integer"}}) == "PASS 42"
    assert t.fn({"value": "5", "schema": {"type": "integer", "maximum": 3}}).startswith("FAIL")
    assert t.fn({"value": "yes", "schema": {"type": "boolean"}}) == "PASS True"


def test_constrained_non_finite_integer_fails_cleanly():
    # float("inf")/float("-inf") raise OverflowError (not ValueError) from
    # int(); _coerce must catch it and FAIL cleanly rather than leak an
    # exception traceback through the broad _run guard.
    from maverick.tools.constrained_output import _coerce

    t = constrained_output()
    for v in (float("inf"), float("-inf")):
        ok, _, _ = _coerce(v, "integer")
        assert ok is False
        out = t.fn({"value": v, "schema": {"type": "integer"}})
        assert out.startswith("FAIL: ")
        assert "is not an integer" in out
        assert "OverflowError" not in out
    # nan already failed via ValueError; keep it covered too.
    assert t.fn({"value": float("nan"), "schema": {"type": "integer"}}).startswith("FAIL")


def test_constrained_enum_and_pattern():
    t = constrained_output()
    assert t.fn({"value": "red", "schema": {"enum": ["red", "green"]}}) == "PASS 'red'"
    assert t.fn({"value": "blue", "schema": {"enum": ["red", "green"]}}).startswith("FAIL")
    ok = t.fn({"value": "a@b.com", "schema": {"type": "string", "pattern": r"^[^@]+@[^@]+$"}})
    assert ok.startswith("PASS")
    assert t.fn({"value": "nope", "schema": {"type": "string", "pattern": r"^\d+$"}}).startswith("FAIL")


def test_constrained_length_and_errors():
    t = constrained_output()
    assert t.fn({"value": "ab", "schema": {"type": "string", "min_length": 3}}).startswith("FAIL")
    assert t.fn({"schema": {"type": "string"}}).startswith("ERROR")  # missing value
    assert t.fn({"value": "x", "schema": {}}).startswith("ERROR")    # empty schema


# Patterns that backtrack for seconds or longer on the paired value. Shape
# checks missed every one of these; the time limit catches them all.
_HANGING = [
    ("^(a|a){30}$", "a" * 30 + "b"),
    ("^(a|a){1,30}$", "a" * 30 + "b"),
    ("^((a?){10}){10}a{100}$", "a" * 100),
    ("^([!-~]+,)+$", "," * 40 + "a "),
    (r"^([\x2c-\x2e]+,)+$", "," * 40 + "a "),
    ("^" + "a?" * 30 + "a" * 30 + "$", "a" * 30),
    ("^(.*a){10}!$", "a" * 40),
    ("^.*a.*a.*a.*a.*!$", "a" * 1000),
]


def test_constrained_slow_patterns_are_a_schema_error(monkeypatch):
    import maverick.tools.constrained_output as co
    monkeypatch.setattr(co, "_PATTERN_TIMEOUT_S", 0.3)
    t = constrained_output()
    for pat, value in _HANGING:
        out = t.fn({"value": value, "schema": {"pattern": pat}})
        assert out.startswith("ERROR: schema pattern") and "too long to evaluate" in out, pat
    out = t.fn({"value": "x", "schema": {"pattern": "[unterminated"}})
    assert out.startswith("ERROR: schema pattern") and "invalid" in out
    out = t.fn({"value": "a" * 5000, "schema": {"pattern": "^a+$"}})
    assert out.startswith("FAIL")


_SEMVER = (r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
           r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
           r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
           r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$")


def test_constrained_ordinary_patterns_are_evaluated():
    t = constrained_output()
    for pat, good, bad in (
        (r"^[a-z]+(-[a-z]+)*$", "kebab-case-name", "Kebab--x"),
        (_SEMVER, "1.2.3-rc.1+build.5", "01.2.3"),
        (r"^[A-Z][a-z]+( [A-Z][a-z]+)*$", "New York City", "new York"),
        (r"^(\w+\s)*\w+$", "three plain words", "trailing space "),
        (r"^(\d+\.){2}\d+$", "1.2.3", "1.2"),
        (r"^(\d{1,3}\.){3}\d{1,3}$", "10.0.0.1", "10.0.0"),
        (r"^\d{4}-\d{2}-\d{2}$", "2026-11-14", "2026-11-1"),
        (r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
         "123e4567-e89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456"),
        (r"^[\w.+-]+@([\w-]+\.)+\w{2,}$", "a.b+c@mail.example.org", "a@b"),
        (r"^(foo|bar)+$", "foobarfoo", "foobaz"),
    ):
        assert t.fn({"value": good, "schema": {"pattern": pat}}).startswith("PASS"), pat
        assert t.fn({"value": bad, "schema": {"pattern": pat}}).startswith("FAIL"), pat


def test_constrained_fail_open_values_now_fail():
    t = constrained_output()
    assert t.fn({"value": "nan", "schema": {"type": "number", "maximum": 10}}).startswith("FAIL")
    assert t.fn({"value": 3.9, "schema": {"type": "integer", "maximum": 3}}).startswith("FAIL")
    assert t.fn({"value": "ed,g", "schema": {"enum": "red,green"}}).startswith("FAIL")
