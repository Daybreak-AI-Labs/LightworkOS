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


def test_constrained_backtracking_pattern_refused_before_matching(monkeypatch):
    import maverick.tools.constrained_output as co
    t = constrained_output()
    calls: list = []
    monkeypatch.setattr(co.re, "search", lambda *a: calls.append(a))
    # (a+)+$ on "a"*40 + "b" backtracks for about a day; it is refused unrun.
    # The refusal is about the schema, not the value. (a?){25}a{25} counts the
    # optional inside a large bounded repeat.
    for pat in ("(a+)+$", "(a|a)*$", "^(a?){25}a{25}$"):
        out = t.fn({"value": "a" * 40 + "b", "schema": {"pattern": pat}})
        assert out.startswith("ERROR: schema pattern") and "refused" in out, pat
    out = t.fn({"value": "a" * 5000, "schema": {"pattern": "^a+$"}})
    assert out.startswith("FAIL") and calls == []


def test_constrained_linear_patterns_are_evaluated():
    t = constrained_output()
    for pat, good, bad in (
        (r"^(\d+\.){2}\d+$", "1.2.3", "1.2"),
        (r"^(\d{1,3}\.){3}\d{1,3}$", "10.0.0.1", "10.0.0"),
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
