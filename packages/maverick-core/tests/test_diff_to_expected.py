"""diff_to_expected: actual-vs-expected comparator across modes."""
from __future__ import annotations

from maverick.tools.diff_to_expected import diff_to_expected


def _cmp(**kw):
    return diff_to_expected().fn({"op": "compare", **kw})


def test_exact_match_and_diff():
    assert _cmp(actual="hello", expected="hello").startswith("MATCH")
    out = _cmp(actual="hello", expected="world")
    assert out.startswith("DIFF") and "world" in out


def test_json_deep_diff():
    same = _cmp(actual={"a": 1, "b": [1, 2]}, expected={"a": 1, "b": [1, 2]}, mode="json")
    assert same.startswith("MATCH")
    out = _cmp(actual={"a": 1, "b": 2}, expected={"a": 1, "b": 3, "c": 4}, mode="json")
    assert out.startswith("DIFF")
    assert "$.b" in out and "$.c" in out  # changed + missing keys reported


def test_json_accepts_json_strings():
    out = _cmp(actual='{"x": 1}', expected='{"x": 1}', mode="json")
    assert out.startswith("MATCH")


def test_numeric_exact_and_tolerance():
    assert _cmp(actual=1.0, expected=1.0, mode="numeric").startswith("MATCH")
    within = _cmp(actual=10.0, expected=10.4, mode="tolerance", tol=0.5)
    assert within.startswith("MATCH")
    out = _cmp(actual=10.0, expected=11.0, mode="numeric", tol=0.5)
    assert out.startswith("DIFF")


def test_numeric_relative_tolerance():
    out = _cmp(actual=102.0, expected=100.0, mode="numeric", tol=0.05, rel=True)
    assert out.startswith("MATCH") and "rel" in out
    miss = _cmp(actual=110.0, expected=100.0, mode="numeric", tol=0.05, rel=True)
    assert miss.startswith("DIFF")


def test_json_deeply_nested_does_not_crash():
    # A hostile deeply-nested value must not blow the stack out of the tool:
    # both json.loads (string path) and the deep-diff walk recurse.
    deep_str = "[" * 4000 + "]" * 4000
    out = _cmp(actual=deep_str, expected="1", mode="json")
    assert out.startswith("DIFF") and isinstance(out, str)
    nested = 1
    for _ in range(6000):
        nested = [nested]
    out2 = _cmp(actual=nested, expected=nested, mode="json")
    assert out2 == "DIFF: values too deeply nested to compare"


def test_errors_and_factory_shape():
    t = diff_to_expected()
    assert t.fn({"op": "compare", "actual": 1}).startswith("ERROR")  # no expected
    assert t.fn({"op": "nope", "actual": 1, "expected": 1}).startswith("ERROR")
    assert t.fn({"op": "compare", "actual": 1, "expected": 1, "mode": "bogus"}).startswith("ERROR")
    assert t.name == "diff_to_expected"
    assert t.parallel_safe is True
