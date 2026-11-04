"""k_anonymity: k-anonymity / l-diversity de-identification checks."""
from __future__ import annotations

from maverick.tools.k_anonymity import k_anonymity


def _c(rows, qis, k, sensitive=None, l_min=None):
    args = {"op": "check", "rows": rows, "quasi_identifiers": qis, "k": k}
    if sensitive is not None:
        args["sensitive"] = sensitive
    if l_min is not None:
        args["l"] = l_min
    return k_anonymity().fn(args)


_ROWS = [
    {"age": 30, "zip": "1000", "cond": "flu"},
    {"age": 30, "zip": "1000", "cond": "cold"},
    {"age": 40, "zip": "2000", "cond": "flu"},
    {"age": 40, "zip": "2000", "cond": "flu"},
]


def test_pass_k2():
    out = _c(_ROWS, ["age", "zip"], 2)
    assert out.startswith("K-ANONYMITY PASS")
    assert "2 groups" in out and "min group size 2" in out


def test_fail_k3():
    out = _c(_ROWS, ["age", "zip"], 3)
    assert out.startswith("K-ANONYMITY FAIL")
    assert "2 of 2 groups below k=3" in out
    assert "{age=30, zip=1000} -> 2" in out


def test_singleton_group():
    rows = _ROWS + [{"age": 99, "zip": "9999", "cond": "x"}]
    out = _c(rows, ["age", "zip"], 2)
    assert out.startswith("K-ANONYMITY FAIL")
    assert "min group size 1" in out
    assert "{age=99, zip=9999} -> 1" in out


def test_l_diversity_pass():
    # group {30,1000} has flu+cold (2 distinct); {40,2000} has flu only (1)
    out = _c(_ROWS, ["age", "zip"], 2, sensitive="cond", l_min=2)
    assert "K-ANONYMITY PASS" in out
    assert "L-DIVERSITY FAIL" in out
    assert "{age=40, zip=2000} -> 1 distinct" in out


def test_l_diversity_all_pass():
    out = _c(_ROWS, ["age", "zip"], 2, sensitive="cond", l_min=1)
    assert "L-DIVERSITY PASS" in out


def test_missing_qi_value_grouped_as_absent():
    rows = [{"age": 30}, {"age": 30}, {"zip": "x"}]
    out = _c(rows, ["age", "zip"], 2)
    assert "zip=(absent)" in out or "age=(absent)" in out


def test_missing_qi_does_not_collide_with_literal_absent_string():
    rows = [{"age": 30}, {"age": 30, "zip": "(absent)"}]
    out = _c(rows, ["age", "zip"], 2)
    assert out.startswith("K-ANONYMITY FAIL")
    assert "2 of 2 groups below k=2" in out
    assert "min group size 1" in out


def test_qi_grouping_preserves_json_value_types():
    rows = [{"id": 1}, {"id": "1"}]
    out = _c(rows, ["id"], 2)
    assert out.startswith("K-ANONYMITY FAIL")
    assert "2 of 2 groups below k=2" in out
    assert "min group size 1" in out


def test_l_diversity_preserves_sensitive_value_types():
    rows = [{"group": "a", "cond": 1}, {"group": "a", "cond": "1"}]
    out = _c(rows, ["group"], 2, sensitive="cond", l_min=2)
    assert "K-ANONYMITY PASS" in out
    assert "L-DIVERSITY PASS" in out


def test_errors():
    t = k_anonymity()
    assert t.fn({"op": "check", "rows": [], "quasi_identifiers": ["a"], "k": 2}).startswith("ERROR")
    assert t.fn({"op": "check", "rows": [{"a": 1}], "quasi_identifiers": [], "k": 2}).startswith("ERROR")
    assert t.fn({"op": "check", "rows": [{"a": 1}], "quasi_identifiers": ["a"], "k": 0}).startswith("ERROR")
    assert t.fn({"op": "check", "rows": [{"a": 1}], "quasi_identifiers": ["a"], "k": "x"}).startswith("ERROR")
    # sensitive without l
    assert t.fn({"op": "check", "rows": [{"a": 1}], "quasi_identifiers": ["a"], "k": 1, "sensitive": "a"}).startswith("ERROR")
    assert t.fn({"op": "nope", "rows": [{"a": 1}], "quasi_identifiers": ["a"], "k": 1}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "k_anonymity" in names
