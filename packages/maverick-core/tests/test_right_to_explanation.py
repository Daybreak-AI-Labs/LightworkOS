"""right_to_explanation: ranked decision explanation + rectification audit."""
from __future__ import annotations

from maverick.tools.right_to_explanation import right_to_explanation


def _explain(decision, factors):
    return right_to_explanation().fn(
        {"op": "explain", "decision": decision, "factors": factors}
    )


def _rectify(record, corrections):
    return right_to_explanation().fn(
        {"op": "rectify", "record": record, "corrections": corrections}
    )


def test_explain_ranks_by_absolute_weight():
    out = _explain("loan denied", [
        {"name": "income", "weight": 0.2, "value": 50000},
        {"name": "debt_ratio", "weight": -0.9, "value": 0.7},
        {"name": "history", "weight": 0.5, "value": "good"},
    ])
    # Highest absolute weight first: debt_ratio (0.9) > history (0.5) > income (0.2).
    assert out.index("debt_ratio") < out.index("history") < out.index("income")
    assert "1. debt_ratio" in out


def test_explain_direction_words():
    out = _explain("approved", [
        {"name": "score", "weight": 1.0},
        {"name": "flags", "weight": -1.0},
    ])
    assert "increased the outcome" in out
    assert "decreased the outcome" in out


def test_explain_includes_value_when_present():
    out = _explain("d", [{"name": "age", "weight": 0.3, "value": 42}])
    assert "(value=42)" in out


def test_rectify_records_changes():
    out = _rectify({"name": "Alise", "age": 30}, {"name": "Alice"})
    assert "corrected record:" in out
    assert "- name: 'Alice'" in out
    assert "audit note:" in out
    assert "name: 'Alise' -> 'Alice'" in out
    # untouched field stays.
    assert "- age: 30" in out


def test_rectify_noop_when_value_matches():
    out = _rectify({"name": "Alice"}, {"name": "Alice"})
    assert "no fields changed" in out


def test_rectify_adds_absent_field():
    out = _rectify({"name": "Bob"}, {"email": "bob@x.io"})
    assert "email: '<absent>' -> 'bob@x.io'" in out


def test_errors():
    t = right_to_explanation()
    assert t.fn({"op": "explain", "factors": []}).startswith("ERROR")  # no decision
    assert t.fn({"op": "explain", "decision": "d", "factors": []}).startswith("ERROR")
    assert t.fn({"op": "explain", "decision": "d",
                 "factors": [{"name": "x", "weight": "nan-ish"}]}).startswith("ERROR")
    assert t.fn({"op": "rectify", "record": {}, "corrections": {}}).startswith("ERROR")
    assert t.fn({"op": "nope"}).startswith("ERROR")
