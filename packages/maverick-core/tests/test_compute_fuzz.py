"""Regression: compute must not crash on non-string model-supplied args."""
from __future__ import annotations

from maverick.tools.compute import compute


def _fn():
    return compute().fn


def test_evaluate_non_string_expr():
    # Non-string expr is coerced to str; must return a string, never raise.
    fn = _fn()
    for v in (5, 1.5, True, [1, 2, 3], {"a": 1}):
        out = fn({"op": "evaluate", "expr": v})
        assert isinstance(out, str)


def test_solve_non_string_equation_and_var():
    fn = _fn()
    out = fn({"op": "solve", "equation": 5, "var": 7})
    assert isinstance(out, str)
