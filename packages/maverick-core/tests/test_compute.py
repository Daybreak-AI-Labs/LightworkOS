"""Tests for the compute tool (maverick.tools.compute)."""
from __future__ import annotations

import importlib.util

import pytest

# --- compute SymPy path must bound exponentiation ---

@pytest.mark.parametrize("expr", ["9**9**9**9", "2**1000000", "(10**100)**100"])
def test_compute_rejects_unbounded_pow(expr):
    from maverick.tools.compute import compute
    # Must return promptly with an error, not hang/OOM the worker.
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR")


def test_compute_allows_small_pow():
    from maverick.tools.compute import compute
    assert compute().fn({"op": "evaluate", "expr": "2**10"}).strip().startswith("1024")


# ---------- compute fallback: power-tower CPU/memory DoS ----------

def test_compute_fallback_blocks_power_tower(monkeypatch):
    import sys as _sys
    # Force the no-sympy fallback path.
    monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": "9**9**9"})
    assert "ERROR" in out  # blocked, not a 370M-digit hang
    ok = compute().fn({"op": "evaluate", "expr": "2**8"})
    assert "256" in ok


def test_compute_fallback_refuses_non_numeric_values(monkeypatch):
    import sys as _sys
    monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    # Strings, f-strings and generators let a short expression allocate
    # gigabytes; only numeric arithmetic is evaluated.
    for expr in ("'ab'*3", "f'{1:>100000000}'", "max(i for i in [0]*10)"):
        assert "ERROR" in compute().fn({"op": "evaluate", "expr": expr}), expr
    assert compute().fn({"op": "evaluate", "expr": "max(2, sqrt(16)) - 1"}).startswith("3")


# ---------- compute (sympy) ----------

_HAS_SYMPY = importlib.util.find_spec("sympy") is not None


def test_compute_evaluate_simple():
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": "2 + 3 * 4"})
    assert "14" in out


def test_compute_evaluate_with_pi_e():
    """Without sympy we still have math.pi via the fallback evaluator."""
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": "pi"})
    # 3.141... whether via sympy.N or math.pi.
    assert "3.14" in out


@pytest.mark.skipif(not _HAS_SYMPY, reason="sympy not installed")
def test_compute_simplify():
    from maverick.tools.compute import compute
    out = compute().fn({"op": "simplify", "expr": "(x**2 - 1)/(x - 1)"})
    assert "x" in out
    assert "+ 1" in out or "1 + x" in out


@pytest.mark.skipif(not _HAS_SYMPY, reason="sympy not installed")
def test_compute_solve_quadratic():
    from maverick.tools.compute import compute
    out = compute().fn({"op": "solve", "equation": "x**2 - 4 = 0", "var": "x"})
    assert "x ∈" in out
    assert "-2" in out and "2" in out


@pytest.mark.skipif(not _HAS_SYMPY, reason="sympy not installed")
def test_compute_diff():
    from maverick.tools.compute import compute
    out = compute().fn({"op": "diff", "expr": "x**3", "var": "x"})
    assert "3" in out and "x" in out


@pytest.mark.skipif(not _HAS_SYMPY, reason="sympy not installed")
def test_compute_sympy_rejects_arbitrary_code():
    from maverick.tools.compute import compute
    out = compute().fn({"op": "simplify", "expr": "__import__('os').system('id')"})
    assert "ERROR" in out


def test_compute_unknown_op_rejected():
    from maverick.tools.compute import compute
    out = compute().fn({"op": "factorial"})
    assert "unknown op" in out


def test_compute_evaluate_rejects_arbitrary_code():
    """The fallback evaluator must refuse imports / attribute access."""
    if _HAS_SYMPY:
        pytest.skip("sympy installed; tests the unsafe path explicitly")
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": "__import__('os')"})
    assert "ERROR" in out


def test_compute_symbolic_op_is_stopped_at_its_time_limit(monkeypatch):
    # sympy cannot be interrupted in a thread; a slow integral used to pin
    # the worker past the goal's wall-clock cap.
    import time

    pytest.importorskip("sympy")
    from maverick.tools import compute as module

    monkeypatch.setattr(module, "_SYMBOLIC_TIMEOUT", 3.0)
    started = time.monotonic()
    out = module.compute().fn({"op": "integrate", "var": "x",
                               "expr": "exp(sin(x))*sin(x)**3/(1+cos(x)**7)"})
    assert out.startswith("ERROR") and "did not finish" in out
    assert time.monotonic() - started < 20


@pytest.mark.parametrize("expr", [
    "85000*(0.075/12)/(1-(1+0.075/12)^(-60))",
    "85000*(0.075/12)/(1-(1+0.075/12)**(-60))",
    "85000*(0.075/12)/(1-(1+0.075/12)**-60)",
])
def test_a_loan_payment_formula_evaluates(expr):
    # Live: the standard loan formula failed six ways ("^" is XOR, and a
    # negative exponent was "not a constant"), so the agent worked the
    # payment out by hand and reported $1,700.56 instead of $1,703.23.
    from maverick.tools.compute import compute

    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("1703.2"), out


def test_the_exponent_bound_still_holds_for_caret_and_negative_powers():
    from maverick.tools.compute import compute

    tool = compute()
    for expr in ("2**(-1000)", "9^9^9", "2^1000000", "2**x"):
        assert tool.fn({"op": "evaluate", "expr": expr}).startswith("ERROR"), expr


def test_a_list_of_figures_evaluates_each_one(monkeypatch):
    # Live: pricing eight reorders in one call failed with "'Tuple' object has
    # no attribute 'evalf'", and the agent worked the figures out by hand.
    from maverick.tools.compute import compute

    expr = "(20-4)*23.21, (20-3)*4.17, 50*38.39"
    if _HAS_SYMPY:
        out = compute().fn({"op": "evaluate", "expr": expr})
        assert [round(float(x), 2) for x in out.split(",")] == [371.36, 70.89, 1919.5], out
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "sympy", None)
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert [round(float(x), 2) for x in out.split(",")] == [371.36, 70.89, 1919.5], out
    # A tuple anywhere but the top could be multiplied into gigabytes.
    for unsafe in ("(1, 2)*10**8", "max((1,)*10**9)", "1, (2, 3)"):
        assert "ERROR" in compute().fn({"op": "evaluate", "expr": unsafe}), unsafe


@pytest.mark.skipif(not _HAS_SYMPY, reason="sympy not installed")
def test_decimals_are_exact_and_unpadded():
    # 16*23.21 came back as 371.360000000000013642420526594.
    from maverick.tools.compute import compute

    assert compute().fn({"op": "evaluate", "expr": "16*23.21"}) == "371.36"
    assert compute().fn({"op": "evaluate", "expr": "0.1+0.2"}) == "0.3"
    assert compute().fn({"op": "evaluate", "expr": "1/3"}).startswith("0.33333333333333333")


def test_a_sum_of_a_list_adds_its_figures(monkeypatch):
    # Live: a bank reconciliation's "sum([4850.00,-1245.60, ...])" failed with
    # "expression contains disallowed characters"; the agent retyped the sum,
    # left two entries out and reported the wrong balance.
    from maverick.tools.compute import compute

    cases = {"sum([4850.00,-1245.60,2317.45])": 5921.85, "sum(1.5, 2.5, -1)": 3.0,
             "2*sum([1, 2]) + sum([])": 6.0, "sum([ 0.1 , 0.2 ])": 0.3}
    import sys as _sys

    for use_sympy in ((True, False) if _HAS_SYMPY else (False,)):
        if not use_sympy:
            monkeypatch.setitem(_sys.modules, "sympy", None)
        for expr, expected in cases.items():
            out = compute().fn({"op": "evaluate", "expr": expr})
            assert round(float(out), 9) == expected, (expr, out)
    # Only a flat list of figures: anything else is still refused.
    for unsafe in ("sum([[1]*10**9])", "sum([1]*10**9)", "sum([x for x in (1,)])"):
        assert "ERROR" in compute().fn({"op": "evaluate", "expr": unsafe}), unsafe
