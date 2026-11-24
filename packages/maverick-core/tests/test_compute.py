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


def test_rounding_floor_and_ceiling_work_out_money(monkeypatch):
    # Live: raising a price list 6% "rounded to the nearest $0.25", the agent's
    # "round((18.50*1.06)/0.25)*0.25" and "floor(...)" were refused as
    # "function not allowed"; it rounded by hand and got 3 of 5 prices wrong.
    from maverick.tools.compute import compute

    cases = {"round((18.50*1.06)/0.25)*0.25": 19.5, "round(64*1.06/0.25)*0.25": 67.75,
             "round(2.5)": 3.0, "round(-2.5)": -3.0, "round(17.755, 2)": 17.76, "round(1234.5678, -2)": 1200.0,
             "floor(19.61)": 19.0, "ceil(19.61)": 20.0, "ceiling(-1.5)": -1.0}
    import sys as _sys

    for use_sympy in ((True, False) if _HAS_SYMPY else (False,)):
        if not use_sympy:
            monkeypatch.setitem(_sys.modules, "sympy", None)
        for expr, expected in cases.items():
            out = compute().fn({"op": "evaluate", "expr": expr})
            assert round(float(out), 9) == expected, (use_sympy, expr, out)
        # The digits are bounded, so a rounding cannot build a huge number.
        assert "ERROR" in compute().fn({"op": "evaluate", "expr": "round(2.5, 10**6)"})
        assert "ERROR" in compute().fn({"op": "evaluate", "expr": "round(2.5, 100)"})


@pytest.mark.parametrize("sympy_missing", [False, True])
def test_dates_work_out_with_sqlite_date_functions(monkeypatch, sympy_missing):
    # Live: a lease's renewal-notice deadline (180 days before March 31,
    # 2030) was refused as "disallowed characters", worked out by hand as
    # October 3, and accepted; October 2 is the last day.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    run = compute().fn
    assert run({"op": "evaluate", "expr": "date('2030-03-31', '-180 days')"}) == "2029-10-02"
    assert run({"op": "evaluate", "expr": "julianday('2030-03-31') - julianday('2029-10-02')"}) == "180"
    assert run({"op": "evaluate", "expr": "date('2025-04-01', '+60 months', '-1 day')"}) == "2030-03-31"
    assert run({"op": "evaluate", "expr": "strftime('%w', '2029-10-02')"}) == "2"


def test_a_date_expression_that_cannot_run_says_how_to_write_one():
    from maverick.tools.compute import compute
    run = compute().fn
    out = run({"op": "evaluate", "expr": "date('2030-03-31') - 180 days"})
    assert out.startswith("ERROR") and "date('2030-03-31', '-180 days')" not in out
    assert "'-180 days'" in out or "'-30 days'" in out
    assert run({"op": "evaluate", "expr": "date('03/31/2030', '-1 day')"}).startswith("ERROR")


@pytest.mark.parametrize("expr", [
    "date('2026-01-01') FROM sqlite_master",
    "(SELECT name FROM sqlite_master)",
    "date('2026-01-01'); SELECT 1",
    "load_extension('x') || date('2026-01-01')",
    "(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT max(x) FROM c) + julianday('2026-01-01')",
])
def test_a_date_expression_cannot_reach_beyond_its_functions(expr):
    from maverick.tools.compute import compute
    assert compute().fn({"op": "evaluate", "expr": expr}).startswith("ERROR")


@pytest.mark.parametrize("expr", [
    "date('2030-03-31') - 180 days",
    "date('2030-03-31') - 180",
    "180 + date('2030-03-31', '+1 day')",
    "julianday('2030-03-31') AS days",
])
def test_a_date_expression_is_never_read_as_a_number_it_does_not_mean(expr):
    # SQLite reads "date('2030-03-31') - 180 days" as 2030 - 180 named
    # "days" and answers 1850.
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "1850" not in out, out
