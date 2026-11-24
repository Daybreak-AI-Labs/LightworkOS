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


@pytest.mark.parametrize("sympy_missing", [False, True])
def test_arithmetic_beside_a_date_call_keeps_true_division_and_money_rounding(monkeypatch, sympy_missing):
    # Prorated rent written as the daily rate times the days came back 768
    # instead of 774.19: SQLite ran the whole expression, divided 1500 by 31
    # as whole numbers and rounded 2.675 down to 2.67.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    elif not _HAS_SYMPY:
        pytest.skip("sympy not installed")
    from maverick.tools.compute import compute
    run = compute().fn
    cases = {
        "1500/31 * (julianday('2026-03-31') - julianday('2026-03-15'))": ("774.193548387096774193548387097", 1500 / 31 * 16),
        "(unixepoch('2026-01-01 17:30') - unixepoch('2026-01-01 08:45')) / 3600": ("8.75", 8.75),
        "7/2 + julianday('2026-01-02') - julianday('2026-01-01')": ("4.5", 4.5),
        "round(2.675, 2) + 0*julianday('2026-01-01')": ("2.68", 2.68),
        "round(1.005, 2) + 0*julianday('2026-01-01')": ("1.01", 1.01),
        "round(41.175 * (julianday('2026-01-02') - julianday('2026-01-01')), 2)": ("41.18", 41.18),
    }
    for expr, (exact, approx) in cases.items():
        out = run({"op": "evaluate", "expr": expr})
        if sympy_missing:
            assert round(float(out), 9) == round(approx, 9), (expr, out)
        else:
            assert out == exact, (expr, out)


@pytest.mark.parametrize("expr", [
    "julianday(2026-03-01) - julianday(2026-01-31)",
    "julianday(2030-03-31) - julianday(2029-10-02)",
    "date(2030-03-31, '-180 days')",
    "date(2030-03-31)",
    "strftime('%w', 2029-10-02)",
    "julianday(date(2030-03-31))",
    "date(1767225600 + 86400, 'unixepoch')",
])
def test_an_unquoted_date_is_refused_not_read_as_arithmetic(expr):
    # SQLite reads julianday(2026-03-01) as julianday(2022), a day in 4708 BC:
    # the gap to an unquoted January 31 came back 28 days instead of 29.
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "in quotes" in out, out


def test_a_quoted_date_inside_another_date_call_still_works():
    from maverick.tools.compute import compute
    run = compute().fn
    assert run({"op": "evaluate", "expr": "julianday('2026-03-01') - julianday('2026-01-31')"}) == "29"
    assert run({"op": "evaluate",
                "expr": "julianday(date('2026-01-31', '+1 month')) - julianday('2026-01-31')"}) == "31"
    assert run({"op": "evaluate", "expr": "DATE ( '2030-03-31' , '-180 days' )"}) == "2029-10-02"


@pytest.mark.parametrize("expr", [
    "length(randomblob(100000000)) + julianday('2026-01-01')",
    "coalesce(zeroblob(10000000), date('2026-01-01'))",
    "printf('%5000000d', julianday('2026-01-01'))",
    "julianday(randomblob(10))",
    "date(zeroblob(1000))",
    "strftime('" + "%J" * 450 + "', '2026-01-01')",
])
def test_a_date_call_cannot_allocate_or_build_huge_text(expr):
    # A short expression made SQLite allocate a gigabyte in the agent's own
    # process (randomblob, zeroblob, printf): its time limit never fires
    # inside a single function call.
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and len(out) < 5000, out[:200]


@pytest.mark.parametrize("expr", [
    "(date('2030-03-31')) - 180",
    "round(date('2030-03-31')) - 180",
    "abs(date('2030-03-31')) - 180",
    "max(date('2030-03-31')) - 180",
    "date('2030-03-31') || '' - 180",
    "/* ' */ date('2030-03-31') - 180 /* ' */",
    "/*'*/ CAST(date('2030-03-31') AS INTEGER) - 180 /*'*/",
    "date('2030-03-31') -- '\n - 180",
    "julianday('2030-03-31') - '2029-10-02'",
])
def test_date_text_cannot_be_slipped_into_arithmetic(expr):
    # Wrapping the date text, or hiding a quote in a comment, got past the
    # check on the call's own neighbours, and SQLite answered 1850 again.
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "1850" not in out and "2460562.5" not in out, out


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize(("expr", "expected"), [
    ("(julianday('2026-01-01 17:30') - julianday('2026-01-01 08:45')) * 24", "8.75"),
    ("(julianday('2026-01-01 17:30') - julianday('2026-01-01 08:45')) * 24 * 60", "525"),
    ("(julianday('2026-01-01 10:00') - julianday('2026-01-01 08:00')) * 24 * 60", "120"),
    ("(julianday('2026-01-01 10:00') - julianday('2026-01-01 08:00')) * 24", "2"),
    ("(unixepoch('2026-01-01 17:30:00.250', 'subsec') - unixepoch('2026-01-01 17:30')) * 4", "1"),
    ("0.1 + julianday('2026-01-02') - julianday('2026-01-01')", "1.1"),
    ("julianday('now') - julianday('now')", "0"),
])
def test_hours_between_two_times_come_out_exact(monkeypatch, sympy_missing, expr, expected):
    # julianday() hands back a float of days off by about 5e-10, and hours
    # worked came back 8.749999993 instead of 8.75. Without SymPy the exact
    # figures went back into float arithmetic near 2.46e6 days and came out
    # 8.74999999254942.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    elif not _HAS_SYMPY:
        pytest.skip("sympy not installed")
    from maverick.tools.compute import compute
    assert compute().fn({"op": "evaluate", "expr": expr}) == expected


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize("expr", [
    "strftime('%Y%m%d', '2026-03-01') - strftime('%Y%m%d', '2026-01-31')",
    "strftime('%H.%M', '2026-01-01 17:30') - strftime('%H.%M', '2026-01-01 08:45')",
    "strftime('%Y', '2030-03-31') - 180",
    "(strftime('%J', '2026-01-01 17:30') - strftime('%J', '2026-01-01 08:45')) * 24",
    "strftime('%w', '2029-10-02') + 0",
])
def test_strftime_text_is_never_read_as_a_figure(monkeypatch, sympy_missing, expr):
    # strftime() text that looked like a number went into the arithmetic: a
    # days-between attempt on '%Y%m%d' came back 170 (the gap is 29), hours
    # from '%H.%M' came back 8.85 (it is 8.75), and '%Y' - 180 came back 1850.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "date text cannot be added to" in out, out
    assert "julianday('2026-03-01') - julianday('2026-01-31')" in out, out


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize(("expr", "expected"), [
    ("(date('2026-01-31', '+30 days'))", "2026-03-02"),
    ("max(date('2026-02-15'), date('2026-03-01'))", "2026-03-01"),
    ("min(date('2026-02-15'), date('2026-03-01'))", "2026-02-15"),
    ("MAX(date('2026-02-15'), (date('2026-03-01')), date('2026-01-31', '+20 days'))", "2026-03-01"),
    ("date('2026-01-31', '+30 days'), date('2026-01-31', '+60 days')", "2026-03-02, 2026-04-01"),
    ("julianday('2026-03-01')\n - julianday('2026-01-31')", "29"),
    ("julianday('2026-03-01') -\r julianday('2026-01-31')", "29"),
    ("date(1767225600, 'unixepoch')", "2026-01-01"),
    ("datetime(1767225600, 'unixepoch')", "2026-01-01 00:00:00"),
    ("date(2461100.5)", "2026-03-01"),
    ('date("2026-01-31")', "2026-01-31"),
    ("date(('2026-01-31'))", "2026-01-31"),
    ("julianday('2026-03-01') - julianday('2026-01-31'), julianday('2026-04-01') - julianday('2026-01-31')", "29, 60"),
])
def test_a_date_standing_alone_or_picked_still_works_out(monkeypatch, sympy_missing, expr, expected):
    # The later of two dates, a date in parentheses, a list of dates, an
    # expression over two lines and seconds since 1970 were all worked out
    # before date calls were split from the arithmetic, then refused.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    elif not _HAS_SYMPY:
        pytest.skip("sympy not installed")
    from maverick.tools.compute import compute
    assert compute().fn({"op": "evaluate", "expr": expr}) == expected


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize(("expr", "problem", "hidden"), [
    ("julianday('2026-03-01') - julianday('2026-01-31') days", "'days' is neither a function nor a figure", "4922201"),
    ("julianday('2026-03-01') - t", "'t' is neither a function nor a figure", "2461100.5"),
    ("length(randomblob(999999999)) + julianday('2026-01-01')", "length(randomblob(999999999)) + julianday", "4922083"),
    ("iif(julianday('2026-03-01') > julianday('2026-01-31'), 1, 0)", "compare dates by subtracting", "BooleanTrue"),
    ("julianday('2026-03-01') - julianday('2026-01-31') == 29", "compare dates by subtracting", "BooleanTrue"),
    ("max(date('2026-02-15'), julianday('2026-03-01'))", "date text cannot be added to", "2461100.5"),
])
def test_a_date_expression_that_cannot_run_quotes_what_the_agent_wrote(monkeypatch, sympy_missing, expr, problem, hidden):
    # The refusal quoted the figures put in place of the date calls, as
    # "cannot evaluate '(4922201/2) - (4922143/2) days': SyntaxError", and a
    # stray symbol came back as the answer "2461100.5 - t".
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    elif not _HAS_SYMPY:
        pytest.skip("sympy not installed")
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith(f"ERROR: cannot evaluate {expr!r}") and problem in out, out
    assert hidden not in out.split(f"{expr!r}", 1)[1] and "'-30 days'" in out, out


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize("expr", [
    "julianday(strftime('%Y', '2030-03-31')) - 180",
    "julianday(strftime('%H.%M', '2026-01-01 17:30')) - julianday(strftime('%H.%M', '2026-01-01 08:45'))",
    "julianday('2030') - 180",
    "julianday(2030) - 180",
    "unixepoch(strftime('%Y', '2030-03-31')) / 86400",
    "julianday('20300331') - julianday('20291002')",
    "date('17.30')",
])
def test_a_number_a_date_function_would_read_as_a_day_number_is_refused(monkeypatch, sympy_missing, expr):
    # Review: SQLite reads numeric text such as '2030' or '17.30' as a Julian
    # day number, so date text wrapped in julianday() still came back 1850
    # and 8.85 hours with no error.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "1850" not in out and "8.85" not in out, out
    assert "YYYY-MM-DD" in out, out


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize(("expr", "expected"), [
    ("ROUND((julianday('2026-01-01 17:30') - julianday('2026-01-01 08:45')) * 24, 2)", "8.75"),
    ("ROUND(JULIANDAY('2026-03-01') - JULIANDAY('2026-01-31'))", "29"),
    ("ABS(julianday('2026-01-31') - julianday('2026-03-01'))", "29"),
    ("MAX(julianday('2026-01-31'), julianday('2026-03-01')) - julianday('2026-01-01')", "59"),
    ("Round(julianday('2026-03-01') - julianday('2026-01-31'), 0)", "29"),
    ("julianday(datetime('2026-03-01 08:00')) - julianday('2026-03-01')", "0.333333333333333"),
])
def test_wrappers_around_date_figures_read_in_any_case(monkeypatch, sympy_missing, expr, expected):
    # Review: SQLite once ran the whole expression and read ROUND, ABS and
    # MAX in any case; with only the date calls going to SQLite they were
    # refused as "function not allowed".
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    elif not _HAS_SYMPY:
        pytest.skip("sympy not installed")
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out[:len(expected)] == expected or round(float(out), 9) == round(float(expected), 9), out


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize("expr", [
    "max(℘℘℘℘℘7, date('2026-01-01'))",
    "℮℮℮℮℮3, date('2026-01-01')",
    "℘℘℘℘℘0, date('2026-01-01')",
    "max(℘, date('2026-01-01'))",
    "_date0, date('2026-01-01')",
])
def test_a_stray_name_beside_date_text_is_refused_not_read_as_the_date(monkeypatch, sympy_missing, expr):
    # Review: a name made of characters Python allows in identifiers but the
    # word scan skipped raised IndexError out of the tool, or was read as the
    # date standing beside it.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "2026-01-01, 2026-01-01" not in out, out


@pytest.mark.parametrize("sympy_missing", [False, True])
@pytest.mark.parametrize("expr", [
    "max(timediff('2026-03-01', '2026-01-31'), timediff('2026-01-31', '2026-03-01'))",
    "max(strftime('%s', '2030-03-31'), strftime('%s', '1999-01-01'))",
    "max(strftime('%m/%d/%Y', '2030-03-09'), strftime('%m/%d/%Y', '2029-12-10'))",
])
def test_max_and_min_pick_only_among_dates_written_year_first(monkeypatch, sympy_missing, expr):
    # Review: max() and min() compare the text, which is date order only for
    # YYYY-MM-DD; the later of 2030 and 1999 as seconds came back 1999's.
    import sys as _sys
    if sympy_missing:
        monkeypatch.setitem(_sys.modules, "sympy", None)
    from maverick.tools.compute import compute
    out = compute().fn({"op": "evaluate", "expr": expr})
    assert out.startswith("ERROR") and "YYYY-MM-DD" in out, out
