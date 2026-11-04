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
