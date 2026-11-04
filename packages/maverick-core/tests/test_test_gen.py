"""Tests for the test_gen tool (maverick.tools.test_gen)."""
from __future__ import annotations

from maverick.tools.test_gen import test_gen as make_test_gen

# ---- test_gen ----

def test_test_gen_infers_strategies_from_hints():
    t = make_test_gen()
    src = "def add(a: int, b: str) -> int:\n    return a\n"
    out = t.fn({"op": "hypothesis", "source": src})
    assert "from hypothesis import given, strategies as st" in out
    assert "a=st.integers()" in out
    assert "b=st.text()" in out
    assert "def test_add_properties(a, b):" in out
    assert "add(a=a, b=b)" in out


def test_test_gen_named_func_and_no_params():
    t = make_test_gen()
    src = "def first():\n    return 1\n\ndef second(x: bool):\n    return x\n"
    out = t.fn({"op": "hypothesis", "source": src, "func": "second"})
    assert "x=st.booleans()" in out and "test_second_properties" in out
    out2 = t.fn({"op": "hypothesis", "source": src, "func": "first"})
    assert "no params to fuzz" in out2 and "test_first_properties()" in out2


def test_test_gen_errors():
    t = make_test_gen()
    assert t.fn({"op": "hypothesis", "source": ""}).startswith("ERROR")
    assert t.fn({"op": "hypothesis", "source": "x = 1"}).startswith("ERROR")
