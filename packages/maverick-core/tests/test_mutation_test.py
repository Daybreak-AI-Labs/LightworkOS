"""mutation_test: Python source mutant generator + malformed-arg robustness."""
from __future__ import annotations

from maverick.tools.mutation_test import mutation_test


def _fn():
    return mutation_test().fn


def test_basic_mutants():
    out = _fn()({"op": "mutants", "source": "x = a + b\n"})
    assert isinstance(out, str)
    assert not out.startswith("Traceback")


def test_non_string_source_does_not_crash():
    # Non-string source is coerced to str; must return a string, never raise.
    fn = _fn()
    for v in (5, 1.5, True, [1, 2, 3], {"a": 1}):
        out = fn({"op": "mutants", "source": v})
        assert isinstance(out, str)
        assert not out.startswith("Traceback")


def test_infinite_max_does_not_crash():
    out = _fn()({"op": "mutants", "source": "x = a + b\n", "max": float("inf")})
    assert isinstance(out, str)
    assert not out.startswith("Traceback")


# ---- mutation_test ----

def test_mutants_cover_operators():
    t = mutation_test()
    src = "def f(a, b):\n    return a + b > 0 and b\n"
    out = t.fn({"op": "mutants", "source": src})
    assert "arithmetic: '+' -> '-'" in out
    assert "comparison: '>' -> '>='" in out
    assert "boolean: 'and' -> 'or'" in out
    assert "number: 0 -> 1" in out


def test_mutants_cap_and_empty():
    t = mutation_test()
    assert t.fn({"op": "mutants", "source": "x = 1 + 2 + 3 + 4", "max": 2}).startswith("2 mutant")
    assert "no mutants" in t.fn({"op": "mutants", "source": "x = 'hello'"})


def test_mutants_syntax_error():
    t = mutation_test()
    assert t.fn({"op": "mutants", "source": "def ("}).startswith("ERROR")
