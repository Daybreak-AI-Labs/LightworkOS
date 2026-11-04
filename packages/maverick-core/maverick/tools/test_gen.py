"""Property-test generator tool.

Given a Python function's source, emit a `Hypothesis` property-test skeleton:
strategies are inferred from the parameter type hints, and the body asserts the
function doesn't raise on valid input (a "doesn't crash" property) plus a
TODO for the real invariant. It writes the *scaffold* a human/agent then fills
in — the tedious part (imports, `@given`, strategy wiring) done for you.

ops:
  - hypothesis(source[, func])  — generate the test for ``func`` (or the first
                                  top-level def) found in ``source``.

Pure ``ast`` on the provided source; no import execution, no network.
"""
from __future__ import annotations

import ast
from typing import Any

from . import Tool

# This is a production tool module, not a pytest module.  Its public factory
# keeps the registry name ``test_gen`` without being collected as a test.
__test__ = False

# Map a type-hint name to a Hypothesis strategy expression.
_STRATEGY = {
    "int": "st.integers()",
    "float": "st.floats(allow_nan=False, allow_infinity=False)",
    "str": "st.text()",
    "bool": "st.booleans()",
    "bytes": "st.binary()",
    "list": "st.lists(st.integers())",
    "dict": "st.dictionaries(st.text(), st.integers())",
    "set": "st.sets(st.integers())",
    "tuple": "st.tuples(st.integers(), st.integers())",
}


def _ann_name(ann: ast.expr | None) -> str | None:
    if ann is None:
        return None
    if isinstance(ann, ast.Name):
        return ann.id
    if isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
        return ann.value.id  # list[int] -> "list"
    return None


def _strategy_for(ann: ast.expr | None) -> str:
    name = _ann_name(ann)
    if name is None:
        return "st.integers()  # TODO: no type hint; pick a strategy"
    if name in _STRATEGY:
        return _STRATEGY[name]
    return f"st.builds({name})  # TODO: verify strategy for {name}"


def _find_func(source: str, want: str) -> ast.FunctionDef | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    if want:
        return next((f for f in funcs if f.name == want), None)
    return funcs[0] if funcs else None


def _generate(func: ast.FunctionDef) -> str:
    params = [
        a for a in func.args.args
        if a.arg not in ("self", "cls")
    ]
    given_args = []
    call_args = []
    for a in params:
        given_args.append(f"    {a.arg}={_strategy_for(a.annotation)},")
        call_args.append(f"{a.arg}={a.arg}")
    given_block = "\n".join(given_args)
    sig = ", ".join(a.arg for a in params)
    call = f"{func.name}({', '.join(call_args)})"
    body_sig = f"def test_{func.name}_properties({sig}):" if params else \
        f"def test_{func.name}_properties():"
    given_decorator = f"@given(\n{given_block}\n)" if params else "# no params to fuzz"
    return (
        "import pytest\n"
        "from hypothesis import given, strategies as st\n\n"
        f"# Property test scaffold for `{func.name}` — fill in the real invariant,\n"
        f"# then DELETE the pytest.skip line so this test actually runs. Until then\n"
        f"# it SKIPS (it must not pass on the tautology below and inflate coverage).\n"
        f"{given_decorator}\n"
        f"{body_sig}\n"
        f'    pytest.skip("TODO: replace the tautological assertion with the real property")\n'
        f"    result = {call}\n"
        f"    # Smoke property: the function returns without raising on valid input.\n"
        f"    assert result is not None or result is None  # TODO: assert the real property\n"
    )


def _run(args: dict[str, Any]) -> str:
    op = args.get("op", "hypothesis")
    if op != "hypothesis":
        return f"ERROR: unknown op {op!r}"
    source = args.get("source") or ""
    if not source.strip():
        return "ERROR: source (function code) is required"
    func = _find_func(source, (args.get("func") or "").strip())
    if func is None:
        return "ERROR: no matching top-level function found in source"
    return _generate(func)


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["hypothesis"]},
        "source": {"type": "string", "description": "Python source containing the function"},
        "func": {"type": "string", "description": "function name (default: first def in source)"},
    },
    "required": ["source"],
}


def test_gen() -> Tool:
    return Tool(
        name="test_gen",
        description=(
            "Generate a Hypothesis property-test scaffold from a function's "
            "source: strategies inferred from parameter type hints, a "
            "@given-decorated test that calls the function and leaves a TODO "
            "for the real invariant. op=hypothesis; pass 'source' (and "
            "optionally 'func'). Pure ast; never executes the code."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
