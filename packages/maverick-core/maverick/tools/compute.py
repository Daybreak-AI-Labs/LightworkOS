"""Symbolic math tool. Replaces flaky LLM mental math.

Backed by SymPy if installed; falls back to Python's ast.literal_eval
+ math module for simple expressions when SymPy isn't available.

Operations:
  - evaluate(expr)       — arithmetic / numeric (e.g. "sin(pi/4)*sqrt(2)")
  - simplify(expr)       — symbolic simplification
  - solve(equation, var) — solve a single-variable equation
  - diff(expr, var)      — derivative
  - integrate(expr, var) — antiderivative

Safety: with SymPy, expressions go through its restricted-grammar parser
(no Python `eval`). The no-SymPy fallback compiles the expression and
runs `eval()` with `__builtins__` stripped and only a math allowlist in
scope, after AST-walking to reject calls to anything outside the
allowlist, attribute access, imports, and unbounded exponentiation. It is
a hardened evaluator, not "never eval" — keep the AST guards intact.
"""
from __future__ import annotations

import ast
import logging
import re
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_COMPUTE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["evaluate", "simplify", "solve", "diff", "integrate"],
            "description": "Math operation.",
        },
        "expr": {
            "type": "string",
            "description": "The expression. Examples: 'sin(pi/4)', 'x**2 + 3*x'.",
        },
        "equation": {
            "type": "string",
            "description": "For solve op. e.g. 'x**2 - 4 = 0' (or '= 0' implied).",
        },
        "var": {
            "type": "string",
            "description": "Variable (default 'x' for solve/diff/integrate).",
        },
    },
    "required": ["op"],
}


def _have_sympy() -> bool:
    try:
        import sympy  # noqa: F401
        return True
    except ImportError:
        return False


def _evaluate_with_sympy(expr: str) -> str:
    import sympy
    parsed = _safe_parse_expr(expr, evaluate=True)
    val = sympy.N(parsed, 30)
    return f"{val}"


def _reject_unsafe_pow(node: ast.AST) -> None:
    """Reject `a ** b` with a non-constant or >100 exponent, and nested
    power-towers. Both can materialize astronomically large numbers
    (CPU/RAM DoS of the worker) whether evaluated by Python (fallback)
    or SymPy (`9**9**9**9`). No-op for non-Pow nodes so callers can run
    it over every walked node.
    """
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Pow)):
        return
    rt = node.right
    if not (
        isinstance(rt, ast.Constant)
        and isinstance(rt.value, (int, float))
        and abs(rt.value) <= 100
    ):
        raise ValueError("exponent must be a constant <= 100")
    for operand in (node.left, node.right):
        if isinstance(operand, ast.BinOp) and isinstance(operand.op, ast.Pow):
            raise ValueError("nested exponentiation not allowed")


_FALLBACK_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Call, ast.Name, ast.Load,
    ast.Constant, ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv,
    ast.Mod, ast.Pow, ast.UAdd, ast.USub,
)
_FALLBACK_MAX_LEN = 1000


def _evaluate_fallback(expr: str) -> str:
    """Minimal evaluator for arithmetic on numeric literals, the math
    constants and the functions in ``safe_globals``.

    Only numeric constants and arithmetic nodes are allowed: strings, lists,
    f-strings and comprehensions would let a short expression allocate
    gigabytes (``f'{1:>100000000}'``, ``'a'*10**10``)."""
    import math
    # Replace common math constants/funcs so simple expressions work.
    safe_globals = {
        "pi": math.pi, "e": math.e, "tau": math.tau,
        "sin": math.sin, "cos": math.cos, "tan": math.tan,
        "sqrt": math.sqrt, "log": math.log, "exp": math.exp,
        "abs": abs, "min": min, "max": max,
    }
    if len(expr) > _FALLBACK_MAX_LEN:
        raise ValueError(f"expression longer than {_FALLBACK_MAX_LEN} characters")
    # Walk the AST to ensure only safe nodes.
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _FALLBACK_NODES):
            raise ValueError(f"not allowed in an expression: {type(node).__name__}")
        if isinstance(node, ast.Constant) and (
            isinstance(node.value, bool) or not isinstance(node.value, (int, float))
        ):
            raise ValueError("only numeric literals are allowed")
        if isinstance(node, ast.Name) and node.id not in safe_globals:
            raise ValueError(f"name not allowed: {node.id}")
        if isinstance(node, ast.Call) and (
            not isinstance(node.func, ast.Name) or node.keywords
        ):
            raise ValueError("only plain calls to the math functions are allowed")
        _reject_unsafe_pow(node)
    code = compile(tree, "<expr>", "eval")
    result = eval(code, {"__builtins__": {}}, safe_globals)
    return repr(result)




_ALLOWED_EXPR_RE = re.compile(r"^[0-9A-Za-z_+\-*/%^().,=\s]*$")
_ALLOWED_FUNCS = {
    "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
    "sinh", "cosh", "tanh", "exp", "log", "sqrt", "Abs", "abs",
    "min", "max",
}
_ALLOWED_CONSTS = {"pi", "e", "tau", "E", "I", "oo"}
_ALLOWED_SYMBOLS = {"x", "y", "z", "t", "u", "v"}


def _validate_expr_safety(expr: str) -> None:
    if not _ALLOWED_EXPR_RE.match(expr):
        raise ValueError("expression contains disallowed characters")
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in _ALLOWED_FUNCS:
                raise ValueError("function not allowed")
        elif isinstance(node, ast.Name):
            if node.id not in _ALLOWED_CONSTS and node.id not in _ALLOWED_FUNCS and node.id not in _ALLOWED_SYMBOLS:
                raise ValueError(f"name not allowed: {node.id}")
        elif isinstance(node, ast.Attribute):
            raise ValueError("attribute access is not allowed")
        # Without an exponent bound on the SymPy path, `9**9**9**9` would
        # reach sympy.N() and OOM the worker. Apply the same Pow guard the
        # fallback uses.
        _reject_unsafe_pow(node)


def _safe_parse_expr(expr: str, *, evaluate: bool):
    import sympy
    from sympy.parsing.sympy_parser import parse_expr

    _validate_expr_safety(expr)
    local_dict = {name: sympy.Symbol(name) for name in ("x", "y", "z", "t", "u", "v")}
    local_dict.update({
        "pi": sympy.pi, "e": sympy.E, "E": sympy.E, "I": sympy.I, "oo": sympy.oo,
        "sin": sympy.sin, "cos": sympy.cos, "tan": sympy.tan,
        "asin": sympy.asin, "acos": sympy.acos, "atan": sympy.atan, "atan2": sympy.atan2,
        "sinh": sympy.sinh, "cosh": sympy.cosh, "tanh": sympy.tanh,
        "exp": sympy.exp, "log": sympy.log, "sqrt": sympy.sqrt,
        "Abs": sympy.Abs, "abs": sympy.Abs,
        "min": sympy.Min, "max": sympy.Max,
    })
    # NOTE: do NOT pass global_dict={"__builtins__": {}} here. sympy's
    # parser emits an AST that references sympy's auto-injected names
    # (Integer, Float, ...); an empty global_dict strips them, so every
    # parse raised `NameError: name 'Integer' is not defined` and the whole
    # tool was dead on any machine with the [math] extra installed. Safety
    # is provided by _validate_expr_safety() above (a strict AST allowlist
    # run BEFORE this call), not by neutering sympy's namespace.
    return parse_expr(expr, local_dict=local_dict, evaluate=evaluate)


_VALID_OPS = {"evaluate", "simplify", "solve", "diff", "integrate"}


def _run_evaluate(args: dict[str, Any]) -> str:
    expr = str(args.get("expr") or "").strip()
    if not expr:
        return "ERROR: evaluate requires expr"
    try:
        if _have_sympy():
            return _evaluate_with_sympy(expr)
        return _evaluate_fallback(expr)
    except Exception as e:
        return f"ERROR: cannot evaluate {expr!r}: {type(e).__name__}: {e}"


def _run_simplify(args: dict[str, Any]) -> str:
    import sympy

    expr = str(args.get("expr") or "").strip()
    if not expr:
        return "ERROR: simplify requires expr"
    try:
        return str(sympy.simplify(_safe_parse_expr(expr, evaluate=True)))
    except Exception as e:
        return f"ERROR: cannot simplify {expr!r}: {type(e).__name__}: {e}"


def _run_solve(args: dict[str, Any]) -> str:
    import sympy

    eqn = str(args.get("equation") or args.get("expr") or "").strip()
    if not eqn:
        return "ERROR: solve requires equation"
    var_name = str(args.get("var") or "x").strip()
    try:
        var = sympy.Symbol(var_name)
        # Parse "A = B" -> A - B. If no "=", treat as "expr = 0".
        # .strip() each side: the split leaves leading/trailing spaces
        # (e.g. right=" 0"), and the parser tokenizes a leading space as
        # an IndentationError.
        if "=" in eqn:
            left, right = eqn.split("=", 1)
            target = (
                _safe_parse_expr(left.strip(), evaluate=True)
                - _safe_parse_expr(right.strip(), evaluate=True)
            )
        else:
            target = _safe_parse_expr(eqn, evaluate=True)
        sols = sympy.solve(target, var)
        return f"{var_name} ∈ {{{', '.join(str(s) for s in sols)}}}"
    except Exception as e:
        return f"ERROR: cannot solve: {type(e).__name__}: {e}"


def _run_diff(args: dict[str, Any]) -> str:
    import sympy

    expr = str(args.get("expr") or "").strip()
    if not expr:
        return "ERROR: diff requires expr"
    var_name = str(args.get("var") or "x").strip()
    try:
        return str(sympy.diff(
            _safe_parse_expr(expr, evaluate=True), sympy.Symbol(var_name),
        ))
    except Exception as e:
        return f"ERROR: cannot differentiate: {type(e).__name__}: {e}"


def _run_integrate(args: dict[str, Any]) -> str:
    import sympy

    expr = str(args.get("expr") or "").strip()
    if not expr:
        return "ERROR: integrate requires expr"
    var_name = str(args.get("var") or "x").strip()
    try:
        return str(sympy.integrate(
            _safe_parse_expr(expr, evaluate=True), sympy.Symbol(var_name),
        ))
    except Exception as e:
        return f"ERROR: cannot integrate: {type(e).__name__}: {e}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not isinstance(op, str) or op not in _VALID_OPS:
        return f"ERROR: unknown op {op!r}"

    if op == "evaluate":
        return _run_evaluate(args)

    # All remaining ops require sympy.
    if not _have_sympy():
        return (
            f"ERROR: '{op}' requires sympy. "
            "Run: python -m pip install -e './packages/maverick-core[math]'"
        )

    if op == "simplify":
        return _run_simplify(args)
    if op == "solve":
        return _run_solve(args)
    if op == "diff":
        return _run_diff(args)
    if op == "integrate":
        return _run_integrate(args)

    return f"ERROR: unknown op {op!r}"


def compute() -> Tool:
    return Tool(
        name="compute",
        description=(
            "Symbolic math. ops: evaluate (numeric, e.g. 'sin(pi/4)'), "
            "simplify (symbolic), solve (single-var equation; '=' or "
            "implicit '=0'), diff (derivative), integrate "
            "(antiderivative). Replaces LLM mental math, which is "
            "unreliable past trivial arithmetic. Symbolic ops require "
            "the [math] extra (sympy)."
        ),
        input_schema=_COMPUTE_SCHEMA,
        fn=_run,
    )
