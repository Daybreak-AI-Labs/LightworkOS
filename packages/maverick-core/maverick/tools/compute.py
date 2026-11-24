"""Symbolic math tool. Replaces flaky LLM mental math.

Backed by SymPy if installed; falls back to Python's ast.literal_eval
+ math module for simple expressions when SymPy isn't available.

Operations:
  - evaluate(expr)       — arithmetic / numeric (e.g. "sin(pi/4)*sqrt(2)")
  - simplify(expr)       — symbolic simplification
  - solve(equation, var) — solve a single-variable equation
  - diff(expr, var)      — derivative
  - integrate(expr, var) — antiderivative

Dates: an ``evaluate`` expression that calls SQLite's date functions
(``date('2026-01-31', '-30 days')``, ``julianday(b) - julianday(a)``) runs
in a private in-memory SQLite database whose authorizer allows functions
only: no table, no subquery, one statement, under a time limit.

Safety: with SymPy, expressions go through its restricted-grammar parser
(no Python `eval`). The no-SymPy fallback compiles the expression and
runs `eval()` with `__builtins__` stripped and only a math allowlist in
scope, after AST-walking to reject calls to anything outside the
allowlist, attribute access, imports, and unbounded exponentiation. It is
a hardened evaluator, not "never eval" — keep the AST guards intact.
"""
from __future__ import annotations

import ast
import json
import logging
import re
import sqlite3
import sys
import time
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
            "description": ("The expression. Examples: 'sin(pi/4)', 'x**2 + 3*x', '1000*(1+0.05/12)^(-60)' (^ is power), "
                            "'sum([4850.00, -1245.60, 2317.45])' to add a list of figures, 'round(x, 2)' "
                            "(half away from zero), 'round(x/0.25)*0.25' for the nearest quarter, floor() and ceil(). "
                            "Dates use SQLite's date functions on YYYY-MM-DD dates: "
                            "date('2026-01-31', '-30 days'), date('2026-01-31', '+3 months'), "
                            "julianday('2026-03-01') - julianday('2026-01-31') for the days between."),
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
    parsed = _safe_parse_expr(expr, evaluate=True, exact=True)
    if isinstance(parsed, (tuple, sympy.Tuple)):
        # "a, b, c" is several figures at once: an agent pricing eight reorders
        # in one call got "'Tuple' object has no attribute 'evalf'".
        return ", ".join(_figure(sympy.N(item, 30)) for item in parsed)
    return _figure(sympy.N(parsed, 30))


def _figure(value) -> str:
    """A result without the zeros that pad an exact decimal to 30 digits."""
    text = f"{value}"
    if "." in text and "e" not in text.lower():
        text = text.rstrip("0").rstrip(".")
    return text


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
    # A signed constant (``**(-60)`` in a loan payment) parses as a unary
    # minus around the constant; it is just as bounded.
    if isinstance(rt, ast.UnaryOp) and isinstance(rt.op, (ast.USub, ast.UAdd)):
        rt = rt.operand
    if not (
        isinstance(rt, ast.Constant)
        and isinstance(rt.value, (int, float))
        and not isinstance(rt.value, bool)
        and abs(rt.value) <= 100
    ):
        raise ValueError("exponent must be a constant between -100 and 100")
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
        "round": _round_half_up, "floor": math.floor, "ceil": math.ceil, "ceiling": math.ceil,
    }
    if len(expr) > _FALLBACK_MAX_LEN:
        raise ValueError(f"expression longer than {_FALLBACK_MAX_LEN} characters")
    # Walk the AST to ensure only safe nodes.
    tree = ast.parse(expr, mode="eval")
    listed = tree.body if isinstance(tree.body, ast.Tuple) and len(tree.body.elts) <= 50 else None
    for node in ast.walk(tree):
        if node is listed:
            continue  # "a, b, c" at the top only: a tuple inside could be multiplied
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
    parts = tree.body.elts if isinstance(tree.body, ast.Tuple) else [tree.body]
    results = [eval(compile(ast.Expression(part), "<expr>", "eval"), {"__builtins__": {}}, safe_globals)
               for part in parts]
    return ", ".join(repr(result) for result in results)




_ALLOWED_EXPR_RE = re.compile(r"^[0-9A-Za-z_+\-*/%^().,=\s]*$")
_ALLOWED_FUNCS = {
    "sin", "cos", "tan", "asin", "acos", "atan", "atan2",
    "sinh", "cosh", "tanh", "exp", "log", "sqrt", "Abs", "abs",
    "min", "max", "round", "floor", "ceil", "ceiling",
}
# Rounding to the cent or the nearest $0.25 was refused as "function not
# allowed", and an agent rounded a price list by hand, wrongly. round() is
# half away from zero, as money is rounded (Python's own rounds 2.5 to 2);
# its digits are bounded so it cannot build a huge number.
_MAX_ROUND_DIGITS = 15


def _round_digits(digits) -> int:
    value = int(digits)
    if value != digits or abs(value) > _MAX_ROUND_DIGITS:
        raise ValueError(f"round() takes a whole number of digits up to {_MAX_ROUND_DIGITS}")
    return value


def _round_half_up(value, digits=0):
    """round() for the no-SymPy fallback: half away from zero, in decimals."""
    from decimal import ROUND_HALF_UP, Decimal

    places = _round_digits(digits)
    result = Decimal(repr(float(value))).quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)
    return float(result)


def _sympy_round(value, digits=0):
    """round() for SymPy: half away from zero, exact on rationals."""
    import sympy

    scale = sympy.Integer(10) ** _round_digits(digits)
    return sympy.sign(value) * sympy.floor(sympy.Abs(value) * scale + sympy.Rational(1, 2)) / scale
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


def _safe_parse_expr(expr: str, *, evaluate: bool, exact: bool = False):
    """``exact`` reads decimals as the exact fractions they write (23.21 is
    2321/100): as binary floats, 16*23.21 came back as 371.360000000000013642."""
    import sympy
    from sympy.parsing.sympy_parser import parse_expr, rationalize, standard_transformations

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
        "round": _sympy_round, "floor": sympy.floor, "ceil": sympy.ceiling, "ceiling": sympy.ceiling,
    })
    # NOTE: do NOT pass global_dict={"__builtins__": {}} here. sympy's
    # parser emits an AST that references sympy's auto-injected names
    # (Integer, Float, ...); an empty global_dict strips them, so every
    # parse raised `NameError: name 'Integer' is not defined` and the whole
    # tool was dead on any machine with the [math] extra installed. Safety
    # is provided by _validate_expr_safety() above (a strict AST allowlist
    # run BEFORE this call), not by neutering sympy's namespace.
    transformations = (*standard_transformations, rationalize) if exact else standard_transformations
    return parse_expr(expr, local_dict=local_dict, evaluate=evaluate, transformations=transformations)


_VALID_OPS = {"evaluate", "simplify", "solve", "diff", "integrate"}

# "sum([a, b, c])" or "sum(a, b, c)" over plain figures, as models write a
# total: a reconciliation's sum of a list was refused as "disallowed
# characters" and the retyped addition left two entries out.
_SUM_CALL = re.compile(r"\bsum\(\s*(?:\[([^\[\]()]*)\]|([^\[\]()]*))\s*\)")


def _sums_as_additions(expr: str) -> str:
    def added(match: re.Match) -> str:
        items = [item.strip() for item in (match.group(1) if match.group(1) is not None
                                           else match.group(2)).split(",")]
        items = [item for item in items if item]
        return "(" + "+".join(f"({item})" for item in items) + ")" if items else "(0)"

    return _SUM_CALL.sub(added, expr)


_DATE_CALL = re.compile(r"\b(?:date|julianday|datetime|strftime|unixepoch|time)\s*\(", re.IGNORECASE)
_SQL_KEYWORD = re.compile(r"\b(?:select|from|with|union|pragma|attach)\b", re.IGNORECASE)
_DATE_HELP = ("For dates, use SQLite's date functions on dates written YYYY-MM-DD: "
              "date('2026-01-31', '-30 days') moves a date, date('2026-01-31', '+3 months') adds months, "
              "and julianday('2026-03-01') - julianday('2026-01-31') counts the days between.")
_DATE_SECONDS = 1.0
_QUOTED = re.compile(r"'(?:[^']|'')*'")
_TEXT_DATE_CALL = re.compile(r"\b(?:date|datetime|time|strftime)\s*\(", re.IGNORECASE)


def _date_shape_problem(expr: str) -> str | None:
    """Why ``expr`` is not one expression of calls, figures and quoted text.
    SQLite reads "date('2030-03-31') - 180 days" as the date's year minus 180,
    named "days" (1850), so a bare word or arithmetic on date text is refused."""
    bare = _QUOTED.sub("''", expr)
    for word in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", bare):
        if not re.match(r"\s*\(", bare[word.end():]):
            return f"{word.group(0)!r} is neither a function nor a figure"
    for call in _TEXT_DATE_CALL.finditer(bare):
        depth, end = 0, len(bare)
        for i in range(call.end() - 1, len(bare)):
            depth += {"(": 1, ")": -1}.get(bare[i], 0)
            if depth == 0:
                end = i + 1
                break
        before, after = bare[:call.start()].rstrip(), bare[end:].lstrip()
        if (before and before[-1] in "+-*/%") or (after and after[0] in "+-*/%"):
            return "date text cannot be added to or subtracted from; give date() the change as a modifier"
    return None


def _evaluate_dates(expr: str) -> str:
    """A date expression, worked out by SQLite. Live: a lease's renewal
    deadline, refused here and counted by hand, came out a day late."""
    if len(expr) > 1000 or ";" in expr or _SQL_KEYWORD.search(expr):
        return f"ERROR: cannot evaluate {expr!r}: only one expression of functions and figures. {_DATE_HELP}"
    problem = _date_shape_problem(expr)
    if problem:
        return f"ERROR: cannot evaluate {expr!r}: {problem}. {_DATE_HELP}"
    db = sqlite3.connect(":memory:")
    try:
        def authorize(action, _arg1, arg2, _db, _trigger):
            if action == sqlite3.SQLITE_SELECT or (
                    action == sqlite3.SQLITE_FUNCTION
                    and str(arg2).lower() not in {"load_extension", "readfile", "writefile"}):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        deadline = time.monotonic() + _DATE_SECONDS
        db.set_authorizer(authorize)
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10_000)
        try:
            row = db.execute("SELECT " + expr).fetchone()
        except (sqlite3.Error, sqlite3.Warning) as exc:
            return f"ERROR: cannot evaluate {expr!r}: {exc}. {_DATE_HELP}"
    finally:
        db.close()
    value = row[0] if row else None
    if value is None:
        return f"ERROR: {expr!r} gave no value; a date must be written YYYY-MM-DD. {_DATE_HELP}"
    if isinstance(value, float):
        value = round(value, 9)
        return str(int(value)) if value.is_integer() else str(value)
    return str(value)


def _run_evaluate(args: dict[str, Any]) -> str:
    expr = str(args.get("expr") or "").strip()
    if not expr:
        return "ERROR: evaluate requires expr"
    expr = _sums_as_additions(expr)
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


# SymPy cannot be interrupted inside a thread, so every SymPy operation runs
# in a child process that is killed at this limit.
_SYMBOLIC_TIMEOUT = 10.0


def _isolated_symbolic(data: bytes) -> str:
    """Child-side entry (``parser_isolation`` whitelist): one SymPy op."""
    request = json.loads(data)
    # The child runs isolated (-I); find SymPy where the parent found it.
    path = request.pop("sympy_path", None)
    if isinstance(path, str) and path not in sys.path:
        sys.path.append(path)
    return _run_sympy(request["op"], request)


def _run_isolated(op: str, args: dict[str, Any]) -> str:
    if getattr(sys, "frozen", False):
        # A frozen build has no interpreter to start; keep the old path.
        return _run_sympy(op, args)
    from pathlib import Path

    import sympy

    from ..parser_isolation import parse_isolated

    request = {key: args.get(key) for key in ("expr", "equation", "var")}
    request.update(op=op, sympy_path=str(Path(sympy.__file__).resolve().parents[1]))
    try:
        result = parse_isolated("compute_symbolic", json.dumps(request, default=str).encode("utf-8"),
                                timeout=_SYMBOLIC_TIMEOUT)
    except RuntimeError as exc:
        if "timed out" in str(exc):
            return (f"ERROR: {op} did not finish within {_SYMBOLIC_TIMEOUT:g} seconds. "
                    "Try a simpler expression or split the problem.")
        return f"ERROR: {op} failed: {exc}"
    return str(result)


def _caret_as_power(args: dict[str, Any]) -> dict[str, Any]:
    """``^`` means power to the people writing these expressions (spreadsheets,
    finance formulas); Python and SymPy read it as XOR and failed with a type
    error on every loan formula. The rewritten ``**`` meets the same bounds."""
    return {key: value.replace("^", "**") if key in ("expr", "equation") and isinstance(value, str) else value
            for key, value in args.items()}


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not isinstance(op, str) or op not in _VALID_OPS:
        return f"ERROR: unknown op {op!r}"
    if op == "evaluate" and _DATE_CALL.search(str(args.get("expr") or "")):
        return _evaluate_dates(str(args.get("expr")).strip())
    args = _caret_as_power(args)

    if op == "evaluate" and not _have_sympy():
        return _run_evaluate(args)

    # All remaining ops require sympy.
    if not _have_sympy():
        return (
            f"ERROR: '{op}' requires sympy. "
            "Run: python -m pip install -e './packages/maverick-core[math]'"
        )
    return _run_isolated(op, args)


def _run_sympy(op: str, args: dict[str, Any]) -> str:
    if op == "evaluate":
        return _run_evaluate(args)
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
            "unreliable past trivial arithmetic, including dates: evaluate "
            "takes SQLite's date functions, such as date('2026-01-31', '-30 days'). "
            "Symbolic ops require the [math] extra (sympy)."
        ),
        input_schema=_COMPUTE_SCHEMA,
        fn=_run,
    )
