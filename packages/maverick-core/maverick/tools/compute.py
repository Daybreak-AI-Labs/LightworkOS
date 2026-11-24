"""Symbolic math tool. Replaces flaky LLM mental math.

Backed by SymPy if installed; falls back to Python's ast.literal_eval
+ math module for simple expressions when SymPy isn't available.

Operations:
  - evaluate(expr)       — arithmetic / numeric (e.g. "sin(pi/4)*sqrt(2)")
  - simplify(expr)       — symbolic simplification
  - solve(equation, var) — solve a single-variable equation
  - diff(expr, var)      — derivative
  - integrate(expr, var) — antiderivative

Dates: an ``evaluate`` expression may call SQLite's date functions
(``date('2026-01-31', '-30 days')``, ``julianday(b) - julianday(a)``). Each
call holds only quoted dates and modifiers, plain numbers and further date
calls, and is worked out in a private in-memory SQLite database whose
authorizer allows the date functions only, with a cap on the text they
build. The exact values of julianday() and unixepoch() then go into the
arithmetic, which is evaluated as any other expression, and exactly without
SymPy too. Date text from the other functions is never a figure: it stands
alone, in a list, or is picked with max() or min().

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
from fractions import Fraction
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
    items = list(parsed) if isinstance(parsed, (tuple, sympy.Tuple)) else [parsed]
    values = [sympy.N(item, 30) for item in items]
    # A division by zero came back "zoo" (and 0/0 "nan") as if it were the
    # figure: a same-day per-diem, amount / days, read as an answer.
    if any(value.has(sympy.zoo, sympy.nan, sympy.oo, -sympy.oo) for value in values):
        raise ValueError("the expression divides by zero or has no finite value")
    # "a, b, c" is several figures at once: an agent pricing eight reorders
    # in one call got "'Tuple' object has no attribute 'evalf'".
    return ", ".join(_figure(value) for value in values)


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


class _ExactFigures(ast.NodeTransformer):
    """Each figure in a checked expression as the exact fraction it writes
    (0.1 is 1/10), as SymPy reads a date expression's figures."""

    def __init__(self) -> None:
        self.figures: dict[str, Fraction] = {}

    def visit_Constant(self, node: ast.Constant) -> ast.Name:
        name = f"_figure{len(self.figures)}"
        self.figures[name] = Fraction(repr(node.value))
        return ast.copy_location(ast.Name(id=name, ctx=ast.Load()), node)


def _fallback_figure(value) -> str:
    """A fallback result as text; an exact fraction as the float it rounds to."""
    if isinstance(value, Fraction):
        return repr(int(value)) if value.denominator == 1 else repr(float(value))
    return repr(value)


def _evaluate_fallback(expr: str, *, exact: bool = False) -> str:
    """Minimal evaluator for arithmetic on numeric literals, the math
    constants and the functions in ``safe_globals``.

    Only numeric constants and arithmetic nodes are allowed: strings, lists,
    f-strings and comprehensions would let a short expression allocate
    gigabytes (``f'{1:>100000000}'``, ``'a'*10**10``). ``exact`` works the
    arithmetic out in fractions: a date expression's julianday() figures,
    subtracted as floats near 2.46e6 days, made 8.75 hours 8.74999999254942."""
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
    if exact:
        figures = _ExactFigures()
        tree = figures.visit(tree)
        safe_globals.update(figures.figures)
    parts = tree.body.elts if isinstance(tree.body, ast.Tuple) else [tree.body]
    results = [eval(compile(ast.Expression(part), "<expr>", "eval"), {"__builtins__": {}}, safe_globals)
               for part in parts]
    return ", ".join(_fallback_figure(result) for result in results)




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


def _rewritten(expr: str, transformer: ast.NodeTransformer) -> str:
    """``expr`` rewritten by ``transformer``, each number kept as written:
    printed back from the tree, a decimal of 16 or more digits came out as
    the float nearest it. Raises SyntaxError when ``expr`` is not Python."""
    import io
    import tokenize

    numbers: list[str] = []
    tokens = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(expr).readline):
            if token.type == tokenize.NUMBER:
                tokens.append((tokenize.NAME, f"_number{len(numbers)}"))
                numbers.append(token.string)
            else:
                tokens.append((token.type, token.string))
    except (tokenize.TokenError, IndentationError) as exc:
        raise SyntaxError(str(exc)) from exc
    tree = transformer.visit(ast.parse(tokenize.untokenize(tokens).strip(), mode="eval"))
    return re.sub(r"\b_number(\d+)\b", lambda found: numbers[int(found.group(1))], ast.unparse(tree))


def _added(items: list[ast.expr]) -> ast.expr:
    """The items' sum as a balanced tree: a chain of 330 or more additions
    was too deep to print back."""
    if len(items) == 1:
        return items[0]
    middle = len(items) // 2
    return ast.BinOp(_added(items[:middle]), ast.Add(), _added(items[middle:]))


class _SumAsAddition(ast.NodeTransformer):
    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if not (isinstance(node.func, ast.Name) and node.func.id == "sum" and node.args and not node.keywords):
            return node
        only = node.args[0] if len(node.args) == 1 else None
        items = only.elts if isinstance(only, ast.List | ast.Tuple) else node.args
        if not items:
            return ast.copy_location(ast.Constant(0), node)
        return ast.copy_location(_added(list(items)), node)


def _sums_as_additions(expr: str) -> str:
    """``sum([a, b, c])`` as ``a + b + c``. Read with a pattern, a sum whose
    items held a call (a lease's round(4200 * 1.03 ** 2, 2) * 12) kept its
    brackets and was refused as "disallowed characters". Run after ``^`` is
    read as ``**``: Python reads ``^`` as a looser operator, and
    sum([1, 2])^2 came back 1 + 2 ** 2."""
    if "sum" in expr:
        try:
            return _rewritten(expr, _SumAsAddition())
        except SyntaxError:
            pass  # SymPy's own grammar: the pattern below

    def added(match: re.Match) -> str:
        items = [item.strip() for item in (match.group(1) if match.group(1) is not None
                                           else match.group(2)).split(",")]
        items = [item for item in items if item]
        return "(" + "+".join(f"({item})" for item in items) + ")" if items else "(0)"

    return _SUM_CALL.sub(added, expr)


_DATE_FUNCTIONS = frozenset({"date", "time", "datetime", "julianday", "unixepoch", "strftime", "timediff"})
# Only these give figures. The others give text, which is never read as one:
# strftime('%Y', '2030-03-31') - 180 came back 1850, and a days-between
# attempt on strftime('%Y%m%d', ...) came back 170 instead of 29.
_DATE_FIGURES = frozenset({"julianday", "unixepoch"})
_DATE_CALL = re.compile(r"\b(?:date|julianday|datetime|strftime|unixepoch|timediff|time)\s*\(", re.IGNORECASE)
_SQL_KEYWORD = re.compile(r"\b(?:select|from|with|union|pragma|attach)\b", re.IGNORECASE)
_SQL_COMMENT = re.compile(r"--|/\*|\*/")
_DATE_HELP = ("For dates, use SQLite's date functions on dates written YYYY-MM-DD: "
              "date('2026-01-31', '-30 days') moves a date, date('2026-01-31', '+3 months') adds months, "
              "and julianday('2026-03-01') - julianday('2026-01-31') counts the days between.")
_DATE_TEXT_PROBLEM = ("date text cannot be added to, subtracted from or used as a figure; give date() the change "
                      "as a modifier, or list dates and pick one with max() or min()")
_DATE_COMPARE = ("compare dates by subtracting them: julianday('2026-03-01') - julianday('2026-01-31') "
                 "is above zero when the first is later")
# The longest text a date function may build. Without it a strftime() format
# repeated to fill the expression built a string many times its length.
_DATE_TEXT_LIMIT = 1000
_WORD = re.compile(r"\w+")
_OPENING = re.compile(r"\s*\(")
_DATE_ARGUMENT = re.compile(r"""\s+|,|\(|\)|'(?:[^']|'')*'|"(?:[^"]|"")*"|\d+(?:\.\d+)?(?![\w.])|(\w+)\s*\(""")
# What may stand between the date calls: arithmetic and the words above.
_ARITHMETIC = frozenset(" \t\r\n+-*/%^().,[]")
# A number given as a date is a Julian day number unless a modifier says it
# is seconds: julianday('2030') - 180 came back 1850, and the hours from
# '17.30' and '08.45' came back 8.85. A day number is let through only
# between 0000-01-01 and 9999-12-31, the days SQLite's dates cover.
_NUMBER_AS_DATE = re.compile(r"\s*[+-]?(?:\d+(?:\.\d*)?|\.\d+)\s*")
_NUMBER_MODIFIERS = frozenset({"unixepoch", "julianday", "auto"})
_DAY_NUMBERS = (1721059.5, 5373484.5)
# Text these give may read as a number, so another date call never takes it.
_TEXT_ONLY_CALLS = frozenset({"strftime", "time", "timediff"})
_NUMBER_AS_DATE_PROBLEM = ("a date function reads {0} as a day number in 4713 BC, not as a date; write the date "
                           "in quotes as YYYY-MM-DD, or add 'unixepoch' when it is seconds since 1970")
# max() and min() compare text, which is date order only for these forms.
_ORDERED_DATE_TEXT = re.compile(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?"
                                r"|\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?")
_PLACEHOLDER = re.compile(r"_date(\d+)")


def _date_call_end(expr: str, i: int, name: str) -> tuple[int, str]:
    """Where the call whose arguments start at ``i`` ends, and its arguments as
    SQLite reads them. Only quoted text, plain numbers, commas, parentheses
    and further date calls may appear inside: SQLite read an unquoted
    julianday(2026-03-01) as julianday(2022), a day in 4708 BC, and a
    randomblob() there allocated a gigabyte in the agent's own process. A
    plain number is a day number, or seconds with 'unixepoch', as in
    date(1767225600, 'unixepoch'), which SQLite reads the same quoted or not."""
    depth, argument, sql = 1, i, []
    while depth:
        token = _DATE_ARGUMENT.match(expr, i)
        if i == len(expr) or (expr[i] in "'\"" and token is None):
            raise ValueError(f"a quote or parenthesis in {name}() is not closed")
        if token is None or (token.group(1) and token.group(1).lower() not in _DATE_FUNCTIONS):
            bare = re.match(r"[^,()'\"]*", expr[argument:]).group(0).strip() or expr[i]
            raise ValueError(f"write the dates and modifiers in {name}() in quotes, "
                             f"such as julianday('2026-03-01'): {bare} is not quoted")
        text = token.group(0)
        if text[0] == '"':
            # SQLite reads "2026-01-31" as a column name before it falls back
            # to text; hand it the text.
            text = "'" + text[1:-1].replace('""', '"').replace("'", "''") + "'"
        sql.append(text)
        opens = bool(token.group(1)) or text == "("
        depth += 1 if opens else -1 if text == ")" else 0
        argument = token.end() if opens or text == "," else argument
        i = token.end()
    return i, "".join(sql)


def _check_date_values(sql: str) -> None:
    """Refuse a date call in ``sql`` whose date SQLite would read as a day
    number: a number, or numeric text, with no modifier saying what it is,
    or the text of strftime(), time() or timediff()."""
    tokens = [t for t in _DATE_ARGUMENT.finditer(sql) if not t.group(0).isspace()]
    position = 0

    def argument() -> tuple[str, str]:
        nonlocal position
        if position >= len(tokens):
            return ("text", "")
        token = tokens[position]
        position += 1
        if token.group(1):
            return call(token.group(1).lower())
        if token.group(0) == "(":
            inner = argument()
            while position < len(tokens) and tokens[position].group(0) != ")":
                if tokens[position].group(0) == ",":
                    position += 1
                else:
                    argument()
            position += 1
            return inner
        text = token.group(0)
        return ("text", text[1:-1].replace("''", "'")) if text[0] == "'" else ("number", text)

    def call(name: str) -> tuple[str, str]:
        nonlocal position
        args: list[tuple[str, str]] = []
        while position < len(tokens) and tokens[position].group(0) != ")":
            if tokens[position].group(0) == ",":
                position += 1
                continue
            args.append(argument())
        position += 1
        dates = args[1:2] if name == "strftime" else args[:2] if name == "timediff" else args[:1]
        modifiers = {value.strip().lower() for kind, value in args[len(dates) + (name == "strftime"):]
                     if kind == "text"}
        for kind, value in dates:
            if kind == "call" and value in _TEXT_ONLY_CALLS:
                raise ValueError(f"{name}() cannot take the text of {value}(), which it may read as a day "
                                 "number; give it a date written YYYY-MM-DD, or date() or datetime()")
            if kind != "call" and _NUMBER_AS_DATE.fullmatch(value) and not modifiers & _NUMBER_MODIFIERS:
                if not _DAY_NUMBERS[0] <= float(value) <= _DAY_NUMBERS[1]:
                    raise ValueError(_NUMBER_AS_DATE_PROBLEM.format(repr(value.strip())))
        return ("call", name)

    while position < len(tokens):
        argument()


def _date_calls(expr: str) -> list[tuple[int, int, str, str]]:
    """The start, end, function and SQL of each outermost date call in
    ``expr``. What lies between the calls must read as arithmetic."""
    calls, i = [], 0
    while i < len(expr):
        if expr[i] in "'\"":
            # Quoted text outside a date call is a date read as a number:
            # julianday('2030-03-31') - '2029-10-02' came back 2460562.5.
            raise ValueError("quoted text belongs inside a date function, such as julianday('2029-10-02')")
        if expr[i] in "<>=!":
            # The arithmetic has no comparisons: "... == 29" failed with
            # "'BooleanTrue' object has no attribute 'evalf'".
            raise ValueError(_DATE_COMPARE)
        word = _WORD.match(expr, i)
        opening = _OPENING.match(expr, word.end()) if word else None
        if word is None:
            if expr[i] not in _ARITHMETIC:
                # A character Python takes in a name but \w does not (℘)
                # once slipped past this scan.
                raise ValueError(f"{expr[i]!r} is neither a function nor a figure")
            i += 1
        elif opening and word.group(0).lower() in _DATE_FUNCTIONS:
            end, arguments = _date_call_end(expr, opening.end(), word.group(0))
            calls.append((i, end, word.group(0).lower(), f"{word.group(0)}({arguments}"))
            _check_date_values(calls[-1][3])
            i = end
        elif opening is None and not word.group(0)[0].isdigit():
            # SQLite read "date('2030-03-31') - 180 days" as 2030 - 180, named
            # days; beside the figures a stray word became a symbol.
            raise ValueError(f"{word.group(0)!r} is neither a function nor a figure")
        else:
            i = word.end()
    return calls


def _authorize_date_function(action, _arg1, arg2, _db, _trigger):
    if action == sqlite3.SQLITE_SELECT or (
            action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in _DATE_FUNCTIONS):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _date_results(calls: list[str]) -> list[Any]:
    """The date calls' values, worked out in a private in-memory SQLite
    database with no tables and only the date functions. They run as one
    statement, so 'now' is the same moment in every call."""
    db = sqlite3.connect(":memory:")
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _DATE_TEXT_LIMIT)
        db.set_authorizer(_authorize_date_function)
        try:
            row = db.execute("SELECT " + ", ".join(calls)).fetchone()
        except (sqlite3.Error, sqlite3.Warning) as exc:
            raise ValueError(str(exc)) from exc
    finally:
        db.close()
    for call, value in zip(calls, row, strict=True):
        if value is None:
            raise ValueError(f"{call} gave no value; a date must be written YYYY-MM-DD")
    return list(row)


def _exact_figure(name: str, value: Any) -> Fraction:
    """A julianday() or unixepoch() value as the exact figure it stands for."""
    if isinstance(value, float):
        # SQLite keeps time in whole milliseconds. julianday() hands them back
        # as a float of days off by about 5e-10, which made 8.75 hours worked
        # 8.749999993; the float is far closer than half a millisecond.
        per_unit = 86_400_000 if name == "julianday" else 1000
        return Fraction(round(value * per_unit), per_unit)
    return Fraction(value)


def _with_values(expr: str, calls: list[tuple[int, int, str, str]], values: list[str]) -> str:
    """``expr`` with each date call replaced, on one line: what is left is
    read as Python, which refused a date expression written over two lines."""
    parts, last = [], 0
    for (start, end, _name, _sql), value in zip(calls, values, strict=True):
        parts += [expr[last:start], value]
        last = end
    return re.sub(r"\s+", " ", "".join(parts) + expr[last:]).strip()


def _chosen_date_text(node: ast.AST, texts: list[Any]) -> str:
    """Date text in parentheses or picked with max() or min(), which compare
    YYYY-MM-DD text in date order, as SQLite does."""
    placed = _PLACEHOLDER.fullmatch(node.id) if isinstance(node, ast.Name) else None
    if placed and int(placed.group(1)) < len(texts) and isinstance(texts[int(placed.group(1))], str):
        return texts[int(placed.group(1))]
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id.lower() in ("max", "min")
            and node.args and not node.keywords):
        choices = [_chosen_date_text(arg, texts) for arg in node.args]
        if not all(_ORDERED_DATE_TEXT.fullmatch(choice) for choice in choices):
            raise ValueError(f"{node.func.id.lower()}() picks among dates written YYYY-MM-DD or times written "
                             "HH:MM; compare other dates by subtracting julianday() values")
        return max(choices) if node.func.id.lower() == "max" else min(choices)
    raise ValueError(_DATE_TEXT_PROBLEM)


def _date_text(placed: str, texts: list[Any]) -> str:
    """The text of an expression that only lists dates or picks among them:
    "(date('2026-01-31', '+30 days'))" and the later of two dates were refused
    once date text could not go into the arithmetic."""
    try:
        tree = ast.parse(placed, mode="eval").body
    except SyntaxError:
        raise ValueError(_DATE_TEXT_PROBLEM) from None
    items = tree.elts if isinstance(tree, ast.Tuple) else [tree]
    return ", ".join(_chosen_date_text(item, texts) for item in items)


def _evaluate_dates(expr: str) -> str:
    """A date expression. SQLite works out only the date calls; their exact
    values go into the arithmetic, which is evaluated as any other expression.
    Live: a lease's renewal deadline, refused here and counted by hand, came
    out a day late. Running the whole expression in SQLite divided 1500 by 31
    as whole numbers, and prorated rent came back 768 instead of 774.19."""
    if len(expr) > 1000 or ";" in expr or _SQL_COMMENT.search(expr) or _SQL_KEYWORD.search(expr):
        return f"ERROR: cannot evaluate {expr!r}: only one expression of functions and figures. {_DATE_HELP}"
    try:
        calls = _date_calls(expr)
        values = _date_results([sql for _start, _end, _name, sql in calls])
        if any(name not in _DATE_FIGURES for _start, _end, name, _sql in calls):
            # Placeholder names: every other word was refused, so none clashes.
            return _date_text(_with_values(expr, calls, [f"_date{k}" for k in range(len(calls))]), values)
        figures = _with_values(expr, calls, [f"({_exact_figure(name, value)})"
                                             for (_start, _end, name, _sql), value in zip(calls, values, strict=True)])
    except ValueError as exc:
        return f"ERROR: cannot evaluate {expr!r}: {exc}. {_DATE_HELP}"
    # SQLite read ROUND, ABS and MAX in any case; the arithmetic reads them lowercase.
    figures = re.sub(r"[A-Za-z_]\w*(?=\s*\()", lambda name: name.group(0).lower(), figures)
    args = _caret_as_power({"expr": figures})
    args["expr"] = _sums_as_additions(args["expr"])
    out = _run_isolated("evaluate", args) if _have_sympy() else _run_evaluate(args, exact=True)
    failed = f"ERROR: cannot evaluate {args['expr']!r}: "
    if out.startswith(failed):
        # The figures are not what the agent wrote: quote its own expression.
        return f"ERROR: cannot evaluate {expr!r}: {out[len(failed):]}. {_DATE_HELP}"
    # A float from the fallback, such as sqrt()'s, printed 3 as "3.0".
    return out if out.startswith("ERROR") else ", ".join(_figure(part) for part in out.split(", "))


def _run_evaluate(args: dict[str, Any], *, exact: bool = False) -> str:
    expr = str(args.get("expr") or "").strip()
    if not expr:
        return "ERROR: evaluate requires expr"
    expr = _sums_as_additions(expr)
    try:
        if _have_sympy():
            return _evaluate_with_sympy(expr)
        return _evaluate_fallback(expr, exact=exact)
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


class _PowAsPower(ast.NodeTransformer):
    def visit_Call(self, node: ast.Call) -> ast.AST:
        self.generic_visit(node)
        if (isinstance(node.func, ast.Name) and node.func.id.lower() == "pow" and len(node.args) == 2
                and not node.keywords):
            return ast.copy_location(ast.BinOp(node.args[0], ast.Pow(), node.args[1]), node)
        return node


def _pow_as_power(expr: str) -> str:
    """``pow(a, b)`` as ``(a) ** (b)``. Live: a lease's rent escalation written
    round(4200*pow(1.03,2),2) was refused six times as "function not allowed"."""
    if not re.search(r"\bpow\s*\(", expr, re.IGNORECASE):
        return expr
    try:
        return _rewritten(expr, _PowAsPower())
    except SyntaxError:
        return expr


def _caret_as_power(args: dict[str, Any]) -> dict[str, Any]:
    """``^`` means power to the people writing these expressions (spreadsheets,
    finance formulas); Python and SymPy read it as XOR and failed with a type
    error on every loan formula. The rewritten ``**`` meets the same bounds,
    and so does ``pow(a, b)``, rewritten the same way."""
    return {key: _pow_as_power(value.replace("^", "**")) if key in ("expr", "equation") and isinstance(value, str)
            else value for key, value in args.items()}


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
