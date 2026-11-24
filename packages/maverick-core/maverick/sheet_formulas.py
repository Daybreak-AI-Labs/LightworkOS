"""Compute plain workbook formulas without a spreadsheet program.

Workbooks Lightwork writes hold formulas Excel calculates when the file
opens, so reading one back gave "=SUM(B2:B13)" with no value. An agent asked
to quote a budget's year-1 revenue added twelve months itself and reported
$825,000; the formula gives $819,000. A read now computes the plain kind of
formula agents write (cells and ranges of the same sheet, + - * / ^ and %,
SUM, AVERAGE, MIN, MAX, COUNT, PRODUCT, ROUND, ROUNDUP, ROUNDDOWN, ABS),
exactly, in decimals. Anything else (another sheet, text in arithmetic, an
error, a cycle, a function outside that set) is left uncomputed: ``None``.
Text in a range is left out of it, as Excel does.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from decimal import ROUND_DOWN, ROUND_HALF_UP, ROUND_UP, Decimal, InvalidOperation
from typing import Any

_TOKEN = re.compile(r"\s*(?:(\$?[A-Za-z]{1,3}\$?[0-9]{1,7})|([A-Za-z][A-Za-z0-9.]*)(?=\s*\()|"
                    r"([0-9]+(?:\.[0-9]*)?(?:[Ee][+-]?[0-9]+)?|\.[0-9]+)|(.))")
_MAX_DEPTH = 200
_MAX_RANGE = 100_000


class _Uncomputable(Exception):
    pass


class Memo:
    """What the formulas of one sheet share: each formula cell's result, so
    it is worked out once, and the work left (cells read plus formula tokens),
    after which the sheet's remaining formulas are left uncomputed. An
    amortization schedule reads the balance above twice a row; working each
    reference out afresh doubled the work with every row, and 23 rows ran for
    minutes. ``steps=None`` leaves the work uncapped, for a caller with a
    time limit of its own: a cap shared by a read's formulas left a ledger's
    running balance blank past about 2,000 rows."""

    def __init__(self, steps: int | None = None):
        self.values: dict[str, Decimal] = {}
        self.steps = steps

    def spend(self, steps: int) -> None:
        if self.steps is None:
            return
        self.steps -= steps
        if self.steps < 0:
            raise _Uncomputable("too much work for one sheet")


def _column(letters: str) -> int:
    number = 0
    for char in letters.upper():
        number = number * 26 + ord(char) - 64
    return number


def _letters(number: int) -> str:
    out = ""
    while number:
        number, rest = divmod(number - 1, 26)
        out = chr(65 + rest) + out
    return out


def _split(ref: str) -> tuple[int, int]:
    match = re.fullmatch(r"([A-Za-z]{1,3})([0-9]{1,7})", ref.replace("$", ""))
    if match is None:
        raise _Uncomputable(ref)
    return _column(match.group(1)), int(match.group(2))


def _number(value: Any) -> Decimal | None:
    """A cell's number; None for an empty cell."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise _Uncomputable("a true/false value")
    if isinstance(value, int | float | Decimal):
        return Decimal(str(value))
    text = str(value).strip()
    try:
        if text.endswith("%"):
            return Decimal(text[:-1].strip()) / 100
        return Decimal(text)
    except InvalidOperation as exc:
        raise _Uncomputable("text in a calculation") from exc


class _Parser:
    def __init__(self, formula: str, cell: Callable[[str, int, bool], Decimal | None], depth: int):
        self.tokens = [(m.group(1), m.group(2), m.group(3), m.group(4)) for m in _TOKEN.finditer(formula)]
        self.at, self.cell, self.depth = 0, cell, depth

    def peek(self, symbol: str) -> bool:
        return self.at < len(self.tokens) and self.tokens[self.at][3] == symbol

    def take(self, symbol: str) -> None:
        if not self.peek(symbol):
            raise _Uncomputable(f"expected {symbol}")
        self.at += 1

    def expression(self) -> Decimal:
        value = self.term()
        while self.peek("+") or self.peek("-"):
            sign = self.tokens[self.at][3]
            self.at += 1
            right = self.term()
            value = value + right if sign == "+" else value - right
        return value

    def term(self) -> Decimal:
        value = self.power()
        while self.peek("*") or self.peek("/"):
            sign = self.tokens[self.at][3]
            self.at += 1
            right = self.power()
            if sign == "/" and right == 0:
                raise _Uncomputable("division by zero")
            value = value * right if sign == "*" else value / right
        return value

    def power(self) -> Decimal:
        value = self.unary()
        if self.peek("^"):
            self.at += 1
            exponent = self.power()
            if exponent != exponent.to_integral_value() or abs(exponent) > 100:
                raise _Uncomputable("only small whole powers")
            value = value ** int(exponent)
        return value

    def unary(self) -> Decimal:
        if self.peek("-"):
            self.at += 1
            return -self.unary()
        if self.peek("+"):
            self.at += 1
            return self.unary()
        value = self.primary()
        while self.peek("%"):
            self.at += 1
            value = value / 100
        return value

    def primary(self) -> Decimal:
        if self.at >= len(self.tokens):
            raise _Uncomputable("formula ends early")
        ref, name, number, symbol = self.tokens[self.at]
        self.at += 1
        if number:
            return Decimal(number)
        if ref:
            if self.peek(":"):
                raise _Uncomputable("a range outside a function")
            return self.cell(ref, self.depth, False) or Decimal(0)
        if name:
            return self.function(name.upper())
        if symbol == "(":
            value = self.expression()
            self.take(")")
            return value
        raise _Uncomputable(f"unexpected {symbol}")

    def arguments(self) -> list[list[Decimal]]:
        """Each argument's numbers: a range gives its non-empty cells."""
        self.take("(")
        values: list[list[Decimal]] = []
        while not self.peek(")"):
            ref = self.tokens[self.at][0] if self.at < len(self.tokens) else None
            if ref and self.at + 2 < len(self.tokens) and self.tokens[self.at + 1][3] == ":":
                end = self.tokens[self.at + 2][0]
                if not end:
                    raise _Uncomputable("a range needs two cells")
                self.at += 3
                values.append(self.range(ref, end))
            else:
                values.append([self.expression()])
            if not self.peek(")"):
                self.take(",")
        self.take(")")
        return values

    def range(self, start: str, end: str) -> list[Decimal]:
        (c1, r1), (c2, r2) = _split(start), _split(end)
        c1, c2, r1, r2 = min(c1, c2), max(c1, c2), min(r1, r2), max(r1, r2)
        if (c2 - c1 + 1) * (r2 - r1 + 1) > _MAX_RANGE:
            raise _Uncomputable("range too large")
        found = []
        for row in range(r1, r2 + 1):
            for column in range(c1, c2 + 1):
                value = self.cell(f"{_letters(column)}{row}", self.depth, True)
                if value is not None:
                    found.append(value)
        return found

    def function(self, name: str) -> Decimal:
        args = self.arguments()
        flat = [value for group in args for value in group]
        if name == "SUM":
            return sum(flat, Decimal(0))
        if name == "PRODUCT":
            product = Decimal(1)
            for value in flat:
                product *= value
            return product
        if name == "COUNT":
            return Decimal(len(flat))
        if name in ("AVERAGE", "MIN", "MAX"):
            if not flat:
                raise _Uncomputable(f"{name} of nothing")
            return {"AVERAGE": lambda: sum(flat, Decimal(0)) / len(flat), "MIN": lambda: min(flat),
                    "MAX": lambda: max(flat)}[name]()
        if name == "ABS" and len(args) == 1 and len(args[0]) == 1:
            return abs(args[0][0])
        if name in ("ROUND", "ROUNDUP", "ROUNDDOWN") and len(args) == 2 and len(args[0]) == len(args[1]) == 1:
            digits = args[1][0]
            if digits != digits.to_integral_value() or abs(digits) > 15:
                raise _Uncomputable("rounding digits")
            mode = {"ROUND": ROUND_HALF_UP, "ROUNDUP": ROUND_UP, "ROUNDDOWN": ROUND_DOWN}[name]
            return args[0][0].quantize(Decimal(1).scaleb(-int(digits)), rounding=mode)
        raise _Uncomputable(f"{name} is not computed here")


def evaluate(formula: Any, get: Callable[[str], Any], memo: Memo | None = None) -> Decimal | None:
    """The value of ``formula`` ("=..."), reading other cells through
    ``get(ref)`` (a value or another formula), or None when it is not a
    plain formula this module computes. Pass one ``memo`` for all the
    formulas of a sheet."""
    if not isinstance(formula, str) or not formula.startswith("=") or "!" in formula or len(formula) > 2000:
        return None
    memo = Memo() if memo is None else memo
    visiting: set[str] = set()

    def cell(ref: str, depth: int, in_range: bool) -> Decimal | None:
        key = ref.replace("$", "").upper()
        # A result read again is work too: free, 25 rows of sums over 50,000
        # worked-out cells never reached the cap and ran for minutes.
        memo.spend(1)
        if key in memo.values:
            return memo.values[key]
        if key in visiting or depth > _MAX_DEPTH:
            raise _Uncomputable("a circular reference")
        value = get(key)
        if isinstance(value, str) and value.startswith("="):
            visiting.add(key)
            try:
                memo.values[key] = run(value, depth + 1)
            finally:
                visiting.discard(key)
            return memo.values[key]
        if in_range and isinstance(value, str):
            # Excel leaves text in a range out of SUM, AVERAGE, MIN, MAX and
            # COUNT: "1200" typed as text added nothing to the file's total.
            return None
        return _number(value)

    def run(text: str, depth: int) -> Decimal:
        parser = _Parser(text[1:], cell, depth)
        memo.spend(len(parser.tokens))
        value = parser.expression()
        if parser.at != len(parser.tokens):
            raise _Uncomputable("unexpected text after the formula")
        return value

    try:
        return run(formula, 0)
    except (_Uncomputable, InvalidOperation, ArithmeticError, RecursionError):
        return None


def plain_number(value: Decimal) -> int | float:
    """``value`` as JSON-friendly number."""
    if value == value.to_integral_value():
        return int(value)
    return float(round(value, 10))
