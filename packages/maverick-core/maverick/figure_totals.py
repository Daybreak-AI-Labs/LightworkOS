"""Check that the totals in an answer or a sheet add up.

A payroll answer gave each employee's pay correctly and a grand total one
dollar off: a child agent typed the total by hand, and the model-based check
let the revision through with the same wrong figure. These checks need no
model. In a Markdown table (or a sheet written with the ``spreadsheet`` tool)
a row labelled "Total", "Subtotal", "Total <group>" or "Grand total" must
equal the rows it covers: the rows since the last total, all the rows, or the
earlier totals plus the rows after them (subtotal, tax, total). A discount,
credit or payment row may count as negative, and a total row may hold a
column's average. A total row is flagged only within 25% of what its rows add
to (a typo or a missed row): a figure far from them is about something else,
such as "Total revenue" in a table of metrics. A "total" line just below a
table is flagged only within 2% of a column's sum. Percent columns, columns
holding other text and sheet columns with formulas are left alone.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

_TOTAL_LABEL = re.compile(r"(grand\s+|sub-?\s*)?totals?\b", re.IGNORECASE)
_SUBTRACTIVE = re.compile(r"discount|less\b|deduct|credit|refund|paid|payment|deposit|withh|minus|return",
                          re.IGNORECASE)
_SEPARATOR = re.compile(r":?-{1,}:?")
_EMPTY = {"", "-", "—", "–", "n/a", "na"}
_MARKUP = re.compile(r"[*_`]")
_CURRENCY = re.compile(r"^(?:usd|eur|gbp|[$€£¥])\s*|\s*(?:usd|eur|gbp)$", re.IGNORECASE)
_LINE_NUMBER = re.compile(r"(?<![\w.])[$€£]?\s?(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)(?![\d,]*%)(?![\w])")
_NEAR = Decimal("0.02")
_NEAR_ROW = Decimal("0.25")
MAX_ISSUES = 3


def _clean(text: str) -> str:
    return _MARKUP.sub("", text).strip()


def _cell(value: Any) -> tuple[str, Decimal | None, int]:
    """``(kind, number, decimals)``; kind is num, empty, percent or text."""
    if isinstance(value, bool):
        return "text", None, 0
    if isinstance(value, int | float):
        number = Decimal(str(value))
        return "num", number, max(0, -number.as_tuple().exponent)  # type: ignore[operator]
    text = _clean(str(value if value is not None else ""))
    if text.lower() in _EMPTY:
        return "empty", None, 0
    if text.endswith("%"):
        return "percent", None, 0
    negative = text.startswith("(") and text.endswith(")")
    text = _CURRENCY.sub("", text.strip("()").replace("−", "-")).replace(",", "").strip()
    if text.startswith("-$"):
        text = "-" + text[2:]
    try:
        number = Decimal(text)
    except InvalidOperation:
        return "text", None, 0
    if not number.is_finite():
        return "text", None, 0
    decimals = max(0, -number.as_tuple().exponent)  # type: ignore[operator]
    return "num", -number if negative else number, decimals


def _money(value: Decimal, decimals: int) -> str:
    return f"{value:,.{decimals}f}"


def _candidates(segment, everything, earlier) -> list[Decimal]:
    """What a total row may equal: each set's sum, with subtractive rows
    either way, and each set's average."""
    out: list[Decimal] = []
    for values in (segment, everything, [*earlier, *segment]):
        if not values:
            continue
        plain = sum((v for v, _ in values), Decimal(0))
        out.append(plain)
        taken = sum((v for v, sub in values if sub), Decimal(0))
        if taken:
            out.append(plain - 2 * taken)
    for values in (segment, everything):
        if values:
            out.append(sum((v for v, _ in values), Decimal(0)) / len(values))
    return out


def _column_issues(header: str, labels: list[str], cells: list[Any]) -> list[str]:
    kinds = [_cell(c) for c in cells]
    if any(kind in ("percent", "text") for kind, _, _ in kinds) or "%" in header:
        return []
    decimals = max([d for _, _, d in kinds] + [0])
    issues: list[str] = []
    segment: list[tuple[Decimal, bool]] = []
    everything: list[tuple[Decimal, bool]] = []
    earlier: list[tuple[Decimal, bool]] = []
    for label, (_, number, _) in zip(labels, kinds, strict=True):
        if not _TOTAL_LABEL.match(label):
            if number is not None:
                entry = (number, bool(_SUBTRACTIVE.search(label)))
                segment.append(entry)
                everything.append(entry)
            continue
        if number is None:
            segment = []
            continue
        options = _candidates(segment, everything, earlier)
        counted = max(len(everything), 1)
        tolerance = Decimal(10) ** -decimals / 2 * (counted + 1)
        expected = min(options, key=lambda option: abs(number - option)) if options else None
        if (expected is not None and abs(number - expected) > tolerance
                and abs(number - expected) <= _NEAR_ROW * max(abs(expected), abs(number))):
            issues.append(f'The "{label}" row gives {header} as {_money(number, decimals)}, but the rows '
                          f"above it add to {_money(expected, decimals)}.")
        earlier.append((number, False))
        segment = []
    return issues


def _table_issues(header: list[str], body: list[list[Any]]) -> list[str]:
    labels = [_clean(str(row[0])) if row else "" for row in body]
    if not any(_TOTAL_LABEL.match(label) for label in labels):
        return []
    issues: list[str] = []
    for index in range(1, len(header)):
        cells = [row[index] if index < len(row) else "" for row in body]
        issues += _column_issues(_clean(str(header[index])) or f"column {index + 1}", labels, cells)
    return issues


def _column_sums(header: list[str], body: list[list[Any]]) -> list[tuple[str, Decimal, int]]:
    sums = []
    for index in range(1, len(header)):
        kinds = [_cell(row[index] if index < len(row) else "") for row in body]
        rows = [(kind, number, d) for (kind, number, d), row in zip(kinds, body, strict=True)
                if not _TOTAL_LABEL.match(_clean(str(row[0])) if row else "")]
        if any(kind in ("percent", "text") for kind, _, _ in rows) or "%" in str(header[index]):
            continue
        numbers = [number for _, number, _ in rows if number is not None]
        if len(numbers) >= 2:
            sums.append((_clean(str(header[index])), sum(numbers, Decimal(0)),
                         max([d for _, _, d in rows] + [0])))
    return sums


def _line_issue(line: str, header: list[str], body: list[list[Any]]) -> str | None:
    """A "total" line under a table whose one figure nearly matches a
    column's sum without matching it."""
    text = _clean(line)
    if not re.search(r"\btotal\b", text, re.IGNORECASE):
        return None
    figures = _LINE_NUMBER.findall(text)
    if len(figures) != 1:
        return None
    value = Decimal(figures[0].replace(",", ""))
    sums = _column_sums(header, body)
    near = None
    for name, total, decimals in sums:
        tolerance = Decimal(10) ** -decimals / 2 * (len(body) + 1)
        if abs(value - total) <= tolerance:
            return None
        if total and abs(value - total) / abs(total) <= _NEAR:
            near = near or (name, total, decimals)
    if near is None:
        return None
    name, total, decimals = near
    return f'"{text}" does not match the table: its {name} column adds to {_money(total, decimals)}.'


def _markdown_tables(text: str):
    """``(header, body, lines after)`` for each Markdown table in ``text``."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].strip().startswith("|"):
            index += 1
            continue
        start = index
        while index < len(lines) and lines[index].strip().startswith("|"):
            index += 1
        rows = [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in lines[start:index]]
        if len(rows) >= 3 and all(_SEPARATOR.fullmatch(cell.replace(" ", "")) for cell in rows[1] if cell):
            yield rows[0], rows[2:], [line for line in lines[index:index + 4] if line.strip()]


def answer_issues(text: str) -> list[str]:
    """The totals in ``text``'s Markdown tables that do not add up."""
    issues: list[str] = []
    for header, body, after in _markdown_tables(text or ""):
        issues += _table_issues(header, body)
        for line in after:
            if line.strip().startswith("|"):
                break
            if (issue := _line_issue(line, header, body)) is not None:
                issues.append(issue)
    return issues[:MAX_ISSUES]


def rows_issues(rows: list[list[Any]]) -> list[str]:
    """The total rows of a sheet about to be written that do not add up. A
    column with a formula is Excel's to calculate (a formula reads as text)."""
    if len(rows) < 3 or not all(isinstance(cell, str) for cell in rows[0]):
        return []
    return _table_issues([str(cell) for cell in rows[0]], [list(row) for row in rows[1:]])[:MAX_ISSUES]


_CENTS = re.compile(r"(?<![\w.,])[$€£]?\s?(\d{1,3}(?:,\d{3})+\.\d{2}|\d{2,}\.\d{2})(?![\d%])(?!\.\d)")


def _cents_figures(text: str) -> set[Decimal]:
    return {Decimal(raw.replace(",", "")) for raw in _CENTS.findall(text or "")}


def drift_issues(answer: str, evidence: str) -> list[str]:
    """Figures in ``answer`` that look like a tool's result with the cents
    garbled: absent from everything the tools returned, while a tool returned
    the same whole amount with different cents.

    A follow-up's compute calls returned $1,647.38 and $20,203.24; its answer
    gave $1,647.56 and $20,203.42, typed by hand. Only that shape is flagged:
    a figure with a different whole amount is about something else."""
    found = _cents_figures(evidence)
    if not found:
        return []
    by_whole: dict[int, set[Decimal]] = {}
    for value in found:
        by_whole.setdefault(int(value), set()).add(value)
    issues = []
    for value in sorted(_cents_figures(answer)):
        near = by_whole.get(int(value), set()) - {value}
        if value not in found and near:
            tool = min(near, key=lambda other: abs(other - value))
            issues.append(f"The answer gives {_money(value, 2)}, but the tools returned {_money(tool, 2)}.")
    return issues[:MAX_ISSUES]
