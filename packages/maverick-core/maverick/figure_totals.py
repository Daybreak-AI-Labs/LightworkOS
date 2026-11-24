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
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
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
# A whole number token, thousands groups included, so "1,234.56" is one
# figure and a CSV field after a comma ("266.32,4284.61") is another.
_NUMBER_TOKEN = re.compile(r"(?<![\w.])[$€£]?\s?(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?(?![\d%])")


def _returned_figures(text: str) -> set[Decimal]:
    """Every decimal figure a tool returned, at any precision: a query gives
    44976.1 for the 44,976.10 an answer writes."""
    return {Decimal(whole.replace(",", "") + decimals)
            for whole, decimals in _NUMBER_TOKEN.findall(text or "") if decimals}


def _whole_figures(text: str) -> set[Decimal]:
    """Every whole number a tool returned: compute prints $4,326.00 as 4326."""
    return {Decimal(whole.replace(",", "")) for whole, decimals in _NUMBER_TOKEN.findall(text or "") if not decimals}


def _cents_figures(text: str) -> set[Decimal]:
    """Two-decimal figures of ten or more: what typed money looks like."""
    found = set()
    for whole, decimals in _NUMBER_TOKEN.findall(text or ""):
        if decimals and len(decimals) == 3 and len(whole.replace(",", "")) >= 2:
            found.add(Decimal(whole.replace(",", "") + decimals))
    return found


def _cents(value: Decimal) -> Decimal | None:
    """``value`` rounded to cents, or None for a figure too long to round (a
    row of cells read as one 39-digit number)."""
    try:
        return value.quantize(Decimal("0.01"), ROUND_HALF_UP)
    except ArithmeticError:
        return None


def drift_issues(answer: str, evidence: str) -> list[str]:
    """Figures in ``answer`` that look like a tool's result with the cents
    garbled: absent from everything the tools returned, while a tool returned
    the same whole amount with different cents.

    A follow-up's compute calls returned $1,647.38 and $20,203.24; its answer
    gave $1,647.56 and $20,203.42, typed by hand. Only that shape is flagged:
    a figure with a different whole amount is about something else."""
    found = _cents_figures(evidence) | _returned_figures(evidence)
    if not found:
        return []
    whole = _whole_figures(evidence)
    by_whole: dict[int, set[Decimal]] = {}
    for value in found:
        by_whole.setdefault(int(value), set()).add(value)
    issues = []
    for value in sorted(_cents_figures(answer)):
        near = by_whole.get(int(value), set()) - {value}
        # A tool's 4589.4534 is the answer's 4,589.45 rounded to cents: it went
        # back as "gives 4,589.45, but the tools returned 4,589.45".
        rounded = any(_cents(other) == value for other in near)
        if value not in found and value not in whole and near and not rounded:
            tool = min(near, key=lambda other: abs(other - value))
            issues.append(f"The answer gives {_money(value, 2)}, but the tools returned {_money(tool, 2)}.")
    return issues[:MAX_ISSUES]


def recalled_issues(answer: str, recalled: str, evidence: str) -> list[str]:
    """Figures in ``answer`` found in a past task's recalled result and in
    nothing this run's other tools returned.

    A statement's compute calls returned 45,638.36 and 44,976.10, but the
    answer copied 100,079.96 and 99,417.70 from an earlier task on a
    different file, which recall_past_goals had shown as done."""
    # A whole amount counts too: compute returned 4326 for a lease's second
    # year, and the answer's $4,326.00 went back as copied from a past task.
    past = _cents_figures(recalled) - _returned_figures(evidence) - _whole_figures(evidence)
    issues = [f"The answer gives {_money(value, 2)}, which comes from a past task's result, not from "
              "this task's data." for value in sorted(_cents_figures(answer) & past)][:MAX_ISSUES]
    if issues:
        # Live: told only to recompute, an agent re-ran its table query for an
        # opening balance printed above the table, and took a row's balance.
        issues[-1] += (" Take each figure from this task's own files, reading a file's text where a "
                       "query's table does not hold it.")
    return issues


_PERCENT = re.compile(r"(?<![\d.])(\d{1,2}(?:\.\d{1,4})?)\s?%")


def percent_issues(answer: str) -> list[str]:
    """A percentage worked out wrong: a line with one percentage whose amount
    nearly equals a nearby base times it, but not quite.

    A receipt check said "Expected tax at 8.25%: $24.00" under "Subtotal
    shown: $291.14" and called the receipt's correct $24.02 wrong. A line is
    left alone when any base within three lines gives its amount exactly, or
    when none comes within 1% of it."""
    from decimal import ROUND_HALF_UP

    lines = (answer or "").splitlines()
    issues = []
    for index, line in enumerate(lines):
        percents = _PERCENT.findall(line)
        amounts = [Decimal(raw.replace(",", "")) for raw in _CENTS.findall(line)]
        if len(percents) != 1 or not 1 <= len(amounts) <= 2 or line.lstrip().startswith("|"):
            continue  # a table row's percentage is usually a ratio of its own, such as growth
        last = list(_CENTS.finditer(line))[-1].start()
        if _PERCENT.search(line).start() > last:
            continue  # "X% of" puts the rate before the amount it gives
        rate, shown = Decimal(percents[0]), amounts[-1]
        nearby = amounts[:-1] + [Decimal(raw.replace(",", "")) for other in lines[max(0, index - 3):index + 4]
                                 if other is not line for raw in _CENTS.findall(other)]
        worked = {base: (base * rate / 100).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                  for base in nearby if base > shown}
        if not worked or shown in worked.values():
            continue
        near = [(base, value) for base, value in worked.items()
                if value != shown and abs(value - shown) <= max(value * Decimal("0.01"), Decimal("0.02"))]
        if near:
            base, value = min(near, key=lambda pair: abs(pair[1] - shown))
            issues.append(f"{_money(base, 2)} × {percents[0]}% is {_money(value, 2)}, not {_money(shown, 2)}.")
    return issues[:MAX_ISSUES]
