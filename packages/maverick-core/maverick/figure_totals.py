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

import datetime
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
    """The totals in ``text``'s Markdown tables, and under its lists, that do
    not add up."""
    issues: list[str] = []
    for header, body, after in _markdown_tables(text or ""):
        issues += _table_issues(header, body)
        for line in after:
            if line.strip().startswith("|"):
                break
            if (issue := _line_issue(line, header, body)) is not None:
                issues.append(issue)
    return (issues + _list_issues(text or ""))[:MAX_ISSUES]


_LIST_ITEM = re.compile(r"^\s*(?:[-*\u2022]|\d+[.)])\s+")
_TOTAL_WORD = re.compile(r"\btotal\b", re.IGNORECASE)


def _list_issues(text: str) -> list[str]:
    """A "total" line right after a list of amounts that nearly, but not
    exactly, equals their sum. Live: a lease answer listed each year's rent
    times 12, $267,580.32 in all, under "Grand total: $267,580.44", and the
    model judge accepted it. Each item's last amount is its figure; a total
    far from the sum (twelve months of rent under the monthly rents) is a
    figure of its own and left alone."""
    issues = []
    block: list[Decimal] = []
    for line in text.splitlines():
        amounts = _CENTS.findall(line)
        if _TOTAL_WORD.search(line) and amounts:
            stated = Decimal(amounts[-1].replace(",", ""))
            added = sum(block, Decimal(0))
            if len(block) >= 2 and added != stated and abs(added - stated) <= stated * Decimal("0.01"):
                issues.append(f"The total {_money(stated, 2)} does not equal the amounts listed above it, "
                              f"which add up to {_money(added, 2)}.")
            block = []
        elif _LIST_ITEM.match(line) and amounts:
            block.append(Decimal(amounts[-1].replace(",", "")))
        elif line.strip():
            block = []
    return issues


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


def _given_figures(given: str) -> set[Decimal]:
    """Every figure the person's own words hold, whole or with decimals."""
    return _returned_figures(given) | _whole_figures(given) | _cents_figures(given)


def drift_issues(answer: str, evidence: str, given: str = "") -> list[str]:
    """Figures in ``answer`` that look like a tool's result with the cents
    garbled: absent from everything the tools returned, while a tool returned
    the same whole amount with different cents.

    A follow-up's compute calls returned $1,647.38 and $20,203.24; its answer
    gave $1,647.56 and $20,203.42, typed by hand. Only that shape is flagged:
    a figure with a different whole amount is about something else."""
    found = _cents_figures(evidence) | _returned_figures(evidence)
    if not found:
        return []
    # A figure the person gave ("the report shows $1,647.56") is theirs, not
    # a tool's garbled: a correct check of it went back to be overwritten.
    whole = _whole_figures(evidence) | _given_figures(given)
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


_MONTH_NAMES = ("january", "february", "march", "april", "may", "june", "july", "august", "september",
                "october", "november", "december")
_MONTH = (r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
          r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)\.?")
_MONTH_FIRST = re.compile(rf"\b{_MONTH}\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+(\d{{4}})\b", re.IGNORECASE)
_DAY_FIRST = re.compile(rf"\b(\d{{1,2}})(?:st|nd|rd|th)?\s+(?:of\s+)?{_MONTH},?\s+(\d{{4}})\b", re.IGNORECASE)
_ISO_DATE = re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])")
_SLASH_DATE = re.compile(r"(?<![\d/])(\d{1,2})/(\d{1,2})/(\d{4})(?![\d/])")


_RULED_OUT = re.compile(r"\b(?:not|instead\s+of|rather\s+than)\s+(?:on\s+|by\s+)?$", re.IGNORECASE)


def _dates(text: str, *, slashes: bool = False, claimed: bool = False) -> set[datetime.date]:
    """The dates ``text`` writes as "March 31, 2029", "31 March 2029" or
    2029-03-31; with ``slashes``, 3/31/2029 too, read both ways round, for
    the text whose dates clear a date rather than name one. With ``claimed``,
    a date the text rules out is left out: an answer that said "October 2,
    2029, not October 3, 2029" went back as copying the past task's October 3."""
    found: set[datetime.date] = set()
    text = text or ""

    def add(match: re.Match, year: str, month: int, day: str) -> None:
        if claimed and _RULED_OUT.search(text[max(0, match.start() - 20):match.start()]):
            return
        try:
            found.add(datetime.date(int(year), month, int(day)))
        except ValueError:
            pass

    def month_number(name: str) -> int:
        return next(index for index, full in enumerate(_MONTH_NAMES, 1) if full.startswith(name.lower()[:3]))

    for match in _MONTH_FIRST.finditer(text):
        add(match, match.group(3), month_number(match.group(1)), match.group(2))
    for match in _DAY_FIRST.finditer(text):
        add(match, match.group(3), month_number(match.group(2)), match.group(1))
    for match in _ISO_DATE.finditer(text):
        add(match, match.group(1), int(match.group(2)), match.group(3))
    if slashes:
        for match in _SLASH_DATE.finditer(text):
            first, second, year = match.groups()
            add(match, year, int(first), second)
            add(match, year, int(second), first)
    return found


def _long_date(day: datetime.date) -> str:
    return f"{_MONTH_NAMES[day.month - 1].capitalize()} {day.day}, {day.year}"


def recalled_issues(answer: str, recalled: str, evidence: str, given: str = "") -> list[str]:
    """Figures and dates in ``answer`` found in a past task's recalled result
    and in nothing this run's other tools returned.

    A statement's compute calls returned 45,638.36 and 44,976.10, but the
    answer copied 100,079.96 and 99,417.70 from an earlier task on a
    different file, which recall_past_goals had shown as done. A lease run
    recalled an earlier answer that put the expiry a year early, started its
    own date arithmetic from that expiry, and repeated it."""
    # A whole amount counts too: compute returned 4326 for a lease's second
    # year, and the answer's $4,326.00 went back as copied from a past task.
    # The person's own figures (a recurring budget's rent, stated in the
    # request) are not copied by mistake.
    past = _cents_figures(recalled) - _returned_figures(evidence) - _whole_figures(evidence) - _given_figures(given)
    issues = [f"The answer gives {_money(value, 2)}, which comes from a past task's result, not from "
              "this task's data." for value in sorted(_cents_figures(answer) & past)]
    # A date the tools returned in any form, the person's own, or today's
    # (a recurring report "as of" today) is not copied.
    today = datetime.date.today()
    cleared = (_dates(evidence, slashes=True) | _dates(given, slashes=True)
               | {today + datetime.timedelta(days=shift) for shift in (-1, 0, 1)})
    copied = sorted(_dates(answer, claimed=True) & (_dates(recalled) - cleared))
    issues += [f"The answer gives {_long_date(day)}, which comes from a past task's result, not from this "
               "task's files." for day in copied]
    issues = issues[:MAX_ISSUES]
    figures, dates = (any(issue.endswith(end) for issue in issues) for end in ("task's data.", "task's files."))
    if figures:
        # Live: told only to recompute, an agent re-ran its table query for an
        # opening balance printed above the table, and took a row's balance.
        issues[-1] += (" Take each figure from this task's own files, reading a file's text where a "
                       "query's table does not hold it.")
    if dates:
        issues[-1] += " Work each date out with compute from the dates this task's files state."
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
