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

import calendar
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
_DATE_FLAGS = re.IGNORECASE
# A Word file or a PDF often joins a date with no-break spaces ("March 31,
# 2030" with U+00A0); read as plain spaces, they still clear the date.
_ODD_SPACES = str.maketrans({" ": " ", " ": " ", " ": " ", " ": " "})
_DAY = r"(\d{1,2})(?!\d)(?:st|nd|rd|th)?"
_YEAR_AFTER = r"(?:,\s*|\s+)"  # "March 31, 2029", "March 31 2029", PDF text's "March 31,2029"
# The forms an answer or a past result claims a date in, as (pattern, order).
_CLAIMED_FORMS = (
    (re.compile(rf"\b{_MONTH}\s+{_DAY}{_YEAR_AFTER}(\d{{4}})\b", _DATE_FLAGS), "mdy"),          # March 31, 2029
    (re.compile(rf"\b{_DAY}\s+(?:of\s+)?{_MONTH}{_YEAR_AFTER}(\d{{4}})\b", _DATE_FLAGS), "dmy"),  # 31 March 2029
    (re.compile(rf"\b(\d{{1,2}})-{_MONTH}-(\d{{4}}|\d{{2}})\b", _DATE_FLAGS), "dmy"),             # 31-Mar-2029
    (re.compile(r"(?<![\d-])(\d{4})-(\d{2})-(\d{2})(?![\d-])"), "ymd"),                          # 2029-03-31
    (re.compile(r"(?<![\d/])(\d{1,2})/(\d{1,2})/(\d{4})(?![\d/])"), "one"),                      # 3/31/2029
)
# More forms a file or a tool writes, read only where they clear a date: a
# lease that "commences on the 1st day of April, 2025" states April 1, 2025.
_CLEARING_FORMS = _CLAIMED_FORMS + (
    (re.compile(rf"\b{_MONTH},?\s+{_DAY}{_YEAR_AFTER}(\d{{4}})\b", _DATE_FLAGS), "mdy"),        # March, 31 2030
    (re.compile(rf"\b{_DAY}\s+day\s+of\s+{_MONTH}{_YEAR_AFTER}(\d{{4}})\b", _DATE_FLAGS), "dmy"),
    (re.compile(rf"\b(\d{{1,2}})[\s-]{_MONTH}[\s,-]+(\d{{4}}|\d{{2}})\b", _DATE_FLAGS), "dmy"),
    (re.compile(r"(?<!\d)(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?!\d)"), "ymd"),  # aging-2026-10-31.csv
    (re.compile(r"(?<!\d)(\d{4})(\d{2})(\d{2})(?!\d)"), "ymd"),               # 20300331
    # 3/31/30, 31.03.2030, a bank export's 03-31-2030 or 31-03-2030
    (re.compile(r"(?<![\d/.-])(\d{1,2})([/.-])(\d{1,2})\2(\d{4}|\d{2})(?![\d/.-])"), "either"),
)
# A statement period: "Oct 1-31, 2026", "March 1 - 31, 2030", "April 1 - June 30, 2026".
_DAY_SPAN = re.compile(rf"\b{_MONTH}\s+{_DAY}\s*[-–—]\s*{_DAY}{_YEAR_AFTER}(\d{{4}})\b", _DATE_FLAGS)
_MONTH_SPAN = re.compile(rf"\b{_MONTH}\s+{_DAY}\s*[-–—]\s*{_MONTH}\s+{_DAY}{_YEAR_AFTER}(\d{{4}})\b",
                         _DATE_FLAGS)
_MONTH_YEAR = re.compile(rf"\b{_MONTH},?\s+(\d{{4}})\b", _DATE_FLAGS)
# A date the answer rules out ("not October 3", "- Was: **October 3**",
# "corrected from October 3") is no claim: a revision that said what it
# corrected went back for the date it had just corrected.
_RULED_OUT = re.compile(r"\b(?:not|instead\s+of|rather\s+than)\b[\s*_:(]*(?:(?:on|by|the)\s+)?[\s*_]*$"
                        r"|\b(?:corrected|changed|moved|updated|revised|fixed(?![-\s]+(?:term|rate|rent|fee|price|amount|monthly)))\b[^\n.;]{0,60}?\bfrom\s+"
                        r"(?:the\s+|an?\s+)?[\s*_]*$"
                        r"|\b(?:previously|formerly|originally)\b[\s*_:(]*$"
                        r"|\b(?:earlier|before|old|was)\s*[*_]*:[\s*_]*$"
                        r"|\b(?:a|one|\d+)\s+(?:day|week|month|year)s?\s+(?:later|earlier)\s+than\s+(?:the\s+)?$",
                        re.IGNORECASE)
_REFUTED = re.compile(
    r"\b(?:wrong(?:ly)?|incorrect(?:ly)?|mistaken(?:ly)?|in\s+error|(?:a|one)\s+(?:day|week|month|year)\s+"
    r"(?:early|late|off|out)|off\s+by|(?:last|prior|previous)\s+(?:month|year|quarter|week|period)'s\s+"
    r"(?:answer|result|report|summary|aging|run|statement|figures?|numbers?|totals?|dates?))\b", re.IGNORECASE)
# A sentence about an earlier answer skips its date only when it also
# corrects something: "180 days' prior written notice" and "per the previous
# summary, the lease expires ..." are claims, and a copied expiry had passed
# for them.
_PAST_REFERENCE = re.compile(
    r"\b(?:(?:earlier|previous|prior|past|original|old|recalled|first|last)\s+(?:answer|result|response|run"
    r"|task|report|summary|version|draft|calculation)s?|previously|originally|formerly"
    r"|earlier\s+I|I\s+(?:earlier|previously))\b", re.IGNORECASE)
_CORRECTION = re.compile(
    r"\b(?:not|instead|rather|unlike|wrong|incorrect|mistaken|mistake|error|typo|correct(?:ed|ion|ly)?|changed|moved"
    r"|updated|revised|fixed|should\s+(?:be|have\s+been)|actually|(?:too|was|is|were|came|comes)\s+(?:\w+\s+){0,2}?(?:early|late)"
    r"|(?:reported|listed|given|stated|shown|put|gave|had)\b[^\n.;]{0,40}?\b(?:as|at))\b|n't\b", re.IGNORECASE)
_FULL_STOP = re.compile(r"[.!?][)\]\"'”’*_]*(?=\s+[A-Z*_(\[\"“$-]|\s*$)|[\n|]")
_SENTENCE_END = re.compile(r"[.!?][)\]\"'”’*_]*(?=\s+[A-Z*_(\[\"“$-]|\s*$)|[;\n|]")


def _month(name: str) -> int | None:
    key = name.lower()[:3]
    return next((index for index, full in enumerate(_MONTH_NAMES, 1) if full.startswith(key)), None)


def _year(text: str) -> int:
    return 2000 + int(text) if len(text) == 2 else int(text)


def _calendar_day(year: int, month: int | None, day: int) -> datetime.date | None:
    try:
        return datetime.date(year, month, day) if month else None
    except (ValueError, OverflowError):
        return None


def _month_edges(year: int, month: int | None) -> set[datetime.date]:
    """A month's first and last day: what a period named by its month stands for."""
    first = _calendar_day(year, month, 1)
    if first is None:
        return set()
    return {first, datetime.date(year, first.month, calendar.monthrange(year, first.month)[1])}


def _ruled_out(text: str, start: int, end: int) -> bool:
    if _RULED_OUT.search(text[max(0, start - 80):start]):
        return True
    before, after = text[max(0, start - 300):start], text[end:end + 300]
    opening = max((match.end() for match in _SENTENCE_END.finditer(before)), default=0)
    closing = next((match.start() for match in _SENTENCE_END.finditer(after)), len(after))
    sentence = before[opening:] + " " + after[:closing]
    if _REFUTED.search(sentence):
        return True
    if not _PAST_REFERENCE.search(sentence):
        return False
    opening = max((match.end() for match in _FULL_STOP.finditer(before)), default=0)
    closing = next((match.start() for match in _FULL_STOP.finditer(after)), len(after))
    return bool(_CORRECTION.search(before[opening:] + " " + after[:closing]))


def _corrected_on_its_line(text: str, start: int, end: int, day: datetime.date) -> bool:
    """Whether the date's line gives the same month and day in another year,
    as a correction does: "| Lease end | March 31, 2029 | March 31, 2030 |",
    "March 31, 2029 -> March 31, 2030"."""
    before, after = text[max(0, start - 300):start], text[end:end + 300]
    sentence = (before[max((match.end() for match in _FULL_STOP.finditer(before)), default=0):] + " "
                + after[:next((match.start() for match in _FULL_STOP.finditer(after)), len(after))])
    if _PAST_REFERENCE.search(sentence) and any(
            other != day and (other.month, other.day) == (day.month, day.day) for other in _dates(text)):
        # "... March 31, 2030 (the earlier summary listed March 31, 2029)", or
        # "Note: a past summary gave March 31, 2029" after the right date.
        return True
    line = text[text.rfind("\n", 0, start) + 1:(text.find("\n", end) + 1 or len(text) + 1) - 1]
    if not line.lstrip().startswith("|"):
        # Beside it, as a correction sets the two: a rent year ending on the
        # same day further along the line is no correction.
        line_start = text.rfind("\n", 0, start) + 1
        line = line[max(0, start - line_start - 40):end - line_start + 40]
    return any(other != day and (other.month, other.day) == (day.month, day.day) for other in _dates(line))


def _dates(text: str, *, clearing: bool = False, claimed: bool = False) -> set[datetime.date]:
    """The dates ``text`` writes. A claim is written "March 31, 2029", "31
    March 2029", 31-Mar-2029, 2029-03-31, or 3/31/2029 where only one reading
    is a date. With ``clearing``, for text whose dates clear a date, numeric
    dates count both ways round, the forms files write count too, a span
    ("Oct 1-31, 2026") counts both its ends, and a month and year count that
    month's first and last day. With ``claimed``, a date the text rules out or
    corrects is left out. Never raises."""
    found: set[datetime.date] = set()
    text = (text or "").translate(_ODD_SPACES)
    for pattern, order in _CLEARING_FORMS if clearing else _CLAIMED_FORMS:
        for match in pattern.finditer(text):
            groups = match.groups()
            if order == "mdy":
                days = [_calendar_day(_year(groups[2]), _month(groups[0]), int(groups[1]))]
            elif order == "dmy":
                days = [_calendar_day(_year(groups[2]), _month(groups[1]), int(groups[0]))]
            elif order == "ymd":
                days = [_calendar_day(int(groups[0]), int(groups[1]), int(groups[2]))]
            else:
                first, second, year = (groups[0], groups[2], groups[3]) if order == "either" else groups
                days = [_calendar_day(_year(year), int(first), int(second)),
                        _calendar_day(_year(year), int(second), int(first))]
                if order == "one" and (None not in days and days[0] != days[1]):
                    continue  # 4/10/2029 is April 10 or October 4: no claim either way
            for day in days:
                if day is None or (claimed and (_ruled_out(text, match.start(), match.end())
                                                or _corrected_on_its_line(text, match.start(), match.end(), day))):
                    continue
                found.add(day)
    if clearing:
        for name, first, last, year in _DAY_SPAN.findall(text):
            found.update(filter(None, (_calendar_day(int(year), _month(name), int(first)),
                                       _calendar_day(int(year), _month(name), int(last)))))
        for name, first, other, last, year in _MONTH_SPAN.findall(text):
            found.update(filter(None, (_calendar_day(int(year), _month(name), int(first)),
                                       _calendar_day(int(year), _month(other), int(last)))))
        for name, year in _MONTH_YEAR.findall(text):
            found |= _month_edges(int(year), _month(name))
    return found


_MONTH_DAY = re.compile(rf"\b{_MONTH}\s+{_DAY}\b(?!\s*(?:,\s*)?\d{{4}})", _DATE_FLAGS)
_DAY_MONTH = re.compile(rf"\b{_DAY}\s+(?:of\s+)?{_MONTH}(?![a-z])(?!\s*(?:,\s*)?\d{{4}})", _DATE_FLAGS)
# "as of 10/31", never "1/2 of the rent", "3/4 time" or "24/7 coverage".
_NUMERIC_DAY = re.compile(r"\b(?:as\s+of|on|by|due|through|thru|until|till|ending|ended|for|from|to|dated"
                          r"|before|after)\s+(\d{1,2})/(\d{1,2})(?![\d/])(?!\s*(?:of|time)\b|-time)",
                          re.ASCII | re.IGNORECASE)
# A capitalized month name, not the verb ("some hours may be missing", "May I").
_MONTH_ALONE = re.compile(r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?"
                          r"|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b\.?"
                          r"(?!\s+(?:I|we|you|they|he|she|it|be|have|need|want)\b)", re.ASCII)
_QUARTER = re.compile(r"\bQ([1-4])(?:\s*(?:of\s+|[,/-]\s*)?(\d{4}))?\b|\b(\d{4})\s*(?:[-/]\s*)?Q([1-4])\b",
                      _DATE_FLAGS)
_QUARTER_WORDS = re.compile(r"\b(first|second|third|fourth)\s+quarter\b(?:\s+(?:of\s+)?(\d{4}))?", _DATE_FLAGS)
_RELATIVE = re.compile(r"\b(this|current|last|previous|prior|next)\s+(week|month|quarter|year)\b", _DATE_FLAGS)
_YEAR_NAMED = re.compile(r"\b(?:FY\s*'?)?(\d{4})\b|\bFY\s*'?(\d{2})\b", _DATE_FLAGS)
_PERIOD_END = re.compile(r"\b(month|quarter|year)[-\s]end\b|\bend\s+of\s+(?:the\s+)?(month|quarter|year)\b"
                         r"|\b(month|quarter|year)ly\b", _DATE_FLAGS)
# A request to set this result beside an earlier one: quoting the earlier
# result's figures and dates is the work asked for.
_COMPARE_TARGET = (r"(?:last|previous|prior|earlier|past|original|before|jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?"
                   r"|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?"
                   r"|dec(?:ember)?|Q[1-4]|(?:19|20)\d\d)\b")
_COMPARES = re.compile(
    # "compare November with October", "how does it compare to last month",
    # "different from the previous run", "November vs. October", "versus Q3";
    # never "budget versus actual for November" or "compare the two quotes".
    r"\b(?:compar(?:e|ed|es|ing|ison)|differen(?:t|ce|ces)|changes?|changed)\b[^?!\n]{0,60}?"
    r"\b(?:with|to|against|and|from|over|vs\.?|versus)\s+(?:(?:the|our|its|their|this|that)\s+)?" + _COMPARE_TARGET
    + r"|\b(?:vs\.?|versus)\s+(?:(?:the|our|its|their|this|that)\s+)?" + _COMPARE_TARGET
    + r"|\bsince\s+(?:the\s+)?(?:last|previous|prior)\s+(?:report|aging|run|summary|statement|close|review|time|one)\b"
    r"|\b(?:year|month|quarter|week)[-\s]over[-\s](?:year|month|quarter|week)\b|\b(?:yoy|mom|qoq)\b"
    r"|\bremind\s+(?:me|us)\s+(?:of\s+)?(?:what|how\s+much|when)\b|\bsame\s+as\s+(?:last|the\s+previous|before|what)\b"
    r"|\bwhat\s+(?:we|I)\s+(?:paid|owed|spent|charged|billed)\s+(?:last|in|for)\b|\blast\s+time\b", re.IGNORECASE)


def _shifted(today: datetime.date, months_back: int) -> tuple[int, int]:
    year, month = divmod(today.year * 12 + today.month - 1 - months_back, 12)
    return year, month + 1


def _quarter_months(year: int, number: int) -> set[tuple[int, int]]:
    return {(year, month) for month in range(3 * number - 2, 3 * number + 1) if 1 <= year <= 9999}


def _request_month_days(given: str) -> set[tuple[int | None, int]]:
    """The month and day pairs a request names without a year."""
    found = {(_month(match.group(1)), int(match.group(2))) for match in _MONTH_DAY.finditer(given)}
    found |= {(_month(match.group(2)), int(match.group(1))) for match in _DAY_MONTH.finditer(given)}
    for first, second in _NUMERIC_DAY.findall(given):
        found |= {(int(first), int(second)), (int(second), int(first))}
    return found


def _request_months(given: str, today: datetime.date) -> set[tuple[int, int]]:
    """The months a request names: "October 2026", "October", "Q3 2026", "the third quarter"."""
    around = (today.year - 1, today.year, today.year + 1)
    found = {(int(year), month) for name, year in _MONTH_YEAR.findall(given)
             if (month := _month(name)) and 1 <= int(year) <= 9999}
    found |= {(year, month) for match in _MONTH_ALONE.finditer(given)
              if (month := _month(match.group(1))) for year in around}
    for q1, year1, year2, q2 in _QUARTER.findall(given):
        for year in ([int(year1 or year2)] if (year1 or year2) else around):
            found |= _quarter_months(year, int(q1 or q2))
    for word, year in _QUARTER_WORDS.findall(given):
        number = ("first", "second", "third", "fourth").index(word.lower()) + 1
        for each in ([int(year)] if year else around):
            found |= _quarter_months(each, number)
    return found


def _request_periods(given: str, today: datetime.date) -> tuple[set[datetime.date], set[tuple[int, int]]]:
    """The days and months a request names relative to today ("last month",
    "this week", "next quarter", "month-end"), or as a year ("FY2026")."""
    days: set[datetime.date] = set()
    months: set[tuple[int, int]] = set()
    for which, span in _RELATIVE.findall(given):
        step = {"last": -1, "previous": -1, "prior": -1, "next": 1}.get(which.lower(), 0)
        span = span.lower()
        if span == "week":
            monday = today - datetime.timedelta(days=today.weekday()) + datetime.timedelta(weeks=step)
            days.update(monday + datetime.timedelta(days=offset) for offset in range(7))
        elif span == "month":
            months.add(_shifted(today, -step))
        elif span == "quarter":
            year, number = divmod(today.year * 4 + (today.month - 1) // 3 + step, 4)
            months |= _quarter_months(year, number + 1)
        else:
            days.update(filter(None, (_calendar_day(today.year + step, 1, 1), _calendar_day(today.year + step, 12, 31))))
    for four, two in _YEAR_NAMED.findall(given):
        year = int(four) if four else 2000 + int(two)
        days.update(filter(None, (_calendar_day(year, 1, 1), _calendar_day(year, 12, 31))))
    for first, second, third in _PERIOD_END.findall(given):
        span = (first or second or third).lower()
        if span == "month":
            months |= {_shifted(today, 0), _shifted(today, 1)}
        elif span == "quarter":
            for back in (0, 3):
                year, month = _shifted(today, back)
                months |= _quarter_months(year, (month - 1) // 3 + 1)
        else:
            days.update(filter(None, (_calendar_day(today.year - 1, 12, 31), _calendar_day(today.year, 12, 31))))
    return days, months


def _request_clears(given: str, today: datetime.date):
    """Whether the person's request states a date: in full, by its month and
    day ("as of 10/31", "Oct 31") within a year of today, or as the end of a
    period it names ("October 2026", "Q3", "last month", "FY2026",
    "month-end"). A rerun of October's aging "as of 10/31" went back for the
    October 31 a past run's result also gave."""
    given = (given or "").translate(_ODD_SPACES)
    month_days = _request_month_days(given)
    days, months = _request_periods(given, today)
    days |= _dates(given, clearing=True)
    months |= _request_months(given, today)

    def in_period(day: datetime.date) -> bool:
        if (day.year, day.month) not in months:
            return False
        return day in _month_edges(day.year, day.month) or ((day.year, day.month) == (today.year, today.month)
                                                            and day <= today)

    return lambda day: (day in days or in_period(day)
                        or ((day.month, day.day) in month_days and abs(day.year - today.year) <= 1))


# A figure the answer sets beside the current one as last period's ("down
# from $4,850.00", "$4,850.00 last month") is no claim of this task's.
_PERIOD_WORD = (r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
                r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|Q[1-4])")
_PAST_PERIOD = r"(?:last|previous|prior)\s+(?:month|quarter|year|week|period)"
_FROM_BEFORE = re.compile(r"\b(?:from|compared\s+(?:with|to)|versus|vs\.?|against)\s+[\s*_(]*$", re.IGNORECASE)
# Last period's figure named by its period: "down from October's $22,191.15",
# "over last month's $4,850.00", "Last month's revenue was $4,850.00", "(last
# month: $4,850.00)", "(October 31: $22,191.15)". Read so only when the request
# names no such period itself: asked for last month's revenue, "last month's
# revenue was $4,850.00" is the answer's claim.
_LABELLED_BEFORE = re.compile(
    r"\b(?:from|compared\s+(?:with|to)|versus|vs\.?|against|over)\s+(?:the\s+)?(?:" + _PAST_PERIOD
    + r"(?:'s|-end)?|" + _PERIOD_WORD + r"(?:'s|\s+\d{1,2}(?:st|nd|rd|th)?))\s+(?:(?:total|balance)\s+(?:of\s+)?)?"
    r"[\s*_(]*$"
    r"|\b" + _PAST_PERIOD + r"(?:'s|-end)?\b[^.;\n$]{0,30}$"
    r"|\(\s*" + _PERIOD_WORD + r"(?:\s+\d{1,2})?(?:,\s*\d{4})?\s*:\s*[*_]*$", re.IGNORECASE)
_LABEL = re.compile(r"\b(?:last|previous|prior)\s+(month|quarter|year|week|period)\b|\b(" + _PERIOD_WORD + r")\b",
                    re.IGNORECASE)


def _labels(text: str) -> set[str]:
    """The periods ``text`` names, as "month" for "last month" and "10" for October."""
    found = set()
    for span, word in _LABEL.findall(text or ""):
        if span:
            found.add(span.lower())
        elif word.lower().startswith("q") and len(word) == 2:
            found.add(word.upper())
        elif (month := _month(word)) is not None:
            found.add(str(month))
    return found
_PERIOD_AFTER = re.compile(r"[\s*_)]*(?:in\s+|for\s+)?(?:last|the\s+(?:previous|prior))\s+"
                           r"(?:month|year|quarter|week|period)\b", re.IGNORECASE)
# A month and day a tool wrote without a year: a statement's "10/15", a
# timesheet's "Tue 11/10", "Oct 15".
_SLASH_DAY = re.compile(r"(?<![\d/.-])(\d{1,2})/(\d{1,2})(?![\d/]|\.\d)")
# "29-Oct", "Oct-29", "10-29" as a spreadsheet saved to CSV writes them.
_DASH_DAY_MONTH = re.compile(rf"(?<![\w-])(\d{{1,2}})-{_MONTH}(?![-\w])", _DATE_FLAGS)
_DASH_MONTH_DAY = re.compile(rf"(?<![\w-]){_MONTH}-(\d{{1,2}})(?![-\d])", _DATE_FLAGS)
_DASH_DAY = re.compile(r"(?<![\d/.-])(\d{1,2})-(\d{1,2})(?![\d/-]|\.\d)")


def _claimed_cents(text: str, given: str = "") -> set[Decimal]:
    """The two-decimal figures ``text`` claims, leaving out one it gives as
    last period's or rules out. A figure named by a period the request names
    too ("last month's revenue" asked for last month's revenue) is a claim."""
    found: set[Decimal] = set()
    asked = _labels(given)
    for match in _NUMBER_TOKEN.finditer(text or ""):
        whole, decimals = match.groups()
        if not decimals or len(decimals) != 3 or len(whole.replace(",", "")) < 2:
            continue
        start, end = match.start(), match.end()
        before = text[max(0, start - 60):start]
        labelled = _LABELLED_BEFORE.search(before) or _PERIOD_AFTER.match(text, end)
        if (_FROM_BEFORE.search(before) or (labelled and not _labels(labelled.group(0)) & asked)
                or _ruled_out(text, start, end)):
            continue
        found.add(Decimal(whole.replace(",", "") + decimals))
    return found


def _cent_forms(values: set[Decimal], near: set[int]) -> set[Decimal]:
    """``values`` rounded to cents the ways people and programs round (half
    up, half even, cut off), for those near a figure in ``near``: compute
    printed 703.125 for pay the answer gives as $703.13."""
    from decimal import ROUND_DOWN, ROUND_HALF_EVEN

    forms: set[Decimal] = set()
    for value in values:
        if int(value) not in near and int(value) + 1 not in near:
            continue
        for rounding in (ROUND_HALF_UP, ROUND_HALF_EVEN, ROUND_DOWN):
            try:
                forms.add(value.quantize(Decimal("0.01"), rounding))
            except ArithmeticError:
                pass
    return forms


def _year_less_days(text: str) -> set[tuple[int | None, int]]:
    """The month and day pairs ``text`` writes without a year, both ways round
    for numbers."""
    text = (text or "").translate(_ODD_SPACES)
    found = {(_month(match.group(1)), int(match.group(2))) for match in _MONTH_DAY.finditer(text)}
    found |= {(_month(match.group(2)), int(match.group(1))) for match in _DAY_MONTH.finditer(text)}
    found |= {(_month(name), int(day)) for day, name in _DASH_DAY_MONTH.findall(text)}
    found |= {(_month(name), int(day)) for name, day in _DASH_MONTH_DAY.findall(text)}
    for first, second in _SLASH_DAY.findall(text) + _DASH_DAY.findall(text):
        found |= {(int(first), int(second)), (int(second), int(first))}
    return found


def recalled_issues(answer: str, recalled: str, evidence: str, given: str = "",
                    today: datetime.date | None = None) -> list[str]:
    """Figures and dates in ``answer`` found in a past task's recalled result
    and in nothing this run's other tools returned.

    A statement's compute calls returned 45,638.36 and 44,976.10, but the
    answer copied 100,079.96 and 99,417.70 from an earlier task on a
    different file, which recall_past_goals had shown as done. A lease run
    recalled an earlier answer that put the expiry a year early, started its
    own date arithmetic from that expiry, and repeated it."""
    # Only what the answer shares with a past result can be copied: the
    # run's tool output, up to millions of characters, is read only then.
    figures = _claimed_cents(answer, given) & _cents_figures(recalled)
    dates = _dates(answer, claimed=True) & _dates(recalled) if recalled else set()
    if not (figures or dates) or _COMPARES.search(given or ""):
        return []
    # A whole amount counts too: compute returned 4326 for a lease's second
    # year, and the answer's $4,326.00 went back as copied from a past task.
    # The person's own figures (a recurring budget's rent, stated in the
    # request) are not copied by mistake.
    if figures:
        returned = _returned_figures(evidence)
        figures -= (returned | _cent_forms(returned, {int(value) for value in figures}) | _whole_figures(evidence)
                    | _given_figures(given))
    issues = [f"The answer gives {_money(value, 2)}, which comes from a past task's result, not from "
              "this task's data." for value in sorted(figures)]
    if dates:
        # A date the tools returned in any form, one the request states or
        # implies, or today's (a recurring report "as of" today) is not copied.
        today = today or datetime.date.today()
        returned, requested = _dates(evidence, clearing=True), _request_clears(given, today)
        # A statement line's "10/15" or a timesheet's "Tue 11/10" names the
        # day without its year: within a year of today, that day is the tool's.
        year_less = _year_less_days(evidence)
        issues += [f"The answer gives {_long_date(day)}, which comes from a past task's result, not from this "
                   "task's files." for day in sorted(dates)
                   if day not in returned and not requested(day) and abs((day - today).days) > 1
                   and not ((day.month, day.day) in year_less and abs(day.year - today.year) <= 1)]
    issues = issues[:MAX_ISSUES]
    has_figures, has_dates = (any(issue.endswith(end) for issue in issues)
                              for end in ("task's data.", "task's files."))
    if has_figures:
        # Live: told only to recompute, an agent re-ran its table query for an
        # opening balance printed above the table, and took a row's balance.
        issues[-1] += (" Take each figure from this task's own files, reading a file's text where a "
                       "query's table does not hold it.")
    if has_dates:
        # Not "leave the past dates out": a correct date the past result also
        # gave is still the answer, and worked out with compute it is the tool's.
        issues[-1] += (" Work each date out with compute from the dates this task's files state, and give the "
                       "dates that gives.")
    return issues


def _long_date(day: datetime.date) -> str:
    return f"{_MONTH_NAMES[day.month - 1].capitalize()} {day.day}, {day.year}"


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
