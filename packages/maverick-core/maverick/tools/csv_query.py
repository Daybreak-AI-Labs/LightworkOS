"""Read-only SQL over CSV text, in a private in-memory SQLite database.

Shared by ``read_attachment`` (one uploaded CSV as ``data``) and
``spreadsheet_read``'s ``query`` (workspace CSV files, one table each). Exact
totals and comparisons replace the model adding numbers in its head. The
authorizer allows reading the loaded tables and calling built-in functions
only, so a statement cannot write, attach a file, change settings or load an
extension; one statement runs per call. A blank in a column of numbers is
NULL; a blank in a text column is ''. A column of dates written 10/29/2026
or 29/10/2026 is stored as 2026-10-29 when its values, or another date
column of the same file that the query reads, show which part is the day, so
SQLite's date functions read it; a query that reads such a column gets a note
saying so.
``hours(start, end)`` and
``overlap(start, end, from, to)`` work out clock times (HH:MM or 3:30 PM),
counting past midnight when the end is not after the start; ``hours(shift)``
and ``overlap(shift, from, to)`` take a shift written as one range
("7:00-15:30"). ``round`` rounds half away from zero on the figure as written,
as money is rounded.
"""
from __future__ import annotations

import csv
import datetime
import io
import re
import sqlite3
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

MAX_QUERY_ROWS = 200

# An amount as people write it: an optional sign, currency sign and accounting
# parentheses around digits grouped in thousands ("4,850.00", "-$1,245.60",
# "($1,000.50)"). A leading zero ("02134", "007") is an identifier, kept as text.
_AMOUNT = re.compile(r"(?P<open>\()?(?P<sign>[-+])?[$£€]?(?P<sign2>-)?"
                     r"(?P<digits>(?:(?:0|[1-9][0-9]{0,2}(?:,[0-9]{3})+|[1-9][0-9]*)(?:\.[0-9]*)?|\.[0-9]+)"
                     r"(?:[eE][-+]?[0-9]+)?)"
                     r"(?P<close>\))?")


def _cell(value: str):
    """A CSV cell as a number when it is one, so SUM and ORDER BY work on it.
    Amounts written with thousands separators or a currency sign count: as
    text, "4,850.00" summed as 4 and a reconciliation came out wrong."""
    text = value.strip()
    match = _AMOUNT.fullmatch(text)
    if match is None or bool(match.group("open")) != bool(match.group("close")) or (
            match.group("sign") and match.group("sign2")):
        return value
    digits = match.group("digits").replace(",", "")
    number = float(digits) if any(c in digits for c in ".eE") else int(digits)
    negative = bool(match.group("open")) or "-" in (match.group("sign") or "") + (match.group("sign2") or "")
    return -number if negative else number


_CLOCK = re.compile(r"([01]?[0-9]|2[0-3]):([0-5][0-9])(?::[0-5][0-9])?")
_CLOCK_12 = re.compile(r"(1[0-2]|0?[1-9])(?::([0-5][0-9]))?\s*([ap])\.?\s*m\.?", re.IGNORECASE)
_RANGE = re.compile(r"\s*(.+?)\s*(?:-|\u2013|\u2014|\bto\b)\s*(.+?)\s*", re.IGNORECASE)
_DAY = 24 * 60


def _minutes(value) -> int | None:
    text = str(value or "").strip()
    match = _CLOCK.fullmatch(text)
    if match:
        return int(match.group(1)) * 60 + int(match.group(2))
    match = _CLOCK_12.fullmatch(text)
    if match is None:
        return None
    hour = int(match.group(1)) % 12 + (12 if match.group(3).lower() == "p" else 0)
    return hour * 60 + int(match.group(2) or 0)


def _ends(shift) -> tuple[str, str] | None:
    """The start and end of a shift written as one range ("7:00-15:30")."""
    match = _RANGE.fullmatch(str(shift or ""))
    return (match.group(1), match.group(2)) if match else None


def _span(start, end) -> tuple[int, int] | None:
    """Minutes from midnight of ``start`` to ``end``, running past midnight
    when ``end`` is not after ``start`` (a night shift)."""
    a, b = _minutes(start), _minutes(end)
    if a is None or b is None:
        return None
    return a, b + _DAY if b <= a else b


def _hours(start, end) -> float | None:
    """SQL ``hours(start, end)``: clock hours from one HH:MM to the next."""
    span = _span(start, end)
    return None if span is None else (span[1] - span[0]) / 60


def _round(value, digits=0) -> float | None:
    """SQL ``round``, half away from zero on the figure as written: SQLite's
    own gives 41.17 for ROUND(41.175, 2), the binary float being 41.17499..."""
    if value is None or digits is None:
        return None
    try:
        number = Decimal(value) if isinstance(value, int) else Decimal(repr(float(value)))
        places = max(0, min(int(digits or 0), 15))
    except (TypeError, ValueError, OverflowError, InvalidOperation):
        return None
    if not number.is_finite():
        return float(number)
    try:
        return float(number.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP))
    except InvalidOperation:
        # More digits than Decimal holds (ROUND(1e30, 2)) raised, and the
        # whole query failed. A float that long has no digit left to round
        # at those places, so SQLite's own answer stands.
        return round(float(number), places)


def _shift_hours(shift) -> float | None:
    """SQL ``hours(shift)``: the hours of a shift written as one range."""
    ends = _ends(shift)
    return None if ends is None else _hours(*ends)


def _shift_overlap(shift, window_start, window_end) -> float | None:
    """SQL ``overlap(shift, from, to)`` for a shift written as one range."""
    ends = _ends(shift)
    return None if ends is None else _overlap(*ends, window_start, window_end)


def _overlap(start, end, window_start, window_end) -> float | None:
    """SQL ``overlap(start, end, from, to)``: the hours of start-end inside
    the daily window from-to, such as the 22:00-06:00 of a night premium."""
    shift, window = _span(start, end), _span(window_start, window_end)
    if shift is None or window is None:
        return None
    total = 0
    for day in (-_DAY, 0, _DAY):
        total += max(0, min(shift[1], window[1] + day) - max(shift[0], window[0] + day))
    return total / 60


# 10/29/2026, 29.10.2026, 2026/10/29: the forms SQLite's date functions
# cannot read, so julianday() gave NULL and an aging report put every balance
# in its last bucket.
_DATE_DMY_MDY = re.compile(r"([0-9]{1,2})([/.-])([0-9]{1,2})\2([0-9]{4})")
_DATE_YMD = re.compile(r"([0-9]{4})([/.])([0-9]{1,2})\2([0-9]{1,2})")


def _date_parts(values: list[str]) -> list[tuple[str, int, int, int]] | None:
    """Each value's numbers, or None when one is not a date in these forms."""
    parts = []
    for text in values:
        match = _DATE_YMD.fullmatch(text)
        if match:
            parts.append(("ymd", int(match.group(1)), int(match.group(3)), int(match.group(4))))
            continue
        match = _DATE_DMY_MDY.fullmatch(text)
        if match is None:
            return None
        parts.append(("xy", int(match.group(1)), int(match.group(3)), int(match.group(4))))
    return parts or None


def _orders_shown(parts: list[tuple[str, int, int, int]]) -> set[str]:
    """"day" when a value can only be day first (29/10/2026), "month" when
    one can only be month first (10/29/2026)."""
    shown = set()
    if any(kind == "xy" and a > 12 for kind, a, _b, _y in parts):
        shown.add("day")
    if any(kind == "xy" and b > 12 for kind, _a, b, _y in parts):
        shown.add("month")
    return shown


def _iso_dates(parts: list[tuple[str, int, int, int]], order: str | None) -> list[str] | str | None:
    """The dates as YYYY-MM-DD, the day first when ``order`` is "day";
    "ambiguous" when no order is given and a value needs one (03/04/2026), or
    None when one is not a real date."""
    if order is None and any(kind == "xy" and a != b for kind, a, b, _y in parts):
        return "ambiguous"
    dates = []
    for kind, a, b, y in parts:
        year, month, day = (a, b, y) if kind == "ymd" else (y, b, a) if order == "day" else (y, a, b)
        try:
            dates.append(datetime.date(year, month, day).isoformat())
        except ValueError:
            return None
    return dates


def _parse(filename: str, text: str) -> tuple[list[str], list[list]] | str:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or not any(cell.strip() for cell in rows[0]):
        return f"ERROR: {filename} has no header row"
    header = [cell.strip() or f"column_{i + 1}" for i, cell in enumerate(rows[0])]
    if len(set(header)) != len(header):
        return f"ERROR: {filename} repeats a column name in its header"
    width = len(header)
    return header, [[_cell(c) for c in (row + [""] * width)[:width]] for row in rows[1:] if row]


def _text_columns(name: str, header: list[str], body: list[list], blanks: dict[tuple[str, str], int]) -> list[int]:
    """The columns of ``body`` holding text. A blank in a column of numbers
    becomes NULL: as text '' it outranked every number in MAX and counted as 0
    in AVG (a statement's withdrawal and deposit columns are each blank where
    the other is filled). A text column keeps '' so a filter such as
    receipt = '' still finds blanks."""
    text = []
    for column in range(len(header)):
        filled = [row[column] for row in body if not (isinstance(row[column], str) and not row[column].strip())]
        if filled and all(isinstance(value, int | float) for value in filled):
            for row in body:
                if isinstance(row[column], str):
                    row[column] = None
            if len(filled) < len(body):
                blanks[(name, header[column])] = len(body) - len(filled)
        elif filled and all(isinstance(value, str) for value in filled):
            text.append(column)
    return text


def _convert(body: list[list], column: int, dates: list[str]) -> None:
    filled = iter(dates)
    for row in body:
        if row[column].strip():
            row[column] = next(filled)


def _load(db, tables: dict[str, tuple[str, str]],
          blanks: dict[tuple[str, str], int]) -> tuple[dict[str, tuple[list[str], list[list]]], list] | str:
    """Parse each CSV text and create its table, still empty: its date
    columns are settled across the whole file before rows go in. The parsed
    tables and their date columns, or an error."""
    parsed: dict[str, tuple[list[str], list[list]]] = {}
    dates = []
    for name, (filename, text) in tables.items():
        table = _parse(filename, text)
        if isinstance(table, str):
            return table
        header, body = parsed[name] = table
        for column in _text_columns(name, header, body, blanks):
            values = [row[column].strip() for row in body if row[column].strip()]
            parts = _date_parts(values)
            if parts:
                dates.append((name, header[column], body, column, values, parts))
        quoted = ", ".join('"' + column.replace('"', '""') + '"' for column in header)
        db.execute(f'CREATE TABLE "{name}" ({quoted})')
    return parsed, dates


def _settle_dates(columns: list) -> tuple[list, list]:
    """Store date columns as YYYY-MM-DD where the day/month order is known:
    the converted (table, column, as written, as read, borrowed order) and
    the ambiguous (table, column, as written). A column whose values show
    the order (10/29/2026 is month first) is converted on its own. One whose
    values cannot show it (10/05/2026, 12/01/2026) takes the order the other
    date columns of its own file agree on: due was converted and paid_on was
    not, and WHERE paid_on > due compared 2026-11-15 with 12/01/2026. Whether
    the query reads them does not matter, so a column reads the same in every
    query: SELECT * showed paid_date as 2026-11-05, and a follow-up filter on
    that form, reading paid_date alone, matched nothing. Another file's order
    is never taken: two files can come from two systems, and a US invoice
    file's order read a European bank file's 05/10/2026 as May 10."""
    converted, ambiguous, undecided = [], [], []
    shown_by: dict[str, dict[str, str]] = {}
    for table, column_name, body, column, values, parts in columns:
        shown = _orders_shown(parts)
        if len(shown) > 1:
            continue
        order = next(iter(shown), None)
        dates = _iso_dates(parts, order)
        if dates == "ambiguous":
            undecided.append((table, column_name, body, column, values, parts))
        elif isinstance(dates, list):
            _convert(body, column, dates)
            converted.append((table, column_name, values[0], dates[0], None))
            if order:
                shows = next(value for value, (kind, a, b, _y) in zip(values, parts, strict=True)
                             if kind == "xy" and (a if order == "day" else b) > 12)
                shown_by.setdefault(table, {}).setdefault(
                    order, f"{order} first, as {table}.{column_name} does ({shows})")
    for table, column_name, body, column, values, parts in undecided:
        orders = shown_by.get(table, {})
        order = next(iter(orders)) if len(orders) == 1 else None
        dates = _iso_dates(parts, order) if order else None
        if order and isinstance(dates, list):
            _convert(body, column, dates)
            converted.append((table, column_name, values[0], dates[0], orders[order]))
        else:
            ambiguous.append((table, column_name, values[0]))
    return converted, ambiguous


_DATE_FUNCTION = re.compile(r"\b(julianday|date|datetime|strftime|unixepoch|timediff)\s*\(", re.IGNORECASE)
_PERCENT_NAME = re.compile(r"pct|percent|%", re.IGNORECASE)
_PER_HUNDRED = re.compile(r"\b100(?:\.0*)?\b|\b0?\.01\b")
_LITERAL = re.compile(r"'(?:[^']|'')*'")
_TOKEN = re.compile(r'"(?:[^"]|"")*"|[(),]')
_NAME = r'[A-Za-z_][A-Za-z0-9_]*|"(?:[^"]|"")+"'
_COLUMN = re.compile(rf"\s*(?:(?P<table>{_NAME})\s*\.\s*)?(?P<column>{_NAME})\s*")


def _unquote(name: str | None) -> str | None:
    return name[1:-1].replace('""', '"') if name and name.startswith('"') else name


def _date_arguments(sql: str) -> list[tuple[str | None, str]]:
    """(table or alias, column) for each date function given a column as
    its date: the first argument, strftime's second, both of timediff's. A
    column inside an expression there (CASE WHEN status ..., substr(d, 7, 4)
    || ..., a modifier) is not one. One pass over the query: rescanning to
    each call's closing parenthesis took seconds on deeply nested calls."""
    text = _LITERAL.sub("''", sql)
    calls = {match.end() - 1: match.group(1).lower() for match in _DATE_FUNCTION.finditer(text)}
    stack: list[tuple[str | None, list[int]]] = []
    found = []
    for token in _TOKEN.finditer(text):
        if token.group() == "(":
            stack.append((calls.get(token.start()), [token.end()]))
        elif token.group() == "," and stack:
            stack[-1][1].append(token.end())
        elif token.group() == ")" and stack:
            function, starts = stack.pop()
            spans = list(zip(starts, [start - 1 for start in starts[1:]] + [token.start()], strict=True))
            dated = spans[1:2] if function == "strftime" else spans[:2] if function == "timediff" else spans[:1]
            for start, end in dated if function else ():
                column = _COLUMN.fullmatch(text, start, end)
                if column:
                    found.append((_unquote(column.group("table")), _unquote(column.group("column"))))
    return found


def _dated_columns(sql: str, reads: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """The (table, column) pairs the query's date functions read as dates,
    each found among the columns the query reads: by name, a same-named
    column of a table the query never read was named too. Each table's
    aliases are found once: looked up again for every date argument, 1,990
    calls over ten tables took 16 seconds."""
    text = _LITERAL.sub("''", sql)
    by_name: dict[str, set[tuple[str, str]]] = {}
    for table, name in reads:
        by_name.setdefault(name.lower(), set()).add((table, name))
    aliases: dict[str, set[str]] = {}
    for table in {table for table, _name in reads}:
        aliases.setdefault(table.lower(), set()).add(table)
        for match in re.finditer(rf'(?<![\w"])"?{re.escape(table)}"?\s+(?:AS\s+)?"?(\w+)"?', text, re.IGNORECASE):
            aliases.setdefault(match.group(1).lower(), set()).add(table)
    dated = set()
    for qualifier, column in set(_date_arguments(sql)):
        named = by_name.get(column.lower(), set())
        if qualifier:
            tables = aliases.get(qualifier.lower(), set())
            named = {(table, name) for table, name in named if table in tables} or named
        dated |= named
    return dated


def _in_arithmetic(column: str, sql: str) -> bool:
    """Whether ``sql`` adds, subtracts, multiplies or divides with ``column``
    (bare, quoted or qualified by a table alias)."""
    name = re.escape(column)
    ref = rf'(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:"{name}"|(?<![\w"]){name}(?![\w"]))'
    return re.search(rf"[-+*/]\s*{ref}|{ref}\s*[-+*/]", sql) is not None


def _blank_notes(blanks: dict[tuple[str, str], int], reads: set[tuple[str, str]], sql: str) -> list[str]:
    """Columns of numbers with blanks that the query does arithmetic with:
    a blank is NULL (so AVG and MAX are right), and NULL in arithmetic is
    NULL. Live: amount - paid was NULL for every unpaid invoice, and an aging
    summary's SUM left them out. Counted per table the query reads: summed
    by column name, a file loaded as data and under its own name had twice
    its blanks, and named per loaded table, it got two notes."""
    notes = []
    for (table, column), count in blanks.items():
        if (table, column) not in reads:
            continue
        name = re.escape(column)
        guarded = re.search(rf'(?:coalesce|ifnull)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"?{name}"?\s*,',
                            sql, re.IGNORECASE)
        if _in_arithmetic(column, sql) and not guarded:
            notes.append(f"Note: {table}.{column} is blank in {count} row{'s' if count != 1 else ''}, and a blank number "
                         f"is NULL, so arithmetic with it gives NULL in those rows and SUM leaves them out. "
                         f"Write COALESCE({column}, 0) to count a blank as 0.")
    return notes


def _percent_notes(db, headers: dict[str, list[str]], reads: set[tuple[str, str]], sql: str) -> list[str]:
    """Percent columns holding whole percents (15 for 15%) that the query
    uses in arithmetic without dividing by 100. Live: revenue as
    qty * price * (1 - discount_pct) came out negative and the answer blamed
    the data."""
    if _PER_HUNDRED.search(sql):
        return []
    notes = []
    for table, columns in headers.items():
        for column in columns:
            if not _PERCENT_NAME.search(column) or (table, column) not in reads:
                continue
            if not _in_arithmetic(column, sql):
                continue
            largest = db.execute(f'SELECT MAX("{column}") FROM "{table}" '
                                 f'WHERE typeof("{column}") IN (\'integer\', \'real\')').fetchone()[0]
            if largest is not None and largest > 1:
                shown = int(largest) if float(largest).is_integer() else largest
                notes.append(f"Note: {table}.{column} holds percents (largest {shown}), so {shown} means {shown}%; "
                             "this query uses it in arithmetic as it stands. To use it as a fraction, "
                             "divide it by 100.")
    return notes


# Text that reads as a date to a person: 10/29/2026 10:00, Oct 29 2026, 29 Oct 2026.
# Text that reads as a date to a person: 10/29/2026 10:00, Oct 29 2026,
# 29 Oct 2026, 29-Oct-2026, Thursday, October 29, 2026, and 20261029 as a
# bank or ERP export writes it.
_LOOSE_DATE = re.compile(
    r"\d{1,4}[/.-]\d{1,2}[/.-]\d{1,4}|[A-Za-z]{3,9}\.? +\d{1,2}(?:st|nd|rd|th)?,? +\d{4}"
    r"|\d{1,2}[ /-]+[A-Za-z]{3,9}\.?,?[ /-]+\d{2,4}"
    r"|(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday|mon|tues?|wed|thur?s?|fri|sat|sun)\.?, +"
    r"[A-Za-z]{3,9}\.? +\d{1,2}"
    r"|(?:19|20)\d\d(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])$", re.IGNORECASE)


def _date_notes(db, ambiguous: list[tuple[str, str, str]], converted: list[tuple[str, str, str, str, str | None]],
                reads: set[tuple[str, str]], sql: str, rows: list) -> list[str]:
    """Notes on dates the query reads. A converted column reads as
    2026-10-29 while the file shows 10/29/2026: WHERE date = '10/29/2026'
    and GROUP BY substr(date, 1, 2) silently matched nothing or grouped on
    the year. The note that date functions cannot read a column needs an
    empty value in the result it explains: fired on any empty result column,
    it sent the agent to fix dates that were fine, and a query that had
    already filtered out 'TBD' was told about it. It names a column a date
    function is given as its date when the result holds an empty value or a
    date function filters the rows, or, when a result column is empty in every
    row, a column the query reads that holds dates in another form: wrapped
    in substr or trim, or renamed in a CTE, such a column got no note."""
    notes = []
    for table, column, written, iso, borrowed in converted:
        if (table, column) not in reads:
            continue
        if borrowed is None:
            notes.append(f"Note: {table}.{column} holds dates written like {written}; queries read them as {iso} "
                         "(YYYY-MM-DD), so compare, filter and group on that form.")
        else:
            notes.append(f"Note: {table}.{column} holds dates written like {written}, and none of them shows "
                         f"whether the day or the month comes first; this query reads them {borrowed}, so "
                         f"{written} is {iso} (YYYY-MM-DD). If they are written the other way, ask which it is.")
    dating = _DATE_FUNCTION.search(sql) is not None
    undecided = {(table, column) for table, column, _example in ambiguous}
    if dating:
        empty = bool(rows) and any(all(row[i] is None for row in rows) for i in range(len(rows[0])))
        # A date function in a filter drops the rows it cannot read without
        # leaving an empty value: WHERE julianday(d) > 0 counted 0 rows.
        text = _LITERAL.sub("''", sql)
        filtering = re.search(r"\b(?:where|having|on)\b", text, re.IGNORECASE)
        filters = bool(filtering and _DATE_FUNCTION.search(text, filtering.end()))
        nulls = any(value is None for row in rows for value in row)
        direct = _dated_columns(sql, reads) if nulls or filters else set()
        for table, column in sorted((direct | (reads if empty else set())) - undecided):
            quoted = '"' + column.replace('"', '""') + '"'
            # A value the query names itself (WHERE due <> 'TBD') is one it
            # has already dealt with.
            unread = [value for (value,) in db.execute(
                f'SELECT {quoted} FROM "{table}" WHERE (typeof({quoted}) = \'text\' OR (typeof({quoted}) = '
                f"'integer' AND {quoted} BETWEEN 19000101 AND 21001231)) "
                f"AND trim({quoted}) <> '' AND julianday({quoted}) IS NULL LIMIT 20")
                if ((table, column) in direct or _LOOSE_DATE.match(str(value).strip()))
                and f"'{value}'" not in sql]
            if unread:
                notes.append(f"Note: {table}.{column} holds values such as '{unread[0]}', which SQLite's date "
                             "functions cannot read: they read dates written YYYY-MM-DD and give nothing for "
                             "other forms.")
    # A column left as written beside one read as YYYY-MM-DD matches nothing,
    # with or without a date function.
    named = [f"{table}.{column} (such as '{example}')" for table, column, example in ambiguous
             if (table, column) in reads]
    if named and (dating or any((table, column) in reads for table, column, *_rest in converted)):
        notes.append(f"Note: {'; '.join(named)} {'was' if len(named) == 1 else 'were'} left as written: "
                     "no value shows whether the day or the month comes first, so date functions cannot "
                     "read it. Ask which it is, or convert it in the query with substr.")
    return notes


_CLOCK_SHOWN = re.compile(r"\d{1,2}:\d{2}|\d\s*[ap]\.?m\b", re.IGNORECASE)


def shift_note(shift: str, where: str, column: str) -> str:
    """What to know about a shift written as ``shift`` in ``column``: how
    hours() reads it, or, when it has no AM or PM and ends before it starts
    on a 12-hour clock (8:00-4:30), that hours() reads it as running past
    midnight. Pushed to hours() with no word on this, a US timesheet's
    8:00-4:30 day shift was offered as 20.5 hours."""
    hours = _shift_hours(shift)
    if hours is None:
        return ""
    figure = int(hours) if float(hours).is_integer() else round(hours, 4)
    ends = _ends(shift)
    twelve = re.search(r"[ap]\.?\s*m", shift, re.IGNORECASE) is None and all(
        (minutes := _minutes(end)) is not None and minutes < 13 * 60 for end in ends)
    if twelve and hours > 12:
        return (f"{where} holds clock times such as {shift}, with no AM or PM: hours() reads that as running past "
                f"midnight ({figure} hours). If they are day shifts, say so and work them out as such "
                "(8:00 AM to 4:30 PM is 8.5 hours), or ask which they are.")
    name = column if re.fullmatch(r"[A-Za-z_]\w*", column) else '"' + column.replace('"', '""') + '"'
    return (f"{where} holds clock times such as {shift}: hours({name}) gives {figure} for that shift and counts "
            f"on past midnight, and a lunch rule is a CASE, as in hours({name}) - CASE WHEN hours({name}) > 6 "
            "THEN 0.5 ELSE 0 END.")


def _clock_notes(columns: list[str], rows: list, sql: str) -> list[str]:
    """A note when the result shows shifts as clock ranges and the query did
    not work them out. Live: SELECT * on a Word timesheet showed 11:00-19:30,
    and the agent counted it 7.5 paid hours by hand where it is 8."""
    if re.search(r"\b(?:hours|overlap)\s*\(", sql, re.IGNORECASE):
        return []
    for row in rows:
        for column, value in zip(columns, row, strict=False):
            if isinstance(value, str) and _CLOCK_SHOWN.search(value) and (
                    note := shift_note(value, column, column)):
                return [f"Note: {note} Work hours out in the query, not by hand."]
    return []


def query_tables(tables: dict[str, tuple[str, str]], sql: str) -> str:
    """Run one SELECT over ``tables`` ({table: (filename, csv text)}) as CSV text."""
    db = sqlite3.connect(":memory:")
    # Clock times (shifts past midnight, hours inside a window) are where
    # hand arithmetic went wrong; these keep them inside the one query.
    db.create_function("hours", 2, _hours, deterministic=True)
    db.create_function("hours", 1, _shift_hours, deterministic=True)
    db.create_function("overlap", 4, _overlap, deterministic=True)
    db.create_function("overlap", 3, _shift_overlap, deterministic=True)
    db.create_function("round", 1, _round, deterministic=True)
    db.create_function("round", 2, _round, deterministic=True)
    blanks: dict[tuple[str, str], int] = {}
    reads: set[tuple[str, str]] = set()
    try:
        loaded = _load(db, tables, blanks)
        if isinstance(loaded, str):
            return loaded
        parsed, dates = loaded
        headers = {name: header for name, (header, _body) in parsed.items()}
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
        names = set(tables)

        def authorize(action, arg1, arg2, _db, _trigger):
            if action not in allowed:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and arg1 not in names:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in {"load_extension", "readfile", "writefile"}:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ:
                reads.add((arg1, arg2))
            return sqlite3.SQLITE_OK

        # The authorizer records the columns the query reads as SQLite
        # prepares it; the notes follow them, not every file loaded.
        converted, ambiguous = _settle_dates(dates)
        for name, (header, body) in parsed.items():
            db.executemany(f'INSERT INTO "{name}" VALUES ({", ".join("?" * len(header))})', body)
        db.set_authorizer(authorize)
        try:
            cursor = db.execute(sql)
            columns = [d[0] for d in cursor.description or ()]
            # An error on a later row (an integer overflow) is raised here,
            # and outside this handler it escaped as an exception.
            found = cursor.fetchmany(MAX_QUERY_ROWS + 1)
        except (sqlite3.Error, sqlite3.Warning) as exc:
            known = ""
            if "no such column" in str(exc):
                # Live: told only "no such column: amount", an agent gave up on
                # the query and added a statement's figures by hand.
                known = "".join(f"; {table} has the columns {', '.join(columns)}"
                                for table, columns in headers.items())
            return f"ERROR: the query was refused or invalid: {exc}{known}"
        # Notes once SQLite has accepted the query, so a query it refuses
        # costs no scan of its text.
        db.set_authorizer(None)
        notes = (_percent_notes(db, headers, reads, sql) + _blank_notes(blanks, reads, sql)
                 + _date_notes(db, ambiguous, converted, reads, sql, found) + _clock_notes(columns, found, sql))
    finally:
        db.close()
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(columns)
    # Round away binary floating-point noise (209166.05000000002) so the
    # model reads the figure the data actually holds.
    writer.writerows([[round(v, 9) if isinstance(v, float) else v for v in row]
                      for row in found[:MAX_QUERY_ROWS]])
    note = f"\n... [first {MAX_QUERY_ROWS} rows only]" if len(found) > MAX_QUERY_ROWS else ""
    return out.getvalue().rstrip("\n") + note + "".join("\n" + n for n in notes)
