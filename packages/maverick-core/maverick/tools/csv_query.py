"""Read-only SQL over CSV text, in a private in-memory SQLite database.

Shared by ``read_attachment`` (one uploaded CSV as ``data``) and
``spreadsheet_read``'s ``query`` (workspace CSV files, one table each). Exact
totals and comparisons replace the model adding numbers in its head. The
authorizer allows reading the loaded tables and calling built-in functions
only, so a statement cannot write, attach a file, change settings or load an
extension; one statement runs per call. A blank in a column of numbers is
NULL; a blank in a text column is ''. A column of dates written 10/29/2026
or 29/10/2026 is stored as 2026-10-29 when its values, or another date
column loaded for the same query, show which part is the day, so SQLite's
date functions read it; a query that names such a column gets a note saying
so. ``hours(start, end)`` and
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


def _load(db, tables: dict[str, tuple[str, str]], ambiguous: list[tuple[str, str, str]],
          blanks: dict[tuple[str, str], int], converted: list[tuple[str, str, str, str]]) -> str | None:
    """Create and fill a table for each CSV text. The day/month order of
    dates is read across every table first: invoices.csv's 10/29/2026 showed
    month first, payments.csv held only 10/05/2026 and 11/02/2026, and with
    one read as 2026-10-05 and the other left as written a join on the date
    matched nothing. Columns that disagree keep their own reading."""
    parsed: dict[str, tuple[list[str], list[list]]] = {}
    undecided = []
    orders: set[str] = set()
    for name, (filename, text) in tables.items():
        table = _parse(filename, text)
        if isinstance(table, str):
            return table
        parsed[name] = table
        header, body = table
        for column in _text_columns(name, header, body, blanks):
            values = [row[column].strip() for row in body if row[column].strip()]
            parts = _date_parts(values)
            shown = _orders_shown(parts) if parts else set()
            if not parts or len(shown) > 1:
                continue
            dates = _iso_dates(parts, next(iter(shown), None))
            if dates == "ambiguous":
                undecided.append((name, header[column], body, column, values[0], parts))
            elif isinstance(dates, list):
                orders |= shown
                _convert(body, column, dates)
                converted.append((name, header[column], values[0], dates[0]))
    order = next(iter(orders)) if len(orders) == 1 else None
    for name, column_name, body, column, example, parts in undecided:
        dates = _iso_dates(parts, order)
        if dates == "ambiguous":
            ambiguous.append((name, column_name, example))
        elif isinstance(dates, list):
            _convert(body, column, dates)
            converted.append((name, column_name, example, dates[0]))
    for name, (header, body) in parsed.items():
        quoted = ", ".join('"' + column.replace('"', '""') + '"' for column in header)
        db.execute(f'CREATE TABLE "{name}" ({quoted})')
        db.executemany(f'INSERT INTO "{name}" VALUES ({", ".join("?" * len(header))})', body)
    return None


_DATE_FUNCTION = re.compile(r"\b(?:julianday|date|datetime|strftime|unixepoch|timediff)\s*\(", re.IGNORECASE)
_PERCENT_NAME = re.compile(r"pct|percent|%", re.IGNORECASE)
_PER_HUNDRED = re.compile(r"\b100(?:\.0*)?\b|\b0?\.01\b")
_LITERAL = re.compile(r"'(?:[^']|'')*'")


def _names(column: str, sql: str) -> bool:
    """Whether ``sql`` names ``column`` outside its quoted text: bare, in
    double quotes or after a table alias. A name followed by ( is a function
    call, so date(due) does not name a column called date."""
    name = re.escape(column)
    return re.search(rf'"{name}"|(?<![\w"]){name}(?![\w"]|\s*\()', _LITERAL.sub("''", sql),
                     re.IGNORECASE) is not None


def _date_arguments(sql: str) -> list[str]:
    """The text inside each date function's parentheses."""
    text = _LITERAL.sub("''", sql)
    arguments = []
    for match in _DATE_FUNCTION.finditer(text):
        depth, end = 1, match.end()
        while end < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            end += 1
        arguments.append(text[match.end():end])
    return arguments


def _in_arithmetic(column: str, sql: str) -> bool:
    """Whether ``sql`` adds, subtracts, multiplies or divides with ``column``
    (bare, quoted or qualified by a table alias)."""
    name = re.escape(column)
    ref = rf'(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:"{name}"|(?<![\w"]){name}(?![\w"]))'
    return re.search(rf"[-+*/]\s*{ref}|{ref}\s*[-+*/]", sql) is not None


def _blank_notes(blanks: dict[tuple[str, str], int], sql: str) -> list[str]:
    """Columns of numbers with blanks that the query does arithmetic with:
    a blank is NULL (so AVG and MAX are right), and NULL in arithmetic is
    NULL. Live: amount - paid was NULL for every unpaid invoice, and an aging
    summary's SUM left them out. Counted per table: summed by column name, a
    file loaded as data and under its own name had twice its blanks."""
    notes = []
    for (table, column), count in blanks.items():
        name = re.escape(column)
        guarded = re.search(rf'(?:coalesce|ifnull)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"?{name}"?\s*,',
                            sql, re.IGNORECASE)
        if _in_arithmetic(column, sql) and not guarded:
            notes.append(f"Note: {table}.{column} is blank in {count} row{'s' if count != 1 else ''}, and a blank number "
                         f"is NULL, so arithmetic with it gives NULL in those rows and SUM leaves them out. "
                         f"Write COALESCE({column}, 0) to count a blank as 0.")
    return notes


def _percent_notes(db, headers: dict[str, list[str]], sql: str) -> list[str]:
    """Percent columns holding whole percents (15 for 15%) that the query
    uses in arithmetic without dividing by 100. Live: revenue as
    qty * price * (1 - discount_pct) came out negative and the answer blamed
    the data."""
    if _PER_HUNDRED.search(sql):
        return []
    notes = []
    for table, columns in headers.items():
        for column in columns:
            if not _PERCENT_NAME.search(column):
                continue
            if not _in_arithmetic(column, sql):
                continue
            largest = db.execute(f'SELECT MAX("{column}") FROM "{table}" '
                                 f'WHERE typeof("{column}") IN (\'integer\', \'real\')').fetchone()[0]
            if largest is not None and largest > 1:
                shown = int(largest) if float(largest).is_integer() else largest
                notes.append(f"Note: {column} holds percents (largest {shown}), so {shown} means {shown}%; "
                             "this query uses it in arithmetic as it stands. To use it as a fraction, "
                             "divide it by 100.")
    return notes


def _date_notes(db, headers: dict[str, list[str]], ambiguous: list[tuple[str, str, str]],
                converted: list[tuple[str, str, str, str]], sql: str) -> list[str]:
    """Notes on dates the query names. A converted column reads as
    2026-10-29 while the file shows 10/29/2026: WHERE date = '10/29/2026'
    and GROUP BY substr(date, 1, 2) silently matched nothing or grouped on
    the year. The note that date functions cannot read a column is for a
    column a date function reads, with one of its values: fired on any empty
    result column, it sent the agent to fix dates that were fine."""
    notes = [f"Note: {table}.{column} holds dates written like {written}; queries read them as {iso} "
             "(YYYY-MM-DD), so compare, filter and group on that form."
             for table, column, written, iso in converted if _names(column, sql)]
    if not _DATE_FUNCTION.search(sql):
        return notes
    undecided = {(table, column) for table, column, _example in ambiguous}
    arguments = _date_arguments(sql)
    for table, columns in headers.items():
        for column in columns:
            if (table, column) in undecided or not any(_names(column, argument) for argument in arguments):
                continue
            quoted = '"' + column.replace('"', '""') + '"'
            unread = db.execute(f'SELECT {quoted} FROM "{table}" WHERE typeof({quoted}) = \'text\' '
                                f"AND trim({quoted}) <> '' AND julianday({quoted}) IS NULL LIMIT 1").fetchone()
            if unread:
                notes.append(f"Note: {table}.{column} holds values such as '{unread[0]}', which SQLite's date "
                             "functions cannot read: they read dates written YYYY-MM-DD and give nothing for "
                             "other forms.")
    named = [f"{table}.{column} (such as '{example}')" for table, column, example in ambiguous if _names(column, sql)]
    if named:
        notes.append(f"Note: {'; '.join(named)} {'was' if len(named) == 1 else 'were'} left as written: "
                     "no value shows whether the day or the month comes first, so date functions cannot "
                     "read it. Ask which it is, or convert it in the query with substr.")
    return notes


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
    ambiguous: list[tuple[str, str, str]] = []
    blanks: dict[tuple[str, str], int] = {}
    converted: list[tuple[str, str, str, str]] = []
    try:
        problem = _load(db, tables, ambiguous, blanks, converted)
        if problem:
            return problem
        headers = {name: [row[1] for row in db.execute(f'PRAGMA table_info("{name}")')] for name in tables}
        notes = (_percent_notes(db, headers, sql) + _blank_notes(blanks, sql)
                 + _date_notes(db, headers, ambiguous, converted, sql))
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
        names = set(tables)

        def authorize(action, arg1, arg2, _db, _trigger):
            if action not in allowed:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and arg1 not in names:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in {"load_extension", "readfile", "writefile"}:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

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
