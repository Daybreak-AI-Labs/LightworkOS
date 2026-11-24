"""Read-only SQL over CSV text, in a private in-memory SQLite database.

Shared by ``read_attachment`` (one uploaded CSV as ``data``) and
``spreadsheet_read``'s ``query`` (workspace CSV files, one table each). Exact
totals and comparisons replace the model adding numbers in its head. The
authorizer allows reading the loaded tables and calling built-in functions
only, so a statement cannot write, attach a file, change settings or load an
extension; one statement runs per call. A blank in a column of numbers is
NULL; a blank in a text column is ''. A column of dates written 10/29/2026
or 29/10/2026 is stored as 2026-10-29 when its values show which part is the
day, so SQLite's date functions read it. ``hours(start, end)`` and
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
    if value is None:
        return None
    try:
        number = Decimal(value) if isinstance(value, int) else Decimal(repr(float(value)))
        places = max(0, min(int(digits or 0), 15))
    except (TypeError, ValueError, InvalidOperation):
        return None
    if not number.is_finite():
        return float(number)
    return float(number.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP))


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


def _iso_dates(values: list[str]) -> list[str] | str | None:
    """The column's dates as YYYY-MM-DD, "ambiguous" when no value shows
    whether the day or the month comes first, or None when not all dates."""
    parts = []
    for value in values:
        text = value.strip()
        match = _DATE_YMD.fullmatch(text)
        if match:
            parts.append(("ymd", int(match.group(1)), int(match.group(3)), int(match.group(4))))
            continue
        match = _DATE_DMY_MDY.fullmatch(text)
        if match is None:
            return None
        parts.append(("xy", int(match.group(1)), int(match.group(3)), int(match.group(4))))
    if not parts:
        return None
    day_first = any(kind == "xy" and a > 12 for kind, a, _b, _y in parts)
    month_first = any(kind == "xy" and b > 12 for kind, _a, b, _y in parts)
    if day_first and month_first:
        return None
    if not (day_first or month_first) and any(kind == "xy" and a != b for kind, a, b, _y in parts):
        return "ambiguous"
    dates = []
    for kind, a, b, y in parts:
        year, month, day = (a, b, y) if kind == "ymd" else (y, b, a) if day_first else (y, a, b)
        try:
            dates.append(datetime.date(year, month, day).isoformat())
        except ValueError:
            return None
    return dates


def _load(db, name: str, filename: str, text: str, ambiguous: list[str] | None = None,
          blanks: dict[str, int] | None = None) -> str | None:
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or not any(cell.strip() for cell in rows[0]):
        return f"ERROR: {filename} has no header row"
    header = [cell.strip() or f"column_{i + 1}" for i, cell in enumerate(rows[0])]
    if len(set(header)) != len(header):
        return f"ERROR: {filename} repeats a column name in its header"
    quoted = ", ".join('"' + column.replace('"', '""') + '"' for column in header)
    db.execute(f'CREATE TABLE "{name}" ({quoted})')
    width = len(header)
    body = [[_cell(c) for c in (row + [""] * width)[:width]] for row in rows[1:] if row]
    # A blank in a column of numbers is NULL: as text '' it outranked every
    # number in MAX and counted as 0 in AVG (a statement's withdrawal and
    # deposit columns are each blank where the other is filled). A text
    # column keeps '' so a filter such as receipt = '' still finds blanks.
    for column in range(width):
        filled = [row[column] for row in body if not (isinstance(row[column], str) and not row[column].strip())]
        if filled and all(isinstance(value, int | float) for value in filled):
            for row in body:
                if isinstance(row[column], str):
                    row[column] = None
            if blanks is not None and len(filled) < len(body):
                blanks[header[column]] = blanks.get(header[column], 0) + len(body) - len(filled)
        elif filled and all(isinstance(value, str) for value in filled):
            dates = _iso_dates(filled)
            if dates == "ambiguous" and ambiguous is not None:
                ambiguous.append(f"{name}.{header[column]} (such as '{filled[0].strip()}')")
            elif isinstance(dates, list):
                converted = iter(dates)
                for row in body:
                    if isinstance(row[column], str) and row[column].strip():
                        row[column] = next(converted)
    db.executemany(f'INSERT INTO "{name}" VALUES ({", ".join("?" * width)})', body)
    return None


_DATE_FUNCTION = re.compile(r"\b(?:julianday|date|datetime|strftime|unixepoch|timediff)\s*\(", re.IGNORECASE)
_PERCENT_NAME = re.compile(r"pct|percent|%", re.IGNORECASE)
_PER_HUNDRED = re.compile(r"\b100(?:\.0*)?\b|\b0?\.01\b")


def _in_arithmetic(column: str, sql: str) -> bool:
    """Whether ``sql`` adds, subtracts, multiplies or divides with ``column``
    (bare, quoted or qualified by a table alias)."""
    name = re.escape(column)
    ref = rf'(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:"{name}"|(?<![\w"]){name}(?![\w"]))'
    return re.search(rf"[-+*/]\s*{ref}|{ref}\s*[-+*/]", sql) is not None


def _blank_notes(blanks: dict[str, int], sql: str) -> list[str]:
    """Columns of numbers with blanks that the query does arithmetic with:
    a blank is NULL (so AVG and MAX are right), and NULL in arithmetic is
    NULL. Live: amount - paid was NULL for every unpaid invoice, and an aging
    summary's SUM left them out."""
    notes = []
    for column, count in blanks.items():
        name = re.escape(column)
        guarded = re.search(rf'(?:coalesce|ifnull)\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?"?{name}"?\s*,',
                            sql, re.IGNORECASE)
        if _in_arithmetic(column, sql) and not guarded:
            notes.append(f"Note: {column} is blank in {count} row{'s' if count != 1 else ''}, and a blank number "
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


def _date_notes(columns: list[str], rows: list, ambiguous: list[str], sql: str) -> list[str]:
    if not _DATE_FUNCTION.search(sql):
        return []
    notes = []
    empty = [c for i, c in enumerate(columns) if rows and all(row[i] is None for row in rows)]
    if empty:
        notes.append(f"Note: {', '.join(empty)} {'is' if len(empty) == 1 else 'are'} empty in every row. "
                     "SQLite's date functions read dates written YYYY-MM-DD and give nothing for other forms.")
    if ambiguous:
        notes.append(f"Note: {'; '.join(ambiguous)} {'was' if len(ambiguous) == 1 else 'were'} left as written: "
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
    ambiguous: list[str] = []
    blanks: dict[str, int] = {}
    try:
        headers: dict[str, list[str]] = {}
        for name, (filename, text) in tables.items():
            problem = _load(db, name, filename, text, ambiguous, blanks)
            if problem:
                return problem
            headers[name] = [row[1] for row in db.execute(f'PRAGMA table_info("{name}")')]
        notes = _percent_notes(db, headers, sql) + _blank_notes(blanks, sql)
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
        except (sqlite3.Error, sqlite3.Warning) as exc:
            known = ""
            if "no such column" in str(exc):
                # Live: told only "no such column: amount", an agent gave up on
                # the query and added a statement's figures by hand.
                known = "".join(f"; {table} has the columns {', '.join(columns)}"
                                for table, columns in headers.items())
            return f"ERROR: the query was refused or invalid: {exc}{known}"
        columns = [d[0] for d in cursor.description or ()]
        found = cursor.fetchmany(MAX_QUERY_ROWS + 1)
        notes += _date_notes(columns, found, ambiguous, sql)
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
