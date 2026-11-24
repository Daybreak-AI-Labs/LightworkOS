"""Read-only SQL over CSV text, in a private in-memory SQLite database.

Shared by ``read_attachment`` (one uploaded CSV as ``data``) and
``spreadsheet_read``'s ``query`` (workspace CSV files, one table each). Exact
totals and comparisons replace the model adding numbers in its head. The
authorizer allows reading the loaded tables and calling built-in functions
only, so a statement cannot write, attach a file, change settings or load an
extension; one statement runs per call. A blank in a column of numbers is
NULL; a blank in a text column is ''. ``hours(start, end)`` and
``overlap(start, end, from, to)`` work out clock times (HH:MM), counting past
midnight when the end is not after the start.
"""
from __future__ import annotations

import csv
import io
import re
import sqlite3

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
_DAY = 24 * 60


def _minutes(value) -> int | None:
    match = _CLOCK.fullmatch(str(value or "").strip())
    return int(match.group(1)) * 60 + int(match.group(2)) if match else None


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


def _load(db, name: str, filename: str, text: str) -> str | None:
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
    db.executemany(f'INSERT INTO "{name}" VALUES ({", ".join("?" * width)})', body)
    return None


def query_tables(tables: dict[str, tuple[str, str]], sql: str) -> str:
    """Run one SELECT over ``tables`` ({table: (filename, csv text)}) as CSV text."""
    db = sqlite3.connect(":memory:")
    # Clock times (shifts past midnight, hours inside a window) are where
    # hand arithmetic went wrong; these keep them inside the one query.
    db.create_function("hours", 2, _hours, deterministic=True)
    db.create_function("overlap", 4, _overlap, deterministic=True)
    try:
        headers: dict[str, list[str]] = {}
        for name, (filename, text) in tables.items():
            problem = _load(db, name, filename, text)
            if problem:
                return problem
            headers[name] = [row[1] for row in db.execute(f'PRAGMA table_info("{name}")')]
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
    return out.getvalue().rstrip("\n") + note
