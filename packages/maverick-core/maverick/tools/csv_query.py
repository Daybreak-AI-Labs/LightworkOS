"""Read-only SQL over CSV text, in a private in-memory SQLite database.

Shared by ``read_attachment`` (one uploaded CSV as ``data``) and
``spreadsheet_read``'s ``query`` (workspace CSV files, one table each). Exact
totals and comparisons replace the model adding numbers in its head. The
authorizer allows reading the loaded tables and calling built-in functions
only, so a statement cannot write, attach a file, change settings or load an
extension; one statement runs per call.
"""
from __future__ import annotations

import csv
import io
import sqlite3

MAX_QUERY_ROWS = 200


def _cell(value: str):
    """A CSV cell as a number when it is one, so SUM and ORDER BY work on it."""
    text = value.strip()
    for kind in (int, float):
        try:
            return kind(text)
        except ValueError:
            continue
    return value


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
    db.executemany(f'INSERT INTO "{name}" VALUES ({", ".join("?" * width)})',
                   [[_cell(c) for c in (row + [""] * width)[:width]] for row in rows[1:] if row])
    return None


def query_tables(tables: dict[str, tuple[str, str]], sql: str) -> str:
    """Run one SELECT over ``tables`` ({table: (filename, csv text)}) as CSV text."""
    db = sqlite3.connect(":memory:")
    try:
        for name, (filename, text) in tables.items():
            problem = _load(db, name, filename, text)
            if problem:
                return problem
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
            return f"ERROR: the query was refused or invalid: {exc}"
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
