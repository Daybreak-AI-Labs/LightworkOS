"""list_attachments / read_attachment tools.

``list_attachments`` enumerates files the user uploaded with the goal;
``read_attachment`` returns one's text by id. Attachments live outside the
agent workspace (``read_file`` cannot reach them) and may be sealed at rest,
so reading goes through :func:`maverick.attachments.read_bytes`, scoped to the
current goal. Images are embedded as vision blocks separately (see
``maverick.attachments.content_blocks_for_goal``).
"""
from __future__ import annotations

from . import Tool


def list_attachments_tool(world, goal_id: int | None) -> Tool:
    def fn(_args: dict) -> str:
        if goal_id is None:
            return "(no goal context; no attachments)"
        atts = world.list_attachments(goal_id)
        if not atts:
            return "(no attachments)"
        lines = [
            f"{a.id}  {a.filename}  {a.mime}  {a.size_bytes}B  {a.path}"
            for a in atts
        ]
        return "\n".join(lines)

    return Tool(
        name="list_attachments",
        description=(
            "List files the user uploaded with this goal. Returns one line per "
            "attachment: id, filename, mime, size, path. Use `read_attachment` "
            "with the id to read text content; images are already visible to you."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        fn=fn,
    )


_MAX_READ_CHARS = 100_000


def read_attachment_tool(world, goal_id: int | None) -> Tool:
    def fn(args: dict) -> str:
        if goal_id is None:
            return "ERROR: no goal context; no attachments"
        try:
            wanted = int(args["id"])
        except (KeyError, TypeError, ValueError):
            return "ERROR: 'id' must be an attachment id from list_attachments"
        match = next((a for a in world.list_attachments(goal_id) if a.id == wanted), None)
        if match is None:
            return f"ERROR: no attachment {wanted} on this goal"
        from ..attachments import READABLE_TEXT_MIMES, read_bytes
        if not match.mime.startswith(READABLE_TEXT_MIMES):
            return (f"ERROR: {match.filename} is {match.mime}; images are already "
                    "visible to you, and documents have a text companion when one "
                    "could be extracted")
        try:
            text = read_bytes(match.path).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as data
            return f"ERROR: {match.filename} could not be read: {exc}"
        if args.get("sql"):
            return query_table(match.filename, match.mime, text, str(args["sql"]))
        if len(text) > _MAX_READ_CHARS:
            return text[:_MAX_READ_CHARS] + f"\n... [truncated, total {len(text)} chars]"
        return text

    return Tool(
        name="read_attachment",
        description=("Read the text of one file the user uploaded with this goal, "
                     "by the id `list_attachments` returns. For a CSV file, pass `sql`: "
                     "one read-only SELECT over the table `data` (its columns are the "
                     "header row). Use it for totals, counts and averages instead of "
                     "adding numbers yourself."),
        input_schema={"type": "object",
                      "properties": {"id": {"type": "integer"},
                                     "sql": {"type": "string",
                                             "description": "Optional. One SELECT over `data` for a CSV."}},
                      "required": ["id"]},
        fn=fn,
    )


_MAX_QUERY_ROWS = 200
_TABLE_MIMES = ("text/csv", "application/csv", "text/comma-separated-values")


def _cell(value: str):
    """A CSV cell as a number when it is one, so SUM and ORDER BY work on it."""
    text = value.strip()
    for kind in (int, float):
        try:
            return kind(text)
        except ValueError:
            continue
    return value


def query_table(filename: str, mime: str, text: str, sql: str) -> str:
    """One read-only SELECT over a CSV attachment, in a private in-memory database.

    The authorizer allows reading the ``data`` table and calling built-in
    functions only, so a statement cannot write, attach a file, change
    settings or load an extension."""
    import csv
    import io
    import sqlite3

    if not (mime.startswith(_TABLE_MIMES) or filename.lower().endswith(".csv")):
        return f"ERROR: {filename} is not a CSV file; `sql` works only on CSV attachments"
    rows = list(csv.reader(io.StringIO(text)))
    if not rows or not any(cell.strip() for cell in rows[0]):
        return f"ERROR: {filename} has no header row"
    header = [cell.strip() or f"column_{i + 1}" for i, cell in enumerate(rows[0])]
    if len(set(header)) != len(header):
        return f"ERROR: {filename} repeats a column name in its header"
    db = sqlite3.connect(":memory:")
    try:
        quoted = ", ".join('"' + name.replace('"', '""') + '"' for name in header)
        db.execute(f"CREATE TABLE data ({quoted})")
        width = len(header)
        db.executemany(f"INSERT INTO data VALUES ({', '.join('?' * width)})",
                       [[_cell(c) for c in (row + [""] * width)[:width]] for row in rows[1:] if row])
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}

        def authorize(action, arg1, arg2, _db, _trigger):
            if action not in allowed:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_READ and arg1 != "data":
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() in {"load_extension", "readfile", "writefile"}:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        try:
            cursor = db.execute(sql)
        except (sqlite3.Error, sqlite3.Warning) as exc:
            return f"ERROR: the query was refused or invalid: {exc}"
        names = [d[0] for d in cursor.description or ()]
        found = cursor.fetchmany(_MAX_QUERY_ROWS + 1)
    finally:
        db.close()
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(names)
    # Round away binary floating-point noise (209166.05000000002) so the
    # model reads the figure the data actually holds.
    writer.writerows([[round(v, 9) if isinstance(v, float) else v for v in row]
                      for row in found[:_MAX_QUERY_ROWS]])
    note = f"\n... [first {_MAX_QUERY_ROWS} rows only]" if len(found) > _MAX_QUERY_ROWS else ""
    return out.getvalue().rstrip("\n") + note
