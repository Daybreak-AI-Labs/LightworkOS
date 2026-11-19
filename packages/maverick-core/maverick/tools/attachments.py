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


_TABLE_MIMES = ("text/csv", "application/csv", "text/comma-separated-values")


def query_table(filename: str, mime: str, text: str, sql: str) -> str:
    """One read-only SELECT over a CSV attachment, as the table ``data``."""
    from .csv_query import query_tables

    if not (mime.startswith(_TABLE_MIMES) or filename.lower().endswith(".csv")):
        return f"ERROR: {filename} is not a CSV file; `sql` works only on CSV attachments"
    return query_tables({"data": (filename, text)}, sql)
