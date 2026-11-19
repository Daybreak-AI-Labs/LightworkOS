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
            "with the id to read text, PDF or CSV content; pass an image's path "
            "to `view_image` to look at it."
        ),
        input_schema={
            "type": "object",
            "properties": {},
        },
        fn=fn,
    )


_MAX_READ_CHARS = 100_000


def goal_attachment_bytes(world, goal_id: int | None, source: str):
    """``(plaintext, attachment)`` when ``source`` is the stored path of one of
    this goal's uploads, else None.

    Attachments live outside the agent workspace and may be sealed at rest,
    so the path ``list_attachments`` reports cannot be opened as a workspace
    file. Only an exact match to a path recorded for this goal is honoured:
    nothing else outside the workspace becomes reachable.
    """
    if world is None or goal_id is None or not isinstance(source, str) or not source.strip():
        return None
    from ..attachments import AttachmentRejected, read_bytes

    wanted = source.strip()
    try:
        match = next((a for a in world.list_attachments(goal_id) if a.path == wanted), None)
    except Exception:  # noqa: BLE001 -- no attachment store: nothing to match
        return None
    if match is None:
        return None
    try:
        return read_bytes(match.path), match
    except (OSError, ValueError, AttachmentRejected):
        return None


def read_attachment_tool(world, goal_id: int | None, sandbox=None) -> Tool:
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
        if match.mime == "application/pdf":
            return _pdf_attachment_text(match, args.get("pages"), sandbox)
        if not match.mime.startswith(READABLE_TEXT_MIMES):
            return (f"ERROR: {match.filename} is {match.mime}; pass an image's path to "
                    "view_image, and read a document through its .extracted.txt "
                    "companion when list_attachments shows one")
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
                     "by the id `list_attachments` returns. A PDF returns its page text; "
                     "pass `pages` (for example '1-3,7') to read part of a long one. "
                     "For a CSV file, pass `sql`: "
                     "one read-only SELECT over the table `data` (its columns are the "
                     "header row). Use it for totals, counts and averages instead of "
                     "adding numbers yourself."),
        input_schema={"type": "object",
                      "properties": {"id": {"type": "integer"},
                                     "sql": {"type": "string",
                                             "description": "Optional. One SELECT over `data` for a CSV."},
                                     "pages": {"type": "string",
                                               "description": "Optional. PDF page ranges, for example '1-3,7'."}},
                      "required": ["id"]},
        fn=fn,
    )


def _pdf_attachment_text(match, pages, sandbox=None) -> str:
    """Page text of an uploaded PDF (sealed or not), through ``read_pdf``'s parser."""
    from ..attachments import AttachmentRejected, read_bytes
    from .pdf_reader import pdf_text

    if pages is not None and not isinstance(pages, str):
        return "ERROR: pages must be a page-range string such as '1-3,7'"
    try:
        data = read_bytes(match.path)
    except (OSError, ValueError, AttachmentRejected) as exc:
        return f"ERROR: {match.filename} could not be read: {exc}"
    return pdf_text(data, pages=pages or "", max_chars=_MAX_READ_CHARS, sandbox=sandbox)


_TABLE_MIMES = ("text/csv", "application/csv", "text/comma-separated-values")


def query_table(filename: str, mime: str, text: str, sql: str) -> str:
    """One read-only SELECT over a CSV attachment, as the table ``data``."""
    from .csv_query import query_tables

    if not (mime.startswith(_TABLE_MIMES) or filename.lower().endswith(".csv")):
        return f"ERROR: {filename} is not a CSV file; `sql` works only on CSV attachments"
    return query_tables({"data": (filename, text)}, sql)
