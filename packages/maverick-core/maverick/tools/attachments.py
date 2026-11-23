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
        # The paths are storage locations outside the workspace: file tools
        # such as spreadsheet_read refuse them, and an agent that got that
        # refusal computed a payroll table by hand and got a row wrong.
        lines.append("Read text, PDF, CSV and Excel files with read_attachment and the id. For a CSV "
                     "or Excel file, "
                     "pass `sql` (one SELECT over the table `data`) to compute totals or "
                     "per-row values exactly. Only view_image and read_pdf accept these paths.")
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
            text = _pdf_attachment_text(match, args.get("pages"), sandbox)
            return text if text.startswith("ERROR:") else _window(text, args)
        if _is_workbook(match):
            return _workbook(match, args)
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
        return _window(text, args)

    return Tool(
        name="read_attachment",
        description=("Read the text of one file the user uploaded with this goal, "
                     "by the id `list_attachments` returns. A PDF returns its page text; "
                     "pass `pages` (for example '1-3,7') to read part of a long one. "
                     "A long file returns its first 100,000 characters: pass `search` "
                     "to get every line containing a phrase, or `offset` to read on. "
                     "An Excel file returns its first sheet as CSV. "
                     "For a CSV or Excel file, pass `sql`: "
                     "one read-only SELECT over the table `data` (its columns are the "
                     "header row). Use it for totals, counts, averages and per-row "
                     "calculations instead of working numbers out yourself, for example "
                     "`SELECT name, ROUND(rate*(MIN(hours,40)+MAX(hours-40,0)*1.5),2) AS pay "
                     "FROM data` or `SELECT dept, SUM(amount) FROM data GROUP BY dept`. "
                     "Before filtering on a column, look at the values it actually holds "
                     "(`SELECT DISTINCT receipt FROM data`): a missing receipt may be 'no', not blank."),
        input_schema={"type": "object",
                      "properties": {"id": {"type": "integer"},
                                     "sql": {"type": "string",
                                             "description": "Optional. One SELECT over `data` for a CSV or Excel file."},
                                     "pages": {"type": "string",
                                               "description": "Optional. PDF page ranges, for example '1-3,7'."},
                                     "search": {"type": "string",
                                                "description": "Optional. Return only the lines containing this text (case-insensitive)."},
                                     "offset": {"type": "integer",
                                                "description": "Optional. Character position to start reading from."}},
                      "required": ["id"]},
        fn=fn,
    )


_WORKBOOK_MIMES = ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                   "application/vnd.ms-excel.sheet.macroenabled.12")


def _is_workbook(match) -> bool:
    return (match.mime or "").lower() in _WORKBOOK_MIMES or match.filename.lower().endswith((".xlsx", ".xlsm"))


def _workbook(match, args: dict) -> str:
    """An Excel attachment's first sheet as a CSV table, so it can be read and
    queried like a CSV. Its cell-by-cell text companion led an agent to list
    items above their reorder level as below it."""
    from ..attachments import read_bytes
    from .csv_query import query_tables
    from .spreadsheet import xlsx_bytes_as_csv

    try:
        text = xlsx_bytes_as_csv(read_bytes(match.path))
    except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as data
        return f"ERROR: {match.filename} could not be read as a workbook: {exc}"
    if args.get("sql"):
        return query_tables({"data": (match.filename, text)}, str(args["sql"]))
    return (f"{match.filename}, first sheet as CSV (cached values of formulas). "
            "Pass `sql` to compute from it exactly.\n" + _window(text, args))


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
    return pdf_text(data, pages=pages or "", max_chars=_MAX_PDF_CHARS, sandbox=sandbox)


_MAX_PDF_CHARS = 1_000_000  # whole-document text, so search and offset reach every page
_MAX_MATCHES = 50
_MAX_MATCH_LINE = 500


def _window(text: str, args: dict) -> str:
    """The part of ``text`` the call asked for: matching lines, or up to
    ``_MAX_READ_CHARS`` from ``offset``, saying how to read on when cut."""
    search = args.get("search")
    if search is not None and str(search).strip():
        return _matching_lines(text, str(search).strip())
    raw = args.get("offset", 0)
    if type(raw) is not int or raw < 0 or (raw and raw >= len(text)):
        return f"ERROR: offset must be a whole number from 0 to {max(0, len(text) - 1)}"
    end = raw + _MAX_READ_CHARS
    part = text[raw:end]
    if end < len(text):
        part += (f"\n... [showing characters {raw}-{end} of {len(text)}; pass offset={end} "
                 "to continue, or search to find a phrase]")
    return part


def _matching_lines(text: str, phrase: str) -> str:
    wanted = phrase.casefold()
    hits = [(number, line) for number, line in enumerate(text.splitlines(), 1)
            if wanted in line.casefold()]
    if not hits:
        return f"no line matches {phrase!r}"
    shown = [f"line {number}: {line[:_MAX_MATCH_LINE]}" for number, line in hits[:_MAX_MATCHES]]
    more = f" (showing the first {_MAX_MATCHES})" if len(hits) > _MAX_MATCHES else ""
    noun = "line matches" if len(hits) == 1 else "lines match"
    return f"{len(hits)} {noun} {phrase!r}{more}:\n" + "\n".join(shown)


_TABLE_MIMES = ("text/csv", "application/csv", "text/comma-separated-values")


def query_table(filename: str, mime: str, text: str, sql: str) -> str:
    """One read-only SELECT over a CSV attachment, as the table ``data``."""
    from .csv_query import query_tables

    if not (mime.startswith(_TABLE_MIMES) or filename.lower().endswith(".csv")):
        return f"ERROR: {filename} is not a CSV file; `sql` works only on CSV attachments"
    return query_tables({"data": (filename, text)}, sql)
