"""list_attachments / read_attachment tools.

``list_attachments`` enumerates files the user uploaded with the goal;
``read_attachment`` returns one's text by id. Attachments live outside the
agent workspace (``read_file`` cannot reach them) and may be sealed at rest,
so reading goes through :func:`maverick.attachments.read_bytes`, scoped to the
current goal. Images are embedded as vision blocks separately (see
``maverick.attachments.content_blocks_for_goal``).
"""
from __future__ import annotations

import re

from . import Tool

_EARLIER = "  (from an earlier message in this conversation)"
_MAX_EARLIER_GOALS = 50


def _earlier_in_chat(world, goal_id: int) -> list[int]:
    """Earlier goals of this goal's dashboard chat, from the same person,
    newest first.

    A follow-up ("Ben's hours were 46, not 50") is a new goal; with only its
    own uploads it could not see the timesheet attached to the first message
    and guessed. A dashboard chat is one conversation per thread; a channel
    conversation (Slack and the like) spans everything a person ever sent
    there, so it does not share."""
    try:
        rows = world.tenant_query(
            "SELECT DISTINCT t2.goal_id FROM turns t "
            "JOIN conversations c ON c.id=t.conversation_id "
            "JOIN turns t2 ON t2.conversation_id=c.id "
            "JOIN goals g ON g.id=t.goal_id JOIN goals g2 ON g2.id=t2.goal_id "
            "WHERE t.goal_id=? AND t.role='user' AND c.channel='web' "
            "AND t2.goal_id IS NOT NULL AND t2.goal_id<? "
            "AND {tenant_exact:g.tenant_id} AND {tenant_exact:g2.tenant_id} "
            "ORDER BY t2.goal_id DESC", (int(goal_id), int(goal_id)))
        own = world.get_goal(goal_id)
    except Exception:  # noqa: BLE001 -- no chat record: the goal's own files only
        return []
    owner = getattr(own, "owner", None)
    earlier = []
    for (other,) in rows[:_MAX_EARLIER_GOALS]:
        goal = world.get_goal(int(other))
        if goal is not None and getattr(goal, "owner", None) == owner:
            earlier.append(int(other))
    return earlier


def visible_attachments(world, goal_id: int) -> list[tuple[object, bool]]:
    """``(attachment, earlier)`` for this goal's uploads, then those of earlier
    messages in its chat (``earlier`` True)."""
    seen = [(a, False) for a in world.list_attachments(goal_id)]
    for other in _earlier_in_chat(world, goal_id):
        seen += [(a, True) for a in world.list_attachments(other)]
    return seen


def list_attachments_tool(world, goal_id: int | None) -> Tool:
    def fn(_args: dict) -> str:
        if goal_id is None:
            return "(no goal context; no attachments)"
        atts = visible_attachments(world, goal_id)
        if not atts:
            return "(no attachments)"
        lines = [
            f"{a.id}  {a.filename}  {a.mime}  {a.size_bytes}B  {a.path}" + (_EARLIER if earlier else "")
            for a, earlier in atts
        ]
        # The paths are storage locations outside the workspace: file tools
        # such as spreadsheet_read refuse them, and an agent that got that
        # refusal computed a payroll table by hand and got a row wrong.
        lines.append("Read text, PDF, CSV and Excel files with read_attachment and the id. For a CSV "
                     "or Excel file, a PDF statement or invoice, or a table in a Word document, "
                     "pass `sql` (one SELECT over the table `data`) to compute totals or "
                     "per-row values exactly. Only view_image and read_pdf accept these paths.")
        names = [name for name, _a in _table_files(a for a, _earlier in atts)]
        if len(names) > 1:
            lines.append("In `sql`, every one of these files is also a table named after it, so one query "
                         f"can join them: {', '.join(names)}.")
        return "\n".join(lines)

    return Tool(
        name="list_attachments",
        description=(
            "List files the user uploaded with this goal and with earlier messages in "
            "this conversation. Returns one line per "
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
        match = next((a for a, _ in visible_attachments(world, goal_id) if a.path == wanted), None)
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
        match = next((a for a, _ in visible_attachments(world, goal_id) if a.id == wanted), None)
        if match is None:
            return f"ERROR: no attachment {wanted} on this goal"
        from ..attachments import READABLE_TEXT_MIMES, read_bytes
        others = _OtherFiles(world, goal_id, match, sandbox) if args.get("sql") else None
        if match.mime == "application/pdf":
            text = _pdf_attachment_text(match, args.get("pages"), sandbox)
            if text.startswith("ERROR:"):
                return text
            if args.get("sql"):
                return _pdf_table_query(match.filename, text, str(args["sql"]), others)
            return _window(text, args)
        source = _companion_source(world, goal_id, match) if args.get("sql") else None
        if source is not None:
            # Live: `sql` on a timesheet's .extracted.txt was refused as "not a
            # CSV file", and the agent worked the shifts out by hand, wrongly.
            others = _OtherFiles(world, goal_id, source, sandbox)
            return _word_query(source, args, others) if _is_word(source) else _workbook(source, args, others)
        if _is_workbook(match):
            return _workbook(match, args, others)
        if _is_word(match):
            if args.get("sql"):
                return _word_query(match, args, others)
            companion = next((a.id for a, _e in visible_attachments(world, goal_id)
                              if a.filename == match.filename + ".extracted.txt"), None)
            return (f"ERROR: {match.filename} is a Word document; read its text through its .extracted.txt "
                    f"companion{f' (id {companion})' if companion is not None else ''}, and pass `sql` with "
                    "this id to query one of its tables exactly")
        if not match.mime.startswith(READABLE_TEXT_MIMES):
            return (f"ERROR: {match.filename} is {match.mime}; pass an image's path to "
                    "view_image, and read a document through its .extracted.txt "
                    "companion when list_attachments shows one")
        try:
            text = read_bytes(match.path).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as data
            return f"ERROR: {match.filename} could not be read: {exc}"
        if args.get("sql"):
            return query_table(match.filename, match.mime, text, str(args["sql"]), others)
        return _window(text, args)

    return Tool(
        name="read_attachment",
        description=("Read the text of one file the user uploaded with this goal, "
                     "by the id `list_attachments` returns. A PDF returns its page text; "
                     "pass `pages` (for example '1-3,7') to read part of a long one. "
                     "A long file returns its first 100,000 characters: pass `search` "
                     "to get every line containing a phrase, or `offset` to read on. "
                     "An Excel file returns one sheet as CSV, the first unless `sheet` names another, "
                     "and lists its sheets. "
                     "For a CSV or Excel file, a PDF with a table of figures (a bank "
                     "statement, an invoice) or a Word document's table (the first unless `table` "
                     "picks another), pass `sql`: "
                     "one read-only SELECT over the table `data` (its columns are the "
                     "header row; in a PDF, the table's headings). The task's other attached files are "
                     "tables in the same query, named after the file (october_sales.csv is october_sales; "
                     "a workbook's sheets are also <name>_<sheet>), so one query can join them. "
                     "Dates written 10/29/2026 become 2026-10-29 when the column shows which part is "
                     "the day. Use it for totals, counts, averages and per-row "
                     "calculations instead of working numbers out yourself, for example "
                     "`SELECT name, ROUND(rate*(MIN(hours,40)+MAX(hours-40,0)*1.5),2) AS pay "
                     "FROM data` or `SELECT dept, SUM(amount) FROM data GROUP BY dept`. "
                     "For clock times (HH:MM or 3:30 PM) use `hours(clock_in, clock_out)`, which runs past "
                     "midnight when the end is not after the start, or `hours(shift)` for a shift written "
                     "'7:00-15:30', and `overlap(clock_in, "
                     "clock_out, '22:00', '06:00')` for the hours inside a window such as a night "
                     "premium's. Before filtering on a column, look at the values it actually holds "
                     "(`SELECT DISTINCT receipt FROM data`): a missing receipt may be 'no', not blank. "
                     "When the request defines a condition (overdue = past its due date and not "
                     "paid), filter on the fields it names, not on a status or label column, "
                     "which can be out of date."),
        input_schema={"type": "object",
                      "properties": {"id": {"type": "integer"},
                                     "sql": {"type": "string",
                                             "description": "Optional. One SELECT over `data` for a CSV or Excel file."},
                                     "sheet": {"type": "string",
                                               "description": "Optional. For an Excel file, the sheet to read or query (default: the first)."},
                                     "table": {"type": "integer",
                                               "description": "Optional. For a Word document, which of its tables `sql` queries (1 is the first)."},
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


def _workbook(match, args: dict, others=None) -> str:
    """An Excel attachment's sheet as a CSV table, so it can be read and
    queried like a CSV: the first sheet, or the one ``sheet`` names. Its
    cell-by-cell text companion led an agent to list items above their
    reorder level as below it; a workbook with its transactions on a second
    sheet could not be totalled at all."""
    from ..attachments import read_bytes
    from .spreadsheet import xlsx_bytes_as_csv, xlsx_bytes_sheet_names

    wanted = str(args.get("sheet") or "").strip() or None
    try:
        data = read_bytes(match.path)
        names = xlsx_bytes_sheet_names(data)
        if wanted is not None:
            found = next((name for name in names if name == wanted), None) or next(
                (name for name in names if name.casefold() == wanted.casefold()), None)
            if found is None:
                return f"ERROR: {match.filename} has no sheet {wanted!r}; its sheets are {', '.join(names)}"
            wanted = found
        text = xlsx_bytes_as_csv(data, wanted)
    except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as data
        return f"ERROR: {match.filename} could not be read as a workbook: {exc}"
    shown = wanted or (names[0] if names else "first sheet")
    if args.get("sql"):
        result = _query((match.filename, text), str(args["sql"]), others)
        if result.startswith("ERROR") and len(names) > 1:
            result += f". This queried the sheet {shown!r}; pass `sheet` to query {', '.join(n for n in names if n != shown)}"
        return result
    sheets = (f" Its sheets are {', '.join(names)}; this is {shown!r}, and `sheet` reads or queries another."
              if len(names) > 1 else "")
    return (f"{match.filename}, sheet {shown!r} as CSV (cached values of formulas).{sheets} "
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


def _pdf_table_query(filename: str, text: str, sql: str, others=None) -> str:
    """One read-only SELECT over a statement or invoice PDF's table."""
    from .pdf_reader import figures_outside_table, table_csv

    table = table_csv(text)
    if table is None:
        return (f"ERROR: no table of figures was found in {filename}; read its text instead "
                "and add any figures with compute")
    result = _query((filename, table), sql, others)
    outside = figures_outside_table(text)
    if result.startswith("ERROR") or not outside:
        return result
    # Live: with only the table in view, an agent took the first row's balance
    # as the statement's opening balance and said it did not reconcile.
    return result + "\n\nFigures in the PDF outside the table:\n" + "\n".join(outside)


_TABLE_MIMES = ("text/csv", "application/csv", "text/comma-separated-values")


def query_table(filename: str, mime: str, text: str, sql: str, others=None) -> str:
    """One read-only SELECT over a CSV attachment, as the table ``data``."""
    if not _is_csv(filename, mime):
        return f"ERROR: {filename} is not a CSV file; `sql` works only on CSV attachments"
    return _query((filename, text), sql, others)


def _is_csv(filename: str, mime: str) -> bool:
    return (mime or "").startswith(_TABLE_MIMES) or filename.lower().endswith(".csv")


_WORD_MIMES = ("application/vnd.openxmlformats-officedocument.wordprocessingml.document",)
_COMPANION_ENDINGS = (".extracted.txt", ".transcript.txt")


def _is_word(match) -> bool:
    return (match.mime or "").lower() in _WORD_MIMES or match.filename.lower().endswith(".docx")


def _rows_csv(rows: list[list[str]]) -> str:
    import csv
    import io

    out = io.StringIO()
    csv.writer(out, lineterminator="\n").writerows(rows)
    return out.getvalue()


def _companion_source(world, goal_id, match):
    """The Word document or workbook a text companion (``<file>.extracted.txt``)
    was made from, when it is visible to this goal."""
    if not match.filename.lower().endswith(".extracted.txt"):
        return None
    name = match.filename[:-len(".extracted.txt")]
    return next((a for a, _e in visible_attachments(world, goal_id)
                 if a.filename == name and (_is_word(a) or _is_workbook(a))), None)


def _word_tables(match):
    """A Word attachment's tables as rows of cell text, or an ERROR string."""
    from ..attachments import AttachmentRejected, read_bytes
    try:
        from maverick_knowledge.parse import word_document_tables
    except ImportError:
        return (f"ERROR: querying {match.filename}'s tables needs the maverick-knowledge package; "
                "read its text through its .extracted.txt companion instead")
    try:
        return word_document_tables(read_bytes(match.path))
    except (OSError, ValueError, AttachmentRejected) as exc:
        return f"ERROR: {match.filename} could not be read as a Word document: {exc}"
    except Exception as exc:  # noqa: BLE001 -- zip and XML errors, surfaced as data
        return f"ERROR: {match.filename} could not be read as a Word document: {type(exc).__name__}"


def _word_query(match, args: dict, others=None) -> str:
    """One read-only SELECT over a table in a Word attachment. Live: a
    timesheet in a Word table was read one cell per line and added up by hand,
    and two of four people's hours came out wrong."""
    tables = _word_tables(match)
    if isinstance(tables, str):
        return tables
    if not tables:
        return (f"ERROR: {match.filename} has no table; read its text through its .extracted.txt "
                "companion and add any figures with compute")
    chosen = args.get("table", 1)
    if type(chosen) is not int or not 1 <= chosen <= len(tables):
        return f"ERROR: {match.filename} has {len(tables)} table{'s' if len(tables) != 1 else ''}; pass `table` from 1 to {len(tables)}"
    result = _query((match.filename, _rows_csv(tables[chosen - 1])), str(args["sql"]), others)
    if len(tables) > 1 and "table" not in args and not result.startswith("ERROR"):
        result += (f"\n\nNote: {match.filename} has {len(tables)} tables; this queried the first, "
                   "and `table` picks another.")
    return result


def _table_name(filename: str) -> str:
    from pathlib import PurePath

    return re.sub(r"[^a-z0-9_]", "_", PurePath(filename).stem.lower()) or "file"


def _table_files(attachments) -> list[tuple[str, object]]:
    """``(table name, attachment)`` for each attachment ``sql`` can read: CSV,
    Excel, PDF and Word files, each named after its file, the first of a name
    winning."""
    found: dict[str, object] = {}
    for a in attachments:
        name = a.filename.lower()
        if name.endswith(_COMPANION_ENDINGS):
            continue
        if not (_is_csv(a.filename, a.mime) or _is_workbook(a) or _is_word(a)
                or (a.mime or "") == "application/pdf"):
            continue
        found.setdefault(_table_name(a.filename), a)
    return list(found.items())


def _mentions(sql: str, name: str) -> bool:
    return re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", sql, re.IGNORECASE) is not None


class _OtherFiles:
    """The task's other attached files as tables of one query, named after
    each file and loaded only when the query names them. Live: an agent wrote
    FROM read_attachment_158 to join sales to a cost workbook, was refused,
    and matched SKUs to categories in its head."""

    def __init__(self, world, goal_id, current, sandbox=None):
        self.sandbox = sandbox
        self.files = [(name, a) for name, a in _table_files(a for a, _e in visible_attachments(world, goal_id))
                      if a.id != current.id and name != "data"]

    def tables(self, sql: str):
        """``{table: (filename, csv text)}`` for the files ``sql`` names, or an ERROR string."""
        tables: dict[str, tuple[str, str]] = {}
        for name, a in self.files:
            if not re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}", sql, re.IGNORECASE):
                continue
            loaded = self._load(name, a, sql)
            if isinstance(loaded, str):
                return loaded
            tables.update(loaded)
        return tables

    def _load(self, name: str, a, sql: str):
        from ..attachments import AttachmentRejected, read_bytes
        if _is_workbook(a):
            from .spreadsheet import xlsx_bytes_as_csv, xlsx_bytes_sheet_names
            try:
                data = read_bytes(a.path)
                sheets = {sheet: xlsx_bytes_as_csv(data, sheet) for sheet in xlsx_bytes_sheet_names(data)}
            except Exception as exc:  # noqa: BLE001 -- surfaced to the agent as data
                return f"ERROR: {a.filename} could not be read as a workbook: {exc}"
            tables = {}
            for sheet, text in sheets.items():
                table = f"{name}_{re.sub(r'[^a-z0-9_]', '_', sheet.lower())}"
                if _mentions(sql, table):
                    tables[table] = (f"{a.filename}, sheet {sheet!r}", text)
            if _mentions(sql, name):
                # The first sheet holding a table, past a "Read me" note.
                sheet, text = next(((s, t) for s, t in sheets.items() if len(t.strip().splitlines()) > 1),
                                   next(iter(sheets.items()), ("", "")))
                tables[name] = (f"{a.filename}, sheet {sheet!r}", text)
            return tables
        if not _mentions(sql, name):
            return {}
        if _is_word(a):
            found = _word_tables(a)
            if isinstance(found, str):
                return found
            if not found:
                return f"ERROR: {a.filename} has no table to query"
            return {name: (a.filename, _rows_csv(found[0]))}
        if (a.mime or "") == "application/pdf":
            from .pdf_reader import table_csv
            text = _pdf_attachment_text(a, None, self.sandbox)
            table = None if text.startswith("ERROR:") else table_csv(text)
            if table is None:
                return f"ERROR: no table of figures was found in {a.filename}"
            return {name: (a.filename, table)}
        try:
            return {name: (a.filename, read_bytes(a.path).decode("utf-8", errors="replace"))}
        except (OSError, ValueError, AttachmentRejected) as exc:
            return f"ERROR: {a.filename} could not be read: {exc}"

    def hint(self, filename: str) -> str:
        def kind(a) -> str:
            return (f"{a.filename}; its sheets are also {_table_name(a.filename)}_<sheet>" if _is_workbook(a)
                    else f"{a.filename}, its first table" if _is_word(a) else a.filename)
        listed = [f"data ({filename}, also {_table_name(filename)})"] + [
            f"{name} ({kind(a)})" for name, a in self.files]
        return f"; this query can read the tables {', '.join(listed)}"


def _query(primary: tuple[str, str], sql: str, others=None) -> str:
    """``sql`` over ``primary`` as the table ``data``, with the task's other
    files it names as tables of their own."""
    from .csv_query import query_tables

    tables = {"data": primary}
    if others is not None:
        extra = others.tables(sql)
        if isinstance(extra, str):
            return extra
        tables.update(extra)
    # The file being read is also a table under its own name: a join over
    # october_sales.csv written FROM october_sales was refused.
    own = _table_name(primary[0].split(",")[0])
    if own not in tables and _mentions(sql, own):
        tables[own] = primary
    result = query_tables(tables, sql)
    if others is not None and result.startswith("ERROR") and "no such table" in result:
        result += others.hint(primary[0])
    return result
