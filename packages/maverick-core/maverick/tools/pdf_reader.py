"""PDF reader tool.

Extracts text from PDFs with page-range slicing. Tries pdfplumber
first (better table handling), falls back to pypdf. Both are in the
``[pdf]`` optional extra.

Reads from local paths or http(s) URLs.
"""
from __future__ import annotations

import io
import logging
import os
import re
import textwrap
from pathlib import Path
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)
_MAX_PDF_BYTES = 100 * 1024 * 1024


_PDF_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "source": {
            "type": "string",
            "description": "Local file path or http(s) URL.",
        },
        "pages": {
            "type": "string",
            "description": "Page range (e.g. '1-5', '3', '10-'); 1-indexed. Default: all.",
        },
        "include_tables": {
            "type": "boolean",
            "description": "Try to extract tables as markdown (pdfplumber path).",
        },
        "ocr": {
            "type": "boolean",
            "description": "Force OCR for scanned or mixed image/text pages; requires documents.pdf_ocr and the offline document engine.",
        },
        "max_chars": {
            "type": "integer",
            "description": "Truncate output (default 100_000; maximum 1_000_000).",
            "minimum": 1,
            "maximum": 1_000_000,
        },
    },
    "required": ["source"],
}


class PageSelectionError(ValueError):
    """A page selection that names no page this PDF has; said as it is."""


_ALL_PAGES = frozenset({"all", "*", "all pages"})


def _parse_pages(spec: str, total: int) -> list[int]:
    """Parse '1-5', '3', '10-' into a list of 0-indexed page indices; empty,
    "all" or "*" mean every page."""
    spec = (spec or "").strip()
    if not spec or spec.casefold() in _ALL_PAGES:
        return list(range(total))
    out: set[int] = set()
    try:
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                a, _, b = chunk.partition("-")
                # Clamp both ends to [1, total] BEFORE building the range so a
                # spec like '1-99999999' can't construct a ~10^8-element loop.
                start = max(1, int(a)) if a else 1
                end = min(total, int(b)) if b else total
                for n in range(start, end + 1):
                    out.add(n - 1)
            else:
                n = int(chunk)
                if 1 <= n <= total:
                    out.add(n - 1)
    except ValueError as exc:
        # Never silently expand an invalid selection to the whole document.
        raise PageSelectionError("invalid PDF page selection; use ranges such as 1-5,8,10-, "
                                 "or leave pages out for all of them") from exc
    return sorted(out)


def _pages_or_say(spec: str | None, total: int) -> list[int]:
    """The selected pages, or a plain error when a selection names none."""
    indices = _parse_pages(spec or "", total)
    if not indices and (spec or "").strip():
        raise PageSelectionError(f"this PDF has {total} page{'' if total == 1 else 's'}; choose pages from "
                                 f"1 to {total}, or leave pages out for all of them")
    return indices


def _load_bytes(source: str, workdir: Path | None = None) -> bytes | None:
    """Get PDF bytes from a workspace-local path or safe URL."""
    if source.startswith(("http://", "https://")):
        try:
            import httpx  # noqa: F401  (presence check; safe_get imports it)
        except ImportError:
            return None
        from ._ssrf import BlockedHost, safe_client
        # Combine both defenses: safe_client pins the connection to the
        # validated public IP (SSRF / DNS-rebinding), AND we stream with a
        # hard byte ceiling so a model-supplied URL can't exhaust memory with
        # a multi-GB / endless body.
        _MAX = _MAX_PDF_BYTES
        try:
            with safe_client(source, timeout=30.0) as client:
                with client.stream("GET", source) as resp:
                    resp.raise_for_status()
                    clen = resp.headers.get("content-length")
                    if clen is not None and clen.isdigit() and int(clen) > _MAX:
                        log.warning("pdf fetch refused: %s bytes > cap", clen)
                        return None
                    buf = bytearray()
                    for chunk in resp.iter_bytes():
                        buf += chunk
                        if len(buf) > _MAX:
                            log.warning("pdf fetch refused: body exceeded cap")
                            return None
                    return bytes(buf)
        except BlockedHost as e:
            log.warning("pdf fetch refused: %s", e)
            return None
        except Exception as e:
            log.warning("pdf fetch failed: %s", e)
            return None

    workdir = Path(workdir or Path.cwd()).resolve()
    p = Path(os.path.expanduser(source))
    if not p.is_absolute():
        p = (workdir / p).resolve()
    else:
        p = p.resolve()
    try:
        p.relative_to(workdir)
    except ValueError:
        return None
    if not p.exists() or not p.is_file():
        return None
    with p.open("rb") as stream:
        data = stream.read(_MAX_PDF_BYTES + 1)
    return data if len(data) <= _MAX_PDF_BYTES else None


_AMOUNT = re.compile(r"(?<![\w.])-?\$?\d{1,3}(?:,\d{3})*\.\d{2}(?!\d)")
_TABULAR_LINES = 4


def _tabular(text: str) -> bool:
    """A page of figures in columns (a statement, an invoice): several lines
    each holding two or more amounts."""
    return sum(len(_AMOUNT.findall(line)) >= 2 for line in text.splitlines()) >= _TABULAR_LINES


class _Layout:
    """A tabular page's text with its columns kept. Plain extraction reads a
    statement row as "10/03 Card-Costco 3,753.21 8,727.34": with the column
    gone, an agent could not tell a withdrawal from a deposit and got both
    totals wrong. pypdf's layout mode keeps each figure under its heading."""

    def __init__(self, data: bytes) -> None:
        self._data, self._reader = data, None

    def page(self, index: int, text: str) -> str:
        if not _tabular(text):
            return text
        try:
            if self._reader is None:
                import pypdf  # type: ignore

                self._reader = pypdf.PdfReader(io.BytesIO(self._data))
            layout = self._reader.pages[index].extract_text(extraction_mode="layout") or ""
        except Exception:  # noqa: BLE001 -- no layout: the plain text stands
            return text
        lines = [line.rstrip() for line in layout.splitlines() if line.strip()]
        return textwrap.dedent("\n".join(lines)) if lines else text


def _extract_with_pdfplumber(data: bytes, pages: str | None, include_tables: bool) -> str | None:
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        return None
    out: list[str] = []
    has_content = False
    layout = _Layout(data)
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        total = len(pdf.pages)
        page_indices = _pages_or_say(pages, total)
        for idx in page_indices:
            page = pdf.pages[idx]
            text = layout.page(idx, (page.extract_text() or "").strip())
            has_content = has_content or bool(text)
            block = f"=== Page {idx + 1} of {total} ===\n{text}"
            if include_tables:
                tables = page.extract_tables() or []
                for ti, table in enumerate(tables, 1):
                    if not table:
                        continue
                    md = _table_to_markdown(table)
                    has_content = has_content or any(
                        cell is not None and str(cell).strip() for row in table for cell in row
                    )
                    block += f"\n\n[Table {ti}]\n{md}"
            out.append(block)
    return "\n\n".join(out) if has_content else ""


def _extract_with_pypdf(data: bytes, pages: str | None) -> str | None:
    try:
        import pypdf  # type: ignore
    except ImportError:
        try:
            import PyPDF2 as pypdf  # type: ignore
        except ImportError:
            return None
    reader = pypdf.PdfReader(io.BytesIO(data))
    total = len(reader.pages)
    page_indices = _pages_or_say(pages, total)
    out: list[str] = []
    has_content = False
    layout = _Layout(data)
    for idx in page_indices:
        text = layout.page(idx, (reader.pages[idx].extract_text() or "").strip())
        has_content = has_content or bool(text)
        out.append(f"=== Page {idx + 1} of {total} ===\n{text}")
    return "\n\n".join(out) if has_content else ""


def _table_to_markdown(rows: list[list]) -> str:
    if not rows:
        return ""
    header = rows[0]
    body = rows[1:]
    def cell_text(cell):
        value = "" if cell is None else str(cell)
        return value.replace("|", r"\|").replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")

    md = "| " + " | ".join(cell_text(c) for c in header) + " |\n"
    md += "|" + "|".join("---" for _ in header) + "|\n"
    for r in body:
        md += "| " + " | ".join(cell_text(c) for c in r) + " |\n"
    return md


def extract_text_from_bytes(data: bytes, *, pages: str = "",
                            include_tables: bool = False) -> str | None:
    """Extract text from PDF bytes (pdfplumber, pypdf fallback).

    Also the **parser-isolation child entry** (``parser_isolation.PARSERS
    ["pdf_text"]``): with ``[security] isolate_parsers`` on, hostile PDF bytes
    are parsed in a scrubbed child process so a memory-safety bug in the
    C-backed parsers can't touch the kernel. Returns None when no parser
    extra is installed.
    """
    text = _extract_with_pdfplumber(data, pages, include_tables)
    if text is None:
        if include_tables:
            return (
                "ERROR: PDF table extraction requires the optional pdfplumber dependency; "
                "use include_tables=false for text-only extraction."
            )
        text = _extract_with_pypdf(data, pages)
    return text


def _selected_text(data, pages, include_tables):
    from ..parser_isolation import parse_isolated, should_isolate
    if should_isolate():
        try:
            return parse_isolated("pdf_text", data, pages=pages, include_tables=include_tables)
        except (RuntimeError, ValueError) as exc:
            return f"ERROR: isolated PDF parse failed: {exc}"
    try:
        return extract_text_from_bytes(data, pages=pages, include_tables=include_tables)
    except PageSelectionError as exc:
        # Live: pages="all" was reported as "PDF parse failed", and the agent
        # gave up on a readable receipt.
        return f"ERROR: {exc}"
    except Exception as exc:
        return f"ERROR: PDF parse failed ({type(exc).__name__}); check the document and page selection"


def _run_read_pdf(args: dict[str, Any], sandbox=None, *, world=None,
                  goal_id: int | None = None) -> str:
    source = args.get("source")
    if not isinstance(source, str):
        return "ERROR: source must be a PDF path or URL string"
    source = source.strip()
    if not source:
        return "ERROR: source is required"
    pages = args.get("pages") or ""
    if not isinstance(pages, str):
        return "ERROR: pages must be a page-range string"
    include_tables = as_bool(args.get("include_tables"))
    force_ocr = args.get("ocr", False)
    if type(force_ocr) is not bool:
        return "ERROR: ocr must be a boolean"
    max_chars = args.get("max_chars", 100_000)
    if type(max_chars) is not int or not 1 <= max_chars <= 1_000_000:
        return "ERROR: max_chars must be an integer between 1 and 1000000"

    from .attachments import goal_attachment_bytes
    attached = goal_attachment_bytes(world, goal_id, source)
    try:
        data = attached[0] if attached is not None else _load_bytes(
            source, getattr(sandbox, "workdir", None))
    except (OSError, ValueError):
        return "ERROR: PDF file could not be opened"
    if data is None:
        return f"ERROR: could not read PDF from {source!r}"
    return pdf_text(data, pages=pages, include_tables=include_tables,
                    force_ocr=force_ocr, max_chars=max_chars, sandbox=sandbox)


def pdf_text(data: bytes, *, pages: str = "", include_tables: bool = False,
             force_ocr: bool = False, max_chars: int = 100_000, sandbox=None) -> str:
    """The selected pages' text, or an ``ERROR:`` line the agent can act on.

    Shared by ``read_pdf`` and ``read_attachment``, so an uploaded PDF goes
    through the same parser isolation and OCR fallback as a workspace one.
    """
    text = "" if force_ocr else _selected_text(data, pages, include_tables)
    if text == "":
        try:
            from ..config import get_document_tools
            if force_ocr or get_document_tools()["pdf_ocr"]:
                from .document_processing import ocr_pdf
                text = ocr_pdf(data, pages, sandbox)
                if include_tables:
                    text += "\n[OCR returns plain text; table structure was not reconstructed.]"
        except (RuntimeError, ValueError, OSError) as exc:
            return f"ERROR: PDF OCR failed: {exc}"
    if text is None:
        return (
            "ERROR: no PDF parser available. Run: "
            "python -m pip install -e './packages/maverick-core[pdf]'"
        )
    if not text:
        return "ERROR: no text found in the selected PDF pages; check the range or enable OCR (documents.pdf_ocr) with the offline document engine"

    if len(text) > max_chars:
        text = text[:max_chars] + f"\n\n[... truncated at {max_chars} chars]"
    return text


def read_pdf(sandbox=None, *, world=None, goal_id: int | None = None) -> Tool:
    """Factory: builds the read_pdf tool."""
    return Tool(
        name="read_pdf",
        description=(
            "Read text from a PDF (local path, the path list_attachments gives "
            "for an uploaded PDF, or http(s) URL). Supports "
            "pages='1-5,8,10-' for ranges, include_tables=true to extract "
            "tables as markdown. Tries pdfplumber first, falls back to "
            "pypdf. Enabled offline OCR handles scans; use ocr=true for mixed image/text pages. "
            "Install with: python -m pip install -e './packages/maverick-core[pdf]'."
        ),
        input_schema=_PDF_INPUT_SCHEMA,
        fn=lambda args: _run_read_pdf(args, sandbox, world=world, goal_id=goal_id),
    )
