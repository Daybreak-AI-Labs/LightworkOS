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


def _parse_pages(spec: str, total: int) -> list[int]:
    """Parse '1-5', '3', '10-' into a list of 0-indexed page indices."""
    spec = (spec or "").strip()
    if not spec:
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
        raise ValueError("invalid PDF page selection; use ranges such as 1-5,8,10-") from exc
    return sorted(out)


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


def _extract_with_pdfplumber(data: bytes, pages: str | None, include_tables: bool) -> str | None:
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        return None
    out: list[str] = []
    has_content = False
    with pdfplumber.open(io.BytesIO(data)) as pdf:
        total = len(pdf.pages)
        page_indices = _parse_pages(pages or "", total)
        for idx in page_indices:
            page = pdf.pages[idx]
            text = (page.extract_text() or "").strip()
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
    page_indices = _parse_pages(pages or "", total)
    out: list[str] = []
    has_content = False
    for idx in page_indices:
        text = (reader.pages[idx].extract_text() or "").strip()
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
    except Exception as exc:
        return f"ERROR: PDF parse failed ({type(exc).__name__}); check the document and page selection"


def _run_read_pdf(args: dict[str, Any], sandbox=None) -> str:
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

    try:
        data = _load_bytes(source, getattr(sandbox, "workdir", None))
    except (OSError, ValueError):
        return "ERROR: PDF file could not be opened"
    if data is None:
        return f"ERROR: could not read PDF from {source!r}"

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


def read_pdf(sandbox=None) -> Tool:
    """Factory: builds the read_pdf tool."""
    return Tool(
        name="read_pdf",
        description=(
            "Read text from a PDF (local path or http(s) URL). Supports "
            "pages='1-5,8,10-' for ranges, include_tables=true to extract "
            "tables as markdown. Tries pdfplumber first, falls back to "
            "pypdf. Enabled offline OCR handles scans; use ocr=true for mixed image/text pages. "
            "Install with: python -m pip install -e './packages/maverick-core[pdf]'."
        ),
        input_schema=_PDF_INPUT_SCHEMA,
        fn=lambda args: _run_read_pdf(args, sandbox),
    )
