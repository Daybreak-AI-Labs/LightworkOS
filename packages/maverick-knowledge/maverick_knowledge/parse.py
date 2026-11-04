"""Extract plain text from uploaded documents, dispatched by extension.

text / markdown / HTML need no extra deps (HTML via stdlib ``html.parser``).
PDF uses the optional ``parsers`` extra (pypdf), imported lazily. DOCX/XLSX use
a bounded OOXML text projection with explicit omitted-region metadata.
"""
from __future__ import annotations

import hashlib
import io
import os
import zipfile
from html.parser import HTMLParser
from pathlib import Path

from .extraction import DocumentExtraction, ExtractionBuilder

# Cap the on-disk size of a document read into memory. Without it a single huge
# file (a multi-GB .txt/.pdf) OOMs the process during extract_text -- mirroring
# the byte cap image.py already enforces before decoding an image. 0 disables.
DEFAULT_MAX_DOC_BYTES = 25 * 1024 * 1024
# Cap the DECOMPRESSED size of a zip-based document (DOCX). A small .docx can
# inflate to gigabytes (a zip bomb); python-docx applies no such limit, and the
# on-disk cap above bounds only the compressed input, not the expansion. 0 off.
DEFAULT_MAX_DOCX_UNCOMPRESSED_BYTES = 200 * 1024 * 1024
# Cap the page count of a PDF. PDF content streams are Flate-compressed, so a
# small on-disk file can decompress to gigabytes and an attacker can pack
# millions of pages via object streams; the on-disk cap above bounds only the
# compressed input, not that expansion. Mirrors the DOCX zip-bomb guard. 0 off.
DEFAULT_MAX_PDF_PAGES = 5000


# Each cap can also be set as ``[knowledge] <key>`` (the environment wins).
_CONFIG_KEYS = {
    "MAVERICK_KNOWLEDGE_MAX_DOC_BYTES": "max_doc_bytes",
    "MAVERICK_KNOWLEDGE_MAX_DOCX_UNCOMPRESSED_BYTES": "max_docx_uncompressed_bytes",
    "MAVERICK_KNOWLEDGE_MAX_PDF_PAGES": "max_pdf_pages",
}


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None and name in _CONFIG_KEYS:
        try:
            from maverick.env_setting import env_or_config

            raw = env_or_config(name, "knowledge", _CONFIG_KEYS[name])
        except ImportError:  # pragma: no cover -- standalone use without the kernel
            raw = None
    try:
        return int(raw if raw is not None else default)
    except ValueError:
        return default


def _check_on_disk_size(path: Path) -> None:
    cap = _int_env("MAVERICK_KNOWLEDGE_MAX_DOC_BYTES", DEFAULT_MAX_DOC_BYTES)
    if cap <= 0:
        return
    size = path.stat().st_size
    if size > cap:
        raise ValueError(
            f"document too large to ingest ({size} bytes > {cap} bytes); raise "
            "MAVERICK_KNOWLEDGE_MAX_DOC_BYTES to allow it"
        )


def _check_docx_uncompressed_size(path: Path) -> None:
    """Reject a DOCX whose declared uncompressed size exceeds the cap, BEFORE
    handing it to python-docx (which would expand a zip bomb into memory)."""
    cap = _int_env("MAVERICK_KNOWLEDGE_MAX_DOCX_UNCOMPRESSED_BYTES",
                   DEFAULT_MAX_DOCX_UNCOMPRESSED_BYTES)
    if cap <= 0:
        return
    try:
        with zipfile.ZipFile(path) as zf:
            total = sum(info.file_size for info in zf.infolist())
    except zipfile.BadZipFile as e:
        raise ValueError("not a valid .docx (corrupt zip container)") from e
    if total > cap:
        raise ValueError(
            f"docx decompresses too large ({total} bytes > {cap} bytes); "
            "refusing to expand a possible zip bomb"
        )


def _check_pdf_page_count(reader) -> None:
    """Reject a PDF whose page count exceeds the cap, BEFORE iterating pages and
    decompressing their (Flate-compressed) content streams into memory."""
    cap = _int_env("MAVERICK_KNOWLEDGE_MAX_PDF_PAGES", DEFAULT_MAX_PDF_PAGES)
    if cap <= 0:
        return
    pages = len(reader.pages)
    if pages > cap:
        raise ValueError(
            f"pdf has too many pages to ingest ({pages} > {cap}); raise "
            "MAVERICK_KNOWLEDGE_MAX_PDF_PAGES to allow it"
        )


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, _attrs):
        if tag in ("script", "style"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def _html_to_text(raw: str) -> str:
    p = _TextExtractor()
    p.feed(raw)
    return " ".join(p.parts)


IMAGE_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tiff", ".tif",
})


def is_image(path: str | Path) -> bool:
    """True if ``path`` looks like an image (by extension). Images can't be read
    as UTF-8 -- they need an image_describer (OCR or a vision model) to become
    text, which the KnowledgeBase routes them through."""
    return Path(path).suffix.lower() in IMAGE_EXTS


_TEXT_EXTS = frozenset({".txt", ".md", ".markdown", ".rst", ".csv", ".tsv", ".log",
                        ".json", ".jsonl", ".yaml", ".yml", ".toml", ".xml", ".html", ".htm"})
_EXTRACTOR_VERSION = "lightwork-normalized-extraction:1"


def extract_document(path: str | Path) -> DocumentExtraction:
    """Extract with explicit failure/coverage instead of decoding unknown binaries.

    Native OCR is never enabled by this parser. Original bytes are hashed before
    parsing, so the normalized document and its coverage remain bound to source.
    """
    path = Path(path)
    suffix = path.suffix.lower()
    format = suffix.lstrip(".") or "unknown"
    digest = ""
    try:
        _check_on_disk_size(path)
        cap = _int_env("MAVERICK_KNOWLEDGE_MAX_DOC_BYTES", DEFAULT_MAX_DOC_BYTES)
        with path.open("rb") as stream:
            data = stream.read(cap + 1) if cap > 0 else stream.read()
        if cap > 0 and len(data) > cap:
            raise ValueError("document too large during read")
        digest = hashlib.sha256(data).hexdigest()
        builder = ExtractionBuilder()
        if suffix == ".pdf":
            if not data.startswith(b"%PDF-"):
                raise ValueError("PDF signature does not match its extension")
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            _check_pdf_page_count(reader)
            for index, page in enumerate(reader.pages, 1):
                text = page.extract_text() or ""
                location = f"pdf/page[{index}]"
                if text.strip():
                    builder.append(text, location, "page")
                else:
                    builder.omit(location + ": no extracted text; blank/image-only/unsupported content unresolved")
            builder.warnings.append("PDF text extraction only; OCR is not configured or invoked by this parser.")
        elif suffix in {".docx", ".xlsx"}:
            from .office_extract import extract_office
            builder = extract_office(data, format, _int_env(
                "MAVERICK_KNOWLEDGE_MAX_DOCX_UNCOMPRESSED_BYTES", DEFAULT_MAX_DOCX_UNCOMPRESSED_BYTES))
        elif suffix in _TEXT_EXTS:
            if data.startswith((b"PK\x03\x04", b"%PDF-", b"\xd0\xcf\x11\xe0")):
                raise ValueError("Binary container does not match its text extension")
            text = data.decode("utf-8-sig", errors="strict")
            if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
                raise ValueError("Text document contains binary control bytes")
            if suffix in {".html", ".htm"}:
                text = _html_to_text(text)
                builder.warnings.append("HTML visible text projection; scripts, styles and layout omitted.")
            builder.append(text, "text/character-stream")
        else:
            warning = ("Images require an explicitly configured image_describer; no OCR was attempted."
                       if is_image(path) else "No qualified extractor is available for this format.")
            return DocumentExtraction("unsupported", format, digest, _EXTRACTOR_VERSION,
                                      omitted_regions=("whole-source",), warnings=(warning,))
        return builder.finish(format, digest, _EXTRACTOR_VERSION)
    except ModuleNotFoundError:
        return DocumentExtraction("unavailable", format, digest, _EXTRACTOR_VERSION,
                                  omitted_regions=("whole-source",),
                                  warnings=("Optional parser unavailable; install maverick-knowledge[parsers].",))
    except (ValueError, UnicodeError, zipfile.BadZipFile) as exc:
        return DocumentExtraction("rejected", format, digest, _EXTRACTOR_VERSION,
                                  omitted_regions=("whole-source",), warnings=(str(exc)[:500],))
    except Exception as exc:
        return DocumentExtraction("failed", format, digest, _EXTRACTOR_VERSION,
                                  omitted_regions=("whole-source",), warnings=(f"Parser failed: {type(exc).__name__}",))


def extract_text(path: str | Path) -> str:
    """Legacy text convenience API; structured callers should use extract_document."""
    result = extract_document(path)
    if result.status in {"unsupported", "unavailable", "failed"}:
        raise RuntimeError("; ".join(result.warnings))
    if result.status == "rejected":
        raise ValueError("; ".join(result.warnings))
    return result.text
