"""Document parsing size guards in extract_text.

Mirrors the byte cap image.py enforces before decoding: a document is bounded
on disk before it is read into memory, and a zip-based DOCX is bounded on its
DECOMPRESSED size before python-docx expands it (zip-bomb guard).
"""
from __future__ import annotations

import zipfile

import pytest
from maverick_knowledge.parse import (
    _check_docx_uncompressed_size,
    _check_pdf_page_count,
    extract_text,
)


class _StubReader:
    """Minimal stand-in for pypdf.PdfReader: only ``.pages`` is consulted by the
    page-count guard, so we avoid needing the optional 'parsers' extra here."""

    def __init__(self, n_pages):
        self.pages = list(range(n_pages))


def test_small_text_file_extracts(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("hello world", encoding="utf-8")
    assert extract_text(p) == "hello world"


def test_oversized_file_rejected_before_read(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_KNOWLEDGE_MAX_DOC_BYTES", "8")
    p = tmp_path / "big.txt"
    p.write_text("x" * 100, encoding="utf-8")
    with pytest.raises(ValueError, match="too large"):
        extract_text(p)


def test_doc_size_cap_disabled_with_zero(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_KNOWLEDGE_MAX_DOC_BYTES", "0")
    p = tmp_path / "big.txt"
    p.write_text("x" * 100, encoding="utf-8")
    assert extract_text(p) == "x" * 100


def test_html_strips_tags_and_scripts(tmp_path):
    p = tmp_path / "page.html"
    p.write_text(
        "<html><body><script>evil()</script><p>keep this</p></body></html>",
        encoding="utf-8",
    )
    out = extract_text(p)
    assert "keep this" in out
    assert "evil" not in out


def test_docx_uncompressed_guard_rejects_bomb(tmp_path, monkeypatch):
    # A zip whose declared uncompressed size exceeds the cap is refused before
    # python-docx ever expands it (the guard reads only the central directory).
    monkeypatch.setenv("MAVERICK_KNOWLEDGE_MAX_DOCX_UNCOMPRESSED_BYTES", "1024")
    z = tmp_path / "bomb.docx"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", b"A" * 100_000)  # >>1KB uncompressed
    with pytest.raises(ValueError, match="too large"):
        _check_docx_uncompressed_size(z)


def test_docx_uncompressed_guard_allows_normal(tmp_path):
    z = tmp_path / "ok.docx"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", b"<xml>small</xml>")
    _check_docx_uncompressed_size(z)  # no raise


def test_corrupt_zip_docx_rejected(tmp_path):
    z = tmp_path / "bad.docx"
    z.write_bytes(b"not a zip at all")
    with pytest.raises(ValueError, match="corrupt zip"):
        _check_docx_uncompressed_size(z)


def test_pdf_page_count_guard_rejects_too_many(monkeypatch):
    # A PDF whose page count exceeds the cap is refused BEFORE the per-page
    # extract loop decompresses each (Flate) content stream into memory.
    monkeypatch.setenv("MAVERICK_KNOWLEDGE_MAX_PDF_PAGES", "10")
    with pytest.raises(ValueError, match="too many pages"):
        _check_pdf_page_count(_StubReader(11))


def test_pdf_page_count_guard_allows_normal(monkeypatch):
    monkeypatch.setenv("MAVERICK_KNOWLEDGE_MAX_PDF_PAGES", "10")
    _check_pdf_page_count(_StubReader(10))  # no raise


def test_pdf_page_count_guard_disabled_with_zero(monkeypatch):
    monkeypatch.setenv("MAVERICK_KNOWLEDGE_MAX_PDF_PAGES", "0")
    _check_pdf_page_count(_StubReader(1_000_000))  # no raise
