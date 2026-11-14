from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from maverick_knowledge import extraction
from maverick_knowledge.image import _pixel_cap
from maverick_knowledge.parse import extract_document
from maverick_knowledge.store import QdrantStore


def test_pixel_cap_serializes_decodes_and_restores_original_value():
    image = SimpleNamespace(MAX_IMAGE_PIXELS=90, DecompressionBombWarning=UserWarning)
    first_entered = threading.Event()
    second_started = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()

    def first():
        with _pixel_cap(image, 20):
            first_entered.set()
            assert release_first.wait(5)
            assert image.MAX_IMAGE_PIXELS == 20

    def second():
        second_started.set()
        with _pixel_cap(image, 30):
            second_entered.set()
            assert image.MAX_IMAGE_PIXELS == 30

    with ThreadPoolExecutor(max_workers=2) as pool:
        a = pool.submit(first)
        assert first_entered.wait(5)
        b = pool.submit(second)
        assert second_started.wait(5)
        try:
            assert not second_entered.wait(0.1)
        finally:
            release_first.set()
        a.result()
        b.result()
    assert second_entered.is_set()
    assert image.MAX_IMAGE_PIXELS == 90


def test_pdf_stops_extracting_pages_after_text_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(extraction, "MAX_TEXT_CHARS", 12)
    calls = []

    class Page:
        def extract_text(self):
            calls.append(True)
            return "x" * 20

    reader = SimpleNamespace(pages=[Page(), Page(), Page()])
    monkeypatch.setitem(sys.modules, "pypdf", SimpleNamespace(PdfReader=lambda _: reader))
    path = tmp_path / "large.pdf"
    path.write_bytes(b"%PDF-test")
    result = extract_document(path)
    assert len(calls) == 1
    assert result.text == "x" * 12
    assert result.status == "partial"
    assert any("2" in region and "3" in region and "bound" in region
               for region in result.omitted_regions)


def test_qdrant_workspace_collection_name_uses_supported_characters():
    store = QdrantStore.__new__(QdrantStore)
    store._namespace = "workspace:" + "a" * 64
    assert store._cname("general") == "workspace_" + "a" * 64 + "__general"
