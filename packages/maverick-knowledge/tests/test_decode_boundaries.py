from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from maverick_knowledge import extraction
from maverick_knowledge.base import KnowledgeBase
from maverick_knowledge.image import _pixel_cap
from maverick_knowledge.parse import extract_document
from maverick_knowledge.store import QdrantStore, _namespace_from_cfg


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


def test_qdrant_workspace_collection_name_uses_supported_characters(monkeypatch):
    store = QdrantStore.__new__(QdrantStore)
    store._namespace = _namespace_from_cfg({"path": "/workspace/owner/knowledge.db"})
    assert store._cname("general").startswith("workspace_")
    assert ":" not in store._cname("general")
    assert store._cname("safe_private").endswith("__safe_private")
    with pytest.raises(ValueError, match="collection name.*colon"):
        store._cname("safe:private")
    custom = QdrantStore.__new__(QdrantStore)
    custom._namespace = "custom_namespace"
    assert custom._cname("general") == "custom_namespace__general"
    custom._namespace = "custom:namespace"
    with pytest.raises(ValueError, match="namespace.*colon"):
        custom._cname("general")
    other = QdrantStore.__new__(QdrantStore)
    other._namespace = _namespace_from_cfg({"path": "/workspace/other/knowledge.db"})
    legacy = QdrantStore.__new__(QdrantStore)
    legacy._namespace = "legacy-valid"
    assert legacy._cname("general") == "legacy-valid__general"
    records = {s._cname("general"): [
        {"subject": "alice", "source": "kept"},
        {"subject": "bob", "source": "withdrawn"},
    ] for s in (store, other, legacy)}

    def matches(row, query):
        return all(row.get(cond.key.removeprefix("meta.")) == cond.match.value
                   for cond in query.must)

    def delete(collection_name, points_selector):
        records[collection_name] = [row for row in records[collection_name]
                                    if not matches(row, points_selector.filter)]

    client = SimpleNamespace(
        get_collections=lambda: SimpleNamespace(collections=[
            SimpleNamespace(name=name) for name in records]),
        collection_exists=lambda name: name in records,
        count=lambda collection_name, count_filter, exact: SimpleNamespace(count=sum(
            matches(row, count_filter) for row in records[collection_name])),
        delete=delete,
    )
    monkeypatch.setitem(sys.modules, "qdrant_client.models", SimpleNamespace(
        Filter=SimpleNamespace, FieldCondition=SimpleNamespace,
        MatchValue=SimpleNamespace, FilterSelector=SimpleNamespace))
    monkeypatch.setitem(sys.modules, "qdrant_client", SimpleNamespace(
        models=sys.modules["qdrant_client.models"]))
    for owned in (store, legacy):
        owned._client = client
        kb = KnowledgeBase(store=owned)
        assert kb.collections() == ["general"]
        assert kb.count_subject("alice") == 1
        assert kb.erase_subject("alice") == {"general": 1}
        assert kb.count_subject("alice") == 0
        assert kb.erase_source("withdrawn") == {"general": 1}
        assert records[owned._cname("general")] == []
    assert len(records[other._cname("general")]) == 2
