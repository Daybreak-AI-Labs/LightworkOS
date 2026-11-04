"""Saved Qdrant connection configuration reaches its adapter without logging it."""
from types import SimpleNamespace

import pytest
from maverick import config
from maverick_knowledge import store


@pytest.mark.parametrize("url", ["", "https://vectors.example.test:6333"])
def test_saved_knowledge_url_reaches_selected_backend(monkeypatch, caplog, capsys, url):
    monkeypatch.setattr(config, "load_config", lambda: {
        "knowledge": {"enable": True, "store": "qdrant", "url": url},
    })
    calls = []

    def adapter(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(store, "QdrantStore", adapter)
    selected = config.get_knowledge()
    store.build_store(selected)
    assert selected["store"] == "qdrant"
    assert selected["url"] == url
    assert calls[0]["url"] == (url or None)
    assert not caplog.records
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.parametrize("store_key", ["", "qdrant-credential"])
def test_embedding_key_never_reaches_qdrant(monkeypatch, store_key):
    monkeypatch.setattr(config, "load_config", lambda: {
        "knowledge": {
            "enable": True, "store": "qdrant", "url": "https://vectors.example.test",
            "api_key": "embedding-credential", "store_api_key": store_key,  # pragma: allowlist secret
        },
    })
    calls = []
    monkeypatch.setattr(store, "QdrantStore", lambda **kw: calls.append(kw))

    selected = config.get_knowledge()
    store.build_store(selected)

    assert selected["api_key"] == "embedding-credential"  # pragma: allowlist secret
    assert calls[0]["api_key"] == (store_key or None)
