"""Tests for the Elasticsearch tool (maverick.tools.elasticsearch_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    """Install a dummy httpx module with the given methods (get/post/...) ."""
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status: int, body: object):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = str(body)
    return r


# ---------- Elasticsearch ----------

def test_elasticsearch_requires_op():
    from maverick.tools.elasticsearch_tool import elasticsearch_tool
    assert "op is required" in elasticsearch_tool().fn({})


def test_elasticsearch_missing_url(monkeypatch):
    monkeypatch.delenv("ES_URL", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.elasticsearch_tool import elasticsearch_tool
    out = elasticsearch_tool().fn({"op": "search", "index": "x"})
    assert "ES_URL" in out


def test_elasticsearch_search_renders(monkeypatch):
    monkeypatch.setenv("ES_URL", "http://es.local:9200")
    body = {
        "took": 5,
        "hits": {"total": {"value": 1}, "hits": [
            {"_id": "1", "_score": 1.5, "_source": {"name": "alice"}},
        ]},
    }
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.elasticsearch_tool import elasticsearch_tool
    out = elasticsearch_tool().fn({"op": "search", "index": "users"})
    assert "total=1" in out and "alice" in out


def test_elasticsearch_index_dry_run(monkeypatch):
    monkeypatch.setenv("ES_URL", "http://es")
    _fake_httpx(monkeypatch, put=MagicMock())
    from maverick.tools.elasticsearch_tool import elasticsearch_tool
    out = elasticsearch_tool().fn({
        "op": "index", "index": "u", "doc_id": "1", "body": {"a": 1},
    })
    assert "DRY RUN" in out


# ---------- crash-on-success: null fields in valid 2xx bodies ----------

def test_elasticsearch_handles_null_score(monkeypatch):
    """Sorted ES queries return hits with _score=null — must not crash."""
    monkeypatch.setenv("ES_URL", "http://es.local:9200")
    body = {"took": 3, "hits": {"total": {"value": 1}, "hits": [
        {"_id": "1", "_score": None, "_source": {"k": "v"}},
    ]}}
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.elasticsearch_tool import elasticsearch_tool
    out = elasticsearch_tool().fn({"op": "search", "index": "logs"})
    assert "ERROR" not in out
    assert "1" in out  # the doc id rendered


class TestElasticsearchSeg:
    def test_path_traversal_encoded(self):
        from maverick.tools.elasticsearch_tool import _seg
        assert _seg("../../_cluster/settings") == "..%2F..%2F_cluster%2Fsettings"
        assert _seg("my-index") == "my-index"
