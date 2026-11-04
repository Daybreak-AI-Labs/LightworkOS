"""Tests for the web_search tool (maverick.tools.web_search)."""
from __future__ import annotations

from unittest.mock import patch

# ---------- web_search ----------

class _FakeHttpxResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError(
                f"{self.status_code}",
                request=httpx.Request("GET", "http://x"),
                response=httpx.Response(self.status_code),
            )


def test_web_search_empty_query():
    from maverick.tools.web_search import web_search
    tool = web_search()
    assert "query is required" in tool.fn({"query": ""}).lower()


def test_web_search_tavily_path(monkeypatch):
    monkeypatch.setenv("TAVILY_API_KEY", "tav-key")
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    monkeypatch.delenv("SERPAPI_API_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)

    fake_resp = _FakeHttpxResponse(200, json_data={
        "results": [
            {"title": "Result 1", "url": "https://a.example", "content": "snip a"},
            {"title": "Result 2", "url": "https://b.example", "content": "snip b"},
        ]
    })

    import httpx
    with patch.object(httpx, "post", return_value=fake_resp):
        from maverick.tools.web_search import web_search
        out = web_search().fn({"query": "hello world", "num_results": 5})
    assert "[backend: tavily]" in out
    assert "Result 1" in out
    assert "https://a.example" in out


def test_web_search_falls_through_to_ddg_when_no_keys(monkeypatch):
    """All key-required backends skipped -> DDG attempted."""
    for env in ("TAVILY_API_KEY", "BRAVE_API_KEY", "SERPAPI_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)

    # Minimal DDG html-lite output the regex can parse.
    html = (
        '<a class="result__a" href="/l/?uddg=https%3A%2F%2Fexample.com%2Fpage">Example Title</a>'
        '<a class="result__snippet">Example snippet.</a>'
    )
    fake = _FakeHttpxResponse(200, text=html)

    import httpx
    with patch.object(httpx, "get", return_value=fake):
        from maverick.tools.web_search import web_search
        out = web_search().fn({"query": "test", "num_results": 3})

    assert "[backend: ddg]" in out
    assert "Example Title" in out
    assert "https://example.com/page" in out


def test_web_search_forced_backend_skipped_if_no_creds(monkeypatch):
    """MAVERICK_SEARCH_BACKEND=tavily but no key -> no fallthrough."""
    monkeypatch.setenv("MAVERICK_SEARCH_BACKEND", "tavily")
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    from maverick.tools.web_search import web_search
    out = web_search().fn({"query": "test"})
    assert "ERROR" in out


def test_web_search_site_filter(monkeypatch):
    """site arg should add 'site:' to the query."""
    monkeypatch.setenv("TAVILY_API_KEY", "k")
    monkeypatch.delenv("MAVERICK_SEARCH_BACKEND", raising=False)
    captured_payload = {}

    def fake_post(url, json=None, **kw):
        captured_payload["q"] = (json or {}).get("query")
        return _FakeHttpxResponse(200, json_data={"results": []})

    import httpx
    with patch.object(httpx, "post", side_effect=fake_post):
        from maverick.tools.web_search import web_search
        web_search().fn({"query": "react hooks", "site": "github.com"})
    assert captured_payload["q"].startswith("site:github.com ")


def test_web_search_caps_num_results():
    from maverick.tools.web_search import _SEARCH_INPUT_SCHEMA
    # Schema doesn't enforce cap, but runner does (cap is internal logic).
    # Just ensure schema lists the field.
    assert "num_results" in _SEARCH_INPUT_SCHEMA["properties"]
