"""API keys must not ride in request URLs.

A key in the query string leaks into httpx error reprs (which embed the
full request URL) and into any request/access log. Regression for:
  - newsapi: ``apiKey`` was a query param -> now an X-Api-Key header.
  - web_search serpapi: ``api_key`` query param is required by the API,
    so the failure log is redacted instead.
"""
import logging


def test_newsapi_key_goes_in_header_not_url(monkeypatch):
    monkeypatch.setenv("NEWSAPI_KEY", "SECRET123")
    captured: dict = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"status": "ok", "articles": []}

    import httpx

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["params"] = params or {}
        captured["headers"] = headers or {}
        return _Resp()

    monkeypatch.setattr(httpx, "get", fake_get)
    from maverick.tools.newsapi_tool import _get
    _get("/top-headlines", {"country": "us"})

    assert "apiKey" not in captured["params"]
    assert "SECRET123" not in str(captured["params"])
    assert captured["headers"].get("X-Api-Key") == "SECRET123"


def test_serpapi_key_redacted_from_error_log(monkeypatch, caplog):
    monkeypatch.setenv("SERPAPI_API_KEY", "SECRET456")
    import httpx

    def boom(*a, **k):
        # Mimic httpx embedding the full request URL (with the key) in the
        # exception text.
        raise RuntimeError(
            "Server error '500' for url "
            "'https://serpapi.com/search.json?q=x&api_key=SECRET456'"
        )

    monkeypatch.setattr(httpx, "get", boom)
    from maverick.tools.web_search import _try_serpapi
    with caplog.at_level(logging.WARNING):
        out = _try_serpapi("hello", 5)

    assert out is None
    assert "SECRET456" not in caplog.text
    assert "***" in caplog.text
