"""Tests for the wikipedia tool."""
from __future__ import annotations

from unittest.mock import patch


class _FakeHttpxResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

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


def test_wikipedia_search_empty_query():
    from maverick.tools.wikipedia import wikipedia
    out = wikipedia().fn({"op": "search", "query": ""})
    assert "query" in out.lower()


def test_wikipedia_search_returns_hits():
    from maverick.tools.wikipedia import wikipedia
    fake = _FakeHttpxResponse(200, json_data={
        "query": {
            "search": [
                {"title": "Python (programming language)",
                 "snippet": "Python is a <b>high-level</b>, general-purpose language."},
                {"title": "Monty Python",
                 "snippet": "British comedy group."},
            ]
        }
    })
    import httpx
    with patch.object(httpx, "get", return_value=fake) as mock_get:
        out = wikipedia().fn({"op": "search", "query": "python", "limit": 5})
    assert "Python (programming language)" in out
    assert "Monty Python" in out
    # HTML stripped:
    assert "<b>" not in out
    assert "high-level" in out
    # URL constructed from title:
    assert "en.wikipedia.org/wiki/Python_%28programming_language%29" in out
    # User-Agent sent:
    assert mock_get.call_args.kwargs["headers"]["User-Agent"].startswith("Lightwork/")


def test_wikipedia_search_no_results():
    from maverick.tools.wikipedia import wikipedia
    fake = _FakeHttpxResponse(200, json_data={"query": {"search": []}})
    import httpx
    with patch.object(httpx, "get", return_value=fake):
        out = wikipedia().fn({"op": "search", "query": "asdfqwerzxcv"})
    assert "no results" in out


def test_wikipedia_fetch_returns_extract():
    from maverick.tools.wikipedia import wikipedia
    fake = _FakeHttpxResponse(200, json_data={
        "query": {
            "pages": [
                {"title": "Python (programming language)",
                 "extract": "Python is a programming language. " * 50},
            ]
        }
    })
    import httpx
    with patch.object(httpx, "get", return_value=fake):
        out = wikipedia().fn({
            "op": "fetch",
            "title": "Python (programming language)",
            "max_chars": 200,
        })
    assert "Python (programming language)" in out
    assert "en.wikipedia.org/wiki/Python" in out
    assert "[truncated at 200 chars]" in out


def test_wikipedia_fetch_missing_page():
    from maverick.tools.wikipedia import wikipedia
    fake = _FakeHttpxResponse(200, json_data={
        "query": {"pages": [{"title": "Nope", "missing": True}]}
    })
    import httpx
    with patch.object(httpx, "get", return_value=fake):
        out = wikipedia().fn({"op": "fetch", "title": "Nope"})
    assert "no article found" in out


def test_wikipedia_unknown_op():
    from maverick.tools.wikipedia import wikipedia
    out = wikipedia().fn({"op": "delete"})
    assert "unknown op" in out


def test_wikipedia_lang_sanitised():
    """Junk in lang shouldn't escape into the URL — fall back to 'en'."""
    from maverick.tools.wikipedia import wikipedia
    fake = _FakeHttpxResponse(200, json_data={"query": {"search": []}})
    import httpx
    with patch.object(httpx, "get", return_value=fake) as mock_get:
        wikipedia().fn({"op": "search", "query": "x", "lang": "../etc/passwd"})
    called_url = mock_get.call_args.args[0]
    assert "etc/passwd" not in called_url
    assert "wikipedia.org" in called_url
