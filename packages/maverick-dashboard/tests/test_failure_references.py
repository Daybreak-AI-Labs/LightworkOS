"""Failure references identify restricted log records without exposing URLs."""
import json
from types import SimpleNamespace

import pytest
from starlette.requests import Request


def _request():
    return Request({"type": "http", "method": "POST", "path": "/private/customer-name",
                    "query_string": b"token=private-value", "headers": [],
                    "scheme": "http", "server": ("127.0.0.1", 80),
                    "route": SimpleNamespace(path="/private/{name}")})


@pytest.mark.asyncio
async def test_distinct_failure_references_exclude_url_and_match_logs(monkeypatch, caplog):
    from maverick_dashboard import app as dash
    monkeypatch.setattr(dash, "_wants_html", lambda request: False)
    first = await dash.unhandled_exception_handler(_request(), ValueError("private stack detail"))
    second = await dash.unhandled_exception_handler(_request(), ValueError("another failure"))
    one, two = json.loads(first.body), json.loads(second.body)
    assert one["failure_reference"] != two["failure_reference"]
    assert one["failure_reference"] in caplog.text and two["failure_reference"] in caplog.text
    assert "customer-name" not in first.body.decode() and "private-value" not in first.body.decode()
    assert "private stack detail" not in first.body.decode()
    assert first.headers["x-lightwork-failure-reference"] == one["failure_reference"]


@pytest.mark.asyncio
async def test_error_page_has_independent_fallback(monkeypatch):
    from maverick_dashboard import app as dash
    monkeypatch.setattr(dash, "_wants_html", lambda request: True)

    def broken_layout(*args, **kwargs):
        raise RuntimeError("layout unavailable")

    monkeypatch.setattr(dash, "templates", SimpleNamespace(TemplateResponse=broken_layout))
    response = await dash.unhandled_exception_handler(_request(), RuntimeError("failure"))
    assert response.status_code == 500
    assert b"lw-failure-" in response.body and b"Open Help" in response.body
    assert b"customer-name" not in response.body and b"private-value" not in response.body
