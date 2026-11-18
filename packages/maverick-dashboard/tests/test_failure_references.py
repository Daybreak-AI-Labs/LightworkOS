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


# Field finding: an app login that did not own the Postgres tables after an
# upgrade turned every page into "Something went wrong" while doctor already
# knew the fix. The page and the API now say what doctor says.
def _owner_refusal():
    from maverick.world_model_backends.postgres import DatabaseUpgradeNeedsOwner
    try:
        try:
            raise DatabaseUpgradeNeedsOwner(56)
        except DatabaseUpgradeNeedsOwner as cause:
            raise RuntimeError("world unavailable") from cause
    except RuntimeError as exc:
        return exc


@pytest.mark.asyncio
@pytest.mark.parametrize("html", [True, False])
async def test_database_owner_refusal_shows_doctors_message(monkeypatch, html):
    from maverick_dashboard import app as dash
    monkeypatch.setattr(dash, "_wants_html", lambda request: html)
    response = await dash.unhandled_exception_handler(_request(), _owner_refusal())
    body = response.body.decode()
    assert response.status_code == 503
    assert "Start Lightwork once as the owner of the tables" in body
    assert "Something went wrong" not in body
    assert "customer-name" not in body and "private-value" not in body


@pytest.mark.asyncio
async def test_detailed_readiness_explains_the_database_refusal_but_public_stays_redacted():
    from maverick_dashboard.health_routes import readiness_response

    def world():
        raise _owner_refusal()

    public = await readiness_response(world_provider=world, provider_key_set=lambda: True)
    assert json.loads(public.body) == {"status": "not_ready"}
    detailed = await readiness_response(world_provider=world, provider_key_set=lambda: True,
                                        include_details=True)
    db = json.loads(detailed.body)["checks"]["db"]
    assert "Start Lightwork once as the owner of the tables" in db
    assert "RuntimeError" not in db
