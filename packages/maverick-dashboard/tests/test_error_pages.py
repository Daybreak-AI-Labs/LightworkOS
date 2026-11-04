"""Branded 404 / 500 error pages."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _restore_test_routes():
    """Keep temporary exception routes from contaminating later app tests."""
    from maverick_dashboard import app as dash_app

    original_routes = list(dash_app.app.router.routes)
    yield
    dash_app.app.router.routes[:] = original_routes
    mark_routes_changed = getattr(dash_app.app.router, "_mark_routes_changed", None)
    if callable(mark_routes_changed):
        mark_routes_changed()


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def test_404_html_for_browser(monkeypatch, tmp_path):
    """Browser navigation to a missing path gets the branded 404 page."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/this/does/not/exist", headers={"Accept": "text/html"})
    assert resp.status_code == 404
    assert "Page not found" in resp.text
    assert "We couldn't find that page" in resp.text
    assert resp.text.count("<h1") == 1
    # Branded chrome present (nav, halt pill).
    assert "halt-pill" in resp.text


def test_404_json_for_api(monkeypatch, tmp_path):
    """API path keeps JSON so SDKs / curl don't get an HTML surprise."""
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    resp = client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404
    assert resp.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize("scoped_cookie", [False, True])
def test_unmatched_browser_route_with_unverified_auth_stays_404(monkeypatch, scoped_cookie):
    """Unmatched routes have no route-auth principal; chrome stays public."""
    from maverick_dashboard import invites, rbac
    from maverick_dashboard.app import app

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    email = "error-page@example.test"
    rbac.set_role("user:" + email, "admin")
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, raise_server_exceptions=False) as client:
        client.cookies.set("mvk_session", invites.mint_local_session(email))
        assert client.get("/users").status_code == 200
        if scoped_cookie:
            client.cookies.set("mvk_pref_context", "unverified-account-context")
            client.cookies.set("mvk_lang", "fr")
        response = client.get("/missing-acceptance-page", headers={"Accept": "text/html"})
    assert response.status_code == 404
    assert "Page not found" in response.text
    assert '<html lang="en"' in response.text
    assert "unverified-account-context" not in response.text


@pytest.mark.parametrize("scoped_cookie", [False, True])
def test_unmatched_route_without_required_dashboard_token_stays_unauthorized(monkeypatch, scoped_cookie):
    """Display recovery must never bypass the earlier static-token gate."""
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "synthetic-error-page-token")
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, raise_server_exceptions=False) as client:
        if scoped_cookie:
            client.cookies.set("mvk_pref_context", "unverified-account-context")
            client.cookies.set("mvk_lang", "fr")
        response = client.get("/missing-acceptance-page", headers={"Accept": "text/html"})
    assert response.status_code == 401
    assert "unverified-account-context" not in response.text


def test_browser_http_errors_are_branded_and_actionable(monkeypatch):
    """Ordinary authorization/conflict/outage failures must not strand a
    browser user on a raw JSON document."""
    from fastapi import HTTPException
    from maverick_dashboard import app as dash_app

    for status in (403, 409, 503):
        path = f"/__http_error_{status}"

        async def fail(code=status):
            raise HTTPException(status_code=code, detail="internal detail is not UI")

        dash_app.app.add_api_route(
            path,
            fail,
            methods=["GET"],
            name=f"test_http_error_{status}",
        )

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = TestClient(dash_app.app, base_url="http://127.0.0.1", raise_server_exceptions=False)
    expected = {
        403: "Permission required",
        409: "Refresh before continuing",
        503: "Temporarily unavailable",
    }
    for status, heading in expected.items():
        response = client.get(
            f"/__http_error_{status}", headers={"Accept": "text/html"}
        )
        assert response.status_code == status
        assert response.headers["content-type"].startswith("text/html")
        assert heading in response.text
        assert "Reload this page" in response.text
        assert "internal detail is not UI" not in response.text


def test_browser_500_has_a_single_primary_heading(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)

    async def fail():
        raise RuntimeError("internal detail")

    dash_app.app.add_api_route("/__server_error", fail, methods=["GET"])
    response = TestClient(dash_app.app, base_url="http://127.0.0.1", raise_server_exceptions=False).get(
        "/__server_error", headers={"Accept": "text/html"}
    )
    assert response.status_code == 500
    assert response.text.count("<h1") == 1
    assert "internal detail" not in response.text


def test_non_browser_http_error_contract_stays_json(monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import app as dash_app

    async def fail_api():
        raise HTTPException(status_code=409, detail="revision mismatch")

    dash_app.app.add_api_route("/__api_conflict", fail_api, methods=["GET"])
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    response = TestClient(dash_app.app, base_url="http://127.0.0.1").get(
        "/__api_conflict", headers={"Accept": "application/json"}
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "revision mismatch"}


def test_unhandled_exception_renders_500(monkeypatch, tmp_path):
    """A route blowing up renders the branded 500 page for browsers."""
    from maverick_dashboard import app as dash_app

    @dash_app.app.get("/__boom")
    async def boom():
        raise RuntimeError("test-only failure")

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # TestClient re-raises unhandled exceptions by default; disable so
    # our exception handler can produce the branded page.
    client = TestClient(dash_app.app, base_url="http://127.0.0.1", raise_server_exceptions=False)
    resp = client.get("/__boom", headers={"Accept": "text/html"})
    assert resp.status_code == 500
    assert "Something went wrong" in resp.text
    assert "RuntimeError" not in resp.text
    assert "test-only failure" not in resp.text


def test_validation_error_page_does_not_echo_detail(monkeypatch, tmp_path):
    """A 422 routed to the branded page must not echo arbitrary request
    detail. validation_exception_handler renders 500.html, so the page
    must not template {{ detail }} — otherwise crafted input could leak
    into the HTML response (reflected-XSS / info-leak surface)."""
    from maverick import world_model
    from maverick_dashboard import app as dash_app

    @dash_app.app.get("/__needs_param")
    async def needs_param(marker_xyzzy: int):  # required query param
        return {"ok": marker_xyzzy}

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = _client()
    # Missing/non-int required param -> RequestValidationError -> branded page.
    resp = client.get(
        "/__needs_param?marker_xyzzy=PWNED_REFLECTED",
        headers={"Accept": "text/html"},
    )
    assert resp.status_code == 400  # handler downgrades 422 -> 400 for browsers
    assert "Something went wrong" in resp.text
    # The crafted value and validation internals must not appear in the HTML.
    assert "PWNED_REFLECTED" not in resp.text
    assert "marker_xyzzy" not in resp.text


def test_runtime_policy_error_is_actionable_and_path_safe(monkeypatch):
    from maverick.runtime_overrides import RuntimeOverridesSecurityError
    from maverick_dashboard import app as dash_app

    @dash_app.app.get("/__policy_unavailable")
    async def policy_unavailable():
        raise RuntimeOverridesSecurityError(
            "private path C:/Users/example/runtime-overrides.toml"
        )

    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    client = TestClient(dash_app.app, base_url="http://127.0.0.1", raise_server_exceptions=False)

    html = client.get(
        "/__policy_unavailable",
        headers={"Accept": "text/html"},
    )
    assert html.status_code == 503
    assert "Safety settings need attention" in html.text
    assert "Run a health check" in html.text and "maverick doctor" not in html.text
    assert "C:/Users/example" not in html.text

    api = client.get(
        "/__policy_unavailable",
        headers={"Accept": "application/json"},
    )
    assert api.status_code == 503
    assert api.json()["code"] == "operator_policy_unavailable"
    assert "C:/Users/example" not in api.text
