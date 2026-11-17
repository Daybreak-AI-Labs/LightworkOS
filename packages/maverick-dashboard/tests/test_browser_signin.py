"""A signed-out browser is sent to sign-in; API and bearer clients keep the 401.

Live (OIDC): opening / without a session showed the raw JSON
{"detail":"OIDC bearer token required"} instead of the sign-in page.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

ISSUER = "https://idp.example.com"
NAVIGATE = {"Accept": "*/*", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
HTML = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    for name, value in {
        "MAVERICK_OIDC_ENABLED": "1", "MAVERICK_OIDC_ISSUER": ISSUER, "MAVERICK_OIDC_AUDIENCE": "maverick",
        "MAVERICK_OIDC_CLIENT_ID": "test-client-id", "MAVERICK_OIDC_CLIENT_SECRET": "test-client-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_REDIRECT_URI": "http://127.0.0.1/auth/callback",
        "MAVERICK_OIDC_SESSION_SECRET": "unit-test-session-secret",  # pragma: allowlist secret
        "MAVERICK_OIDC_AUTHORIZATION_ENDPOINT": ISSUER + "/authorize",
        "MAVERICK_OIDC_TOKEN_ENDPOINT": ISSUER + "/token",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    config.reset_config_cache()
    from maverick_dashboard.app import app

    yield TestClient(app, base_url="http://127.0.0.1")
    config.reset_config_cache()


def _return_to(response):
    assert response.status_code == 302, response.text
    location = urlparse(response.headers["location"])
    assert location.path == "/auth/login" and not location.netloc
    return parse_qs(location.query)["return_to"][0]


@pytest.mark.parametrize("headers", [HTML, NAVIGATE], ids=["accept-html", "navigation-markers"])
def test_a_signed_out_page_load_goes_to_sign_in_and_back(client, headers):
    assert _return_to(client.get("/", headers=headers, follow_redirects=False)) == "/"
    assert _return_to(client.get("/goals?view=mine", headers=headers, follow_redirects=False)) == "/goals?view=mine"


@pytest.mark.parametrize("path", ["/api/v1/goals", "/"])
def test_api_clients_keep_the_json_401(client, path):
    for headers in ({}, {"Accept": "application/json"}, {"Accept": "*/*"}):
        if path.startswith("/api/") or headers.get("Accept") != "text/html":
            response = client.get(path, headers=headers, follow_redirects=False)
            assert response.status_code == 401
            assert response.json() == {"detail": "OIDC bearer token required"}
    api = client.get("/api/v1/goals", headers=HTML, follow_redirects=False)
    assert api.status_code == 401 and api.headers["content-type"].startswith("application/json")


def test_a_bearer_request_keeps_the_401_even_from_a_browser(client):
    response = client.get("/", headers={**HTML, "Authorization": "Bearer not-a-token"}, follow_redirects=False)
    assert response.status_code == 401
    assert response.headers.get("WWW-Authenticate") == "Bearer"
    assert "location" not in response.headers


def test_only_a_page_load_is_redirected(client):
    response = client.post("/styles/set", headers={**HTML, "Origin": "http://127.0.0.1"}, follow_redirects=False)
    assert response.status_code == 401 and "location" not in response.headers


def test_return_path_helper_refuses_off_site_paths():
    from types import SimpleNamespace

    from maverick_dashboard.browser_signin import return_path

    def request(path, query=""):
        return SimpleNamespace(url=SimpleNamespace(path=path, query=query))

    assert return_path(request("/goals", "a=1")) == "/goals?a=1"
    for unsafe in ("//evil.example.com", "/\\evil.example.com", "/x\r\nSet-Cookie:a", "https://evil.example.com"):
        assert return_path(request(unsafe)) == "/"


def test_a_websocket_is_never_a_page_load():
    """A WebSocket refused with 401 passes through the same error handler;
    it has no ``method``, and must keep its refusal instead of crashing."""
    from starlette.websockets import WebSocket

    from maverick_dashboard import browser_signin

    scope = {"type": "websocket", "path": "/ws/firehose", "headers": [(b"accept", b"text/html")],
             "query_string": b"", "scheme": "ws", "server": ("127.0.0.1", 80), "client": ("127.0.0.1", 1)}

    async def receive():
        return {"type": "websocket.connect"}

    async def send(message):
        return None

    assert browser_signin.is_browser_navigation(WebSocket(scope, receive, send)) is False
