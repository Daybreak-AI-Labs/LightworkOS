"""A credential or context value with non-ASCII text is refused like any other wrong value.

``hmac.compare_digest`` raises ``TypeError`` for a ``str`` holding a non-ASCII
character, so every place that compared request-supplied text with it turned a
crafted header or JSON field into an HTTP 500 instead of the 401/409 a wrong
ASCII value gets.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
# The same mistake in ASCII and in non-ASCII.
WRONG = ("0" * 64, "é" * 64, "café")
# JSON can also carry a lone surrogate. Only routes whose body models accept it are
# listed with it; the others answer 422 (and echo it back, which is a separate matter
# from the comparison under test).
WRONG_WITH_SURROGATE = (*WRONG, "\ud800")


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import api, app, auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:customer")
    config.reset_config_cache()
    api._world_cache.clear()
    yield TestClient(app.app, base_url="http://127.0.0.1", headers=ORIGIN, raise_server_exceptions=False)
    config.reset_config_cache()
    api._world_cache.clear()


def _post(client, path, body, headers=None):
    # Raw JSON text: the test client's own encoder refuses a lone surrogate.
    return client.post(path, content=json.dumps(body),
                       headers={"Content-Type": "application/json", **(headers or {})})


def test_static_token_with_non_ascii_text_is_a_plain_401(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-token-for-tests")  # pragma: allowlist secret
    from maverick_dashboard.app import app

    c = TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, raise_server_exceptions=False)
    ascii_wrong = c.get("/api/v1/account/me", headers={"Authorization": "Bearer wrong"})
    assert ascii_wrong.status_code == 401
    # Header text arrives decoded as latin-1, so e-acute is a non-ASCII str.
    odd = c.get("/api/v1/account/me", headers={"Authorization": b"Bearer \xe9abc"})
    assert odd.status_code == 401
    ok = c.get("/api/v1/account/me", headers={"Authorization": "Bearer static-token-for-tests"})
    assert ok.status_code == 200


@pytest.mark.parametrize("wrong", WRONG_WITH_SURROGATE)
def test_preferences_save_context(client, wrong):
    body = {"expected_revision": "0" * 64, "context": wrong, "changes": {}}
    for path in ("/api/v1/preferences", "/api/v1/preferences/original"):
        if path.endswith("original"):
            body = {**body, "operation_id": "a" * 32}
        refused = _post(client, path, body)
        assert refused.status_code == 409, (path, wrong, refused.status_code, refused.text)


@pytest.mark.parametrize("wrong", WRONG_WITH_SURROGATE)
def test_display_preference_context(client, wrong):
    refused = _post(client, "/api/v1/preferences/display",
                    {"key": "theme", "value": "dark", "context": wrong})
    assert refused.status_code == 409, (wrong, refused.status_code, refused.text)


@pytest.mark.parametrize("wrong", WRONG)
def test_navigation_context(client, wrong):
    refused = _post(client, "/api/v1/navigation/pins",
                    {"op": "add", "href": "/overview", "context": wrong})
    assert refused.status_code == 409, (wrong, refused.status_code, refused.text)
    # A page visit with a stale context records nothing instead of failing.
    visit = _post(client, "/api/v1/navigation/recent", {"path": "/overview", "context": wrong})
    assert visit.status_code == 200 and visit.json() == {"recorded": False}


@pytest.mark.parametrize("wrong", WRONG)
def test_personal_notification_preferences_context(client, wrong):
    refused = _post(client, "/api/v1/notifications/personal/preferences",
                    {"context": wrong, "expected_revision": "0" * 64, "preferences": {}})
    assert refused.status_code == 409, (wrong, refused.status_code, refused.text)


def test_copilot_context_header(client):
    def ask(value):
        return _post(client, "/api/v1/copilot", {"message": "hello", "page": "/overview"},
                     {"X-Lightwork-Copilot-Context": value})

    assert ask("0" * 64).status_code == 409
    assert ask(b"caf\xe9").status_code == 409


@pytest.mark.parametrize("wrong", WRONG)
def test_budget_accounting_case_context(client, wrong):
    refused = _post(client, "/api/v1/budget/cases",
                    {"context": wrong, "provider": "anthropic", "period": "2026-10"})
    assert refused.status_code == 409, (wrong, refused.status_code, refused.text)


def test_deliverable_bundle_context_header(client, monkeypatch):
    from maverick_dashboard import deliverable_bundles_api as bundles

    monkeypatch.setattr(bundles.config, "get_features", lambda: {"deliverable_bundles": True})
    monkeypatch.setattr(bundles.config, "config_source_errors", lambda **kwargs: [])
    for value in ("0" * 64, b"caf\xe9"):
        refused = client.get("/api/v1/deliverable-bundles", headers={"X-Lightwork-Bundle-Context": value})
        assert refused.status_code == 409, (value, refused.status_code, refused.text)


def test_a_lone_surrogate_in_a_rejected_body_is_a_422_not_a_500(client):
    """The 422 echoes the rejected input; UTF-8 cannot encode a lone surrogate."""
    refused = _post(client, "/api/v1/navigation/pins", {"op": ["\ud800"], "href": "/overview", "context": "x"})
    assert refused.status_code == 422, (refused.status_code, refused.text)
    assert refused.headers["content-type"].startswith("application/json")
    assert refused.json()["detail"]


def test_a_non_finite_number_in_a_rejected_body_is_a_422_not_a_500(client):
    """JSON text may carry NaN and Infinity; the 422 that echoes one must still be JSON."""
    for value in ("NaN", "Infinity"):
        refused = client.post("/api/v1/outcomes", content=f'{{"goal_id": 1, "episode_id": 1, "value": {value}}}',
                              headers={"Content-Type": "application/json"})
        assert refused.status_code == 422, (value, refused.status_code, refused.text)
        assert refused.json()["detail"][0]["loc"] == ["body", "value"]
