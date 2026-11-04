"""Short-lived visitor sessions for the public consent service.

``[consent_preferences.public_api] token_ttl_seconds`` (60 to 86400 seconds)
makes websites and apps swap their site key for a visitor session before they
read or save consent, and renew it before it ends; an ended session is
refused. Sessions are bound to the enrolled client and its site origin, go
through the service's existing rate limit, and are never written to logs.
Unset keeps today's behaviour: the site key alone on every request.
"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app
from maverick_dashboard.consent_public_api import (
    PublicConsentRateLimitExceeded,
    PublicConsentValidationError,
    configured_token_ttl_seconds,
)

from test_support.consent_public_seed import (
    CLIENT_CREDENTIAL,
    NOW,
    ORIGIN,
    OTHER_CREDENTIAL,
    OTHER_ORIGIN,
    browser_headers,
    seed,
)

CONFIGURATION = "/api/v1/public/consent/configuration"
SESSIONS = "/api/v1/public/consent/sessions"
RENEW = "/api/v1/public/consent/sessions/renew"
TTL_ID = "consent_preferences.public_api.token_ttl_seconds"
REQUIRED = {"detail": "consent session required"}
INVALID = {"detail": "consent session expired or invalid"}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _start(env, credential=CLIENT_CREDENTIAL, origin=ORIGIN) -> dict:
    response = env.client.post(SESSIONS, headers=browser_headers(credential, origin))
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store, private"
    return response.json()


def _read(env, session=None, credential=CLIENT_CREDENTIAL, origin=ORIGIN):
    return env.client.get(CONFIGURATION, headers=browser_headers(credential, origin, session))


def test_without_a_lifetime_the_site_key_alone_works_as_before(tmp_path):
    env = seed(tmp_path, session_ttl=lambda: None)
    assert _read(env).status_code == 200
    assert env.client.post(SESSIONS, headers=browser_headers()).status_code == 404
    assert env.client.post(RENEW, headers=browser_headers(session="x" * 48)).status_code == 404


def test_session_issue_use_renew_and_expire(tmp_path):
    env = seed(tmp_path, session_ttl=lambda: 120)
    assert _read(env).json() == REQUIRED and _read(env).status_code == 401
    first = _start(env)
    assert first["ttl_seconds"] == 120 and first["expires_at"] == NOW + 120
    assert first["session_token"].startswith("lwcs_")
    assert _read(env, first["session_token"]).status_code == 200
    # Renewal before the end gives a new session; the old one lingers briefly.
    env.clock["now"] = NOW + 100
    renewed = env.client.post(RENEW, headers=browser_headers(session=first["session_token"]))
    assert renewed.status_code == 201, renewed.text
    second = renewed.json()
    assert second["session_token"] != first["session_token"]
    assert second["expires_at"] == NOW + 220
    assert _read(env, first["session_token"]).status_code == 200
    # A replaced session cannot be renewed again.
    again = env.client.post(RENEW, headers=browser_headers(session=first["session_token"]))
    assert again.status_code == 401 and again.json() == INVALID
    env.clock["now"] = NOW + 131
    assert _read(env, first["session_token"]).json() == INVALID
    assert _read(env, second["session_token"]).status_code == 200
    # After its end a session is refused, and so is renewing it.
    env.clock["now"] = NOW + 221
    assert _read(env, second["session_token"]).status_code == 401
    late = env.client.post(RENEW, headers=browser_headers(session=second["session_token"]))
    assert late.status_code == 401 and late.json() == INVALID
    assert env.client.post(RENEW, headers=browser_headers()).json() == REQUIRED
    # A new visit starts a new session.
    assert _read(env, _start(env)["session_token"]).status_code == 200


def test_sessions_are_bound_to_their_site_and_client(tmp_path):
    env = seed(tmp_path, session_ttl=lambda: 600)
    mine = _start(env)["session_token"]
    other = _start(env, OTHER_CREDENTIAL, OTHER_ORIGIN)["session_token"]
    assert _read(env, other, OTHER_CREDENTIAL, OTHER_ORIGIN).status_code == 200
    # Another website's session is refused, whichever way round.
    assert _read(env, mine, OTHER_CREDENTIAL, OTHER_ORIGIN).json() == INVALID
    assert _read(env, other).json() == INVALID
    renew = env.client.post(RENEW, headers=browser_headers(OTHER_CREDENTIAL, OTHER_ORIGIN, mine))
    assert renew.status_code == 401
    # A site key used from another origin is refused before any session check.
    assert _read(env, mine, CLIENT_CREDENTIAL, OTHER_ORIGIN).status_code == 401
    # Revoking the website's enrollment ends its sessions too.
    binding = env.bindings[ORIGIN]
    env.registry.revoke_client(CLIENT_CREDENTIAL, expected_revision=binding.revision)
    assert _read(env, mine).status_code == 401


def test_sessions_use_the_existing_rate_limit(tmp_path):
    limited = {"left": 2}
    calls: list[tuple[str, str]] = []

    def rate_limit(credential_sha256: str, action: str) -> None:
        calls.append((credential_sha256, action))
        if limited["left"] <= 0:
            raise PublicConsentRateLimitExceeded("rate limit reached")
        limited["left"] -= 1

    env = seed(tmp_path, session_ttl=lambda: 120, rate_limit=rate_limit)
    _start(env)
    _start(env)
    refused = env.client.post(SESSIONS, headers=browser_headers())
    assert refused.status_code == 429 and refused.headers["retry-after"] == "60"
    assert {action for _sha, action in calls} == {"request"}
    assert len({sha for sha, _action in calls}) == 1


def test_one_site_key_cannot_fill_every_session(tmp_path, monkeypatch):
    """Each site key has its own share of live sessions, so one key can't use
    up the installation's capacity for every other site."""
    from maverick_dashboard import consent_public_api

    monkeypatch.setattr(consent_public_api, "_MAX_LIVE_SESSIONS", 5)
    monkeypatch.setattr(consent_public_api, "_MAX_LIVE_SESSIONS_PER_CLIENT", 2)
    env = seed(tmp_path, session_ttl=lambda: 600)
    _start(env)
    _start(env)
    refused = env.client.post(SESSIONS, headers=browser_headers())
    assert refused.status_code == 429 and refused.json() == {"detail": "rate limit reached"}
    # Another website still gets its sessions.
    other = _start(env, OTHER_CREDENTIAL, OTHER_ORIGIN)["session_token"]
    assert _read(env, other, OTHER_CREDENTIAL, OTHER_ORIGIN).status_code == 200
    # Ended sessions free the key's share again.
    env.clock["now"] = NOW + 601
    assert _start(env)["session_token"]


def test_session_lifetime_bounds(tmp_path, monkeypatch):
    from maverick import config

    for value, expected in ((59, None), (60, 60), (900, 900), (86_400, 86_400),
                            (86_401, None), (True, None), ("600", None), (0, None)):
        path = tmp_path / f"config-{expected}-{value!r}.toml"
        literal = "true" if value is True else (f'"{value}"' if isinstance(value, str) else value)
        path.write_text("[consent_preferences.public_api]\n"
                        f"token_ttl_seconds = {literal}\n", encoding="utf-8")
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        config.reset_config_cache()
        assert configured_token_ttl_seconds() == expected, value
    monkeypatch.delenv("MAVERICK_CONFIG")
    config.reset_config_cache()
    env = seed(tmp_path / "store", session_ttl=lambda: 120)
    binding = env.bindings[ORIGIN]
    for bad in (59, 86_401, True, 60.5):
        with pytest.raises(PublicConsentValidationError):
            env.registry.issue_session(binding, audience=ORIGIN, ttl_seconds=bad)
    # A lifetime outside the bounds never turns sessions on.
    out_of_bounds = seed(tmp_path / "bounds", session_ttl=lambda: 30)
    assert _read(out_of_bounds).status_code == 200


def test_no_session_token_is_written_to_logs(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    env = seed(tmp_path, session_ttl=lambda: 120)
    first = _start(env)["session_token"]
    _read(env, first)
    env.clock["now"] = NOW + 90
    second = env.client.post(RENEW, headers=browser_headers(session=first)).json()["session_token"]
    env.clock["now"] = NOW + 500
    _read(env, second)
    env.client.post(RENEW, headers=browser_headers(session=second))
    text = caplog.text + "".join(repr(record.args) for record in caplog.records)
    for secret in (first, second, CLIENT_CREDENTIAL):
        assert secret not in text


# ------------------------------------------------ the setting takes effect
def _save(value, confirm=False):
    from test_support.settings_pages import save_catalog

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    change = {"id": TTL_ID, "reset": True} if value is None else {"id": TTL_ID, "value": value}
    return save_catalog(client, "/api/v1/settings/catalog", json={"changes": [change],
                                                          "confirm": confirm})


def test_saved_lifetime_takes_effect_and_turning_sessions_off_needs_confirmation(tmp_path):
    env = seed(tmp_path)  # the installation's own setting decides
    assert configured_token_ttl_seconds() is None
    assert _read(env).status_code == 200
    for bad in (0, 1441, "many", True):
        assert _save(bad).status_code == 400, bad
    assert _save(2).status_code == 200  # minutes on the page, seconds in the setting
    assert configured_token_ttl_seconds() == 120
    assert _read(env).json() == REQUIRED
    session = _start(env)
    assert session["ttl_seconds"] == 120
    assert _read(env, session["session_token"]).status_code == 200
    # Longer sessions, or no sessions at all, loosen a protection: confirm first.
    assert _save(5).status_code == 409 and configured_token_ttl_seconds() == 120
    assert _save(None).status_code == 409
    assert _save(None, confirm=True).status_code == 200
    assert configured_token_ttl_seconds() is None
    assert _read(env).status_code == 200


def test_the_consent_script_is_allowed_to_send_the_session_header(tmp_path):
    env = seed(tmp_path, session_ttl=lambda: 120)
    response = env.client.options(
        SESSIONS.replace("/sessions", "/sessions/renew"),
        headers={"Origin": ORIGIN, "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "authorization,x-lightwork-consent-session"})
    assert response.status_code == 204
    assert "x-lightwork-consent-session" in response.headers["access-control-allow-headers"]
