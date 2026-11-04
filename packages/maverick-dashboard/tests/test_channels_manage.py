"""Channel setup from the dashboard: enable/disable + credentials stored in the
overlay (dashboard-config.toml), which load_config() deep-merges so
`maverick serve` picks them up with no config.toml edit."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from test_support.channel_review import channel_review_token

_ORIGIN = {"origin": "http://127.0.0.1"}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def _iso(monkeypatch, tmp_path):
    # MAVERICK_CONFIG anchors both config.toml and its sibling
    # dashboard-config.toml (the overlay settings_store writes) under tmp.
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("VOICE_ALLOWED_CALLERS", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    yield


# ---- settings_store unit level ------------------------------------------------

def test_set_channel_writes_enabled_and_fields():
    from maverick_dashboard import settings_store as ss
    ss.set_channel("slack", True, {"app_token": "xapp-1", "bot_token": "xoxb-1"})
    overlay = ss.load_overlay()
    assert overlay["channels"]["slack"]["enabled"] is True
    assert overlay["channels"]["slack"]["app_token"] == "xapp-1"


def test_channels_state_masks_secrets():
    from maverick_dashboard import settings_store as ss
    ss.set_channel("slack", True, {"app_token": "xapp-supersecret", "bot_token": "xoxb-1"})
    state = {c["name"]: c for c in ss.channels_state()}
    slack = state["slack"]
    assert slack["enabled"] is True
    f = {x["key"]: x for x in slack["fields"]}
    # secret never echoed back; a masked hint is shown instead
    assert f["app_token"]["value"] == ""
    assert "supersecret" not in f["app_token"]["hint"]
    assert f["app_token"]["hint"]  # some mask present


def test_blank_secret_keeps_existing():
    from maverick_dashboard import settings_store as ss
    ss.set_channel("discord", True, {"bot_token": "keepme"})
    # toggle off without re-entering the token
    ss.set_channel("discord", False, {"bot_token": ""})
    overlay = ss.load_overlay()
    assert overlay["channels"]["discord"]["enabled"] is False
    assert overlay["channels"]["discord"]["bot_token"] == "keepme"


def test_int_field_typed_and_validated():
    from maverick_dashboard import settings_store as ss
    ss.set_channel("sms", True, {"account_sid": "AC1", "auth_token": "t",
                                 "from_number": "+1", "port": "8770"})
    assert ss.load_overlay()["channels"]["sms"]["port"] == 8770
    with pytest.raises(ValueError):
        ss.set_channel("sms", True, {"port": "not-a-number"})


def test_clear_and_unknown_channel():
    from maverick_dashboard import settings_store as ss
    ss.set_channel("telegram", True, {"bot_token": "t"})
    ss.clear_channel("telegram")
    assert "telegram" not in (ss.load_overlay().get("channels") or {})
    with pytest.raises(ValueError):
        ss.set_channel("nope", True, {})
    with pytest.raises(ValueError):
        ss.clear_channel("nope")


def test_overlay_deep_merges_into_load_config():
    from maverick import config
    from maverick_dashboard import settings_store as ss
    ss.set_channel("telegram", True, {"bot_token": "12345:secret"})
    # this is the real wiring proof: server.build_from_config reads load_config()
    merged = config.load_config()
    assert merged["channels"]["telegram"]["enabled"] is True
    assert merged["channels"]["telegram"]["bot_token"] == "12345:secret"


def test_channel_coexists_with_provider_keys():
    from maverick_dashboard import settings_store as ss
    ss.set_provider("anthropic", api_key="sk-ant-xxx")  # pragma: allowlist secret
    ss.set_channel("slack", True, {"app_token": "xapp", "bot_token": "xoxb"})
    overlay = ss.load_overlay()
    # one file, full-state writes: neither clobbers the other
    assert overlay["providers"]["anthropic"]["api_key"] == "sk-ant-xxx"  # pragma: allowlist secret
    assert overlay["channels"]["slack"]["enabled"] is True


# ---- route level --------------------------------------------------------------

def test_page_renders_management_forms():
    r = _client().get("/channels")
    assert r.status_code == 200
    assert 'action="/channels/save"' in r.text
    assert 'value="slack"' in r.text and 'value="telegram"' in r.text
    assert 'name="enabled"' in r.text
    assert 'name="allowed_user_ids"' in r.text
    assert "Who can message Lightwork" in r.text


def test_channel_page_saves_and_checks_permitted_people():
    from maverick import config
    from maverick_dashboard import integration_readiness, settings_store

    client = _client()
    saved = client.post("/channels/save", headers=_ORIGIN, data={
        "review_token": channel_review_token(client), "confirm_people": "yes",
        "channel": "slack", "enabled": "on", "app_token": "xapp-fixture",
        "bot_token": "xoxb-fixture", "allowed_user_ids": "U01ABCDEF\nU02ABCDE,U01ABCDEF",
    }, follow_redirects=False)
    assert saved.status_code == 303
    assert settings_store.load_overlay()["channels"]["slack"]["allowed_user_ids"] == [
        "U01ABCDEF", "U02ABCDE",
    ]
    page = client.get("/channels")
    assert "U01ABCDEF\nU02ABCDE" in page.text
    invalid = client.post("/channels/save", headers=_ORIGIN, data={
        "review_token": channel_review_token(client), "confirm_people": "yes",
        "channel": "slack", "enabled": "on", "allowed_user_ids": "anyone",
    })
    assert invalid.status_code == 400
    assert settings_store.load_overlay()["channels"]["slack"]["allowed_user_ids"] == [
        "U01ABCDEF", "U02ABCDE",
    ]
    cleared = client.post("/channels/save", headers=_ORIGIN, data={
        "review_token": channel_review_token(client), "confirm_people": "yes",
        "channel": "slack", "enabled": "on", "allowed_user_ids": "",
    }, follow_redirects=False)
    assert cleared.status_code == 303
    # An explicit empty list denies everyone; removing the key would silently
    # restore installer access (settings_store.set_channel).
    assert settings_store.load_overlay()["channels"]["slack"]["allowed_user_ids"] == []
    config.reset_config_cache()
    readiness = integration_readiness.channel_readiness("slack", config.load_config()["channels"]["slack"])
    assert readiness["runtime"]["status"] == "failed"
    assert "permitted people" in readiness["runtime"]["detail"]


def test_voice_inventory_and_settings_explain_required_caller_list(tmp_path):
    from maverick import config
    from maverick_dashboard import integration_readiness

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[channels.voice]\nenabled = true\napi_key = "fixture"\n'  # pragma: allowlist secret
        'webhook_token = "fixture"\n', encoding="utf-8",
    )
    config.reset_config_cache()
    client = _client()
    page = client.get("/channels")
    assert page.status_code == 200
    assert "Set permitted callers" in page.text
    assert "/settings/all?id=channels.voice.allowed_callers" in page.text
    assert "An empty list blocks incoming work" in page.text
    assert "Needs attention" in page.text

    settings = client.get("/settings/all?id=channels.voice.allowed_callers")
    assert settings.status_code == 200
    assert "With no permitted callers, incoming calls cannot start work" in settings.text
    assert "Saving a blank list denies everyone" in settings.text

    configured = {"enabled": True, "api_key": "fixture", "webhook_token": "fixture",
                  "allowed_callers": ["+12025550111"]}
    # Incoming calls also need the saved assistant from the phone service.
    no_assistant = integration_readiness.channel_readiness("voice", configured)["runtime"]
    assert no_assistant["status"] != "passed"
    if not ("adapter is unavailable" in no_assistant["detail"]
            or "not installed" in no_assistant["detail"]):
        assert "saved assistant" in no_assistant["detail"]
    configured["assistant_id"] = "assistant-fixture"
    voice_runtime = integration_readiness.channel_readiness("voice", configured)["runtime"]
    if voice_runtime["status"] != "passed":
        assert "adapter is unavailable" in voice_runtime["detail"] or "not installed" in voice_runtime["detail"]


def test_email_sender_check_is_configurable_and_required_from_the_page():
    from maverick_dashboard import integration_readiness, settings_store

    client = _client()
    page = client.get("/channels")
    assert page.status_code == 200
    assert 'name="trusted_authserv_id"' in page.text
    assert "Messages without that confirmation are refused" in page.text
    bad = client.post("/channels/save", headers=_ORIGIN, data={
        "review_token": channel_review_token(client),
        "channel": "email", "enabled": "on", "trusted_authserv_id": "not a server",
    })
    assert bad.status_code == 400
    saved = client.post("/channels/save", headers=_ORIGIN, data={
        "review_token": channel_review_token(client), "confirm_people": "yes",
        "channel": "email", "enabled": "on", "trusted_authserv_id": "mx.example.com",
        "allowed_user_ids": "owner@example.com",
    }, follow_redirects=False)
    assert saved.status_code == 303
    assert settings_store.load_overlay()["channels"]["email"]["trusted_authserv_id"] == "mx.example.com"
    assert settings_store.load_overlay()["channels"]["email"]["allowed_user_ids"] == ["owner@example.com"]
    required = {"enabled": True, "imap_host": "imap.example.com", "imap_user": "bot@example.com",
                "imap_password": "fixture", "smtp_host": "smtp.example.com",
                "smtp_user": "bot@example.com", "smtp_password": "fixture"}
    assert integration_readiness.channel_readiness("email", required)["runtime"]["status"] == "failed"
    assert integration_readiness.channel_readiness("email", {
        **required, "trusted_authserv_id": "mx.example.com",
        "allowed_user_ids": [],
    })["runtime"]["status"] == "failed"
    assert integration_readiness.channel_readiness("email", {
        **required, "trusted_authserv_id": "mx.example.com",
        "allowed_user_ids": ["owner@example.com"],
    })["runtime"]["status"] == "passed"


@pytest.mark.parametrize("channel,missing,config", [
    ("telegram", "telegram", {"bot_token": "fixture"}),
    ("slack", "slack_sdk", {"app_token": "fixture", "bot_token": "fixture"}),
    ("discord", "discord", {"bot_token": "fixture"}),
    ("matrix", "nio", {}),
    ("sms", "twilio", {"account_sid": "fixture", "auth_token": "fixture",
                        "from_number": "+12025550111"}),
    ("rcs", "google.auth", {}),
    ("teams", "jwt", {"app_id": "fixture", "app_password": "fixture",
                      "tenant_id": "fixture"}),
])
def test_missing_channel_sdk_blocks_readiness_and_local_preflight(monkeypatch, channel, missing, config):
    from maverick_dashboard import integration_readiness

    original = integration_readiness.importlib.util.find_spec
    monkeypatch.setattr(integration_readiness.importlib.util, "find_spec",
                        lambda name: None if name == missing else original(name))
    configured = {"enabled": True, **config}
    readiness = integration_readiness.channel_readiness(channel, configured)
    assert readiness["state"] == "dependency_failed"
    assert readiness["dependency"]["status"] == "failed"
    assert missing in readiness["dependency"]["evidence"]["missing_modules"]
    assert "installation administrator" in readiness["dependency"]["detail"]
    assert "restart the chat service in Settings" in readiness["dependency"]["detail"]
    assert integration_readiness.probe_channel(channel, configured)["verified"] is False


def test_missing_telegram_sdk_is_visible_on_channels_page_and_api(monkeypatch):
    from maverick.config import load_config
    from maverick_dashboard import integration_readiness, settings_store

    original = integration_readiness.importlib.util.find_spec
    monkeypatch.setattr(integration_readiness.importlib.util, "find_spec",
                        lambda name: None if name == "telegram" else original(name))
    settings_store.set_channel("telegram", True, {"bot_token": "fixture"})
    effective = load_config()["channels"]["telegram"]
    integration_readiness.record("channel", "telegram", effective, verified=True,
                                 detail="previous connection test worked")
    client = _client()
    page = client.get("/channels")
    assert page.status_code == 200
    assert "Telegram support is missing" in page.text
    assert "Manage the chat service" in page.text
    assert "1 turned on · 0 working · 1 failed" in page.text
    response = client.get("/api/v1/channels")
    assert response.status_code == 200
    telegram = next(row for row in response.json()["channels"] if row["name"] == "telegram")
    assert telegram["readiness"]["state"] == "dependency_failed"
    integration_readiness.clear("channel", "telegram")


def test_channel_tests_stop_before_external_call_when_support_is_missing(monkeypatch):
    from maverick_dashboard import channel_check_api, integration_readiness, settings_store

    original = integration_readiness.importlib.util.find_spec
    monkeypatch.setattr(integration_readiness.importlib.util, "find_spec",
                        lambda name: None if name == "slack_sdk" else original(name))
    monkeypatch.setattr(channel_check_api, "check_credentials",
                        lambda *_args: pytest.fail("external credential test must not run"))
    monkeypatch.setattr(channel_check_api, "send_test",
                        lambda *_args: pytest.fail("external send must not run"))
    settings_store.set_channel("slack", True, {"app_token": "fixture", "bot_token": "fixture"})
    client = _client()
    headers = {**_ORIGIN, "accept": "application/json"}
    checked = client.post("/channels/test", headers=headers, data={"channel": "slack"})
    assert checked.status_code == 200
    assert checked.json()["ok"] is False
    assert "Slack support is missing" in checked.json()["message"]
    sent = client.post("/channels/send-test", headers=headers,
                       data={"channel": "slack", "to": "#general"})
    assert sent.status_code == 200
    assert sent.json()["ok"] is False
    assert "Slack support is missing" in sent.json()["message"]
    integration_readiness.clear("channel", "slack")


def test_save_channel_enables_and_hides_secret():
    c = _client()
    r = c.post("/channels/save", headers=_ORIGIN, follow_redirects=False, data={
        "channel": "slack", "enabled": "on", "review_token": channel_review_token(c),
        "app_token": "xapp-leak", "bot_token": "xoxb-leak"})
    assert r.status_code == 303
    from maverick_dashboard import settings_store as ss
    assert ss.load_overlay()["channels"]["slack"]["enabled"] is True
    # the secret must never render back on the page
    page = c.get("/channels").text
    assert "xapp-leak" not in page and "xoxb-leak" not in page


def test_save_without_checkbox_disables():
    c = _client()
    c.post("/channels/save", headers=_ORIGIN, data={
        "channel": "telegram", "enabled": "on", "bot_token": "t", "review_token": channel_review_token(c)})
    # second save omits the checkbox -> disabled, token kept
    r = c.post("/channels/save", headers=_ORIGIN, follow_redirects=False, data={
        "channel": "telegram", "bot_token": "", "review_token": channel_review_token(c)})
    assert r.status_code == 303
    from maverick_dashboard import settings_store as ss
    ch = ss.load_overlay()["channels"]["telegram"]
    assert ch["enabled"] is False and ch["bot_token"] == "t"


def test_clear_route_removes_channel():
    c = _client()
    c.post("/channels/save", headers=_ORIGIN, data={
        "channel": "discord", "enabled": "on", "bot_token": "t", "review_token": channel_review_token(c)})
    # Clearing restores the inherited people list, so it is reviewed and confirmed.
    r = c.post("/channels/clear", headers=_ORIGIN, follow_redirects=False,
               data={"channel": "discord", "review_token": channel_review_token(c), "confirm_people": "yes"})
    assert r.status_code == 303
    from maverick_dashboard import settings_store as ss
    assert "discord" not in (ss.load_overlay().get("channels") or {})


def test_invalid_channel_rejected():
    r = _client().post("/channels/save", headers=_ORIGIN, follow_redirects=False,
                       data={"channel": "nope", "enabled": "on"})
    assert r.status_code == 400


def test_cross_origin_blocked():
    r = _client().post("/channels/save", follow_redirects=False, data={
        "channel": "slack", "enabled": "on"})
    assert r.status_code == 403
