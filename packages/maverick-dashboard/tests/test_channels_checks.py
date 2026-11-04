"""Channels: Test connection and Send a test message buttons."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

from test_support.channel_review import channel_review_token


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


def visible_text(page: str) -> str:
    main = page.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    main = re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", main)))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import integration_readiness
    integration_readiness._clear_for_testing()
    dash_app._world_cache.clear()
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    integration_readiness._clear_for_testing()
    config.reset_config_cache()


def _slack(client):
    r = client.post("/channels/save", data={"channel": "slack", "enabled": "on",
                                              "review_token": channel_review_token(client), "confirm_people": "yes",
                                              "app_token": "xapp-1", "bot_token": "xoxb-1",
                                              "allowed_user_ids": "U01ABCDEF"},  # pragma: allowlist secret
                    follow_redirects=False)
    assert r.status_code == 303
    from maverick import config
    config.reset_config_cache()


def test_test_connection_marks_the_channel_working(client, monkeypatch):
    from maverick_dashboard import channel_check_api, integration_readiness
    _slack(client)
    monkeypatch.setattr(integration_readiness, "_channel_dependency",
                        lambda _name: integration_readiness.check(
                            "passed", "fixture", kind="channel_adapter"))
    seen = []
    monkeypatch.setattr(channel_check_api, "_get", lambda url, headers: seen.append(url) or _Resp(200, {"ok": True}))
    r = client.post("/channels/test", data={"channel": "slack"}, follow_redirects=False)
    assert r.status_code == 303 and "saved=tested" in r.headers["location"]
    assert seen == ["https://slack.com/api/auth.test"]
    page = client.get("/channels?saved=tested").text
    assert "Connection test passed." in page and "Working" in page


def test_send_test_message_validates_the_destination_and_records_result(client, monkeypatch):
    from maverick_dashboard import channel_check_api, integration_readiness
    _slack(client)
    monkeypatch.setattr(integration_readiness, "_channel_dependency",
                        lambda _name: integration_readiness.check(
                            "passed", "fixture", kind="channel_adapter"))
    sent = []
    monkeypatch.setattr(channel_check_api, "_post",
                        lambda url, **kw: sent.append((url, kw.get("json"))) or _Resp(200, {"ok": False}))
    assert client.post("/channels/send-test", data={"channel": "slack", "to": "not a channel!"}).status_code == 422
    r = client.post("/channels/send-test", data={"channel": "slack", "to": "#general"}, follow_redirects=False)
    assert "saved=send_failed" in r.headers["location"]
    assert sent[0][0] == "https://slack.com/api/chat.postMessage" and sent[0][1]["channel"] == "#general"
    assert "Test failed" in client.get("/channels").text
    assert client.post("/channels/send-test", data={"channel": "telegram", "to": "x"}).status_code == 400


def test_channel_tests_stop_before_network_when_no_people_are_permitted(client, monkeypatch):
    from maverick_dashboard import channel_check_api, integration_readiness

    _slack(client)
    monkeypatch.setattr(integration_readiness, "_channel_dependency",
                        lambda _name: integration_readiness.check(
                            "passed", "fixture", kind="channel_adapter"))
    monkeypatch.setattr(channel_check_api, "_channel_config",
                        lambda _name: {"enabled": True, "app_token": "xapp-1", "bot_token": "xoxb-1"})
    monkeypatch.setattr(channel_check_api, "_get",
                        lambda *_args, **_kwargs: pytest.fail("credential test reached the network"))
    monkeypatch.setattr(channel_check_api, "_post",
                        lambda *_args, **_kwargs: pytest.fail("message test reached the network"))

    for path, data, result in (
        ("/channels/test", {"channel": "slack"}, "test_failed"),
        ("/channels/send-test", {"channel": "slack", "to": "#general"}, "send_failed"),
    ):
        response = client.post(path, data=data, follow_redirects=False)
        assert response.status_code == 303
        assert f"saved={result}" in response.headers["location"]


def test_email_server_named_in_the_environment_passes_the_page_and_connection_checks(monkeypatch):
    # The email channel accepts EMAIL_TRUSTED_AUTHSERV_ID when the setting is
    # not saved; the Channels page and Test connection must agree with it.
    from maverick_dashboard import channel_check_api, integration_readiness

    cfg = {"imap_host": "imap.example.test", "imap_user": "bot@example.test",
           "imap_password": "fixture", "smtp_host": "smtp.example.test",  # pragma: allowlist secret
           "smtp_user": "bot@example.test", "smtp_password": "fixture",
           "allowed_user_ids": ["alice@example.test"]}
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_ID", "mx.example.test")
    assert integration_readiness._email_configuration_problem(cfg) == ""
    reached = []

    def imap(host, **_kwargs):
        reached.append(host)
        raise ConnectionRefusedError("fixture")

    monkeypatch.setattr(channel_check_api.imaplib, "IMAP4_SSL", imap)
    channel_check_api.check_credentials("email", cfg)
    assert reached == ["imap.example.test"]          # past the setup check, to sign-in
    assert integration_readiness._email_configuration_problem(
        {**cfg, "trusted_authserv_id": "not a server"})  # the saved setting wins
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV_ID", "mx..example.test")
    assert integration_readiness._email_configuration_problem(
        {**cfg, "trusted_authserv_id": "mx.example.test"}) == ""
    assert "server that checks incoming mail" in integration_readiness._email_configuration_problem(cfg)


def test_email_check_requires_sender_setup_and_tests_both_mail_signins(monkeypatch):
    from maverick_dashboard import channel_check_api

    monkeypatch.delenv("EMAIL_TRUSTED_AUTHSERV_ID", raising=False)
    cfg = {"imap_host": "imap.example.test", "imap_user": "bot@example.test",
           "imap_password": "fixture", "smtp_host": "smtp.example.test",  # pragma: allowlist secret
           "smtp_user": "bot@example.test", "smtp_password": "fixture",
           "allowed_user_ids": ["alice@example.test"]}
    assert channel_check_api.check_credentials("email", cfg)[0] is False
    steps = []
    class IMAP:
        def __init__(self, host, *, ssl_context, timeout):
            assert host == "imap.example.test" and ssl_context and timeout
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def login(self, user, password):
            steps.append("incoming sign-in")
            return "OK", []
        def select(self, mailbox, *, readonly):
            assert mailbox == "INBOX" and readonly
            steps.append("mailbox")
            return "OK", []
        def response(self, key):
            assert key == "UIDVALIDITY"
            return key, [b"42"]
    class SMTP:
        def quit(self):
            steps.append("outgoing sign-in")
    monkeypatch.setattr(channel_check_api.imaplib, "IMAP4_SSL", IMAP)
    monkeypatch.setattr(channel_check_api, "_smtp", lambda _: SMTP())
    ok, detail = channel_check_api.check_credentials(
        "email", {**cfg, "trusted_authserv_id": "mx.example.test"},
    )
    assert ok is True and "live sender check" in detail
    assert steps == ["incoming sign-in", "mailbox", "outgoing sign-in"]


def test_checks_are_admin_only_same_origin_and_need_a_turned_on_app(client, monkeypatch):
    assert client.post("/channels/test", data={"channel": "slack"}).status_code == 409
    assert TestClient(client.app, base_url="http://127.0.0.1").post("/channels/test", data={"channel": "slack"}).status_code == 403
    from maverick_dashboard import auth, rbac
    rbac.set_role("user:vic", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:vic")
    assert client.post("/channels/send-test", data={"channel": "email", "to": "a@b.co"}).status_code == 403


def test_channels_page_reads_plainly(client):
    _slack(client)
    text = visible_text(client.get("/channels").text)
    for word in ("preflight", "adapter", "config.toml", "verification unknown", "IMAP host", "SMTP port", "Webhook port", "[redacted]"):
        assert word not in text, word
    for label in ("Test connection", "Send a test message", "Remove saved settings", "Where do I find these details?",
                  "Advanced settings", "Your email provider"):
        assert label in text, label


def test_connections_page_reads_plainly_and_offers_people_and_regions(client, monkeypatch):
    from maverick import connections
    from maverick_dashboard import rbac
    rbac.set_role("user:dana@example.com", "operator")
    # The setup form is shown once Connections is turned on; while off the
    # page stays quiet and offers the shared Turn on banner.
    quiet = client.get("/connections").text
    assert 'data-module-gate="connections"' in quiet
    monkeypatch.setattr(connections, "enabled", lambda: True)
    page = client.get("/connections").text
    text = visible_text(page)
    for word in ("user:id", "principals", "Base URL", "API token", "encrypted at rest", "bearer",
                 "Connector (tool name)", "Installation administrator: provider registration",
                 "Configuration does not prove", "Exact provider permissions"):
        assert word not in text, word
    assert 'value="user:dana@example.com"' in page and "dana@example.com" in text
    assert '<option value="eu-west-1">Europe (Ireland)</option>' in page
    assert "Copy return address" in text
