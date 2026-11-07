"""The personal My work page, its choices and chat-account links, the admin
controls, the Test email button and the signed Slack HTTP receivers."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
SECRET = "8f742231b10e8888abcd99yyyzzz85a5"  # pragma: allowlist secret -- Slack's doc example


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import app as app_mod

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda kind, **p: True)
    app_mod._world_cache.clear()
    app_mod._issue_webhook_seen.clear()
    config.reset_config_cache()
    yield
    app_mod._world_cache.clear()
    config.reset_config_cache()


def _as(monkeypatch, principal, role="operator"):
    from maverick_dashboard import auth, rbac

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: role)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: role)
    monkeypatch.setattr(rbac, "list_users", lambda: {principal: role})


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, follow_redirects=False)


def _world(tmp_path):
    from maverick.world_model import WorldModel

    return WorldModel(tmp_path / "world.db")


def _card():
    from maverick.approval_cards import build_approval_card

    return build_approval_card(
        action="wire_funds", summary="Pay the reviewed invoice", target_label="Invoice 12",
        target={"i": 12}, parameters={"amount": 5}, parameter_summary=["Pay $5 once"],
        actor="user:requester", workspace="t", role="operator", authority_versions={},
        input_versions={}, credential_versions={}, budget={"currency": "USD", "maximum": 5.0},
        expires_at=time.time() + 300, known_effects=["Money leaves the account."],
        unresolved_assumptions=[], before="Unpaid.", after="Paid.", irreversible=True,
    )


def _seed(tmp_path):
    from maverick.approval_cards import encode_approval_detail

    world = _world(tmp_path)
    goal = world.create_goal("Forecast", owner="user:alice")
    world.set_goal_status(goal, "done", result="Done well.")
    ep = world.start_episode(goal)
    world.end_episode(ep, summary="s", outcome="ok", cost_dollars=2.5)
    world.ask("Which quarter?", goal_id=goal)
    other = world.create_goal("Bob's", owner="user:bob")
    world.set_goal_status(other, "done", result="x")
    card = _card()
    aid = world.create_approval("wire_funds", risk="high", detail=encode_approval_detail(card),
                                requested_by="user:requester")
    return {"goal": goal, "other": other, "approval": aid, "card": card}


# ------------------------------------------------------------------- the page

def test_me_page_for_an_operator_shows_only_their_work(tmp_path, monkeypatch):
    ids = _seed(tmp_path)
    _as(monkeypatch, "user:alice")
    page = _client().get("/me")
    assert page.status_code == 200
    text = page.text
    assert "My work" in text and "Forecast" in text and "Which quarter?" in text
    assert "Bob&#39;s" not in text and "Bob's" not in text
    assert f"#{ids['approval']} Wire funds" in text and "Can't be undone" in text
    assert "$2.50" in text
    assert 'href="/me"' in text  # in the sidebar under Work


def test_me_page_for_a_viewer_and_an_administrator(tmp_path, monkeypatch):
    ids = _seed(tmp_path)
    _as(monkeypatch, "user:carol", role="viewer")
    text = _client().get("/me").text
    assert "Nothing is waiting for your decision" in text  # viewers see only their own requests
    assert "No results in the last 7 days" in text
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")
    _as(monkeypatch, "user:root", role="admin")
    text = _client().get("/me").text
    # Administrator authority does not make colleagues' work appear in a
    # personal digest. Cross-owner reads require a separate reviewed action.
    assert "Forecast" not in text and "Bob" not in text
    assert f"#{ids['approval']}" in text
    body = _client().get("/api/v1/me/work").json()
    assert body["principal"] == "user:root" and body["digest"]["counts"]["results"] == 0


def test_me_page_with_sign_in_off_uses_the_local_identity(tmp_path):
    _seed(tmp_path)
    page = _client().get("/me")
    assert page.status_code == 200 and "local:dashboard" not in page.text.split("<main")[0]
    assert _client().get("/api/v1/me/work").json()["principal"] == "local:dashboard"


def test_preferences_form_saves_and_rejects_bad_values(tmp_path, monkeypatch):
    from maverick import user_preferences

    _as(monkeypatch, "user:alice")
    client = _client()
    r = client.post("/me/preferences", data={
        "time_zone": "Europe/Berlin", "digest_hour": "7", "email": "Alice@Example.com",
        "digest_enabled": "on"})
    assert r.status_code == 303 and r.headers["location"] == "/me?saved=preferences"
    prefs = user_preferences.get_preferences("user:alice")
    assert prefs["time_zone"] == "Europe/Berlin" and prefs["digest_hour"] == 7
    assert prefs["email"] == "alice@example.com" and prefs["send_when_empty"] is False
    r = client.post("/me/preferences", data={"time_zone": "Mars/Base", "digest_hour": "7"})
    assert r.headers["location"] == "/me?saved=bad_preferences"
    assert "Your choices are saved" in client.get("/me?saved=preferences").text
    r = client.post("/me/preferences", data={"time_zone": "UTC"}, headers={"Origin": "http://evil"})
    assert r.status_code == 403


def test_link_code_and_unlink_flow(tmp_path, monkeypatch):
    from maverick import channel_identities

    _as(monkeypatch, "user:alice")
    client = _client()
    r = client.post("/me/channels/link-code", data={"channel": "slack"})
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    import re

    code = re.search(r"/lightwork link ([A-Za-z0-9]{8})", r.text).group(1)
    assert len(code) == 8
    assert f"/lightwork link {code}" in r.text
    assert code not in client.get(f"/me?channel=slack&code={code}").text
    assert channel_identities.redeem_link_code("slack", "U77", code) == "user:alice"
    assert "U77" in client.get("/me").text
    r = client.post("/me/channels/unlink", data={"channel": "slack", "external_id": "U77"})
    assert r.status_code == 303 and channel_identities.principal_for("slack", "U77") is None
    assert client.post("/me/channels/link-code", data={"channel": "pigeon"}).status_code == 400


def test_send_now_reports_whether_anything_went_out(tmp_path, monkeypatch):
    from maverick import channel_identities, daily_digest

    _seed(tmp_path)
    _as(monkeypatch, "user:alice")
    client = _client()
    assert client.post("/me/digest/send-now").headers["location"] == "/me?saved=not_sent"
    channel_identities.link("slack", "U1", "user:alice", actor="admin")
    seen = []
    monkeypatch.setattr(daily_digest, "_send_slack",
                        lambda p, d, links, prefs: seen.append((p, d["counts"])) or True)
    assert client.post("/me/digest/send-now").headers["location"] == "/me?saved=sent"
    assert seen[0][0] == "user:alice" and seen[0][1]["approvals"] == 1


def test_send_now_says_when_a_summary_may_have_gone_out_unconfirmed(tmp_path, monkeypatch):
    from maverick import channel_identities, daily_digest

    _seed(tmp_path)
    _as(monkeypatch, "user:alice")
    client = _client()
    channel_identities.link("slack", "U1", "user:alice", actor="admin")

    def lost(p, d, links, prefs):
        raise TimeoutError("no reply after posting")
    monkeypatch.setattr(daily_digest, "_send_slack", lost)
    location = client.post("/me/digest/send-now").headers["location"]
    assert location == "/me?saved=unconfirmed"
    assert "did not confirm it. Check your chat app or inbox before sending it again." in client.get(location).text


# ---------------------------------------------------------- administrators

def test_admin_links_and_unlinks_chat_accounts_on_users_page(tmp_path, monkeypatch):
    from maverick import channel_identities

    _as(monkeypatch, "user:root", role="admin")
    client = _client()
    r = client.post("/users/channels/link",
                    data={"principal": "user:alice", "channel": "slack", "external_id": "U5"})
    assert r.status_code == 303 and channel_identities.principal_for("slack", "U5") == "user:alice"
    page = client.get("/users?saved=channel_linked").text
    assert "Chat account linked." in page and "U5" in page and "Link a chat account" in page
    r = client.post("/users/channels/link",
                    data={"principal": "user:bob", "channel": "slack", "external_id": "U5"})
    assert r.status_code == 400
    r = client.post("/users/channels/unlink", data={"channel": "slack", "external_id": "U5"})
    assert r.status_code == 303 and channel_identities.principal_for("slack", "U5") is None
    _as(monkeypatch, "user:alice", role="operator")
    r = client.post("/users/channels/link",
                    data={"principal": "user:alice", "channel": "slack", "external_id": "U6"})
    assert r.status_code == 403


def test_test_email_button(tmp_path, monkeypatch):
    from maverick import notifications

    _as(monkeypatch, "user:root", role="admin")
    client = _client()
    monkeypatch.setattr(notifications, "email_configured", lambda cfg=None: True)
    page = client.get("/channels").text
    assert "Test email" in page and 'action="/channels/test-email"' in page
    calls = []
    monkeypatch.setattr(notifications, "send_email",
                        lambda to, subject, text, html_body=None, cfg=None: calls.append(to) or True)
    r = client.post("/channels/test-email", data={"to": "ops@example.test"})
    assert r.headers["location"] == "/channels?saved=email_sent" and calls == ["ops@example.test"]
    monkeypatch.setattr(notifications, "send_email", lambda *a, **k: False)
    assert client.post("/channels/test-email", data={"to": "x@example.test"}).headers["location"] == "/channels?saved=email_failed"
    assert "could not be sent" in client.get("/channels?saved=email_failed").text
    monkeypatch.setattr(notifications, "email_configured", lambda cfg=None: False)
    assert "Email sending is not set up" in client.get("/channels").text


# -------------------------------------------------------- Slack over HTTP

def _signed(body: bytes, secret=SECRET, ts=None):
    stamp = str(int(ts if ts is not None else time.time()))
    digest = hmac.new(secret.encode(), f"v0:{stamp}:".encode() + body, hashlib.sha256).hexdigest()
    return {"X-Slack-Request-Timestamp": stamp, "X-Slack-Signature": "v0=" + digest,
            "Content-Type": "application/x-www-form-urlencoded"}


def _configure_secret(tmp_path):
    (tmp_path / "config.toml").write_text(f'[channels.slack]\nsigning_secret = "{SECRET}"\n')
    from maverick import config

    config.reset_config_cache()


def test_slack_interactions_refuse_unconfigured_unsigned_and_replayed(tmp_path, monkeypatch):
    client = _client()
    body = urlencode({"payload": json.dumps({"type": "block_actions", "actions": []})}).encode()
    assert client.post("/webhook/slack/interactions", content=body, headers=_signed(body)).status_code == 503
    _configure_secret(tmp_path)
    assert client.post("/webhook/slack/interactions", content=body,
                       headers=_signed(body, secret="wrong")).status_code == 401
    assert client.post("/webhook/slack/interactions", content=body,
                       headers=_signed(body, ts=time.time() - 400)).status_code == 401
    assert client.post("/webhook/slack/interactions", content=body).status_code == 401
    headers = _signed(body)
    assert client.post("/webhook/slack/interactions", content=body, headers=headers).status_code == 200
    assert client.post("/webhook/slack/interactions", content=body, headers=headers).status_code == 409


def test_slack_button_press_over_http_decides_and_updates_the_card(tmp_path, monkeypatch):
    from maverick import channel_identities, slack_interactive
    from maverick.slack_interactive import ACTION_APPROVE, encode_button_value
    from maverick_dashboard import rbac

    ids = _seed(tmp_path)
    rbac.set_role("user:alice", "operator")
    _configure_secret(tmp_path)
    channel_identities.link("slack", "U1", "user:alice", actor="admin")
    updates = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: updates.append((url, payload)) or True)
    payload = {"type": "block_actions", "user": {"id": "U1"}, "response_url": "https://hooks.slack.com/actions/a",
               "actions": [{"action_id": ACTION_APPROVE, "type": "button",
                            "value": encode_button_value(ids["approval"], ids["card"]["binding_sha256"])}]}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    r = _client().post("/webhook/slack/interactions", content=body, headers=_signed(body))
    assert r.status_code == 200
    assert _world(tmp_path).get_approval(ids["approval"]).status == "approved"
    assert updates[0][0] == "https://hooks.slack.com/actions/a"
    assert updates[0][1]["replace_original"] is True and "user:alice" in json.dumps(updates[0][1]["blocks"])


def test_slack_slash_command_over_http(tmp_path):
    from maverick import channel_identities
    from maverick_dashboard import rbac

    ids = _seed(tmp_path)
    rbac.set_role("user:alice", "operator")
    _configure_secret(tmp_path)
    client = _client()
    body = urlencode({"command": "/lightwork", "text": "status", "user_id": "U1"}).encode()
    r = client.post("/webhook/slack/commands", content=body, headers=_signed(body))
    assert r.status_code == 200 and "not linked" in r.json()["text"]
    channel_identities.link("slack", "U1", "user:alice", actor="admin")
    body = urlencode({"command": "/lightwork", "text": f"reject {ids['approval']} confirm",
                      "user_id": "U1"}).encode()
    r = client.post("/webhook/slack/commands", content=body, headers=_signed(body))
    assert r.json()["response_type"] == "ephemeral" and "rejected" in r.json()["text"]
    assert _world(tmp_path).get_approval(ids["approval"]).status == "denied"
    body = urlencode({"command": "/lightwork", "text": "ask write the report", "user_id": "U1"}).encode()
    r = client.post("/webhook/slack/commands", content=body, headers=_signed(body))
    assert "not available" in r.json()["text"]


def test_waiting_for_decision_table_stacks_on_phones():
    # At 390 px the table scrolled sideways and pushed "Decide by" and
    # "Waiting on" off screen. Each cell carries its column name, and the
    # shared stylesheet turns each row into a labelled card under 560 px.
    import re
    from pathlib import Path

    package = Path(__file__).resolve().parents[1] / "maverick_dashboard"
    page = (package / "templates" / "me.html").read_text(encoding="utf-8")
    start = page.index("Waiting for your decision")
    table = page[page.index("<table", start):page.index("</table>", start)]
    assert 'class="table--stacked"' in table
    headers = re.findall(r'<th scope="col">([^<]+)</th>', table)
    labels = re.findall(r'<td data-label="([^"]+)"', table)
    assert headers == labels == ["Request", "Risk", "Spending", "Decide by", "Waiting on"]
    css = (package / "static" / "lightwork.css").read_text(encoding="utf-8")
    assert ".table--stacked td[data-label]::before" in css


def test_slack_receivers_bypass_dashboard_bearer_and_still_verify_signature(tmp_path, monkeypatch):
    """Slack signs its own requests; a tokened or OIDC deployment must not demand
    the dashboard bearer first (that refused every Slack delivery before the
    signature check ran). The receivers stay self-authenticating."""
    from maverick_dashboard import auth

    assert "/webhook/slack/interactions" in auth.SELF_AUTH_WEBHOOK_PATHS
    assert "/webhook/slack/commands" in auth.SELF_AUTH_WEBHOOK_PATHS
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-token")
    _configure_secret(tmp_path)
    client = _client()
    body = urlencode({"payload": json.dumps({"type": "block_actions", "actions": []})}).encode()
    # No dashboard bearer, no Origin header, but a valid Slack signature: accepted.
    client.headers.pop("Origin", None)
    assert client.post("/webhook/slack/interactions", content=body, headers=_signed(body)).status_code == 200
    # The provider signature is still the gate.
    assert client.post("/webhook/slack/interactions", content=body,
                       headers=_signed(body, secret="wrong")).status_code == 401
    assert client.post("/webhook/slack/commands", content=body).status_code == 401
