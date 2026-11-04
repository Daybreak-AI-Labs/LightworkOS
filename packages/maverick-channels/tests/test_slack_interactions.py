"""The Slack adapter: button and slash-command envelopes over Socket Mode,
mentions in channels and groups, DMs unchanged, approval cards posted."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda kind, **p: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _channel(monkeypatch, tmp_path, **kw):
    import maverick_channels.slack as slack_mod
    from maverick.world_model import WorldModel

    monkeypatch.setattr(slack_mod, "_HAVE_SLACK", True)
    monkeypatch.setattr(slack_mod, "AsyncWebClient", MagicMock())
    monkeypatch.setattr(slack_mod, "SocketModeClient", MagicMock())
    monkeypatch.setattr(slack_mod, "SocketModeResponse", lambda **k: k)
    ch = slack_mod.SlackChannel(
        handler=AsyncMock(return_value="the answer"), app_token="xapp-1", bot_token="xoxb-1",
        allowed_user_ids=["U123"], world=WorldModel(tmp_path / "world.db"), **kw,
    )
    ch._web = MagicMock()
    ch._web.chat_postMessage = AsyncMock(return_value={"ok": True, "ts": "reply-1"})
    ch._account_id, ch._team_id, ch._bot_user_id = "T1:B1", "T1", "UBOT"
    return ch


def _req(kind, payload):
    req = MagicMock()
    req.type = kind
    req.envelope_id = "env-1"
    req.payload = payload
    return req


def _client():
    client = MagicMock()
    client.send_socket_mode_response = AsyncMock()
    return client


def _card():
    import time

    from maverick.approval_cards import build_approval_card

    return build_approval_card(
        action="wire_funds", summary="Pay the invoice", target_label="Invoice", target={},
        parameters={}, parameter_summary=["Pay once"], actor="user:r", workspace="t",
        role="operator", authority_versions={}, input_versions={}, credential_versions={},
        budget={}, expires_at=time.time() + 300, known_effects=["Money moves."],
        unresolved_assumptions=[], before="Unpaid.", after="Paid.", irreversible=False,
    )


def test_button_press_is_acked_decided_and_card_updated(monkeypatch, tmp_path):
    from maverick import channel_identities, slack_interactive
    from maverick.approval_cards import encode_approval_detail
    from maverick.slack_interactive import ACTION_APPROVE, encode_button_value
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    ch = _channel(monkeypatch, tmp_path)
    card = _card()
    aid = ch._world.create_approval("wire_funds", risk="medium", detail=encode_approval_detail(card))
    channel_identities.link("slack", "U123", "user:alice", actor="admin")
    updates = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: updates.append((url, payload)) or True)
    payload = {"type": "block_actions", "user": {"id": "U123"}, "response_url": "https://hooks.slack.com/a",
               "actions": [{"action_id": ACTION_APPROVE, "type": "button",
                            "value": encode_button_value(aid, card["binding_sha256"])}]}
    client = _client()
    result = asyncio.run(ch._on_request(client, _req("interactive", payload)))
    client.send_socket_mode_response.assert_awaited_once_with({"envelope_id": "env-1"})
    assert result["replace_original"] is True
    assert ch._world.get_approval(aid).status == "approved"
    assert updates[0][0] == "https://hooks.slack.com/a"


def test_critical_button_opens_modal_and_submission_is_answered_in_the_ack(monkeypatch, tmp_path):
    from maverick import channel_identities, slack_interactive
    from maverick.approval_cards import encode_approval_detail
    from maverick.slack_interactive import (
        ACTION_APPROVE,
        CONFIRM_BLOCK,
        CONFIRM_INPUT,
        CONFIRM_VIEW_CALLBACK,
        encode_button_value,
    )
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    ch = _channel(monkeypatch, tmp_path)
    ch._web.views_open = AsyncMock(return_value={"ok": True})
    card = _card()
    aid = ch._world.create_approval("wire_funds", risk="critical", detail=encode_approval_detail(card))
    channel_identities.link("slack", "U123", "user:alice", actor="admin")
    updates = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: updates.append(payload) or True)
    payload = {"type": "block_actions", "user": {"id": "U123"}, "trigger_id": "trig",
               "response_url": "https://hooks.slack.com/a",
               "actions": [{"action_id": ACTION_APPROVE, "type": "button",
                            "value": encode_button_value(aid, card["binding_sha256"])}]}
    asyncio.run(ch._on_request(_client(), _req("interactive", payload)))
    assert ch._web.views_open.await_args.kwargs["trigger_id"] == "trig"
    view = ch._web.views_open.await_args.kwargs["view"]
    assert ch._world.get_approval(aid).status == "pending"
    submission = {"type": "view_submission", "user": {"id": "U123"},
                  "view": {"callback_id": CONFIRM_VIEW_CALLBACK, "private_metadata": view["private_metadata"],
                           "state": {"values": {CONFIRM_BLOCK: {CONFIRM_INPUT: {"value": "APPROVE"}}}}}}
    client = _client()
    asyncio.run(ch._on_request(client, _req("interactive", submission)))
    client.send_socket_mode_response.assert_awaited_once_with(
        {"envelope_id": "env-1", "payload": {"response_action": "clear"}})
    assert ch._world.get_approval(aid).status == "approved"
    assert updates[-1]["replace_original"] is True


def test_button_press_from_unlisted_user_is_only_acked(monkeypatch, tmp_path):
    from maverick.slack_interactive import ACTION_REJECT

    ch = _channel(monkeypatch, tmp_path)
    aid = ch._world.create_approval("x", detail="d")
    payload = {"type": "block_actions", "user": {"id": "U999"},
               "actions": [{"action_id": ACTION_REJECT, "type": "button", "value": f"{aid}:"}]}
    client = _client()
    assert asyncio.run(ch._on_request(client, _req("interactive", payload))) is None
    client.send_socket_mode_response.assert_awaited_once()
    assert ch._world.get_approval(aid).status == "pending"


def test_slash_command_status_and_ask_run_through_the_handler(monkeypatch, tmp_path):
    from maverick import channel_identities, slack_interactive

    ch = _channel(monkeypatch, tmp_path)
    channel_identities.link("slack", "U123", "user:alice", actor="admin")
    replies = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: replies.append(payload) or True)
    form = {"command": "/lightwork", "text": "status", "user_id": "U123", "channel_id": "D1",
            "response_url": "https://hooks.slack.com/c"}
    asyncio.run(ch._on_request(_client(), _req("slash_commands", form)))
    assert "Your Lightwork status" in replies[-1]["text"]
    asyncio.run(ch._on_request(_client(), _req("slash_commands", {**form, "text": "ask draft the memo"})))
    assert replies[-1]["text"] == "the answer"
    sent = ch.handler.call_args.args[0]
    assert sent.text == "draft the memo" and sent.sender_id == "U123" and sent.user_id == "D1"
    asyncio.run(ch._on_request(_client(), _req("slash_commands", {**form, "user_id": "U999"})))
    assert len(replies) == 2  # not on the allow list: acked, nothing else


def test_oidc_slash_ask_refuses_without_durable_receipt(monkeypatch, tmp_path):
    from maverick import oidc, slack_interactive

    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    ch = _channel(monkeypatch, tmp_path)
    replies = []
    monkeypatch.setattr(slack_interactive, "respond",
                        lambda url, payload: replies.append(payload) or True)
    form = {"command": "/lightwork", "text": "ask draft the memo", "team_id": "T1",
            "user_id": "U123", "channel_id": "D1", "response_url": "https://hooks.slack.com/c"}
    asyncio.run(ch._on_request(_client(), _req("slash_commands", form)))
    assert "direct message" in replies[-1]["text"]
    ch.handler.assert_not_called()
    assert "direct message" in asyncio.run(ch._ask_from_slash(form))
    asyncio.run(ch._on_request(_client(), _req("slash_commands", {**form, "team_id": "TOTHER"})))
    assert len(replies) == 1


def test_channel_message_needs_a_mention_and_answers_in_thread(monkeypatch, tmp_path):
    ch = _channel(monkeypatch, tmp_path)
    client = _client()
    silent = {"team_id": "T1", "event": {"type": "message", "user": "U123", "channel": "C9",
                                         "channel_type": "channel", "text": "hello all", "ts": "1.1"}}
    asyncio.run(ch._on_request(client, _req("events_api", silent)))
    ch.handler.assert_not_called()
    mention = {"team_id": "T1", "event": {"type": "message", "user": "U123", "channel": "C9",
                                          "channel_type": "channel",
                                          "text": "<@UBOT> summarise this", "ts": "1.2"}}
    asyncio.run(ch._on_request(client, _req("events_api", mention)))
    sent = ch.handler.call_args.args[0]
    assert sent.text == "summarise this"
    assert sent.conversation_ref == "1.2"
    assert sent.question_reply_only is False
    kw = ch._web.chat_postMessage.call_args.kwargs
    assert kw["channel"] == "C9" and kw["thread_ts"] == "1.2"
    app_mention = {"team_id": "T1", "event": {"type": "app_mention", "user": "U123", "channel": "G7",
                                              "text": "<@UBOT|lightwork> status?", "ts": "1.3",
                                              "thread_ts": "1.0"}}
    asyncio.run(ch._on_request(client, _req("events_api", app_mention)))
    assert ch.handler.call_args.args[0].text == "status?"
    assert ch._web.chat_postMessage.call_args.kwargs["thread_ts"] == "1.0"

    # A plain reply in an existing thread can answer a pending question.
    # The server will ignore it when that sender/thread has no open question.
    plain_answer = {"team_id": "T1", "event": {"type": "message", "user": "U123",
                                              "channel": "C9", "channel_type": "channel",
                                              "text": "Acme", "ts": "1.4", "thread_ts": "1.2"}}
    asyncio.run(ch._on_request(client, _req("events_api", plain_answer)))
    sent = ch.handler.call_args.args[0]
    assert sent.text == "Acme"
    assert sent.conversation_ref == "1.2"
    assert sent.question_reply_only is True


def test_dm_and_file_share_behave_as_before(monkeypatch, tmp_path):
    ch = _channel(monkeypatch, tmp_path)
    client = _client()
    dm = {"team_id": "T1", "event": {"type": "message", "user": "U123", "channel": "D5",
                                     "channel_type": "im", "text": "do it", "ts": "2.1"}}
    asyncio.run(ch._on_request(client, _req("events_api", dm)))
    assert ch.handler.call_args.args[0].text == "do it"
    assert ch.handler.call_args.args[0].provider_tenant_id == "T1"
    assert ch.handler.call_args.args[0].provider_sender_id == "U123"
    from maverick_channels.delivery import _digest
    assert ch.handler.call_args.args[0]._verified_channel_account_sha256 == _digest("T1:B1")
    assert "thread_ts" not in ch._web.chat_postMessage.call_args.kwargs
    edited = {"team_id": "T1", "event": {"type": "message", "subtype": "message_changed",
                                         "user": "U123", "channel": "D5", "text": "x", "ts": "2.2"}}
    asyncio.run(ch._on_request(client, _req("events_api", edited)))
    assert ch.handler.call_count == 1
    shared = {"team_id": "T1", "event": {"type": "message", "subtype": "file_share", "user": "U123",
                                         "channel": "D5", "text": "", "ts": "2.3",
                                         "files": [{"id": "F1", "name": "a.txt", "size": 3}]}}
    monkeypatch.setattr(ch, "_download_files", AsyncMock(return_value=[]))
    asyncio.run(ch._on_request(client, _req("events_api", shared)))
    assert ch.handler.call_count == 2


def test_oidc_slack_ingress_rejects_other_workspace_and_legacy_identity(monkeypatch, tmp_path):
    from maverick import channel_identities, oidc

    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    ch = _channel(monkeypatch, tmp_path)
    channel_identities.link("slack", "U123", "user:alice", actor="admin")
    assert ch._principal_for("U123") is None
    other_team = {"team_id": "TOTHER", "event": {
        "type": "message", "user": "U123", "channel": "D5",
        "channel_type": "im", "text": "do it", "ts": "3.1",
    }}
    with pytest.raises(PermissionError, match="account/message identity"):
        asyncio.run(ch._on_request(_client(), _req("events_api", other_team)))
    ch.handler.assert_not_called()
    correct_team = {**other_team, "team_id": "T1"}
    asyncio.run(ch._on_request(_client(), _req("events_api", correct_team)))
    assert ch.handler.await_count == 1


def test_post_approval_card_sends_blocks(monkeypatch, tmp_path):
    from maverick.approval_cards import encode_approval_detail

    ch = _channel(monkeypatch, tmp_path, approvals_channel="C1")
    aid = ch._world.create_approval("wire_funds", risk="high", detail=encode_approval_detail(_card()))
    ts = asyncio.run(ch.post_approval_card("C1", ch._world.get_approval(aid), dashboard_url="https://lw"))
    assert ts == "reply-1"
    kw = ch._web.chat_postMessage.call_args.kwargs
    assert kw["channel"] == "C1" and kw["blocks"][-1]["type"] == "actions"
    assert "confirm" in kw["blocks"][-1]["elements"][0]
    assert ch.approvals_channel == "C1"


def _viewer_decision_setup(monkeypatch, tmp_path):
    """A pending request and a linked Slack user whose Lightwork role is only viewer."""
    from maverick import channel_identities, slack_interactive
    from maverick.approval_cards import encode_approval_detail
    from maverick_dashboard import rbac

    ch = _channel(monkeypatch, tmp_path)
    card = _card()
    aid = ch._world.create_approval("wire_funds", risk="medium", detail=encode_approval_detail(card))
    rbac.set_role("user:viewer1", "viewer", actor="user:admin")
    channel_identities.link("slack", "U123", "user:viewer1", actor="admin")
    replies = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: replies.append(payload) or True)
    return ch, aid, card, replies


def test_socket_mode_button_refuses_a_viewer_like_the_http_receiver(monkeypatch, tmp_path):
    from maverick.slack_interactive import ACTION_APPROVE, encode_button_value

    ch, aid, card, replies = _viewer_decision_setup(monkeypatch, tmp_path)
    payload = {"type": "block_actions", "user": {"id": "U123"}, "response_url": "https://hooks.slack.com/a",
               "actions": [{"action_id": ACTION_APPROVE, "type": "button",
                            "value": encode_button_value(aid, card["binding_sha256"])}]}
    asyncio.run(ch._on_request(_client(), _req("interactive", payload)))
    assert ch._world.get_approval(aid).status == "pending"
    assert "can't decide approvals" in replies[-1]["text"]


def test_socket_mode_slash_command_refuses_a_viewer(monkeypatch, tmp_path):
    ch, aid, _card_, replies = _viewer_decision_setup(monkeypatch, tmp_path)
    form = {"command": "/lightwork", "text": f"approve {aid}", "user_id": "U123", "channel_id": "D1",
            "response_url": "https://hooks.slack.com/c"}
    asyncio.run(ch._on_request(_client(), _req("slash_commands", form)))
    assert ch._world.get_approval(aid).status == "pending"
    assert "can't decide approvals" in replies[-1]["text"]
    asyncio.run(ch._on_request(_client(), _req("slash_commands", {**form, "text": f"reject {aid}"})))
    assert ch._world.get_approval(aid).status == "pending"


def test_socket_mode_confirmation_modal_refuses_a_viewer(monkeypatch, tmp_path):
    from maverick.slack_interactive import (
        CONFIRM_BLOCK,
        CONFIRM_INPUT,
        CONFIRM_VIEW_CALLBACK,
        confirm_view,
    )

    ch, aid, card, _replies = _viewer_decision_setup(monkeypatch, tmp_path)
    from maverick.channel_approvals import card_content

    view = confirm_view(card_content(ch._world.get_approval(aid)), binding=card["binding_sha256"],
                        response_url="https://hooks.slack.com/a")
    submission = {"type": "view_submission", "user": {"id": "U123"},
                  "view": {"callback_id": CONFIRM_VIEW_CALLBACK, "private_metadata": view["private_metadata"],
                           "state": {"values": {CONFIRM_BLOCK: {CONFIRM_INPUT: {"value": "APPROVE"}}}}}}
    client = _client()
    asyncio.run(ch._on_request(client, _req("interactive", submission)))
    assert ch._world.get_approval(aid).status == "pending"
    ack = client.send_socket_mode_response.await_args.args[0]["payload"]
    assert ack["response_action"] == "errors"


def test_socket_mode_decisions_fail_closed_without_an_authorizer(monkeypatch, tmp_path):
    import sys

    from maverick import channel_identities, slack_interactive
    from maverick.approval_cards import encode_approval_detail
    from maverick.slack_interactive import ACTION_APPROVE, encode_button_value

    # No dashboard to supply the operate rule and none injected: nobody may decide.
    monkeypatch.setitem(sys.modules, "maverick_dashboard.approval_decisions", None)
    ch = _channel(monkeypatch, tmp_path)
    card = _card()
    aid = ch._world.create_approval("wire_funds", risk="medium", detail=encode_approval_detail(card))
    channel_identities.link("slack", "U123", "user:alice", actor="admin")
    replies = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: replies.append(payload) or True)
    payload = {"type": "block_actions", "user": {"id": "U123"}, "response_url": "https://hooks.slack.com/a",
               "actions": [{"action_id": ACTION_APPROVE, "type": "button",
                            "value": encode_button_value(aid, card["binding_sha256"])}]}
    asyncio.run(ch._on_request(_client(), _req("interactive", payload)))
    assert ch._world.get_approval(aid).status == "pending"
    assert replies[-1]["response_type"] == "ephemeral"


def test_socket_mode_uses_an_injected_authorizer(monkeypatch, tmp_path):
    from maverick import channel_identities, slack_interactive
    from maverick.approval_cards import encode_approval_detail
    from maverick.channel_approvals import ChannelApprovalRefused
    from maverick.slack_interactive import ACTION_APPROVE, encode_button_value

    seen = []

    def authorize(principal, approval_id):
        seen.append((principal, approval_id))
        raise ChannelApprovalRefused("not_permitted", "Not for you.")

    ch = _channel(monkeypatch, tmp_path, authorize=authorize)
    card = _card()
    aid = ch._world.create_approval("wire_funds", risk="medium", detail=encode_approval_detail(card))
    channel_identities.link("slack", "U123", "user:alice", actor="admin")
    replies = []
    monkeypatch.setattr(slack_interactive, "respond", lambda url, payload: replies.append(payload) or True)
    payload = {"type": "block_actions", "user": {"id": "U123"}, "response_url": "https://hooks.slack.com/a",
               "actions": [{"action_id": ACTION_APPROVE, "type": "button",
                            "value": encode_button_value(aid, card["binding_sha256"])}]}
    asyncio.run(ch._on_request(_client(), _req("interactive", payload)))
    assert seen == [("user:alice", aid)]
    assert ch._world.get_approval(aid).status == "pending"
    assert replies[-1]["text"] == "Not for you."
