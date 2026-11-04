"""Saved task outputs reach a chat reply only where the chat can send files."""
from __future__ import annotations

from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("channel", ["discord", "whatsapp", "matrix", "sms"])
def test_a_chat_that_cannot_send_files_gets_no_files_to_seal_and_store(monkeypatch, channel):
    # The reply says files cannot be delivered here, yet every output was still
    # validated, sealed and written with the receipt, then never read.
    from maverick import channel_reply_results

    monkeypatch.setattr(channel_reply_results, "require_source", lambda _source: None)
    artifact = {"id": 3, "version": 1, "kind": "text", "title": "Totals", "content": "42"}
    world = SimpleNamespace(get_goal=lambda _id: SimpleNamespace(status="done"),
                            latest_artifacts=lambda _id: [artifact])
    msg = SimpleNamespace(channel=channel, provider_tenant_id=None, provider_sender_id=None,
                          conversation_ref=None, message_id="m1")
    reply = channel_reply_results.prepare_reply(world, msg, 1, "Done.", owner="user:a",
                                                execution_principal="user:a", principal="user:a")
    assert reply.attachments == [] and "cannot be delivered in this chat" in reply.text
    assert msg._channel_reply_material["files"] == []
    assert msg._channel_reply_material["source"]["goal_id"] == 1  # still re-checked at delivery
    slack = SimpleNamespace(channel="slack", provider_tenant_id=None, provider_sender_id=None,
                            conversation_ref="thread", message_id="m1")
    sent = channel_reply_results.prepare_reply(world, slack, 1, "Done.", owner="user:a",
                                               execution_principal="user:a", principal="user:a")
    assert len(sent.attachments) == 1 and len(slack._channel_reply_material["files"]) == 1
