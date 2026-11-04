"""Telegram inbound identity: the reply/send target is the CHAT, the human is
the sender. Regression for proactive sends landing in the wrong place (a
group member's private chat instead of the group)."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("telegram")

from maverick_channels.telegram import TelegramChannel  # noqa: E402


def _update(*, user_id: int, chat_id: int, chat_type: str, text: str = "hi"):
    return SimpleNamespace(
        message=SimpleNamespace(text=text, message_id=7, reply_text=AsyncMock()),
        effective_user=SimpleNamespace(id=user_id),
        effective_chat=SimpleNamespace(id=chat_id, type=chat_type),
    )


def _dispatch_and_capture(ch, update) -> object:
    captured = {}

    async def handler(msg):
        captured["msg"] = msg
        return ""  # empty -> no outbound reply needed for this assertion

    ch.handler = handler
    asyncio.run(ch._on_message(update, None))
    return captured["msg"]


def test_group_message_targets_chat_keeps_sender_identity():
    ch = TelegramChannel(handler=lambda m: "", token="x:y",
                         allowed_user_ids={"111"})
    msg = _dispatch_and_capture(
        ch, _update(user_id=111, chat_id=-555, chat_type="group"))
    # Reply/send target is the GROUP chat, not the sender's private chat.
    assert msg.user_id == "-555"
    # The human identity is the sender...
    assert msg.sender_id == "111"
    # ...and per-user state (auth/history/tenant) keys on the human, as before.
    assert msg.principal_id == "111"


def test_private_chat_ids_coincide_unchanged():
    ch = TelegramChannel(handler=lambda m: "", token="x:y",
                         allowed_user_ids={"111"})
    msg = _dispatch_and_capture(
        ch, _update(user_id=111, chat_id=111, chat_type="private"))
    # 1:1 chat: chat id == user id, so behavior is identical to before.
    assert msg.user_id == "111"
    assert msg.principal_id == "111"
