"""Copilot opens the complete protected native chat-message test form."""
from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import channel_test_requests as native
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class ChannelInput(StrictInput):
    channel: str = Field(min_length=2, max_length=30)


def snapshot(request, _selection):
    context, _actor = native.authority(request)
    return Snapshot(digest(context), "Current administrator chat controls", "Choose a chat app, then open its protected form. Read a previously permitted conversation, review its current name and the fixed test sentence before separately confirming a send. " + native.NOTICE,
                    details={"context": context}, fields=[{"name": "channel", "label": "Chat app", "kind": "select", "required": True,
                    "choices": [{"value": name, "label": label} for name, label in native.CHANNELS.items()]}])


def prepare(request, selection, arguments):
    current = snapshot(request, selection)
    if arguments["channel"] not in native.CHANNELS:
        raise HTTPException(422, "Choose a supported chat app.")
    return Preview(current.summary, native={"channel_message_test": {"context": current.details["context"], "channel": arguments["channel"]}})


def entries():
    return (Adapter("channels.message_test", "Review a chat test message", "connections", native.PAGE, ("/channels", "/settings", "/settings/all"),
                    ChannelInput, snapshot, prepare, aliases=("test Telegram delivery", "test Discord delivery", "test WhatsApp delivery", "test Mattermost delivery")),)
