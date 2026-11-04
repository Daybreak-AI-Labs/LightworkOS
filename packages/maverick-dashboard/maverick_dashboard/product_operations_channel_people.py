"""Open the complete protected channel-access form without relaying people lists."""
from __future__ import annotations

from fastapi import HTTPException
from pydantic import Field

from . import settings_all_page, settings_store
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class ChannelInput(StrictInput):
    channel: str = Field(min_length=2, max_length=30)


def snapshot(request, _selection):
    from .app import _channel_form_context

    context = _channel_form_context(request)
    choices = [{"value": row["name"], "label": row["label"]} for row in settings_store.CHANNELS
               if any(field.get("type") == "list" for field in row["fields"])]
    return Snapshot(settings_all_page._revision(), "Current installation-wide chat access controls",
        "Choose a chat app, then review its complete current and replacement people lists in the protected native form. This handoff saves nothing and does not start a chat service or send a message.",
        details={"context": context}, fields=[{"name": "channel", "label": "Chat app", "kind": "select",
            "required": True, "choices": choices}])


def prepare(request, selection, arguments):
    value = snapshot(request, selection)
    if arguments["channel"] not in {choice["value"] for choice in value.fields[0]["choices"]}:
        raise HTTPException(422, "Choose a chat app with a permitted-people list.")
    return Preview(value.summary, native={"channels_people": {"context": value.details["context"],
                                                               "channel": arguments["channel"]}})


def entries():
    return (Adapter("channels.people.configure", "Manage who may message Lightwork", "connections", "/channels",
        ("/channels", "/settings", "/settings/all"), ChannelInput, snapshot, prepare,
        aliases=("channel people", "permitted chat users", "slack access", "email access", "who can message Lightwork")),)
