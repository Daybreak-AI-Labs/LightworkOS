"""Check held chat replies: the Message delivery answer, read only."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import channel_holds
from .plain_labels import datetime_text
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

# What a person sees; the time a status was last renewed is left out, so a
# renewal alone never makes a prepared answer out of date.
_STABLE = ("state", "held", "behind_unreadable", "unreadable", "retrying", "release_at", "release_passed",
           "went_ahead", "went_ahead_at", "reporting", "not_reporting", "running_off", "last_seen", "unavailable")


def _state(request):
    state = channel_holds.held_reply_status(request)
    details = {"Answer": state["summary"]}
    if state["state"] in {"holding", "clear"}:
        # A count never reads as covering an app that is turned off or not reporting.
        only = "" if channel_holds.covers_every_app(state) else f" ({channel_holds.scope(state)} only)"
        details["Waiting behind an earlier reply" + only] = state["held"]
        details["Waiting behind a reply that cannot be read" + only] = state["behind_unreadable"]
        if state["retrying"]:
            details["Could not be sent or handled, tried again" + only] = state["retrying"]
        if state["release_at"] is not None:
            label = "Was due to go out at" if state["release_passed"] else "Go out by, at the latest"
            details[label] = datetime_text(state["release_at"])
        if state["went_ahead"]:
            details["Went out without waiting since the chat service started"] = state["went_ahead"]
    details["Scope"] = ("Signal and IRC replies held by the chat service on this computer. Reading this does not "
                        "send, resend or change any message.")
    details["open"] = {"label": "Open Message delivery", "href": "/channels#channel-delivery"}
    return digest({key: state[key] for key in _STABLE}), state["summary"], details


def snapshot(request, _selection):
    revision, summary, details = _state(request)
    return Snapshot(revision, "Current held chat replies", summary, details)


def prepare(request, _selection, _arguments):
    _, summary, details = _state(request)
    return Preview(summary + " Nothing was sent, resent or changed.", native=details)


def entries():
    return (Adapter("channels.held_replies", "Check held chat replies", "connections", "/channels#channel-delivery",
                    ("/channels", "/settings", "/settings/all"), EmptyInput, snapshot, prepare,
                    aliases=("held chat replies", "are chat replies waiting", "are any chat replies waiting",
                             "why is a chat reply waiting", "signal replies waiting", "irc replies waiting")),)
