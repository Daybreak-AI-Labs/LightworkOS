"""Held chat replies: one plain answer for Channels > Message delivery and Copilot.

Signal and IRC keep each chat's replies in order, so a reply can wait behind an
earlier one (see maverick_channels.hold_status). The page and the Copilot
operation both call held_reply_status, so they give the same answer under the
same administrator check, which runs before anything is read.
"""
from __future__ import annotations

from fastapi import HTTPException
from maverick_channels import hold_status

from .auth import require_global_permission
from .plain_labels import datetime_text

# The chat apps whose replies wait in order (they run a transport worker).
WORKER_CHANNELS = ("signal", "irc")
_LABELS = {"signal": "Signal", "irc": "IRC"}
UNAVAILABLE = "Held chat replies could not be checked. Refresh this page."


def _enabled_channels():
    from .integration_readiness import require_readable_config

    channels = require_readable_config().get("channels") or {}
    return {name for name in WORKER_CHANNELS
            if isinstance(channels.get(name), dict) and bool(channels[name].get("enabled", False))}


def held_reply_status(request):
    """The held reply state with its plain ``summary``; administrators only."""
    require_global_permission(request, "admin")
    state = hold_status.summary(_enabled_channels())
    return {**state, "summary": describe(state)}


def page_summary(request):
    """The Message delivery sentence. A refusal still refuses; anything else
    that stops the check is said plainly instead of failing the page."""
    try:
        return held_reply_status(request)["summary"]
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001 -- the page states it could not check
        return UNAVAILABLE


def _replies(count, *, more=False):
    noun = "more" if more else ("chat reply" if count == 1 else "chat replies")
    return f"{count} {noun} {'is' if count == 1 else 'are'}"


def describe(state):
    """One short paragraph: what is waiting, when it goes out, what to do."""
    kind = state["state"]
    if kind == "off":
        return "Signal and IRC are turned off, so no chat replies are held."
    if kind == "not_reporting":
        return ("Signal or IRC is turned on, but the chat service is not reporting from this computer, so held "
                "chat replies cannot be checked. Start the chat service, then refresh this page. If your IT team "
                "runs it on another computer, ask them.")
    if kind == "stale":
        return (f"The chat service last reported at {datetime_text(state['last_seen'])} and has stopped reporting, "
                "so held chat replies cannot be checked. Check that the chat service is running, then refresh "
                "this page.")
    if kind == "unavailable":
        return ("Held chat replies could not be checked because the chat service's status could not be read. "
                "Refresh this page. If it keeps happening, check that this computer's encryption key is available.")
    behind = state["behind_unreadable"]
    waiting = state["held"] - behind
    parts = []
    if behind:
        it = "They go" if behind != 1 else "It goes"
        when = datetime_text(state["release_at"]) if state["release_at"] is not None else ""
        parts.append(f"{_replies(behind)} waiting because an earlier reply in the same chat cannot be read right "
                     f"now. {it} out once it can be read" + (f", or by {when} at the latest." if when else "."))
    if waiting:
        it = "They go" if waiting != 1 else "It goes"
        parts.append(f"{_replies(waiting, more=bool(behind))} waiting for an earlier reply in the same chat to be "
                     f"sent first." + ("" if behind else f" {it} out after that one does."))
    if not parts:
        parts.append("No chat replies are waiting.")
    if behind:
        parts.append("This usually clears on its own. If this lasts, ask whoever manages this computer's "
                     "encryption key to check that it is available.")
    if waiting:
        parts.append("Check the chat app's connection on the Channels page and send a test message.")
    if state["went_ahead"]:
        count = state["went_ahead"]
        recent = datetime_text(state["went_ahead_at"]) if state["went_ahead_at"] is not None else ""
        parts.append(f"Since the chat service started, {count} {'reply' if count == 1 else 'replies'} went out "
                     "without waiting, after an earlier reply stayed unreadable for 24 hours"
                     + (f" (most recently {recent})." if recent else "."))
    for channel in state["not_reporting"]:
        parts.append(f"{_LABELS.get(channel, channel)} is not reporting, so its replies cannot be checked.")
    if state["unavailable"]:
        parts.append("The status of another chat app could not be read.")
    return " ".join(parts)
