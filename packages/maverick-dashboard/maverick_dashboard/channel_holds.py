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
    from .integration_readiness import IntegrationConfigurationUnavailable, require_readable_config

    try:
        channels = require_readable_config().get("channels") or {}
    except IntegrationConfigurationUnavailable as exc:
        raise ValueError("chat app settings are unreadable") from exc
    if not isinstance(channels, dict):
        # A [channels] value of the wrong type: the page and Copilot say they
        # could not check, as for any unreadable setting.
        raise ValueError("chat app settings are unreadable")
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


def app_names(channels):
    return " and ".join(_LABELS.get(channel, channel) for channel in channels)


def scope(state):
    """Whose replies the counts cover: "chat" when every app that holds
    replies reports, otherwise the apps that do (one turned off, or not
    reporting, is not counted)."""
    reporting = state["reporting"]
    return "chat" if set(reporting) >= set(WORKER_CHANNELS) or not reporting else app_names(reporting)


def _waiting_parts(state):
    """What is waiting and when it goes out, then what to do about it."""
    behind = state["behind_unreadable"]
    waiting, retrying = state["held"] - behind, state["retrying"]
    parts = []
    if behind:
        when = datetime_text(state["release_at"]) if state["release_at"] is not None else ""
        lead = f"{_replies(behind)} waiting because an earlier reply in the same chat cannot be read right now."
        if when and state.get("release_passed"):
            parts.append(lead + (f" {'They were' if behind != 1 else 'It was'} due to go out at {when} and "
                                 f"{'go' if behind != 1 else 'goes'} out as soon as the chat service finishes "
                                 "what it is working on."))
        else:
            it = "They go" if behind != 1 else "It goes"
            parts.append(lead + f" {it} out once it can be read" + (f", or by {when} at the latest." if when else "."))
    if waiting:
        it = "They go" if waiting != 1 else "It goes"
        parts.append(f"{_replies(waiting, more=bool(behind))} waiting for an earlier reply in the same chat to be "
                     f"sent first." + ("" if behind else f" {it} out after that one does."))
    if retrying:
        parts.append(f"{retrying} chat {'reply' if retrying == 1 else 'replies'} could not be sent and "
                     f"{'is' if retrying == 1 else 'are'} tried again every 30 seconds.")
    if behind:
        parts.append("This usually clears on its own. If this lasts, ask whoever manages this computer's "
                     "encryption key to check that it is available.")
    if waiting or retrying:
        parts.append("If this lasts, open Manage the chat service to check that the chat service is running and "
                     "see what it last reported, then restart it.")
    return parts


def describe(state):
    """One short paragraph: what is waiting, when it goes out, what to do."""
    kind = state["state"]
    if kind == "off":
        # Nothing reads the saved replies of an app that is turned off, so
        # whether any wait is not known.
        return ("Signal and IRC are turned off, so held chat replies are not being checked. A reply that was "
                "waiting when its app was turned off stays saved until that app is turned on again.")
    if kind == "not_reporting":
        names = app_names(state["not_reporting"]) or "Signal or IRC"
        verb = "are" if len(state["not_reporting"]) > 1 else "is"
        return (f"{names} {verb} turned on but not reporting from the chat service on this computer, so held chat "
                "replies cannot be checked. If the chat service is stopped, start it with Manage the chat service. "
                "If it is running, restart it, then refresh this page. If your IT team runs it on another "
                "computer, ask them.")
    if kind == "stale":
        return (f"The chat service last reported at {datetime_text(state['last_seen'])} and has stopped reporting, "
                "so held chat replies cannot be checked. Check that the chat service is running, then refresh "
                "this page.")
    if kind == "unavailable":
        names = app_names(state["unavailable"]) if "unknown" not in state["unavailable"] else ""
        whose = f"The saved status for {names}" if names else "The chat service's saved status"
        return (f"{whose} could not be read, so held chat replies cannot be checked. Refresh this page. If it "
                "keeps happening, check that this computer's encryption key is available.")
    parts = _waiting_parts(state)
    if not parts:
        parts.append(f"No {scope(state)} replies are waiting.")
    if state["went_ahead"]:
        count = state["went_ahead"]
        recent = datetime_text(state["went_ahead_at"]) if state["went_ahead_at"] is not None else ""
        parts.append(f"Since the chat service started, {count} {'reply' if count == 1 else 'replies'} went out "
                     "without waiting, after an earlier reply stayed unreadable for 24 hours"
                     + (f" (most recently {recent})." if recent else "."))
    for channel in state["not_reporting"]:
        label = _LABELS.get(channel, channel)
        parts.append(f"{label} is not reporting, so its replies cannot be checked. Check that {label} is running "
                     "in the chat service, then refresh this page.")
    for channel in state["running_off"]:
        parts.append(f"{_LABELS.get(channel, channel)} is turned off, but the chat service keeps running it until "
                     "the chat service is restarted.")
    for channel in state["unavailable"]:
        whose = f"A saved status for {_LABELS.get(channel, channel)}" if channel != "unknown" else "A saved status"
        parts.append(f"{whose} could not be read. If this keeps happening, check that this computer's encryption "
                     "key is available.")
    return " ".join(parts)
