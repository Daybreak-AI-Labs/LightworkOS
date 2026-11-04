"""Reviewed personal alert preferences share the direct inbox save contract."""
from __future__ import annotations

import copy
import hashlib
import json
import time
from typing import Literal

from fastapi import HTTPException, Response
from pydantic import Field

from . import personal_notifications_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

ACTIONS = {
    "mode": "Delivery timing", "timezone": "Time zone", "digest_time": "Daily digest time",
    "quiet_hours": "Quiet hours", "event": "Event subscription",
    "critical_exceptions": "Approval and deadline exception", "watch_all_projects": "Watch all my tasks",
    "project": "Watch a project", "mute": "Mute or unmute a task", "channel": "Private delivery channel",
}


class ChangeInput(StrictInput):
    action: Literal["mode", "timezone", "digest_time", "quiet_hours", "event", "critical_exceptions",
                    "watch_all_projects", "project", "mute", "channel"]
    value: str = Field(default="", max_length=100)
    enabled: bool = True
    start: str = Field(default="22:00", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    end: str = Field(default="08:00", pattern=r"^(?:[01][0-9]|2[0-3]):[0-5][0-9]$")
    minutes: int = Field(default=60, ge=1, le=10079)


def _choices(state):
    from maverick.personal_notifications import EVENTS
    return {
        "mode": [{"value": value, "label": label} for value, label in
                 (("immediate", "As changes are observed"), ("digest", "Daily digest"), ("off", "Off"))],
        "event": [{"value": value, "label": value.replace("-", " ").capitalize()} for value in sorted(EVENTS)],
        "project": [{"value": str(row["id"]), "label": row["name"]} for row in state["projects"]],
        "mute": [{"value": str(row["id"]), "label": row["title"]} for row in state["tasks"]],
        "channel": [{"value": row["id"], "label": row["channel"].capitalize() + " verified private identity"}
                    for row in state["private_delivery"].get("channels", [])],
    }


def snapshot(request, _selection, *, edit=True):
    state = native._state(request)
    fields = []
    if edit:
        fields = [
            {"name": "action", "label": "Preference to change", "kind": "select", "required": True,
             "choices": [{"value": key, "label": label} for key, label in ACTIONS.items()]},
            {"name": "value", "label": "Choice, time, or IANA time zone", "kind": "text", "value": "",
             "depends_on": "action", "choices_by": _choices(state)},
            {"name": "enabled", "label": "Enable selected option (off removes a subscription or mute)",
             "kind": "boolean", "value": True},
            {"name": "start", "label": "Quiet hours start (24-hour HH:MM)", "kind": "text", "value": state["preferences"]["quiet_start"]},
            {"name": "end", "label": "Quiet hours end (24-hour HH:MM)", "kind": "text", "value": state["preferences"]["quiet_end"]},
            {"name": "minutes", "label": "Task mute duration in minutes (up to seven days)", "kind": "number", "value": 60},
        ]
    # Bind policy and selectable resources as well as the native preference CAS.
    revision = hashlib.sha256(json.dumps({"revision": state["revision"], "choices": _choices(state),
        "critical": state["critical_allowed"], "external": state["private_delivery"].get("enabled", False)},
        sort_keys=True).encode()).hexdigest()
    observed = state["background"].get("last_observed_at")
    selected = set(state["preferences"]["external_links"])
    ready = sum(row["id"] in selected and row["available"]
                for row in state["private_delivery"].get("channels", []))
    if not state["background_enabled"]:
        observation = "Background checking is off; your inbox catches up when you open Lightwork."
    elif observed is None:
        observation = "Background checking is on, but no completed check has been recorded yet."
    else:
        observation = "Background checking is on; the last completed check is recorded in your inbox."
    summary = ("Personal alerts follow your subscriptions and quiet hours. " + observation
               + " The shared organization channel, including ntfy, does not receive your private task updates.")
    return Snapshot(revision, "Your personal notification preferences in the current workspace",
        summary,
        {"preferences": state["preferences"], "critical_allowed": state["critical_allowed"],
         "background_enabled": state["background_enabled"], "last_observed_at": observed,
         "private_channels_selected": len(selected), "private_channels_ready": ready,
         "private_delivery_enabled": state["private_delivery"].get("enabled", False),
         "partial": state["partial"], "href": "/notifications"}, fields)


def _change(current, arguments, *, now):
    """Build one change without modifying the stored/snapshotted value."""
    choice = copy.deepcopy(current)
    action, value, enabled = arguments["action"], arguments.get("value", ""), arguments.get("enabled", True)
    if action in {"mode", "timezone", "digest_time"}:
        choice[action] = value
    elif action in {"critical_exceptions", "watch_all_projects"}:
        choice[action] = enabled
    elif action == "quiet_hours":
        choice.update(quiet_enabled=enabled, quiet_start=arguments["start"], quiet_end=arguments["end"])
    elif action == "mute":
        if enabled:
            choice["muted_tasks"][value] = now + arguments["minutes"] * 60
        else:
            choice["muted_tasks"].pop(value, None)
    else:
        key = {"event": "events", "project": "projects", "channel": "external_links"}[action]
        if action == "project":
            try:
                value = int(value)
            except ValueError as exc:
                raise HTTPException(422, "Choose an available project.") from exc
        choice[key] = sorted((set(choice[key]) | {value}) if enabled else (set(choice[key]) - {value}))
    return choice


def prepare(request, _selection, arguments):
    state = native._state(request)
    if arguments["action"] == "critical_exceptions" and arguments["enabled"] and not state["critical_allowed"]:
        raise HTTPException(403, "Your organization does not permit personal approval or deadline exceptions.")
    try:
        _, choice = native.validate_current_preferences(request, _change(state["preferences"], arguments, now=time.time()))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    changed = [{"label": key.replace("_", " ").capitalize(), "before": state["preferences"][key], "after": value}
               for key, value in choice.items() if value != state["preferences"][key]]
    return Preview("Save this personal notification preference. This does not send a test or replay earlier deliveries.",
                   changed, {"preferences": choice, "revision": state["revision"], "context": state["context"]})


def execute(request, _selection, _arguments, prepared, operation_id):
    state = native.save_preferences(request, Response(), native.PreferencesIn(
        context=prepared["context"], expected_revision=prepared["revision"],
        preferences=prepared["preferences"], operation_id=operation_id))
    return Outcome("confirmed", "Your personal notification preference was saved.",
                   {"preferences": state["preferences"], "revision": state["revision"]})


def recover(request, _selection, _arguments, prepared, operation_id):
    from maverick import experience_preferences as preferences
    actor = native._identity(request)
    if preferences.operation_confirmed(actor, scope="personal", changes={"notification_preferences": prepared["preferences"]},
            expected_revision=prepared["revision"], operation_id=operation_id):
        return Outcome("replayed", "This exact personal preference change was already saved. Refresh to see current policy and values.")
    return None


def _read(request, selection, _arguments):
    snapshot(request, selection, edit=False)
    return Preview("These are your current personal notification preferences. No delivery was triggered.")


def _inbox_snapshot(request, _selection):
    state = native._state(request)
    items = [{key: item[key] for key in ("id", "title", "label", "href", "category", "seen_at")}
             for item in state["items"][:20]]
    unseen = sum(item["seen_at"] is None for item in state["items"])
    summary = f"You have {unseen} new notification{'s' if unseen != 1 else ''}."
    if state["partial"]:
        summary += " Some assigned decisions could not be checked; refresh the inbox."
    if len(state["items"]) > len(items):
        summary += " Open your inbox to see older notifications."
    details = {"items": items, "unseen": unseen, "href": "/notifications", "partial": state["partial"]}
    revision = hashlib.sha256(json.dumps(details, sort_keys=True).encode()).hexdigest()
    return Snapshot(revision, "Your current notifications", summary, details)


def _read_inbox(request, selection, _arguments):
    current = _inbox_snapshot(request, selection)
    return Preview(current.summary, native=current.details)


def test_snapshot(request, _selection):
    state = native._state(request)
    return Snapshot(hashlib.sha256(json.dumps([state["context"], state["private_delivery"]], sort_keys=True).encode()).hexdigest(),
                    "Your verified private notification accounts", "Review one fixed private message using the same notification controls. It does not change preferences.")


def test_prepare(request, selection, _arguments):
    state = test_snapshot(request, selection)
    return Preview(state.summary + " Choose your verified private account, read the full message and explicitly send it. Original results can be read without another send.",
                   native={"open": {"label": "Review a private notification test", "href": "/notifications#private-alert-test-title"}})


def entries():
    shared = {"family": "notifications", "direct_ui": "/notifications#notification-preferences",
              "pages": ("/notifications", "/preferences", "/account", "/chat", "/chat/goal/*")}
    return (
        Adapter(id="notifications.personal_inbox", label="Show my notifications", input_model=EmptyInput,
                snapshot=_inbox_snapshot, prepare=_read_inbox, **shared),
        Adapter(id="notifications.personal_status", label="Show my personal alert preferences", input_model=EmptyInput,
                snapshot=lambda request, selection: snapshot(request, selection, edit=False), prepare=_read, **shared),
        Adapter(id="notifications.personal_test", label="Try my private notification account", input_model=EmptyInput,
                snapshot=test_snapshot, prepare=test_prepare, **shared),
        Adapter(id="notifications.personal_update", label="Change my personal alert preferences", input_model=ChangeInput,
                snapshot=snapshot, prepare=prepare, execute=execute, recover=recover, **shared),
    )
