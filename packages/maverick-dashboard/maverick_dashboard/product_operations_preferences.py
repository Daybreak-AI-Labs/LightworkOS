"""Copilot preference changes use the same principal-scoped native API."""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import preferences_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

KEYS = ("preferred_name", "tone", "language", "verbosity", "output_style", "custom_style_name",
        "custom_style", "theme", "font", "density", "text_size", "glass", "conversation_mode", "conversation_detail", "chat_model", "chat_effort", "chat_specialist")
STYLE_KEYS = {"tone", "language", "verbosity", "output_style", "custom_style_name", "custom_style"}


class ChangeInput(StrictInput):
    scope: Literal["personal", "workspace", "organization"] = "personal"
    key: str = Field(min_length=1, max_length=40)
    value: str = Field(default="", max_length=2000)
    inherit: bool = False


def _thread(selection):
    if not selection:
        return None
    if selection.get("kind") == "goal" and type(selection.get("id")) is int and selection["id"] > 0:
        return selection["id"]
    if selection.get("kind") == "preferences" and set(selection) <= {"kind", "thread"}:
        thread = selection.get("thread")
        if thread is None or type(thread) is int and thread > 0:
            return thread
    raise HTTPException(404, "Choose your account preferences or one of your own conversations.")


def _current(request, selection):
    thread = _thread(selection)
    return thread, native._state(request, thread)


def _authorize_scope(request, scope):
    if scope == "organization":
        auth.require_global_permission(request, "admin")
    elif scope == "workspace":
        auth.require_permission(request, "admin")


def _choices(current):
    from maverick.persona import style_choices
    from maverick.styles import BUILTIN_STYLES
    return {
        "chat_specialist": (("", "Let Lightwork choose the team"), *tuple((row["value"], row["label"]) for row in current["chat_specialists"])),
        "chat_model": (("", "Use workspace settings"), *tuple((row["value"], row["label"]) for row in current["chat_models"])),
        "chat_effort": (("", "Use the model’s usual thinking depth"), *tuple((row["value"], row["label"])
            for model in current["chat_models"] if model["value"] == current["values"]["chat_model"] for row in model["efforts"])),
        "tone": style_choices(), "language": (("en", "English"), ("fr", "French"), ("de", "German"), ("ja", "Japanese"), ("ar", "Arabic"), ("zh", "Chinese")),
        "verbosity": (("brief", "Brief"), ("balanced", "Balanced"), ("detailed", "Detailed")),
        "output_style": (("", "Ordinary response style"), *tuple((key, key.capitalize()) for key in BUILTIN_STYLES), ("custom", "My named style")),
        "theme": (("system", "Follow system"), *tuple((key, key.capitalize()) for key in sorted(native._app()._valid_theme_names()))),
        "font": (("default", "Default"), ("dyslexic", "Dyslexia-friendly")),
        "density": (("comfortable", "Comfortable"), ("compact", "Compact")),
        "text_size": (("standard", "Standard"), ("large", "Large"), ("larger", "Larger")),
        "glass": (("off", "Off"), ("on", "On")),
        "conversation_mode": (("queue", "Queue next message"), ("guidance", "Review task guidance"), ("independent", "Start separately")),
        "conversation_detail": (("brief", "Brief"), ("balanced", "Balanced"), ("detailed", "Detailed")),
    }


def snapshot(request, selection):
    thread, current = _current(request, selection)
    choices = _choices(current)
    keys = [key for key in KEYS if key not in current["locked"] and (thread is None or key in STYLE_KEYS)
            and (key not in {"chat_model", "chat_effort", "chat_specialist"} or auth.has_permission(request, "operate"))]
    return Snapshot(digest([current["revision"], current["chat_models"], current["chat_specialists"]]), "Your saved preferences in the current workspace",
                    "Review writing, display and future Chat choices with their effective source. Personal names never become shared defaults.",
                    {"values": {key: current["values"][key] for key in KEYS},
                     "sources": {key: current["sources"][key] for key in KEYS}, "locked": current["locked"]},
                    [{"name": "scope", "label": "Apply to", "kind": "select", "value": "personal",
                      "choices": [{"value": value, "label": "This conversation" if thread else value.capitalize()}
                                  for value in (["personal"] if thread else current["scopes"])]},
                     {"name": "key", "label": "Preference", "kind": "select", "required": True,
                      "choices": [{"value": key, "label": {"chat_model":"Default Chat model", "chat_effort":"Default Chat thinking depth", "chat_specialist":"Default Chat specialist"}.get(key, key.replace("_", " ").capitalize())} for key in keys]},
                     {"name": "value", "label": "New value", "kind": "text", "value": "", "depends_on": "key",
                      "choices_by": {key: [{"value": value, "label": label} for value, label in options] for key, options in choices.items()}},
                     {"name": "inherit", "label": "Use inherited value instead", "kind": "boolean", "value": False}],
                    "Organization policy controls every available response preference." if not keys else "")


def _plan(request, selection, args):
    thread, current = _current(request, selection)
    _authorize_scope(request, args["scope"])
    key = args["key"]
    if key not in KEYS or key in current["locked"]:
        raise HTTPException(403, "Choose an available preference that your organization allows you to change.")
    if thread and (args["scope"] != "personal" or key not in STYLE_KEYS):
        raise HTTPException(422, "Only your response style can change for this conversation.")
    if args["scope"] != "personal" and key in native.preferences.PERSONAL_ONLY:
        raise HTTPException(422, "This preference belongs to one person. Choose Personal scope.")
    value = None if args["inherit"] else args["value"]
    try:
        if value is not None:
            value = native.preferences._validate(key, value)
            if key in {"theme", "font", "density", "language", "text_size", "glass"}:
                native._check_display(key, value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    layer = "conversation" if thread else args["scope"]
    effective = current["effective_by_scope"][layer]
    inherited = current["inherited_by_scope"][layer]
    return current, thread, value, effective, inherited


def preview(request, selection, args):
    current, thread, value, effective, inherited = _plan(request, selection, args)
    key = args["key"]
    changes = {key: value}
    if key == "chat_model":
        changes["chat_effort"] = None
    specialist_revision = None
    if key == "chat_specialist":
        from .product_operations_task_launch import published_selection
        specialist_revision = published_selection(request, value or "")["revision"]
    native._validate_chat_defaults(request, native.PreferenceUpdate(expected_revision=current["revision"], context=current["context"],
        scope=args["scope"], thread=thread, changes=changes, specialist_revision=specialist_revision))
    choices = _choices(current)
    def label(field, item):
        if field == "chat_specialist" and item and item not in dict(choices.get(field, ())):
            return "Saved specialist — unavailable"
        return dict(choices.get(field, ()) ).get(item, item)
    return Preview("Save reviewed preferences for " + ("this conversation" if thread else args["scope"]) +
                   ". Chat AI defaults prefill future tasks only; each composer can choose workspace settings or another permitted model. Running tasks, tools, spending limits and approvals are unchanged.",
                   [{"label": {"chat_model":"Default Chat model", "chat_effort":"Default Chat thinking depth", "chat_specialist":"Default Chat specialist"}.get(field, field.replace("_", " ")),
                     "before": label(field, effective["values"][field]),
                     "after": label(field, inherited["values"][field] if item is None else item),
                     "source": effective["sources"][field], "scope": "conversation" if thread else args["scope"],
                     "resulting_source": inherited["sources"][field] if item is None else args["scope"]} for field, item in changes.items()],
                   {"revision": current["revision"], "context": current["context"], "thread": thread,
                    "scope": args["scope"], "changes": changes, "specialist_revision": specialist_revision})


def execute(request, selection, args, prepared, operation_id):
    _plan(request, selection, args)
    response = native.update_preferences(request, native.PreferenceUpdate(
        expected_revision=prepared["revision"], context=prepared["context"], scope=prepared["scope"],
        thread=prepared["thread"], changes=prepared["changes"], operation_id=operation_id,
        specialist_revision=prepared.get("specialist_revision")))
    state = json.loads(response.body)
    return Outcome("confirmed", "The reviewed preference was saved. New work uses this value; running work keeps its captured settings.",
                   {"values": {key: state["values"][key] for key in prepared["changes"]},
                    "sources": {key: state["sources"][key] for key in prepared["changes"]}, "revision": state["revision"]},
                   delete_cookies=tuple("mvk_lang" if key == "language" else "mvk_" + key
                                        for key in prepared["changes"] if key in {"theme", "font", "density", "text_size", "glass", "language"})
                                  if prepared["scope"] == "personal" and not prepared["thread"] else ())


def recover(request, selection, args, prepared, operation_id):
    _authorize_scope(request, prepared["scope"])
    principal = native._principal(request)
    thread = native._thread(request, _thread(selection))
    if native.preferences.operation_confirmed(principal, scope=prepared["scope"], changes=prepared["changes"],
            expected_revision=prepared["revision"], operation_id=operation_id, thread=thread,
            specialist_revision=prepared.get("specialist_revision")):
        return Outcome("replayed", "This exact preference change was already saved. Refresh current preferences to see any later policy changes.")
    return None


def _read_preview(request, selection, args):
    _current(request, selection)
    return Preview("These are your current values and their effective sources. No preference was changed.")


def entries():
    pages = ("/preferences", "/account", "/chat", "/chat/goal/*")
    return (
        Adapter("preferences.status", "Show my preferences", "preferences", "/preferences", pages,
                EmptyInput, lambda request, selection: replace(snapshot(request, selection), fields=[]), _read_preview,
                aliases=("my preferences", "show my writing style", "what are my preferences", "show my Chat defaults")),
        Adapter("preferences.update", "Change my preferences", "preferences", "/preferences", pages,
                ChangeInput, snapshot, preview, execute, recover,
                read_recovery=recover,
                aliases=("change my writing style", "change my theme", "change my preferences", "make my replies shorter", "use inherited preferences", "change my Chat defaults", "change my default Chat model", "change my default thinking depth", "change my default specialist")),
    )
