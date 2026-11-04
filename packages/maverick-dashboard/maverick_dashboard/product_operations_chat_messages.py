"""Copilot opens the same complete human Chat alternative form without relaying history."""
from __future__ import annotations

from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import _shared
from . import chat_message_actions as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection, *, action):
    bound = native.authority(request, write=True)
    try:
        goal_id = int(selection.get("id", selection.get("goal_id", 0)))
    except (TypeError, ValueError) as exc:
        raise HTTPException(422, "Open the conversation message first.") from exc
    goal = _shared._world().get_goal(goal_id)
    if goal is None:
        return Snapshot(digest(bound), "Current Chat message", "Open a saved conversation message first.",
                        blocked="Choose a message in Chat.")
    material = native._source(request, goal_id, action)
    details = {"chat_message_action": {"context": bound["context"], "goal": goal_id,
               "action": action, "source": digest(material)}}
    return Snapshot(digest([bound, details]), "Your selected saved Chat message",
        "Open the complete protected conversation review. Your prior messages stay unchanged; opening this form starts no AI work.", details=details)


def prepare(request, selection, _arguments, *, action):
    value = snapshot(request, selection, action=action)
    return Preview(value.summary, native=value.details)


def entries():
    # Reuse the ordinary current goal selection; never disclose private history to the model.
    pages = ("/chat/goal/*",)
    return tuple(Adapter("conversation.message." + action, label, "tasks", "/chat", pages, EmptyInput,
        partial(snapshot, action=action), partial(prepare, action=action), aliases=aliases)
        for action, label, aliases in (
            ("retry", "Try this answer again in a separate conversation", ("try again", "regenerate this answer")),
            ("edit", "Edit and resend this saved message", ("edit and resend", "change my last message")),
            ("branch", "Branch from this saved answer", ("branch from here", "make a separate conversation"))))
