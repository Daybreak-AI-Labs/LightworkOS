"""Reviewed saved task-filter operations over the native owned-view service."""
from __future__ import annotations

from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from pydantic import Field

from . import task_saved_views as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class Save(StrictInput):
    name: str = Field(min_length=1, max_length=80)
    q: str = Field(default="", max_length=256)
    status: Literal["", "running", "waiting", "failed", "done"] = ""


class Remove(StrictInput):
    name: str = Field(min_length=1, max_length=80)


def snapshot(request, selection):
    state = native.current(request)
    filters = selection.get("filters", {}) if selection.get("kind") == "task_filter" else {}
    q, status = filters.get("q", ""), filters.get("status", "")
    selected = native.params(q, status)
    return Snapshot(state["revision"], "Your saved task views in this workspace", state["coverage"], state,
                    [{"name": "name", "label": "Saved view name", "kind": "text", "required": True, "max_length": 80},
                     {"name": "q", "label": "Task search", "kind": "text", "value": selected["q"], "max_length": 256},
                     {"name": "status", "label": "Task status", "kind": "select", "value": selected["status"],
                      "choices": [{"value": key, "label": label} for key, label in native.STATUSES.items()]}])


def removal_snapshot(request, selection):
    state = snapshot(request, selection)
    return replace(state, fields=[{"name": "name", "label": "Saved view", "kind": "select", "required": True,
                                  "choices": [{"value": row["name"], "label": row["name"]} for row in state.details["views"]]}],
                   blocked="Save a task view first." if not state.details["views"] else "")


def _preview(request, args, *, delete):
    state = native.current(request)
    name = native._name(args["name"])
    previous = next((row for row in state["views"] if row["name"] == name), None)
    if delete and previous is None:
        raise HTTPException(409, "Choose a current saved task view before reviewing removal.")
    after = None if delete else native.params(args["q"], args["status"])
    return Preview(("Remove" if delete else "Save") + " this named task view in your account and workspace. This does not start or change tasks.",
                   [{"label": name, "before": previous["params"] if previous else None, "after": after}],
                   {"name": name, "delete": delete, "context": state["context"], "expected_revision": state["revision"],
                    "q": "" if delete else after["q"], "status": "" if delete else after["status"]})


def recover(request, selection, args, prepared, operation_id):
    state = native.current(request)
    if state["context"] != prepared["context"]:
        raise HTTPException(409, "The account or workspace changed. Review saved views again.")
    if state["revision"] == prepared["expected_revision"]:
        return None
    # UxStore predates durable operation receipts. A state read is evidence of
    # present values, never proof that this particular request was committed.
    return Outcome("unconfirmed", "Saved views changed after this review. Current values are shown; no further change was sent. Refresh and review again if needed.", state)


def execute(request, selection, args, prepared, operation_id):
    body = native.Change(**{key: prepared[key] for key in ("context", "expected_revision", "q", "status")})
    state = native.change(request, prepared["name"], body, delete=prepared["delete"])
    return Outcome("confirmed", "The saved task view was removed." if prepared["delete"] else "The task view was saved to your account in this workspace.", state)


def entries():
    pages = ("/goals", "/today", "/preferences")
    return (
        Adapter("task_views.status", "Show my saved task views", "preferences", "/goals", pages,
                EmptyInput, lambda request, selection: replace(snapshot(request, selection), fields=[]),
                lambda request, selection, args: Preview("Current saved filters; no tasks or views changed.", native=native.current(request))),
        Adapter("task_views.save", "Save a task view", "preferences", "/goals", pages,
                Save, snapshot, lambda request, selection, args: _preview(request, args, delete=False), execute, recover,
                aliases=("save this task search", "save these task filters")),
        Adapter("task_views.remove", "Remove a saved task view", "preferences", "/goals", pages,
                Remove, removal_snapshot, lambda request, selection, args: _preview(request, args, delete=True), execute, recover),
    )
