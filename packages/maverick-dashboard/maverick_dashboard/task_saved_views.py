"""Named, owned task filters using the existing dashboard UX view store."""
from __future__ import annotations

import hmac
from typing import Literal
from urllib.parse import urlencode

from fastapi import HTTPException
from maverick import ux_store
from pydantic import BaseModel, ConfigDict, Field

from .draft_api import context_for
from .preferences_api import _principal

STATUSES = {"": "All tasks", "running": "Running", "waiting": "Waiting for you",
            "failed": "Failed", "done": "Done"}


class Change(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    expected_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    q: str = Field(default="", max_length=256)
    status: Literal["", "running", "waiting", "failed", "done"] = ""


def params(q: str, status: str) -> dict:
    if not isinstance(q, str) or len(q) > 256 or status not in STATUSES:
        raise HTTPException(422, "Use a task search of at most 256 characters and an available task status.")
    return {"page": "/goals", "q": q.strip(), "status": status}


def _name(name: str) -> str:
    if not isinstance(name, str) or not name.strip() or len(name) > 80 or any(ord(c) < 32 or c in "/\\" for c in name):
        raise HTTPException(422, "Name this view with 1–80 characters, without slashes or control characters.")
    return name.strip()


def _entry(name, entry):
    """Never replay arbitrary legacy URL parameters or privately stored markup."""
    try:
        values = entry["params"]
        if not isinstance(values, dict) or set(values) - {"page", "q", "status"} or values.get("page", "/goals") != "/goals":
            return None
        values = params(values.get("q", ""), values.get("status", ""))
        return {"name": _name(name), "params": values, "href": "/goals?" + urlencode({"q": values["q"], "status": values["status"]}),
                "saved_at": entry.get("saved_at"), "status_label": STATUSES[values["status"]]}
    except (TypeError, KeyError, HTTPException):
        return None


def current(request) -> dict:
    principal = _principal(request)
    snapshot = ux_store.shared().view_snapshot(principal)
    rows = [_entry(name, entry) for name, entry in snapshot["views"].items()]
    return {"context": context_for(request), "revision": snapshot["revision"],
            "views": [row for row in rows if row is not None],
            "other_views": sum(row is None for row in rows),
            "coverage": "Filters apply to the current task results: 200 recent tasks, or up to 100 matching search results. Opening a view rechecks current task access."}


def change(request, name: str, body: Change, *, delete=False) -> dict:
    from maverick.authority_effects import authority_effect_fence

    from .app import _require_same_origin

    with authority_effect_fence():
        _require_same_origin(request)
        principal = _principal(request)
        if not hmac.compare_digest(body.context, context_for(request)):
            raise HTTPException(409, detail={"code": "context_changed", "message": "Your account or workspace changed. Reload before changing saved views."})
        name = _name(name)
        store = ux_store.shared()
        snapshot = store.view_snapshot(principal)
        if snapshot["revision"] != body.expected_revision:
            raise HTTPException(409, "Saved views changed. Refresh and review your changes again.")
        if name in snapshot["views"] and _entry(name, snapshot["views"][name]) is None:
            raise HTTPException(409, "That name belongs to another saved dashboard view. Choose a different name; that view has been preserved.")
        try:
            if delete:
                if not store.delete_view(principal, name, expected_revision=body.expected_revision):
                    raise HTTPException(404, "This saved view is no longer present. Refresh saved views.")
            else:
                store.save_view(principal, name, params(body.q, body.status), expected_revision=body.expected_revision)
        except ux_store.ViewConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        return {**current(request), "saved" if not delete else "deleted": name}
