"""Reviewed encryption actions use the same native Settings service."""
from __future__ import annotations

from . import encryption_maintenance as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


def snapshot(request, _selection, *, action="read"):
    value = native.current(request)
    blocked = value["blocked"]
    if action == "rotate" and not value["can_rotate"]:
        blocked = blocked or "These keys are managed outside this local installation."
    if action == "protect" and not value["can_protect"]:
        blocked = blocked or "This local control cannot protect this installation's shared records."
    return Snapshot(value["revision"], "Current local encryption settings and key history",
        "Check older supported records or review a local key change.",
        {"enabled": value["enabled"], "older_unprotected": value["older_unprotected"],
         "local_key_change_available": value["can_rotate"], "direct_ui": "/settings#maintenance-encryption"},
        blocked=blocked)


def prepare(request, _selection, _arguments, *, action="read"):
    if action == "read":
        value = native.current(request)
        return Preview("Current stored-data protection settings and the supported older-record count.",
                       native={key: value[key] for key in ("enabled", "older_unprotected", "can_rotate", "can_protect", "blocked")})
    value = native.prepare(request, action)
    return Preview(value["summary"], native={"review": value["token"]})


def _outcome(value, *, replay=False):
    return Outcome("replayed" if replay and value["state"] == "confirmed" else
                   "confirmed" if value["state"] == "confirmed" else "unconfirmed",
                   value["message"] or "The original maintenance result is unconfirmed. Check encryption before considering a separately reviewed action.",
                   value)


def execute(request, _selection, _arguments, prepared, operation_id, *, action):
    return _outcome(native.execute(request, action, prepared["review"], operation_id))


def recover(request, _selection, _arguments, _prepared, operation_id):
    value = native.receipt(request, operation_id)
    return _outcome(value, replay=True) if value else None


def entries():
    from functools import partial
    return tuple(Adapter("preferences.encryption_" + action, label, "preferences", "/settings#maintenance-encryption",
        ("/settings", "/settings/all"), EmptyInput, partial(snapshot, action=action), partial(prepare, action=action),
        None if action == "read" else partial(execute, action=action),
        None if action == "read" else recover, aliases)
        for action, label, aliases in (
            ("read", "Check stored-data protection", ("check encryption",)),
            ("protect", "Protect older saved records", ("encrypt older records",)),
            ("rotate", "Make a new local encryption key", ("make a new encryption key",))))
