"""Protected, read-only opening of a person's ordinary private alert controls."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import personal_push_devices_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

PAGE = "/notifications#private-device-setup"


def _current(request, selection):
    if selection:
        raise HTTPException(422, "Open Notifications to choose your private destinations.")
    state = native.state(request)
    native._authority(request, state["context"])
    return state


def snapshot(request, selection):
    state = _current(request, selection)
    return Snapshot(digest(state), "Your private notification setup",
        "Read the same complete private destination controls. Registration, test messages, "
        "quiet hours, enabling, pausing and removal each use their own separate review. "
        "Opening these controls changes and sends nothing.",
        details={"Saved destinations": len(state["devices"]),
                 "External delivery available": state["external_available"]})


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    state = _current(request, selection)
    if digest(state) != current.revision:
        raise HTTPException(409, "Your account, access or private destination setup changed. Read the current controls again.")
    return Preview(current.summary, native={"personal_push_setup": {"context": state["context"]}})


def entries():
    return (Adapter("notifications.private_destination_setup", "Open private notification setup", "notifications",
        PAGE, ("/notifications",), EmptyInput, snapshot, prepare,
        aliases=("set up private phone alerts", "open private notification controls", "add a private notification destination",
                 "change notification quiet hours", "pause private notifications", "read an original private alert result")),)
