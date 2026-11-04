"""Copilot can inspect or explicitly remove a caller's paired device."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException, Response
from pydantic import Field

from . import device_pairing_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class RemoveInput(StrictInput):
    device_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def _state(request):
    return native.state(request, Response())


def _find(state, ident):
    return next((row for row in state["devices"] if row["id"] == ident), None)


def snapshot(request, _selection, *, remove=False):
    state = _state(request)
    fields = [{"name": "device_id", "label": "Device to remove", "kind": "select", "required": True,
               "choices": [{"value": row["id"], "label": row["label"]} for row in state["devices"]]}] if remove else []
    return Snapshot(hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest(),
        "Your currently paired devices in this workspace",
        "Pair new devices by comparing a short-lived code on Your paired devices. Removing a device denies its next request.",
        {"devices": state["devices"], "offline_copies": "A disconnected device retains permitted saved copies until their existing expiry."},
        fields, "No paired device is available to remove." if remove and not state["devices"] else "")


def _read(request, selection, _arguments):
    snapshot(request, selection)
    return Preview("These are your current paired devices. Compare the code and review each permission in the complete pairing form.",
        native={"open": {"label": "Open device pairing and permissions", "href": "/devices#device-review-form"}})


def prepare(request, _selection, arguments):
    state = _state(request)
    row = _find(state, arguments["device_id"])
    if not row:
        raise HTTPException(404, "That paired device is unavailable.")
    return Preview("Remove this device's access. It must be paired again to reconnect. Existing offline copies expire under their saved retention policy.",
        [{"label": row["label"], "before": "Paired", "after": "Access removed"}],
        {"device": row, "context": state["context"]})


def execute(request, _selection, _arguments, prepared, _operation_id):
    state = _state(request)
    row = _find(state, prepared["device"]["id"])
    if row is None:
        return Outcome("replayed", "This device is already removed or its enrollment expired.")
    if row != prepared["device"]:
        raise HTTPException(409, "This device connection changed. Review it again before removing access.")
    native.remove(request, Response(), native.Remove(id=row["id"], context=prepared["context"]))
    return Outcome("confirmed", "Device removed. Its next request will be denied.")


def recover(request, _selection, _arguments, prepared, _operation_id):
    if _find(_state(request), prepared["device"]["id"]) is None:
        return Outcome("replayed", "This device is already removed or its enrollment expired.")
    return None


def entries():
    shared = {"family": "connections", "direct_ui": "/devices", "pages": ("/devices", "/account", "/preferences")}
    return (
        Adapter(id="devices.status", label="View or pair my devices", input_model=EmptyInput, snapshot=snapshot, prepare=_read,
                aliases=("pair my phone", "connect my device", "review device permissions"), **shared),
        Adapter(id="devices.remove", label="Remove a paired device", input_model=RemoveInput,
                snapshot=lambda request, selection: snapshot(request, selection, remove=True), prepare=prepare, execute=execute, recover=recover, **shared),
    )
