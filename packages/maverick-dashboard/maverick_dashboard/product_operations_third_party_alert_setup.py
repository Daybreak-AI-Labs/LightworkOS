"""Read-only Copilot handoff to the current ordinary vendor-alert controls."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import third_party_intelligence_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Open Vendor monitoring to set up alert recipients.")
    state = native.alert_setup_overview(request)
    return Snapshot(digest(state), "Current vendor-alert setup",
        "Open the complete ordinary recipient controls. Opening them saves and sends nothing.",
        details={"Saved recipients": state["saved_recipients"]})


def prepare(request, selection, _arguments):
    before = snapshot(request, selection)
    state = native.alert_setup_overview(request)
    if digest(state) != before.revision:
        raise HTTPException(409, "Your alert setup changed. Read the current controls before opening them.")
    return Preview(before.summary,
        native={"third_party_alert_setup_form": {"context": state["context"]}})


def entries():
    return (Adapter("notifications.third_party_alert_setup", "Open vendor-alert recipient setup", "notifications",
        "/third-party/intelligence#tpi-recipient-setup", ("/third-party/intelligence",),
        EmptyInput, snapshot, prepare,
        aliases=("set up vendor alert recipients", "open vendor monitoring alerts", "add a vendor alert recipient")),)
