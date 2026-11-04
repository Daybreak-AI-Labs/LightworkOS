"""Read-only Copilot handoff to native safeguard activity; never evaluates text."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import runtime_enforcement_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Open Governance to read safeguard activity.")
    state = native.catalog(request)
    return Snapshot(digest(state), "Saved safeguard activity",
        f"{state['total']} native connection attempts have retained local activity. " + state["notice"],
        details={"Saved attempts": state["total"], "New safeguard checks enabled": state["runtime_enabled"],
            "Governance loop enabled": state["loop_enabled"]})


def prepare(request, selection, _arguments):
    before = snapshot(request, selection)
    state = native.catalog(request)
    if digest(state) != before.revision:
        raise HTTPException(409, "Safeguard activity changed. Read the current list before opening it.")
    return Preview(before.summary, native={"runtime_enforcement_form": {"context": state["context"]}})


def entries():
    return (Adapter("reviews.runtime_enforcement", "Read actual safeguard activity", "reviews",
        "/security/governance#runtime-enforcement", ("/security/governance",), EmptyInput, snapshot, prepare,
        aliases=("read safeguard activity", "did safeguards stop the action", "open enforcement activity")),)
