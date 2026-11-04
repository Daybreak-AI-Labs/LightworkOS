"""Protected ordinary outcome controls for the current native privacy request."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import dsar_handling_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .product_operations_dsar_handoff import _id
from .product_operations_dsar_status import KINDS


def snapshot(request, selection):
    record, _actor, context = native.state(request, _id(selection))
    return Snapshot(digest({"context": context, "record": record}),
        "Current privacy request and recorded outcome",
        "Open the complete action and response review. Nothing is changed or sent by opening it.",
        {"Request": KINDS.get(record.get("kind"), "Privacy request"),
         "Outcome already recorded": bool(record.get("outcome"))},
        blocked="This request already has an immutable outcome. Read its recorded statement on the request page."
        if record.get("outcome") else "")


def prepare(request, selection, _arguments):
    snapshot(request, selection)
    _record, _actor, context = native.state(request, _id(selection))
    return Preview("Open the complete privacy outcome controls. Your existing entries stay in place; nothing is closed, changed or sent.",
                   native={"dsar_handling_review": {"scope": "current_page", "context": context}})


def entries():
    return (Adapter("artifacts.privacy_request_handling", "Open the complete privacy action and response controls",
        "artifacts", "/privacy", ("/privacy/dsar/*",), EmptyInput, snapshot, prepare,
        aliases=("open privacy action and response controls", "record action and response", "record this privacy request outcome")),)
