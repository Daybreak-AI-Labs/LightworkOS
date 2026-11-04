"""Open the real dataset update form without sharing scan contents in chat."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import privacy_discovery_data_use_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

PAGE = "/privacy/data-discovery"


def _current(request, selection):
    if selection:
        raise HTTPException(422, "Open the current data-discovery page to choose a report and dataset.")
    return native.overview(request)


def snapshot(request, selection):
    value = _current(request, selection)
    return Snapshot(digest(value), "Review approved findings for a saved dataset",
        "Open the protected report and dataset choices. Opening the form changes nothing. Every finding needs current independent approval before a dataset update can be confirmed.",
        blocked="Save a Data Use dataset and complete a scan with findings first." if not value["reports"] or not value["datasets"] else "")


def prepare(request, selection, _arguments):
    value = _current(request, selection)
    return Preview("Choose the report and dataset in the current protected controls, then review and confirm separately.",
                   native={"privacy_data_use_bridge_form": {"context": value["context"]}})


def entries():
    return (Adapter("connections.discovery_data_use_review", "Use approved scan findings in Data Use", "connections",
        PAGE + "#pddb-root", (PAGE,), EmptyInput, snapshot, prepare,
        aliases=("use approved findings in Data Use", "update a dataset from a reviewed scan", "open dataset classification review")),)
