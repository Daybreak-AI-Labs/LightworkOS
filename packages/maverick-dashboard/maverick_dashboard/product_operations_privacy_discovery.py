"""Copilot reads retained scan states and opens the same protected controls."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import auth
from . import privacy_data_discovery_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

PAGE = "/privacy/data-discovery"
STATES = {"queued": "Waiting", "leased": "In progress", "complete": "Finished",
          "dead_letter": "Needs attention", "cancelled": "Cancelled"}


def _state(request, selection):
    if selection:
        raise HTTPException(422, "Open the current data-discovery page to review its scan controls.")
    auth.require_permission(request, "view")
    auth.require_page_permission(request, PAGE)
    service, tenant, store = native._authority(request)
    try:
        rows = store.list_jobs(tenant, limit=101)
    except service.PrivacyDataDiscoveryError as exc:
        raise HTTPException(503, "Current scan information could not be verified. Open the data-discovery page to check its retained work.") from exc
    counts = Counter(STATES.get(row.state, "Other retained state") for row in rows[:100])
    details = {
        "Recent scans included": min(len(rows), 100),
        "Recent scan states": dict(counts),
        "More retained scans": len(rows) > 100,
        "Scope": "The newest 100 retained scans at most. Finished describes a saved scan, not complete "
                 "coverage of your systems or proof that personal data is absent.",
        "Next step": "Open the current controls to review a queued scan or read its saved result. "
                     "Starting or cancelling work needs a separate review and confirmation there.",
    }
    return digest({"tenant": tenant, "jobs": [asdict(row) for row in rows]}), details


def snapshot(request, selection):
    revision, details = _state(request, selection)
    return Snapshot(revision, "Current retained scans in this workspace",
                    "Read recent scan states and open their existing protected controls.", details)


def prepare(request, selection, _arguments):
    _, details = _state(request, selection)
    return Preview("Current retained scan status. No scan was started or cancelled.", native={
        **details, "privacy_discovery_review": {"scope": "current_page"},
    })


def entries():
    return (Adapter("connections.privacy_discovery_status", "Read recent discovery scans and open their controls",
                    "connections", PAGE, (PAGE,), EmptyInput, snapshot, prepare,
                    aliases=("review a discovery scan", "read recent discovery scans",
                             "show current discovery scans", "open discovery scan controls")),)
