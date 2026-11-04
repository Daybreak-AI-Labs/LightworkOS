"""Selected outside-agent execution metadata, through its native read service."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from .draft_api import context_for
from .external_agent_detail_service import detail_for, readback_details
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _detail(request, selection):
    if (set(selection) != {"kind", "id"} or selection.get("kind") != "external_agent"
            or not isinstance(selection.get("id"), str) or not 1 <= len(selection["id"]) <= 200):
        raise HTTPException(404, "Open an outside agent to review its connected changes.")
    return detail_for(request, selection["id"])


def snapshot(request, selection):
    details = readback_details(_detail(request, selection))
    return Snapshot(digest([context_for(request), details]), "Selected outside agent's retained execution metadata",
        "Read recorded changes and outcomes needing a check in the connected service. No change is retried.", details)


def prepare(request, selection, _arguments):
    return Preview("Current saved execution metadata. An unknown result must be checked in the connected service; this read starts no work and contacts no provider.",
                   native=readback_details(_detail(request, selection)))


def entries():
    return (Adapter("external_agents.execution_status", "Review this outside agent's connected changes", "connections",
        "/external-agents", ("/external-agents/*",), EmptyInput, snapshot, prepare,
        aliases=("check this outside agent", "show outside agent uncertain changes")),)
