"""Installation checks are explicitly started in their protected native form."""
from __future__ import annotations

from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .system_checks_api import installation_health_context


def snapshot(request, _selection):
    current = installation_health_context(request)
    return Snapshot(current["context"], "Current installation health controls",
        "Open Help to review and explicitly start the installation checks. They may contact configured services. Copilot does not run them or change safety settings.",
        details={"installation_health": current})


def prepare(request, selection, _arguments):
    value = snapshot(request, selection)
    return Preview(value.summary, native=value.details)


def entries():
    return (Adapter("preferences.installation_health", "Check installation health", "preferences",
        "/help#installation-health", ("/help", "/settings", "/settings/all"),
        EmptyInput, snapshot, prepare, aliases=("health check", "check installation", "safety settings need attention")),)
