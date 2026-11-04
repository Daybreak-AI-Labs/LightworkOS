"""Copilot opens the same protected local-practice setting; it never saves it."""
from __future__ import annotations

from . import auth, settings_all_page
from .draft_api import context_for
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

_HREF = "/settings/all?id=plugins.workbench_image"


def snapshot(request, _selection):
    auth.require_global_permission(request, "admin")
    return Snapshot(settings_all_page._revision(), "Current installation practice-environment settings",
        "Open the protected setting, explicitly load already installed environments, then choose, review and save. This handoff does not download, start or qualify anything.",
        details={"installed_practice_environment": {"context": context_for(request)}})


def prepare(request, selection, _arguments):
    value = snapshot(request, selection)
    return Preview(value.summary, native=value.details)


def entries():
    return (Adapter("plugins.environment.configure", "Choose a local plugin practice environment", "connections", _HREF,
        ("/plugins", "/settings", "/settings/all"), EmptyInput, snapshot, prepare,
        aliases=("plugin practice environment", "choose installed plugin environment", "set up plugin checks")),)
