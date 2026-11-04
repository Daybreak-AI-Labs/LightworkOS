"""Open the existing schedule form through current native page authority."""
from __future__ import annotations

from fastapi import HTTPException
from maverick import config
from maverick.governed_operations import digest

from . import auth
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, _context

PAGE = "/automations"


def _current(request, selection):
    from .app import require_page_visible

    if selection:
        raise HTTPException(422, "Open Automations to choose and review a new schedule.")
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    auth.require_permission(request, "operate")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Schedule settings could not be read. Your entered work is kept.")
    context = _context(request)
    if not config.get_features().get("scheduling", True):
        raise HTTPException(403, "Schedule creation is turned off. An administrator can turn on automations in Settings.")
    auth.require_page_permission(request, PAGE)
    require_page_visible(request, PAGE)
    auth.require_permission(request, "operate")
    if _context(request) != context:
        raise HTTPException(409, "Your account, workspace or access changed. Open the current schedule controls again.")
    return digest([context, "schedule_creation_available"])


def snapshot(request, selection):
    return Snapshot(_current(request, selection), "Create a schedule in Automations",
                    "Choose the work, repeat pattern, time and time zone in the complete schedule form. "
                    "Check its next run times before choosing Create schedule. Opening the form changes no saved work.")


def prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    return Preview(current.summary, native={"schedule_creation_review": {"scope": "current_page"}})


def original_snapshot(request, selection):
    from .schedule_ops_api import _creation_authority

    if selection:
        raise HTTPException(422, "Open Automations to check your original schedule request.")
    current = _creation_authority(request)
    return Snapshot(digest(current), "Your original schedule request in Automations",
        "Open the retained original-result controls for this account and workspace. "
        "Reading an original never creates a schedule or repeats a task. Original controls remain available with scheduling turned off.")


def original_prepare(request, selection, _arguments):
    from .schedule_ops_api import _creation_authority

    current = original_snapshot(request, selection)
    value = _creation_authority(request)
    if digest(value) != current.revision:
        raise HTTPException(409, "Your account or access changed. Open the current original-result controls again.")
    return Preview(current.summary, native={"schedule_creation_original": {
        "scope": "current_page", "context": value["context"],
    }})


def entries():
    return (
        Adapter("schedules.creation_controls", "Open the complete schedule form", "schedules",
                    PAGE + "#auto-new-sched", (PAGE,), EmptyInput, snapshot, prepare,
                    aliases=("create a schedule", "set up a schedule", "schedule a task",
                             "schedule a saved workflow", "open schedule creation controls")),
        Adapter("schedules.creation_original", "Open the original schedule result", "schedules",
                PAGE + "#auto-create-original", (PAGE,), EmptyInput, original_snapshot, original_prepare,
                aliases=("check my original schedule request", "recover a lost schedule reply", "did my schedule save")),
    )
