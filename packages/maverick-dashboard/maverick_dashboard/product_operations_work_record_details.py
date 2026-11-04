"""Read-only Copilot entry to the ordinary reviewed business-details form."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .work_record_details_api import _authority, context

PAGE = "/work-details"


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Choose the current work in Business details.")
    current = _authority(request, "task")
    if context(request) != current:
        raise HTTPException(409, "Your account or access changed. Open the current business details again.")
    return Snapshot(digest(current), "Open business details",
                    "Choose named work, enter business fields and a stage, then review the complete change before saving. "
                    "An administrator can set up fields for each category. Business labels do not execute or approve work.")


def prepare(request, selection, _arguments):
    value = snapshot(request, selection)
    current = context(request)
    if digest(current) != value.revision:
        raise HTTPException(409, "Your account or access changed. Open the current controls again.")
    return Preview(value.summary, native={"work_record_details_review": {"scope": "current_page", "context": current}})


def entries():
    return (Adapter("tasks.business_details_controls", "Open business fields and stages", "tasks",
                    PAGE, (PAGE,), EmptyInput, snapshot, prepare,
                    aliases=("open business details", "open business fields", "open business stages",
                             "set up custom fields", "change business details", "open complete business details controls")),)
