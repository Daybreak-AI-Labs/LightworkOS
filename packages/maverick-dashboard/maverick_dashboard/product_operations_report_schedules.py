"""Read-only protected handoff to the native recurring-report form."""
from fastapi import HTTPException
from maverick.governed_operations import digest

from . import executive_report_schedules as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def snapshot(request, selection):
    if selection:
        raise HTTPException(422, "Open the named report schedule controls on the current page.")
    catalog = native.options(request)
    return Snapshot(digest(catalog), "Current native report schedule controls",
        "Review a named saved layout, current selected records and a timetable in the protected form. "
        "Each run creates a fresh PDF without AI. Original and Stop remain separate; nothing is scheduled here.",
        details={"Available saved layouts": len(catalog["choices"]), "New scheduling available": catalog["enabled"]})


def prepare(request, selection, arguments):
    before = snapshot(request, selection)
    catalog = native.options(request)
    if before.revision != digest(catalog):
        raise HTTPException(409, "Current report choices changed. Check the current controls again; your entered work is kept.")
    return Preview("Open the protected report schedule form. Your entered choices and Original are kept; nothing is created or run.",
        native={"report_schedule_form": {"context": catalog["context"]}})


def entries():
    return (Adapter("reports.executive_schedule_form", "Schedule executive reports", "artifacts",
        native.PAGE+"#tper-schedules", (native.PAGE,), EmptyInput, snapshot, prepare,
        aliases=("recurring executive reports", "schedule a vendor report", "report schedule original")),)
