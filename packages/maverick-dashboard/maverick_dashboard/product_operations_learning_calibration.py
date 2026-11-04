"""Read-only checker status and the same complete protected ordinary form."""
from __future__ import annotations

from maverick.governed_operations import digest

from . import learning_calibration as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _status(request):
    row = native.catalog(request)
    return {"Current answer checker": row["checker"], "Current-checker retained measurements": row["retained_current_checker_samples"],
            "Current reliability assessment": row["current_receipt"], "Minimum measurements": row["minimum_samples"],
            "Scope": row["scope"], "Current setup": "Available" if row["available"] else row.get("problem", "Unavailable")}


def snapshot(request, _selection):
    value = _status(request)
    return Snapshot(digest(value), "Current answer-checker reliability", native.NOTICE, details=value)


def prepare(request, _selection, _arguments, *, controls=False):
    native.authority(request)
    if controls:
        return Preview("Open the complete private checker controls. Current questions, supplied responses, independent labels and spending are reviewed there; opening makes no AI call or record change.",
            native={"calibration_review": {"scope": "current_page"}})
    return Preview("Read current checker counts and readiness without calling an AI or refreshing an assessment.", native=_status(request))


def entries():
    common = {"family": "learning", "pages": ("/learned",), "direct_ui": native.PAGE, "input_model": EmptyInput, "snapshot": snapshot}
    return (Adapter("learning.read_checker_status", "Read current answer-checker status", prepare=prepare,
                    aliases=("read current answer checker status", "read current checker reliability"), **common),
            Adapter("learning.checker_calibration_form", "Open complete answer-checker controls",
                    prepare=lambda r, s, a: prepare(r, s, a, controls=True),
                    aliases=("open complete answer checker controls", "check the answer checker"), **common))
