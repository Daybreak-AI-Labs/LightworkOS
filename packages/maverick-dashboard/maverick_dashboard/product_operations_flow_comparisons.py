"""Current authorized native case-review handoff, with no private data in chat."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Response
from maverick.governed_operations import digest
from pydantic import Field

from . import local_flow_comparisons as native
from . import local_flow_promotions as release
from .product_operations import Adapter, Preview, Snapshot, StrictInput


class Workflow(StrictInput):
    flow: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class Result(StrictInput):
    comparison: str = Field(pattern=r"^FCP-[a-f0-9]{32}$")


def snapshot(request, selection):
    value = release._native_call(lambda: native.listing(request))
    flows = value["flows"]
    return Snapshot(digest([value["context"], flows]), "Current owned saved workflows",
        "Choose real retained cases and expected answers in the protected native form. Both complete rule versions run locally, with no AI or connected actions.",
        details={"scope": "Selected known-case agreement and local timings; no held-out accuracy or business-lift claim."},
        fields=[{"name": "flow", "label": "Saved workflow", "kind": "select", "required": True,
                 "choices": [{"value": row["id"], "label": row["name"]} for row in flows]}],
        blocked="Save a taught workflow first, then open its native comparison controls." if not flows else "")


def prepare(request, selection, arguments):
    snapshot(request, selection)
    value = release._native_call(lambda: native.options(request, arguments["flow"]))
    return Preview("Review original values and freeze expected answers in the native form. Nothing ran from this status check and no case-use permission was granted.",
        native={"workflow": value["name"], "saved_version": value["version"], "published_baseline": value["baseline_version"],
                "available_real_cases": len(value["cases"]), "scope": value["scope"],
                "included_workflows": value["included_workflows"],
                "open": {"label": "Choose real cases and compare saved rules",
                         "href": native.PAGE + "?workflow=" + arguments["flow"]}})


def result_snapshot(request, selection):
    tenant, owner, context = native._binding(request, Response())
    rows = release._native_call(lambda: native.records().list(limit=1000))
    rows = [row for row in rows if row.get("tenant") == tenant and row.get("owner") == owner][-50:]
    return Snapshot(digest([context, [(row["id"], row["revision"]) for row in rows]]),
        "Current retained rule comparisons", "Check the original saved result without running either version again. Private case values stay in the protected native page.",
        fields=[{"name": "comparison", "label": "Recorded comparison", "kind": "select", "required": True,
                 "choices": [{"value": row["id"], "label": datetime.fromtimestamp(row["created_at"], timezone.utc).strftime("%d %b %Y, %H:%M UTC")
                              + " · " + str(len(row["cases"])) + " selected cases"} for row in rows]}],
        blocked="No retained rule comparison is available in this account. Compare a saved workflow on its real cases first." if not rows else "")


def result_prepare(request, _selection, arguments):
    value = release._native_call(lambda: native.view(request, arguments["comparison"]))
    details = {**value["summary"]}
    details["recorded"] = datetime.fromtimestamp(details.pop("when"), timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    return Preview(value["detail"], native={"workflow": value["name"], "saved_version": value["version"],
        "current_saved_version": value["current"], "complete_results": value["state"] == "done", **details,
        "included_workflows": value["included_workflows"],
        "open": {"label": "Review protected original cases and recorded results", "href": native.PAGE + "?workflow=" + value["flow_id"]}})


def entries():
    pages = (native.PAGE, "/research", "/flows/designer/*")
    return (Adapter("learning.flow_case_compare", "Compare saved rules on real cases", "learning", native.PAGE, pages,
                    Workflow, snapshot, prepare, aliases=("compare real workflow cases",)),
            Adapter("learning.flow_case_results", "Review retained rule comparison results", "learning", native.PAGE, pages,
                    Result, result_snapshot, result_prepare))
