"""Copilot opens the same private report controls without receiving file bytes."""
from __future__ import annotations

from typing import Literal

from maverick.governed_operations import digest

from . import report_downloads as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, StrictInput


class ReportIn(StrictInput):
    report: Literal["soc2", "ai_inventory", "oscal", "soa"] = "ai_inventory"


def snapshot(request, _selection):
    value = native.catalog(request)
    choices = [{"value": row["value"], "label": row["label"]} for row in value["choices"] if row["value"] != "public_key"]
    return Snapshot(digest(value), "Current permitted report controls", "Choose a named report in the protected page. Copilot does not receive the file or confirm its delivery.",
                    fields=[{"name": "report", "choices": choices, "label": "Report", "kind": "select", "required": True}],
                    blocked="Your current role cannot download these reports." if not choices else "")


def key_snapshot(request, _selection):
    context = native.capture(request, "public_key")
    return Snapshot(digest(context), "Current public signing-key controls", "The public key is offered only from the current workspace's protected download control. Its private key is never downloaded.")


def prepare(request, _selection, arguments):
    kind = arguments.get("report", "public_key")
    context = native.capture(request, kind)
    return Preview("Open the protected download control. Choose the current assessment where needed, then explicitly download there. Browser delivery is not independently confirmed.",
                   native={"report_download": {"context": context, "kind": kind}, "Open download controls": {"href": native.REPORTS[kind][2], "label": native.REPORTS[kind][0]}})


def entries():
    return (Adapter("compliance.reports.download", "Download an auditor report", "artifacts", "/compliance#cmp-reports", ("/compliance",), ReportIn, snapshot, prepare),
            Adapter("consent.signing_key.download", "Download the public consent signing key", "preferences", "/consent/publishing#cpp-signing", ("/consent/publishing",), EmptyInput, key_snapshot, prepare))
