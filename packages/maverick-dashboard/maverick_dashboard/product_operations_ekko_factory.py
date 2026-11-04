"""Copilot finds and builds through Ekko's native, scoped draft service."""
from __future__ import annotations

import time

from fastapi import HTTPException
from maverick.governed_records import GovernedRecordStore
from maverick.privacy_ops import RecordConflict
from pydantic import Field

from . import auth
from . import ekko_factory_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput

JOURNAL = GovernedRecordStore("ekko_build_operations", "EKB", "ekko_build_operation")


class TasksIn(StrictInput):
    device_id: str = Field("local-device", min_length=1, max_length=64)
    brief: str = Field("", max_length=4000)


def snapshot(request, _selection):
    state = native.options_endpoint(request)
    return Snapshot(state["context"], "Current Ekko draft-building permissions",
        "Find repeated accessible business work and reviewed activity, then build private workflow drafts. "
        "Task notes stay on the protected page. No workflow is published, scheduled or executed.",
        fields=[{"name": "device_id", "label": "Device name", "kind": "text", "value": "local-device", "required": True},
                {"name": "brief", "label": "Additional work to automate (optional, one task per line)", "kind": "text"}],
        blocked="Enable Ekko automatic draft building and Workflows in All settings." if not state["enabled"] else "")


def prepare(request, _selection, arguments):
    state = native.options_endpoint(request)
    found = native.scan(request, native.ScanIn(context=state["context"], **arguments))
    return Preview(f"Build private drafts for {found['ready']} discovered tasks; preserve {found['existing']} existing workflows. "
        f"{len(found['missing'])} observations need more context. Drafts remain in Workflows until removed; nothing is published or run.",
        changes=[{"label": "Workflows", "after": f"Up to {found['ready']} new private drafts"}],
        native={"context": found["context"], "scan_revision": found["scan_revision"]})


def recover(request, _selection, _arguments, prepared, operation):
    native.authority(request, prepared["context"], write=True)
    row = JOURNAL.get("EKB-" + operation)
    if row is None:
        return None
    if row["owner"] != (auth.caller_principal(request) or "") or row["context"] != prepared["context"]:
        raise HTTPException(409, "This build belongs to a different workspace context. Start a new review.")
    if row["state"] != "finished" or row.get("_audit_pending"):
        return Outcome("unconfirmed", "The earlier build may have saved some drafts. Inspect Ekko, then start a fresh review for remaining work; this request was not repeated.")
    return Outcome("replayed", row["message"], {"Review drafts": {"href": "/ekko#ekko-build", "label": "Inspect the saved results"}})


def execute(request, selection, arguments, prepared, operation):
    prior = recover(request, selection, arguments, prepared, operation)
    if prior is not None:
        return prior
    # Tokens expire after ten minutes. Keep bounded receipts longer so a lost
    # reply cannot recreate a workflow the customer subsequently removed.
    for row in JOURNAL.list(limit=1001):
        if row.get("expires_at", float("inf")) < time.time():
            JOURNAL.delete(row["id"], expected_revision=row["revision"])
    actor = auth.caller_principal(request) or "local"
    try:
        receipt = JOURNAL.create({"id": "EKB-" + operation, "owner": auth.caller_principal(request) or "",
            "context": prepared["context"], "state": "started", "expires_at": time.time() + 900},
            action="ekko.build_started", actor=actor, max_records=1000,
            effect_guard=lambda: native.authority(request, prepared["context"], write=True))
    except RecordConflict:
        return recover(request, selection, arguments, prepared, operation)
    if receipt.get("_audit_pending"):
        return Outcome("unconfirmed", "The build is waiting for its audit record. Inspect Ekko before starting a new review.")
    body = native.BuildIn(**arguments, **prepared, acknowledge_draft_storage=True)
    total, blocked = 0, 0
    for _ in range(13):
        result = native.build(request, body)
        total += result["built"]
        blocked += result["blocked"]
        if blocked or not result["remaining"]:
            break
        found = native.scan(request, body)
        body = body.model_copy(update={"scan_revision": found["scan_revision"]})
    message = (f"{total} workflow drafts built. " + (f"{blocked} tasks need attention in Ekko. " if blocked else "") +
               "Existing workflows were preserved. Nothing was published or run.")
    final = JOURNAL.update(receipt["id"], lambda row: row.update(state="finished", message=message),
        expected_revision=receipt["revision"], action="ekko.build_finished", actor=actor,
        effect_guard=lambda: native.authority(request, prepared["context"], write=True))
    return Outcome("unconfirmed" if blocked or final.get("_audit_pending") else "confirmed", message,
        {"Review drafts": {"href": "/ekko#ekko-build", "label": "Inspect the discovery and build results"}})


def entries():
    return (Adapter("learning.ekko_find_build", "Find and build my workflows", "learning", "/ekko#ekko-build",
                    ("/ekko",), TasksIn, snapshot, prepare, execute, recover,
                    read_recovery=recover,
                    aliases=("find and build everything", "build my automation opportunities", "automate my repeated work")),)
