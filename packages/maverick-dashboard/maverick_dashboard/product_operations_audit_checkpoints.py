"""Read existing activity checkpoints through the same native audit authority."""
from __future__ import annotations

import json

from fastapi import HTTPException
from maverick.audit.checkpoints import AuditCheckpointError
from maverick.governed_operations import digest
from pydantic import Field

from . import audit_ops_api as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot, StrictInput


class ReceiptInput(StrictInput):
    checkpoint: int = Field(ge=1, le=10**9)


def _read(request, function, *arguments):
    native.require_permission(request, "audit")
    try:
        value = function(*arguments)
    except HTTPException:
        raise
    except (AuditCheckpointError, ValueError) as exc:
        raise HTTPException(409, "The checkpoints could not be trusted. Open Activity log to check the recorded problem.") from exc
    except (ImportError, OSError, RuntimeError) as exc:
        raise HTTPException(503, "Checkpoints are not available right now. Open Activity log to check their status.") from exc
    native.require_permission(request, "audit")
    return value


def status_snapshot(request, selection):
    overview = _read(request, native._overview)
    return Snapshot(digest(overview), "Current workspace activity checkpoints",
                    "Read retained checkpoints and their current problems. A locally matching chain alone does not prove independent custody or every real-world event.")


def status_prepare(request, selection, arguments):
    overview = _read(request, native._overview)
    return Preview("Showing the latest retained checkpoints. This read does not publish, retire or change the activity log.",
                   native={"retained_checkpoints": overview["total"], "problem": overview["problem"] or "No list-reading problem found",
                           "latest_checkpoints": [{"day": row["day"], "kind": row["kind"],
                                                   "recorded_entries": row["entries"], "recorded_at": row["created_at"],
                                                   "current_for_day": row["latest"]} for row in overview["checkpoints"][:25]],
                           "coverage": "Latest 25 checkpoints. Open Activity log for the retained list and days awaiting a checkpoint."})


def check_snapshot(request, selection):
    value = status_snapshot(request, selection)
    return Snapshot(value.revision, value.source,
                    "Check the native signed checkpoint chain against the current activity log. A separately kept receipt must be selected in Activity log to check for rollback against that receipt.")


def check_prepare(request, selection, arguments):
    result = _read(request, native._verify, native.VerifyIn())
    return Preview("The native checkpoint check finished. No separately kept receipt was provided.",
                   native={"current_stored_chain_matches": result["intact"], "no_checkpoints_yet": result["none_yet"],
                           "trusted_signing_keys_selected": result["keys_pinned"], "problems": result["problems"],
                           "meaning": "This checks the stored chain and retained log. Upload a receipt you kept elsewhere on Activity log to compare independent history. It does not establish who approved business work or that every event was recorded."})


def receipt_snapshot(request, selection):
    overview = _read(request, native._overview)
    choices = [{"value": row["sequence"],
                "label": row["day"] + " — " + row["kind"] + " — " + str(row["entries"]) + " entries"}
               for row in overview["checkpoints"]]
    return Snapshot(digest(overview), "Current retained activity checkpoint list",
                    "Choose a saved checkpoint to download its native receipt and keep it separately.",
                    fields=[{"name": "checkpoint", "label": "Saved checkpoint", "kind": "select", "required": True,
                             "value": choices[0]["value"] if choices else None, "choices": choices}],
                    blocked="No saved checkpoint is available. Publish one in Activity log first." if not choices else "")


def receipt_prepare(request, selection, arguments):
    receipt = json.loads(_read(request, native._receipt, arguments["checkpoint"]))
    return Preview("The selected checkpoint's native receipt is ready. Keep the downloaded file independently before using it to check later history.",
                   native={"recorded_day": receipt["day"],
                           "download": {"label": "Download this checkpoint receipt",
                                        "href": "/api/v1/audit/checkpoints/" + str(receipt["sequence"]) + "/receipt"}})


def entries():
    common = {"family": "reviews", "direct_ui": "/audit", "pages": ("/audit",)}
    return (
        Adapter("audit.checkpoints.read", "Read retained activity checkpoints", input_model=EmptyInput,
                snapshot=status_snapshot, prepare=status_prepare, **common),
        Adapter("audit.checkpoints.check", "Check the current activity checkpoint chain", input_model=EmptyInput,
                snapshot=check_snapshot, prepare=check_prepare, **common),
        Adapter("audit.checkpoints.receipt", "Download a saved activity checkpoint receipt", input_model=ReceiptInput,
                snapshot=receipt_snapshot, prepare=receipt_prepare, **common),
    )
