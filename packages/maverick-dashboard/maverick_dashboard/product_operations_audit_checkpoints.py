"""Read, publish, check and retire activity checkpoints through the Activity
log page's own functions: the same permissions, refusals and log entries."""
from __future__ import annotations

import json

from fastapi import HTTPException
from maverick.audit.checkpoints import AuditCheckpointError
from maverick.governed_operations import digest
from pydantic import Field

from . import audit_ops_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


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


class KeptReceipt(StrictInput):
    receipt: str = Field(min_length=2, max_length=native._MAX_RECEIPT_BYTES)


def receipt_check_snapshot(request, selection):
    value = status_snapshot(request, selection)
    return Snapshot(value.revision, value.source,
                    "Check the checkpoints against a receipt you kept elsewhere. "
                    "The check also reports any day replaced or retired after that receipt. Nothing is changed.",
                    fields=[{"name": "receipt", "label": "The text of a receipt file you kept elsewhere",
                             "kind": "textarea", "value": "", "max_length": native._MAX_RECEIPT_BYTES}])


def receipt_check_prepare(request, selection, arguments):
    """The page's "Check the checkpoints" with a kept receipt: the same check,
    the same sentences."""
    native.require_permission(request, "audit")
    result = native.run_checked(native._verify, native.VerifyIn(receipt=arguments["receipt"]))
    native.require_permission(request, "audit")
    sentences = native.check_sentences(result)
    # The page keeps the raw reason codes in a closed "Technical details" box;
    # here only its sentences are shown. Auditors read the codes on the page.
    return Preview(sentences[0], native={"result": sentences, "matches": result["intact"]})


_ERASED = "The log changed after a person's data was erased"
_NO_RECORD = "Replace it without an erasure record"


class PublishInput(StrictInput):
    day: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    after_erasure: bool = False
    without_erasure_record: bool = False


def _administrator_overview(request) -> dict:
    native.require_permission(request, "admin")
    overview = native.run_checked(native._overview)
    native.require_permission(request, "admin")
    return overview


def publish_snapshot(request, selection):
    overview = _administrator_overview(request)
    choices = [{"value": row["day"], "label": row["day"] + (" (has a checkpoint)" if row["has_checkpoint"] else "")}
               for row in overview["days"]]
    return Snapshot(digest(overview), "Days in the activity log and their checkpoints",
                    (overview["problem"] + " " if overview["problem"] else "")
                    + "Publish a signed checkpoint for one day of the activity log. "
                    "Tick the second box only for a day that was already erased and has no erasure record.",
                    fields=[{"name": "day", "label": "Day", "kind": "select", "choices": choices,
                             "value": choices[0]["value"] if choices else ""},
                            {"name": "after_erasure", "label": _ERASED, "kind": "boolean", "value": False},
                            {"name": "without_erasure_record", "label": _NO_RECORD, "kind": "boolean",
                             "value": False}],
                    blocked="" if choices else "No days recorded yet.")


def publish_prepare(request, selection, arguments):
    overview = _administrator_overview(request)
    day = arguments["day"]
    row = next((row for row in overview["days"] if row["day"] == day), None)
    if row is None:
        raise HTTPException(422, "Choose a day from the list.")
    before = "Published" if row["has_checkpoint"] else "None yet"
    if not arguments["after_erasure"]:
        if arguments["without_erasure_record"]:
            raise HTTPException(422, f"Tick \u201c{_ERASED}\u201d as well. Nothing was published.")
        return Preview(f"Publish the checkpoint of {day}? It is kept in a separate folder so a later change "
                       "to that day can be proven.",
                       changes=[{"field": f"Checkpoint for {day}", "before": before, "after": "Published"}])
    native.run_checked(native._latest_digest_for_day, day)   # the page's refusal for a day with none
    changes = [{"field": f"Checkpoint for {day}", "before": before,
                "after": "Replaced; the earlier checkpoint stays on record"}]
    if not arguments["without_erasure_record"]:
        return Preview(f"Start a new checkpoint for {day} because its log changed after a person's data was "
                       "erased? The earlier checkpoint stays on record.", changes=changes)
    changes.append({"field": "Erasure record for this change", "before": "Needed",
                    "after": "Not needed; the activity log records this replacement first"})
    return Preview(f"Replace the checkpoint for {day} without an erasure record? Do this only for a day that "
                   "was already erased. A later check with an older receipt will report it.", changes=changes)


def publish_execute(request, selection, arguments, review, operation_id):
    done = native.run_checked(native.publish_change, request, native.PublishIn(**arguments))
    return Outcome("confirmed", f"Published checkpoint {done['sequence']} for {done['day']}. Keep its receipt "
                   "somewhere else, such as your email, so rolling it back can be caught.", done)


class RetireInput(StrictInput):
    checkpoint: int = Field(ge=1, le=10**9)
    confirmed: bool = False


def _retirable(overview: dict) -> list[dict]:
    return [row for row in overview["checkpoints"] if row["can_retire"]]


def retire_snapshot(request, selection):
    overview = _administrator_overview(request)
    choices = [{"value": row["sequence"], "label": row["day"] + " \u2014 " + row["kind"]}
               for row in _retirable(overview)]
    return Snapshot(digest(overview), "Checkpoints of days your record-keeping policy deleted",
                    "Retire the checkpoint of a day your record-keeping policy deleted, so later checks do not flag it.",
                    fields=[{"name": "checkpoint", "label": "Checkpoint to retire", "kind": "select",
                             "choices": choices, "value": choices[0]["value"] if choices else None},
                            {"name": "confirmed", "kind": "boolean", "value": False,
                             "label": "Retire this checkpoint. This cannot be undone."}],
                    blocked=overview["problem"] or ("" if choices else
                                                    "Only a day your record-keeping policy deleted can be retired. "
                                                    "No such day has a checkpoint."))


def retire_prepare(request, selection, arguments):
    row = next((row for row in _retirable(_administrator_overview(request))
                if row["sequence"] == arguments["checkpoint"]), None)
    if row is None:
        raise HTTPException(409, "That checkpoint changed since the page loaded. Refresh the list.")
    if arguments["confirmed"] is not True:
        raise HTTPException(409, "Confirm the retirement to continue. Nothing was changed.")
    return Preview(f"Retire the checkpoint of {row['day']}? That day was deleted by your record-keeping policy. "
                   "Retiring records that on purpose so later checks do not flag it. This cannot be undone.",
                   changes=[{"field": f"Checkpoint for {row['day']}", "before": row["kind"],
                             "after": "Retired (day deleted by policy)"}])


def retire_execute(request, selection, arguments, review, operation_id):
    done = native.run_checked(native.retire_change, request,
                              native.RetireIn(sequence=arguments["checkpoint"], confirm=arguments["confirmed"]))
    return Outcome("confirmed", f"The checkpoint of {done['day']} was retired.", done)


def entries():
    common = {"family": "reviews", "direct_ui": "/audit", "pages": ("/audit",)}
    return (
        Adapter("audit.checkpoints.read", "Read retained activity checkpoints", input_model=EmptyInput,
                snapshot=status_snapshot, prepare=status_prepare, **common),
        Adapter("audit.checkpoints.check", "Check the current activity checkpoint chain", input_model=EmptyInput,
                snapshot=check_snapshot, prepare=check_prepare, **common),
        Adapter("audit.checkpoints.receipt", "Download a saved activity checkpoint receipt", input_model=ReceiptInput,
                snapshot=receipt_snapshot, prepare=receipt_prepare, **common),
        Adapter("audit.checkpoints.check_receipt", "Check the checkpoints against a receipt you kept",
                input_model=KeptReceipt, snapshot=receipt_check_snapshot, prepare=receipt_check_prepare,
                aliases=("check my kept receipt", "were the checkpoints rolled back",
                         "was a checkpoint replaced after my receipt"), **common),
        Adapter("audit.checkpoints.publish", "Publish an activity checkpoint", input_model=PublishInput,
                snapshot=publish_snapshot, prepare=publish_prepare, execute=publish_execute,
                aliases=("publish a checkpoint", "publish a checkpoint after an erasure",
                         "replace a checkpoint without an erasure record"), **common),
        Adapter("audit.checkpoints.retire", "Retire the checkpoint of a deleted day", input_model=RetireInput,
                snapshot=retire_snapshot, prepare=retire_prepare, execute=retire_execute,
                aliases=("retire a checkpoint",), **common),
    )
