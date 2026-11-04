"""Typed Copilot attestation uses the same officer/package/receipt service as Privacy."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from fastapi import HTTPException
from maverick import dsar_export_handoff as service
from maverick.governed_operations import digest
from pydantic import Field

from . import dsar_export_handoff_api as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class Handoff(StrictInput):
    channel: Literal["secure_portal", "encrypted_email", "approved_transfer", "in_person"]
    handed_at: str = Field(min_length=10, max_length=50)
    reference: str = Field(min_length=3, max_length=200)
    reviewed: bool = Field(strict=True)
    identity_checked: bool = Field(strict=True)
    sent: bool = Field(strict=True)


def _id(selection):
    if (set(selection) != {"kind", "id"} or selection.get("kind") != "dsar"
            or not isinstance(selection.get("id"), str)
            or not re.fullmatch(r"DSAR-[0-9a-f]{10}", selection["id"])):
        raise HTTPException(422, "Open the exact privacy request first.")
    return selection["id"]


def snapshot(request, selection):
    value = native.state(request, _id(selection))
    fields = [
        {"name": "channel", "label": "Secure channel you used", "kind": "select",
         "choices": [{"value": key, "label": label} for key, label in service.CHANNELS.items()]},
        {"name": "handed_at", "label": "When you handed off this package", "kind": "datetime-local", "required": True},
        {"name": "reference", "label": "Evidence reference (no personal data or access links)", "kind": "text", "required": True},
        {"name": "reviewed", "label": "I reviewed this exact collected package and its disclosure limits", "kind": "boolean", "required": True},
        {"name": "identity_checked", "label": "I checked the recipient's identity and destination", "kind": "boolean", "required": True},
        {"name": "sent", "label": "I already handed off this package through the chosen channel", "kind": "boolean", "required": True},
    ]
    return Snapshot(digest(value), "The verified collected package and current privacy request",
                    service.SCOPE, {"recorded_statements": [_public(row) for row in value["receipts"]],
                                    "package_available": value["package_available"], "scope": service.SCOPE}, fields,
                    blocked="This request is closed; review its historical statements on the request page."
                    if not value["package_available"] else "")


def prepare(request, selection, arguments):
    if not all(arguments[key] is True for key in ("reviewed", "identity_checked", "sent")):
        raise HTTPException(422, "Confirm the package review, recipient checks and completed secure handoff before continuing.")
    value = native.state(request, _id(selection))
    return Preview("Record your statement about a completed handoff of this exact collected package. "
                   "Nothing will be sent and requester receipt will remain unverified.",
                   changes=[{"label": "Secure channel", "after": service.CHANNELS[arguments["channel"]]},
                            {"label": "When you handed it off", "after": arguments["handed_at"]}],
                   native={"binding": value["binding"], "artifact_sha256": value["artifact_sha256"]})


def _public(receipt):
    from .identity_format import humanize_principal
    return {"secure_channel": service.CHANNELS[receipt["channel"]],
            "handed_off_at": receipt["handed_at"], "evidence_reference": receipt["reference"],
            "recorded_by": str(humanize_principal(receipt["actor"])),
            "basis": "Operator-recorded statement; requester receipt remains unverified."}


def execute(request, selection, arguments, review, operation):
    value = native.record(request, _id(selection), native.HandoffIn(binding=review["binding"], **arguments))
    return Outcome("replayed" if value["replayed"] else "confirmed", value["message"],
                   {"receipt": _public(value["receipt"])})


def recover(request, selection, arguments, review, operation):
    actor = native.authority(request)
    value = native.state(request, _id(selection))
    for receipt in value["receipts"]:
        if (receipt["actor"] == actor and receipt["channel"] == arguments["channel"]
                and receipt["artifact_sha256"] == review["artifact_sha256"]
                and receipt["reference"] == arguments["reference"].strip()
                and datetime.fromisoformat(receipt["handed_at"]) ==
                datetime.fromisoformat(arguments["handed_at"].replace("Z", "+00:00"))):
            if not value["package_available"]:
                if value["audit_pending"]:
                    native.confirm_saved(request, _id(selection), receipt["id"])
                return Outcome("replayed", "This statement was already recorded before the request closed. "
                               "Requester receipt remains unverified.", {"receipt": _public(receipt)})
            return execute(request, selection, arguments, review, operation)
    return None


def entries():
    return (Adapter("artifacts.privacy_package_handoff", "Record a privacy package handoff", "artifacts", "/privacy",
                    ("/privacy/dsar/*",), Handoff, snapshot, prepare, execute, recover,
                    aliases=("record this privacy package handoff", "record that i shared this privacy package")),)
