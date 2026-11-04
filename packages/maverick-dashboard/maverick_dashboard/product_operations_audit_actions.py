"""Reviewed audit encryption and custody use the page's native request service."""
from __future__ import annotations

from datetime import datetime, timezone
from functools import partial

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import audit_action_service as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ResultInput(StrictInput):
    review: str = Field(pattern=r"^AAR-[a-f0-9]{32}$")


class SeparateCopyInput(StrictInput):
    acknowledge_prior: bool


def snapshot(request, selection, *, action):
    if selection:
        raise HTTPException(422, "Choose an activity-log action in this review.")
    if action == "result":
        state = native.inventory(request)
        choices = [{"value": row["review"], "label": ("Encryption" if row["action"] == "seal" else "Storage copy") +
                    " · " + datetime.fromtimestamp(row["recorded_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC") + " · " +
                    {"prepared": "Awaiting review", "reserved": "Original result uncertain", "unknown": "Original result uncertain",
                     "confirmed": "Completed", "failed": "Completed with problems", "cancelled": "Cancelled"}[row["state"]]} for row in state["reviews"]]
        return Snapshot(digest(state), "Your retained activity-log maintenance requests", "Read one original saved result. Reading never encrypts or copies again.",
            fields=[{"name": "review", "label": "Saved maintenance review", "kind": "select", "required": True, "choices": choices}],
            blocked="No saved maintenance review is available." if not choices else "")
    state = native.current(request, "copy" if action == "reconcile" else action, reconcile=action == "reconcile")
    eligible = sum(row["selected"] for row in state["rows"])
    return Snapshot(state["revision"], "Current closed activity days and effective storage settings",
        "Review exact closed days before encryption or a storage copy. Today's activity is excluded.",
        {"closed_days": len(state["rows"]), "eligible_days": eligible, "destination": state["destination_display"]},
        fields=[{"name": "acknowledge_prior", "label": "I understand an earlier copy may already exist and remains unknown. A separate copy may create another retained version.",
                 "kind": "boolean", "value": False}] if action == "reconcile" else [],
        blocked="No eligible closed days are available. Check the activity log for records or encryption prerequisites." if not eligible else "")


def prepare(request, selection, arguments, *, action):
    if action == "result":
        value = native.receipt(request, arguments["review"])
        return Preview(value["message"], native=_display(value))
    snapshot(request, selection, action=action)
    if action == "reconcile" and arguments["acknowledge_prior"] is not True:
        raise HTTPException(409, "Acknowledge the earlier uncertain effect before reviewing a separate intentional copy.")
    value = native.prepare(request, "copy" if action == "reconcile" else action, reconcile=action == "reconcile")
    summary = ("Encrypt these exact closed days in place. They remain readable in Lightwork and their signatures remain checkable."
               if action == "seal" else "Check saved copies and copy these exact closed record versions only when needed, to the reviewed destination and retention date. A transport problem can leave the result uncertain; the original request will not repeat.")
    changes = [{"label": "Closed day " + row["day"], "after": row["status"] + " · " + str(row["bytes"]) + " bytes" +
                (" · existing recorded retention through " + row["existing_retention"] + "; current proof checked only at execution" if row.get("existing_retention") else "")} for row in value["rows"]]
    if action in {"copy", "reconcile"}:
        changes += [{"label": "Destination", "after": value["destination"]["location"]},
                    {"label": "Protection", "after": value["destination"]["mode"] + ": " + value["destination"]["protection"]},
                    {"label": "Retention through", "after": value["retain_until"]}]
    if action == "reconcile":
        summary = "Authorize a NEW intentional copy after this independent review of current sources, destination and retention. The earlier result remains unknown and a retained copy may already exist. This can create another version. No original effect is repeated or relabeled by reading it."
    return Preview(summary, changes, {"review": value["review"], "acknowledge_uncertain": action == "reconcile"})


def outcome(value, *, replay=False):
    status = "replayed" if replay and value["state"] == "confirmed" else "confirmed" if value["state"] == "confirmed" else "unconfirmed"
    return Outcome(status, value["message"], _display(value))


def _display(value):
    return {"source": value["source"], "recorded": datetime.fromtimestamp(value["recorded_at"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "days_changed": value["days"], "existing_copies_checked": value["already_present"],
        "uncertain_days": value["unknown_days"], "days_with_problems": value["failed_days"],
        "protection": value["destination"], "new_copy_retention_through": value["retain_until"],
        "meaning": "Earlier uncertain copies remain unknown." if value["reconcile"] else "This is the saved original request result.",
        "open": {"label": "Read saved maintenance results", "href": "/audit#maintenance-results"}}


def check_snapshot(request, selection):
    native.authority(request)
    binding, display = native._destination()
    return Snapshot(digest([binding, native.context_for(request)]), "Current copy destination and your audit permission",
                    "Check current closed bytes and retained destination proof. Empty results do not test storage.", {"destination": display})


def check_prepare(request, selection, arguments):
    value = native.check_copies(request)
    return Preview(value["message"], native={"closed_days_checked": value["days"], "copies_with_current_proof": value["copied"],
        "days_not_verified": value["not_copied"], "uncertain_earlier_attempts": [{"day": row["day"], "attempted": row["attempted_at"],
            "meaning": row["meaning"]} for row in value["native_unknown"]],
        "automatic_copy_enabled": value["automatic_copy_enabled"], "protection": value["destination"]})


def execute(request, _selection, _arguments, prepared, operation, *, action):
    return outcome(native.execute(request, "copy" if action == "reconcile" else action, prepared["review"], operation,
                                  acknowledge_uncertain=prepared.get("acknowledge_uncertain", False)))


def recover(request, _selection, _arguments, prepared, operation):
    value = native.receipt(request, prepared["review"], operation)
    return outcome(value, replay=True) if value["state"] != "prepared" else None


def entries():
    common = {"family": "reviews", "direct_ui": "/audit", "pages": ("/audit",)}
    return tuple(Adapter("audit.maintenance_" + action, label, input_model=EmptyInput,
        snapshot=partial(snapshot, action=action), prepare=partial(prepare, action=action),
        execute=partial(execute, action=action), recover=recover, read_recovery=recover, aliases=aliases, **common)
        for action, label, aliases in (
            ("seal", "Encrypt older activity days", ("encrypt activity log",)),
            ("copy", "Copy older activity days to reviewed storage", ("copy activity log", "write once copy")))) + (
        Adapter("audit.maintenance_result", "Read an original audit maintenance result", input_model=ResultInput,
                snapshot=partial(snapshot, action="result"), prepare=partial(prepare, action="result"), **common),
        Adapter("audit.maintenance_reconcile", "Review a separate copy after an uncertain result", input_model=SeparateCopyInput,
                snapshot=partial(snapshot, action="reconcile"), prepare=partial(prepare, action="reconcile"),
                execute=partial(execute, action="reconcile"), recover=recover, read_recovery=recover, **common),
        Adapter("audit.copies_check", "Check current activity copies and their protection", input_model=EmptyInput,
                snapshot=check_snapshot, prepare=check_prepare, **common))
