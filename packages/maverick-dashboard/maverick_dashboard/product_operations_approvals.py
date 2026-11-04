"""Ordinary selected approval forms backed by the native queue decision path."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.approval_cards import digest
from maverick.channel_approvals import card_content
from pydantic import Field

from . import approval_queue_operations as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class ApproveInput(StrictInput):
    acknowledged: bool
    confirmation: str = Field(default="", max_length=20)


class RejectInput(StrictInput):
    reason: str = Field(default="", max_length=2000)


def snapshot(request, selection, *, status=None):
    if not selection:
        from . import auth

        if auth.api_key_permissions(request) is not None:
            auth.require_api_key_scope(request, "approvals:decide")
        else:
            auth.require_permission(request, "operate")
        return Snapshot(digest({"selected": False}), "The current Approvals queue",
                        "Choose Review with Copilot on the request you want to read or decide.",
                        {"Next step": {"label": "Open Approvals", "href": "/approvals"}},
                        blocked="Choose a request's Review with Copilot button first.")
    approval_id = native.selected_id(selection)
    world, row = native.owned(request, approval_id, status=status)
    who, card = native.actor(request), card_content(row)
    details = native.public(world, row, who)
    blocked = ""
    fields = []
    if status:
        if row.status != "pending":
            blocked = "This request has been decided. Read its original decision."
        elif world.get_approval_audit_event(world.approval_audit_event_id(approval_id, status, who)) is not None:
            blocked = "Your decision is already recorded. Read its original decision."
        elif status == "approved" and card["status"] != "current":
            blocked = "This request needs a fresh verified review before it can be approved. You may still reject it."
        elif status == "approved" and row.approvals_required > 1 and row.requested_by == who:
            from maverick.safety.dual_control import allow_self_approval

            if not allow_self_approval():
                blocked = "You asked for this, so other people must approve it."
        if status == "approved":
            fields = [{"name": "acknowledged", "label": "I have read the full request and what this action will do", "kind": "boolean", "required": True}]
            if card["needs_typed_confirmation"]:
                fields.append({"name": "confirmation", "label": "This is a critical action. Type APPROVE to confirm", "kind": "text", "required": True, "max_length": 20})
        else:
            fields = [{"name": "reason", "label": "Why are you rejecting it? (optional)", "kind": "textarea", "max_length": 2000}]
    verb = "Approve" if status == "approved" else "Reject" if status else "Read"
    return Snapshot(native.revision(world, row, who), "Current exact approval card, access and original decision receipts",
                    f"{verb} this selected request. Authorization does not prove the action ran.", details, fields, blocked)


def read_prepare(request, selection, _arguments):
    current = snapshot(request, selection)
    return Preview(current.summary, native=native.private_review(request, native.selected_id(selection)))


def prepare(request, selection, arguments, *, status):
    approval_id = native.selected_id(selection)
    review = native.reviewed(request, approval_id, status)
    if status == "approved":
        if arguments["acknowledged"] is not True:
            raise HTTPException(422, "Read the full request and select its acknowledgement before approving.")
        world, row = native.owned(request, approval_id, status=status)
        if card_content(row)["needs_typed_confirmation"] and arguments["confirmation"].strip().lower() != "approve":
            raise HTTPException(422, "Type APPROVE to confirm this critical action.")
    snapshot(request, selection, status=status)
    details = native.private_review(request, approval_id, status=status)
    changes = [{"field": key, "after": value} for key, value in details.items() if key not in {"Your original decisions", "Next step"}]
    if status == "denied" and arguments["reason"]:
        changes.append({"field": "Rejection reason", "after": native.safe(arguments["reason"])})
    return Preview("Record your approval vote for this exact request. Quorum and audit delivery are required; execution remains separate."
                   if status == "approved" else "Reject this exact request. The decision is recorded through the same audited queue as the Approvals page.",
                   changes, review)


def outcome(value, *, replayed=False):
    audit_delivered = value["Audit delivery"] == "Delivered"
    decision = value["Current request decision"]
    message = ("Read back your original recorded decision without another vote or audit write. " if replayed else "Your decision was recorded. ")
    message += ("Audit delivery is still pending; the vote is not in effect. Do not submit it again automatically."
                if not audit_delivered else "More approvers are needed before authorization is complete."
                if decision == "Pending" else "This is an authorization decision, not evidence that the action ran.")
    return Outcome("replayed" if replayed and audit_delivered else "confirmed" if audit_delivered else "unconfirmed", message, value)


def execute(request, selection, arguments, review, _operation_id, *, status, effect_guard=None):
    from . import api

    approval_id = native.selected_id(selection)
    response = api._decide_approval(request, approval_id, arguments, status,
                                    binding=review["binding"], reviewed=review, **({"effect_guard": effect_guard} if effect_guard is not None else {}))
    value = native.recover(request, approval_id, status, review)
    if value is None or response.headers.get("X-Lightwork-Decision-Id") != review["event_id"]:
        raise HTTPException(503, "The original decision result could not be verified. Read its current status before another attempt.")
    return outcome(value)


def recover(request, selection, _arguments, review, _operation_id, *, status):
    value = native.recover(request, native.selected_id(selection), status, review)
    return outcome(value, replayed=True) if value is not None else None


def entries():
    from functools import partial

    pages = ("/approvals", "/oversight")
    return (Adapter("reviews.approval_read", "Read the selected approval", "reviews", "/approvals", pages,
                    EmptyInput, snapshot, read_prepare, aliases=("read this approval", "check this decision")),
            Adapter("reviews.approval_approve", "Approve the selected request", "reviews", "/approvals", pages,
                    ApproveInput, partial(snapshot, status="approved"), partial(prepare, status="approved"),
                    partial(execute, status="approved"), partial(recover, status="approved"), aliases=("approve this request",),
                    read_recovery=partial(recover, status="approved")),
            Adapter("reviews.approval_reject", "Reject the selected request", "reviews", "/approvals", pages,
                    RejectInput, partial(snapshot, status="denied"), partial(prepare, status="denied"),
                    partial(execute, status="denied"), partial(recover, status="denied"), aliases=("reject this request", "deny this request"),
                    read_recovery=partial(recover, status="denied")))
