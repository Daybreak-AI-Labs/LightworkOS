"""Reviewed task-transfer operations backed by the native handoff receipts."""
from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput
from .task_handoffs_api import call, service


class OfferInput(StrictInput):
    title: str = Field(min_length=1, max_length=160)
    instruction: str = Field(min_length=1, max_length=12000)
    commitments: str = Field(min_length=1, max_length=4000)
    max_dollars: float = Field(gt=0, le=1000000, allow_inf_nan=False)


class RespondInput(StrictInput):
    action: Literal["accept", "decline", "withdraw"]


def _id(selection, kind):
    identifier = selection.get("id")
    if selection.get("kind") != kind or not isinstance(identifier, str):
        raise HTTPException(404, "Select a " + kind + " in Task handoffs first.")
    return identifier


def offer_snapshot(request, selection):
    auth.require_permission(request, "operate")
    source = service(request)
    from maverick.task_handoffs import closure
    bundle = call(lambda: source.bundles.get(_id(selection, "bundle")))
    if bundle["owner"] != source.actor:
        raise HTTPException(404, "Only the source owner may offer a handoff.")
    closed = closure(source.world, bundle["payload"]["source"]["goal_id"])
    return Snapshot(digest([bundle["revision"], bundle["stale"], bundle["status"], closed]),
                    "Current selected bundle and named recipient",
                    "Offer an unstarted continuation to the selected recipient; explicit acceptance is required.",
                    {"recipient": bundle["payload"]["recipient"], "selected_items": [{k: v for k, v in item.items() if k != "content_base64"} for item in bundle["payload"]["items"]]},
                    [{"name": "title", "label": "Continuation title", "kind": "text", "required": True},
                     {"name": "instruction", "label": "Next work", "kind": "textarea", "required": True},
                     {"name": "commitments", "label": "Pending commitments and costs", "kind": "textarea", "required": True},
                     {"name": "max_dollars", "label": "New task ceiling (USD)", "kind": "number", "required": True, "min": 0.01, "max": 1000000, "step": 0.01}],
                    "This source was handed off or its selected evidence is no longer current." if closed or bundle["stale"] or bundle["status"] != "shared" else "")


def offer_preview(request, selection, args):
    source = service(request)
    prepared = call(lambda: source.prepare(_id(selection, "bundle"), **args))
    return Preview("Offer only this selected evidence and continuation. No execution begins; the recipient must accept responsibility.",
                   [{"label": "Named recipient", "after": prepared["recipient"]},
                    {"label": "Next work", "after": prepared["instruction"]},
                    {"label": "Pending commitments", "after": prepared["commitments"]},
                    {"label": "Reviewed new-task ceiling (USD)", "after": prepared["max_dollars"]},
                    {"label": "Selected evidence", "after": prepared["items"]},
                    {"label": "Source recorded cost and open questions", "after": {"cost": prepared["source_cost_dollars"], "questions": prepared["open_questions"]}},
                    {"label": "Consequences", "after": prepared["consequences"]}],
                   {"expected_review": prepared["review_version"]})


def offer_execute(request, selection, args, native, operation_id):
    auth.require_permission(request, "operate")
    source = service(request)
    record = call(lambda: source.create(_id(selection, "bundle"), **args, **native, operation_id=operation_id))
    return Outcome("confirmed", "The named handoff offer was saved. Responsibility remains with its sender until explicit acceptance.",
                   {"handoff_id": record["id"], "state": record["state"], "open": {"label": "Review handoff", "href": "/task-handoffs"}})


def offer_recover(request, selection, args, native, operation_id):
    source = service(request)
    if source.store.get("HOF-" + digest([source.actor, operation_id])[:32]) is None:
        return None
    return replace(offer_execute(request, selection, args, native, operation_id), status="replayed")


def response_snapshot(request, selection):
    auth.require_permission(request, "operate")
    source = service(request)
    identifier = _id(selection, "handoff")
    saved = source.store.get(identifier)
    if saved and saved["state"] == "declined" and source.actor == saved["recipient"]:
        source.bundles._allowed(source.actor, saved["domain"], "operate")
        return Snapshot(digest([saved["revision"], "declined"]), "Saved response receipt", "Handoff declined",
                        {"state": "declined"}, blocked="Future offer content access ended.")
    row = call(lambda: source.get(identifier))
    choices = []
    if row["can_accept"]:
        choices += [{"value": "accept", "label": "Accept responsibility; create an unstarted continuation"}, {"value": "decline", "label": "Decline this offer"}]
    if row["can_withdraw"]:
        choices.append({"value": "withdraw", "label": "Withdraw the offer before acceptance"})
    return Snapshot(digest([row["revision"], row["state"], row["expired"], choices]), "Current named offer and native acceptance receipt",
                    row["preview"]["title"], {"state": row["state"], "preview": row["preview"]},
                    [{"name": "action", "label": "Your response", "kind": "select", "required": True, "choices": choices}],
                    "This handoff is no longer awaiting your response." if not choices else "")


def response_preview(request, selection, args):
    source = service(request)
    row = call(lambda: source.get(_id(selection, "handoff")))
    if not (row["can_accept"] if args["action"] in {"accept", "decline"} else row["can_withdraw"]):
        raise HTTPException(409, "This response is unavailable. Refresh the handoff.")
    return Preview("Accepting closes the sender's original conversation to further work and creates your separate unstarted task. Withdrawal ends future offer access, without recalling copies.",
                   [{"label": "Your decision", "after": args["action"]}, {"label": "Exact offer", "after": row["preview"]}],
                   {"expected_revision": row["revision"]})


def response_execute(request, selection, args, native, operation_id):
    auth.require_permission(request, "operate")
    source = service(request)
    row = call(lambda: source.respond(_id(selection, "handoff"), **args, **native, operation_id=operation_id))
    details = {"state": row["state"], "handoff_id": row["id"]}
    successor = (row.get("acceptance") or {}).get("successor_id")
    if successor:
        details["open"] = {"label": "Review and explicitly start your continuation", "href": "/chat/goal/" + str(successor)}
    return Outcome("confirmed", "Your handoff response was saved. No paid work started automatically.", details)


def response_recover(request, selection, args, native, operation_id):
    source = service(request)
    row = source.store.get(_id(selection, "handoff"))
    if not row or source.actor not in {row["owner"], row["recipient"]}:
        return None
    accepted = source._accepted(row)
    if operation_id not in row["operations"] and not (accepted and accepted["operation_id"] == operation_id):
        return None
    return replace(response_execute(request, selection, args, native, operation_id), status="replayed")


def entries():
    return (
        Adapter("tasks.offer_handoff", "Offer a selected-evidence task handoff", "tasks", "/task-handoffs",
                ("/task-handoffs", "/deliverable-bundles"), OfferInput,
                offer_snapshot, offer_preview, offer_execute, offer_recover),
        Adapter("tasks.respond_handoff", "Accept, decline or withdraw a task handoff", "tasks", "/task-handoffs",
                ("/task-handoffs",), RespondInput,
                response_snapshot, response_preview, response_execute, response_recover),
    )
