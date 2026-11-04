"""Typed Copilot controls for the same bounded promise-review service as the UI."""
from __future__ import annotations

import re
from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from maverick.privacy_ops import RecordConflict
from pydantic import Field

from . import commitment_viability_api as native
from . import commitment_viability_store as reviews
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_ID = re.compile(r"CMV-[a-f0-9]{48}\Z")
PAGE = "/commitment-reviews"


class ChoiceInput(StrictInput):
    pass


class SharedWorkInput(StrictInput):
    proposal_id: str = Field(min_length=1, max_length=120)


class ObservationInput(StrictInput):
    running_order: Literal["order-a", "order-b"]
    blocked_order: Literal["order-a", "order-b"]
    started_at: str = Field(min_length=20, max_length=40)
    ended_at: str = Field(min_length=20, max_length=40)
    observed_at: str = Field(min_length=20, max_length=40)
    review_by: str = Field(min_length=20, max_length=40)
    basis: str = Field(min_length=10, max_length=2000)


class CreateInput(StrictInput):
    title: str = Field(min_length=1, max_length=200)
    order_a_name: str = Field(min_length=1, max_length=160)
    order_a_due_at: str = Field(min_length=20, max_length=40)
    order_a_material_units: int = Field(ge=1, le=1_000_000)
    order_a_uses_capacity: bool
    order_b_name: str = Field(min_length=1, max_length=160)
    order_b_due_at: str = Field(min_length=20, max_length=40)
    order_b_material_units: int = Field(ge=1, le=1_000_000)
    order_b_uses_capacity: bool
    capacity_name: str = Field(min_length=1, max_length=160)
    capacity_units: int = Field(ge=1, le=1_000_000)
    material_name: str = Field(min_length=1, max_length=160)
    stock_units: int = Field(ge=0, le=1_000_000)
    stock_certainty: Literal["confirmed", "unknown", "unavailable"]
    option_name: str = Field(min_length=1, max_length=160)
    option_kind: Literal["capacity", "material"]
    option_units: int = Field(ge=1, le=1_000_000)
    option_ready_at: str = Field(min_length=20, max_length=40)
    option_expires_at: str = Field(min_length=20, max_length=40)
    option_lead_hours: int = Field(ge=0, le=277_777)
    option_cost_note: str = Field(default="", max_length=240)
    basis: str = Field(min_length=10, max_length=2000)
    review_by: str = Field(min_length=20, max_length=40)


def _selected(request, selection, *, owner=False, allow_archived=False,
              allow_retiring=False):
    context = native._context(request)
    if (not isinstance(selection, dict) or set(selection) != {"kind", "id"}
            or selection["kind"] != "commitment_review"
            or not isinstance(selection["id"], str) or not _ID.fullmatch(selection["id"])):
        raise HTTPException(404, "Open a saved promise review first.")
    try:
        if allow_archived:
            row, archive = reviews.read(selection["id"], context)
        else:
            row, archive = reviews.get(selection["id"], context), None
    except LookupError as exc:
        if not allow_archived:
            try:
                reviews.archived_get(selection["id"], context)
            except LookupError:
                pass
            else:
                raise HTTPException(409, "This review is archived and read-only.") from exc
        raise HTTPException(404, "This review is no longer available in your account and workspace.") from exc
    if archive is not None and owner:
        raise HTTPException(409, "This review is archived and read-only.")
    if owner and row["owner"] != native._actor(request):
        raise HTTPException(403, "Only the person who started this review can confirm its choices.")
    if owner and row.get("retirement") and not allow_retiring:
        raise HTTPException(409, "This review is being archived. Its decisions are closed.")
    return context, row, reviews.project(row, archive=archive)


def _state_revision(context, row, projection):
    result = projection["assessment"]
    return digest([context, row["id"], row["revision"], result["status"],
                   result["stale_source_ids"], result["latest_safe_bundle_decision_at"],
                   projection["proposals"], projection["resource_gaps"],
                   projection["resource_gap_blocked_by_order_change"]])


def _checked(call):
    try:
        return call()
    except reviews.CommitmentAuditPending as exc:
        raise HTTPException(503, str(exc)) from exc
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, "This review is unavailable in your account and workspace.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def assessment_snapshot(request, selection):
    context, row, projection = _selected(request, selection, allow_archived=True)
    result = projection["assessment"]
    return Snapshot(_state_revision(context, row, projection),
                    "Current reported orders, resource gaps and source review windows",
                    "Assess both accepted orders and any reported stock or capacity shortfall. No stock, supplier choice, or external reservation is independently verified.",
                    {"title": row["title"], "assessment": result, "labels": row["labels"],
                     "resource_gaps": projection["resource_gaps"],
                     "resource_gap_blocked_by_order_change": projection["resource_gap_blocked_by_order_change"],
                     "sources": projection["sources"], "proposals": projection["proposals"],
                     "archived": projection["archived"], "retired_at": projection["retired_at"],
                     "source_quality": "operator_reported", "external_reservation_verified": False,
                     "href": PAGE})


def assessment_prepare(request, selection, _args):
    state = assessment_snapshot(request, selection)
    return Preview(state.summary, native=state.details)


def choice_snapshot(request, selection):
    context, row, projection = _selected(request, selection, owner=True)
    option = projection["model"]["options"][0]
    plans = [plan for component in projection["assessment"]["components"]
             for plan in component["plans"]
             if option["id"] in plan["option_ids"]
             and plan["conditional_status"] == "feasible"
             and projection["assessment"]["evaluated_at"] < plan["latest_safe_bundle_decision_at"]]
    blocked = ("The activity receipt is still pending. Refresh this review before deciding." if row.get("_audit_pending") else
               "This choice is already confirmed in this review." if option["owner_confirmation"] else
               "No current actionable path uses this choice. Refresh the reported figures." if not plans else "")
    details = {"title": row["title"], "choice": row["labels"][option["id"]],
               "kind": option["kind"], "units": option["units"],
               "expires_at": option["expires_at"],
               "latest_safe_decision_before": plans[0]["latest_safe_bundle_decision_at"] if plans else None,
               "source_quality": "operator_reported", "external_reservation_verified": False}
    return Snapshot(_state_revision(context, row, projection),
                    "Current conditional choice and owner authority",
                    "Confirm intent to consider this choice in the model; this does not order or reserve anything.",
                    details, blocked=blocked)


def choice_prepare(request, selection, _args):
    state = choice_snapshot(request, selection)
    if state.blocked:
        raise HTTPException(409, state.blocked)
    _, row, _ = _selected(request, selection, owner=True)
    return Preview(state.summary, [{"label": "Choice", "after": state.details},
                                   {"label": "External effect", "after": "None"}],
                   {"expected_revision": row["revision"], "option_id": "conditional-option"})


def _receipt(request, selection, operation_id):
    _, row, _ = _selected(request, selection, owner=True)
    if operation_id in row.get("operations", {}):
        return Outcome("unconfirmed" if row.get("_audit_pending") else "replayed",
                       "The saved decision is waiting for its activity receipt. Refresh this review." if row.get("_audit_pending") else
                       "This owner decision was already recorded. No external action was taken.",
                       {"id": row["id"], "revision": row["revision"], "href": PAGE})
    return None


def choice_execute(request, selection, _args, prepared, operation_id):
    context, row, _ = _selected(request, selection, owner=True)
    body = {"expected_revision": prepared["expected_revision"], "operation_id": operation_id,
            "kind": "option", "proposal_id": "", "option_id": prepared["option_id"]}
    result = _checked(lambda: reviews.confirm(row["id"], context, native._actor(request), body))
    return Outcome("unconfirmed" if result.get("_audit_pending") else "confirmed",
                   "The choice was saved, but its activity receipt is still pending. Refresh this review." if result.get("_audit_pending") else
                   "The owner’s choice was recorded in this model. Nothing was ordered or reserved.",
                   {"id": row["id"], "revision": result["revision"], "href": PAGE})


def choice_recover(request, selection, _args, _prepared, operation_id):
    return _receipt(request, selection, operation_id)


def shared_snapshot(request, selection):
    context, row, projection = _selected(request, selection, owner=True)
    proposals = projection["proposals"]
    return Snapshot(_state_revision(context, row, projection),
                    "Current observed contention and owner authority",
                    "Review a reported overlap before adding a shared work dependency to this model.",
                    {"title": row["title"], "proposals": proposals,
                     "source_quality": "operator_reported", "external_effect_verified": False},
                    [{"name": "proposal_id", "label": "Suggested shared work", "kind": "select",
                      "required": True, "choices": [{"value": p["id"], "label":
                          row["labels"].get(p["left_id"],p["left_id"]) + " and " +
                          row["labels"].get(p["right_id"],p["right_id"])} for p in proposals]}],
                    "The activity receipt is still pending. Refresh this review before deciding." if row.get("_audit_pending") else
                    "No current shared-work suggestion is available." if not proposals else "")


def shared_prepare(request, selection, args):
    state = shared_snapshot(request, selection)
    proposal = next((item for item in state.details["proposals"] if item["id"] == args["proposal_id"]), None)
    if proposal is None:
        raise HTTPException(409, "This suggestion changed. Refresh and review the current observation.")
    _, row, _ = _selected(request, selection, owner=True)
    return Preview("Add the observed shared work to this model and reassess affected orders. No customer order or external system changes.",
                   [{"label": "Reported shared work", "after": proposal}],
                   {"expected_revision": row["revision"], "proposal_id": proposal["id"]})


def shared_execute(request, selection, args, prepared, operation_id):
    context, row, _ = _selected(request, selection, owner=True)
    if args["proposal_id"] != prepared["proposal_id"]:
        raise HTTPException(409, "The reviewed suggestion changed. Prepare a new decision.")
    body = {"expected_revision": prepared["expected_revision"], "operation_id": operation_id,
            "kind": "dependency", "proposal_id": prepared["proposal_id"],
            "option_id": "conditional-option"}
    result = _checked(lambda: reviews.confirm(row["id"], context, native._actor(request), body))
    return Outcome("unconfirmed" if result.get("_audit_pending") else "confirmed",
                   "The shared work was saved, but its activity receipt is still pending. Refresh this review." if result.get("_audit_pending") else
                   "The shared work was added to the model and affected orders can be reassessed.",
                   {"id": row["id"], "revision": result["revision"], "href": PAGE})


def shared_recover(request, selection, _args, _prepared, operation_id):
    return _receipt(request, selection, operation_id)


def observation_snapshot(request, selection):
    context, row, projection = _selected(request, selection)
    choices = [{"value": item["id"], "label": row["labels"][item["id"]]}
               for item in projection["model"]["commitments"]]
    fields = [{"name": name, "label": label, "kind": "select", "required": True,
               "choices": choices} for name, label in
              (("running_order", "Order that ran"), ("blocked_order", "Order that waited"))]
    fields += [{"name": name, "label": label, "kind": "datetime-local", "required": True}
               for name, label in (("started_at", "Work started"), ("ended_at", "Work ended"),
                                   ("observed_at", "Observed at"), ("review_by", "Check again by"))]
    fields.append({"name": "basis", "label": "Source of this observation", "kind": "textarea",
                   "required": True, "max_length": 2000})
    return Snapshot(_state_revision(context, row, projection),
                    "Current accepted orders in this review",
                    "Record a completed interval reported by your team; this may suggest shared work for owner review.",
                    {"title": row["title"], "source_quality": "operator_reported"}, fields,
                    "The activity receipt is still pending. Refresh this review before recording more work."
                    if row.get("_audit_pending") else "")


def observation_prepare(request, selection, args):
    observation_snapshot(request, selection)
    _, row, _ = _selected(request, selection)
    _checked(lambda: native.TraceIn(expected_revision=row["revision"], operation_id="0"*16, **args))
    return Preview("Record this team-reported contention. This does not confirm the inferred dependency.",
                   [{"label": "Observation", "after": args}], {"expected_revision": row["revision"]})


def observation_execute(request, selection, args, prepared, operation_id):
    context, row, _ = _selected(request, selection)
    body = native.TraceIn(expected_revision=prepared["expected_revision"], operation_id=operation_id,
                          **args).service_body()
    result = _checked(lambda: reviews.record_trace(row["id"], context, native._actor(request), body))
    return Outcome("unconfirmed" if result.get("_audit_pending") else "confirmed",
                   "The observation was saved, but its activity receipt is still pending. Refresh this review." if result.get("_audit_pending") else
                   "The reported observation was recorded for owner review.",
                   {"id": row["id"], "revision": result["revision"], "href": PAGE})


def observation_recover(request, selection, _args, _prepared, operation_id):
    context, row, _ = _selected(request, selection)
    if operation_id in row.get("operations", {}):
        return Outcome("unconfirmed" if row.get("_audit_pending") else "replayed",
                       "The saved observation is waiting for its activity receipt. Refresh this review." if row.get("_audit_pending") else
                       "This observation was already recorded.",
                       {"id": row["id"], "revision": row["revision"], "href": PAGE})
    return None


def create_snapshot(request, _selection):
    context = native._context(request)
    labels = (("title", "Review name", "text"), ("order_a_name", "First accepted order", "text"),
              ("order_a_due_at", "First delivery date and time", "datetime-local"),
              ("order_a_material_units", "First order material units", "number"),
              ("order_a_uses_capacity", "First order uses shared work center", "boolean"),
              ("order_b_name", "Second accepted order", "text"),
              ("order_b_due_at", "Second delivery date and time", "datetime-local"),
              ("order_b_material_units", "Second order material units", "number"),
              ("order_b_uses_capacity", "Second order uses shared work center", "boolean"),
              ("capacity_name", "Shared work center", "text"),
              ("capacity_units", "Reported work units available", "number"),
              ("material_name", "Material name", "text"),
              ("stock_units", "Reported stock units", "number"),
              ("option_name", "Conditional choice", "text"),
              ("option_units", "Units the choice could add", "number"),
              ("option_ready_at", "Earliest ready date and time", "datetime-local"),
              ("option_expires_at", "Choice expiry date and time", "datetime-local"),
              ("option_lead_hours", "Lead time in hours after a decision", "number"),
              ("option_cost_note", "Cost or condition", "text"),
              ("basis", "Source and basis for entered figures", "textarea"),
              ("review_by", "Check figures again by", "datetime-local"))
    fields = [{"name": name, "label": label, "kind": kind,
               "required": name != "option_cost_note"}
              for name,label,kind in labels]
    fields += [{"name":"stock_certainty", "label":"Confidence in stock report", "kind":"select",
                "required":True, "choices":[{"value":"confirmed","label":"Team reports available"},
                                              {"value":"unknown","label":"Not confirmed"},
                                              {"value":"unavailable","label":"Team reports unavailable"}]},
               {"name":"option_kind", "label":"What the choice adds", "kind":"select",
                "required":True, "choices":[{"value":"material","label":"Material"},
                                             {"value":"capacity","label":"Work capacity"}]}]
    return Snapshot(digest([context,"new-promise-review"]),
                    "Current account and workspace",
                    "Start a reported-figures review for two accepted orders. This does not verify or reserve any external resource.",
                    {"source_quality":"operator_reported", "external_reservation_verified":False}, fields)


def create_prepare(request, selection, args):
    service_args = {**args, "option_lead_seconds": args["option_lead_hours"] * 3600}
    service_args.pop("option_lead_hours")
    native.NewReviewIn(operation_id="0"*16, **service_args)
    return Preview("Save two accepted orders and the team's reported stock, capacity, and expiring choice for review.",
                   [{"label":"Entered review", "after":args}], {"context":native._context(request)})


def create_execute(request, selection, args, prepared, operation_id):
    context = native._context(request)
    if context != prepared["context"]:
        raise HTTPException(409,"The account or workspace changed. Prepare this review again.")
    service_args = {**args, "option_lead_seconds": args["option_lead_hours"] * 3600}
    service_args.pop("option_lead_hours")
    body = native.NewReviewIn(operation_id=operation_id, **service_args).service_body()
    row = _checked(lambda: reviews.create(context, native._actor(request), body))
    return Outcome("unconfirmed" if row.get("_audit_pending") else "confirmed",
                   "The review was saved, but its activity receipt is still pending. Refresh saved reviews." if row.get("_audit_pending") else
                   "The reported-figures review was saved. No external resource was reserved.",
                   {"id":row["id"], "revision":row["revision"], "href":PAGE})


def archive_snapshot(request, selection):
    context, row, projection = _selected(request, selection, owner=True, allow_retiring=True)
    return Snapshot(digest([context, row["id"], row["revision"], row.get("retirement")]),
                    "Current promise review and owner authority",
                    "Finish this review and release its active slot. The full saved history remains readable, but no further decisions or observations can be added.",
                    {"id": row["id"], "title": row["title"], "revision": row["revision"],
                     "archive_pending": projection["archive_pending"], "href": PAGE},
                    blocked=("The last activity receipt is pending. Refresh this review before archiving."
                             if row.get("_audit_pending") else ""))


def archive_prepare(request, selection, _args):
    state = archive_snapshot(request, selection)
    if state.blocked:
        raise HTTPException(409, state.blocked)
    return Preview("Finish this review and keep its sources, observations, decisions and receipts as read-only history.",
                   [{"label": "Review", "before": state.details["title"],
                     "after": "Archived, read-only history"},
                    {"label": "Active review capacity", "after": "One slot released after archive verification"}],
                   {"expected_revision": state.details["revision"]})


def archive_execute(request, selection, _args, prepared, operation_id):
    context, row, _ = _selected(request, selection, owner=True, allow_retiring=True)
    if row["revision"] != prepared["expected_revision"]:
        raise HTTPException(409, "This review changed. Prepare the archive again.")
    archive = _checked(lambda: reviews.retire(row["id"], context, native._actor(request),
                                               {"expected_revision": row["revision"],
                                                "operation_id": operation_id,
                                                "confirm_finished": True}))
    return Outcome("confirmed", "This review is archived. Its full history remains readable, and one active slot is free.",
                   {"id": row["id"], "revision": archive["source"]["revision"],
                    "archived": True, "href": PAGE})


def archive_recover(request, selection, _args, _prepared, operation_id):
    context = native._context(request)
    if (not isinstance(selection, dict) or set(selection) != {"kind", "id"}
            or selection["kind"] != "commitment_review"
            or not _ID.fullmatch(str(selection.get("id", "")))):
        return None
    try:
        row, archive = reviews.read(selection["id"], context)
    except LookupError:
        return None
    if row["owner"] != native._actor(request):
        raise HTTPException(403, "Only the person who started this review can view its archive result.")
    marker = row.get("retirement") or {}
    if marker.get("operation_id") != operation_id:
        return None
    return Outcome("replayed" if archive is not None else "unconfirmed",
                   "This review is archived and its full history remains readable." if archive is not None else
                   "The archive is in progress. Open this review to resume after its activity receipt is recorded.",
                   {"id": row["id"], "revision": row["revision"],
                    "archived": archive is not None, "href": PAGE})


def entries():
    return (
        Adapter("commitments.assess", "Assess these accepted orders", "commitments", PAGE, (PAGE,),
                EmptyInput, assessment_snapshot, assessment_prepare,
                aliases=("assess the orders", "can we fulfill these orders")),
        Adapter("commitments.confirm_choice", "Confirm this conditional choice", "commitments", PAGE, (PAGE,),
                ChoiceInput, choice_snapshot, choice_prepare, choice_execute, choice_recover,
                aliases=("confirm choice", "confirm this choice")),
        Adapter("commitments.confirm_shared_work", "Confirm observed shared work", "commitments", PAGE, (PAGE,),
                SharedWorkInput, shared_snapshot, shared_prepare, shared_execute, shared_recover,
                aliases=("confirm shared work",)),
        Adapter("commitments.record_observation", "Record observed work contention", "commitments", PAGE, (PAGE,),
                ObservationInput, observation_snapshot, observation_prepare,
                observation_execute, observation_recover),
        Adapter("commitments.create_review", "Start a promise review", "commitments", PAGE, (PAGE,),
                CreateInput, create_snapshot, create_prepare, create_execute,
                aliases=("start promise review", "create promise review")),
        Adapter("commitments.archive_review", "Finish and archive promise review", "commitments", PAGE, (PAGE,),
                EmptyInput, archive_snapshot, archive_prepare, archive_execute, archive_recover,
                aliases=("archive promise review", "finish promise review")),
    )


__all__ = ["entries"]
