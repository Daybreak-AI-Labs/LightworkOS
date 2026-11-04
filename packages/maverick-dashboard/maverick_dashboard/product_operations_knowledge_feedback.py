"""Exact-source employee feedback never grants independent review or apply rights."""
from __future__ import annotations

import re
from typing import Literal

from fastapi import HTTPException, Response
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from pydantic import Field, ValidationError

from . import knowledge_access_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class Feedback(StrictInput):
    request_type: Literal["correction", "exclusion", "deletion"]
    reason: str = Field(min_length=1, max_length=2000)
    correction: str = Field(default="", max_length=8192)


def _scope(request):
    tenant, actor, context = native._binding(request, Response())
    return tenant, actor, context, native.call_native(native._service, request)


def _selected(selection, context):
    if set(selection) != {"kind", "reference", "purpose"} or selection.get("kind") != "knowledge_source":
        raise HTTPException(422, "Open a currently permitted source detail in Knowledge first.")
    try:
        return native.DetailIn(context=context, reference=selection["reference"], purpose=selection["purpose"])
    except ValidationError as exc:
        raise HTTPException(422, "Choose the exact source and permitted use from Knowledge.") from exc


def feedback_snapshot(request, selection):
    tenant, actor, context, service = _scope(request)
    if not selection:
        return Snapshot(digest([context, "no-source"]), "Exact knowledge feedback", "Select the source you can currently read.",
                        blocked="Open a source's details in Knowledge before reporting a correction or exclusion.")
    selected = _selected(selection, context)
    native.call_native(service.detail, tenant, actor, selected.reference.exact(), purpose=selected.purpose)
    return Snapshot(digest([context, selection]), "Currently authorized exact source", "Submitting records a request for independent review. It does not edit shared knowledge, approve deletion or grant training rights.", fields=[
        {"name": "request_type", "label": "Requested review", "kind": "select", "required": True, "choices": [
            {"value": kind, "label": label} for kind, label in (("correction", "Correct information"), ("exclusion", "Stop future use"), ("deletion", "Review source deletion"))]},
        {"name": "reason", "label": "Business reason", "kind": "textarea", "required": True, "max_length": 2000},
        {"name": "correction", "label": "Proposed corrected information (required for correction)", "kind": "textarea", "max_length": 8192}])


def feedback_prepare(request, selection, arguments):
    _, _, context, _ = _scope(request)
    feedback_snapshot(request, selection)
    reason, correction = arguments["reason"].strip(), arguments["correction"].strip()
    if not reason or arguments["request_type"] == "correction" and not correction:
        raise HTTPException(422, "Give a business reason and the proposed information for a correction.")
    return Preview("Send an exact-source request to independent administrators. Existing evidence, legal holds and separate training rights remain unchanged.",
                   changes=[{"label": "Requested review", "before": "No request", "after": arguments["request_type"]},
                            {"label": "Reason", "before": "", "after": reason},
                            {"label": "Proposed information", "before": "", "after": correction}],
                   native={"context": context, "selection": selection, "request_type": arguments["request_type"],
                           "reason": reason, "proposed_correction": correction or None})


def feedback_execute(request, selection, arguments, prepared, operation):
    with authority_effect_fence():
        tenant, actor, context, service = _scope(request)
        if context != prepared["context"] or selection != prepared["selection"]:
            raise HTTPException(409, "Account, workspace or source selection changed. Review again.")
        selected = _selected(selection, context)
        payload = native.RightsRequestIn(context=context, confirm=True, reference=selected.reference,
                                        purpose=selected.purpose, request_key=operation, request_type=prepared["request_type"],
                                        reason=prepared["reason"], proposed_correction=prepared["proposed_correction"])
        native._binding(request, Response(), payload, administrator=False)
        # Always use the employee intake even for an administrator. This action
        # cannot inherit the separate administrator review/apply interface.
        item = native.call_native(service.submit_feedback, tenant, actor, selected.reference.exact(),
                                  purpose=selected.purpose, request_type=payload.request_type, reason=payload.reason,
                                  proposed_correction=payload.proposed_correction, request_key=operation)
        receipt = service.request_store.get(item["id"])
        if (not receipt or receipt.get("tenant") != tenant or receipt.get("requested_by") != actor
                or receipt.get("_audit_pending")):
            return Outcome("unconfirmed", "The request returned, but its durable audit receipt is not confirmed. Refresh your requests before another submission.")
        return Outcome("confirmed", "Your request is recorded for independent review. No source, deletion or training permission was applied.", item)


def status_snapshot(request, selection):
    tenant, actor, context, service = _scope(request)
    items = native.call_native(service.feedback_requests, tenant, actor, limit=100)
    return Snapshot(digest([context, items]), "Your knowledge feedback", "Up to 100 of your requests from the retained history currently searched. For an older request, use its saved receipt in Knowledge. Independent administrative evidence is withheld.")


def status_prepare(request, selection, arguments):
    tenant, actor, _, service = _scope(request)
    items = native.call_native(service.feedback_requests, tenant, actor, limit=100)
    return Preview("Your request status, including separately retained requests when source use changes.", native={"items": items, "limit": 100})


def _archive_scope(request):
    tenant, actor, context = native._binding(request, Response(), administrator=True)
    return tenant, actor, context, native.call_native(native._service, request)


def _archive_selection(selection):
    if (set(selection) != {"kind", "id"} or selection.get("kind") != "knowledge_request"
            or not isinstance(selection.get("id"), str)
            or re.fullmatch(r"knowledge-req-[A-Za-z0-9_.-]{1,114}", selection["id"]) is None):
        raise HTTPException(422, "Select a finished rights request in Knowledge first.")
    return selection["id"]


def _archive_record(request, selection):
    tenant, actor, context, service = _archive_scope(request)
    request_id = _archive_selection(selection)
    record = native.call_native(service.get_request, tenant, request_id)
    return tenant, actor, context, service, request_id, record


def archive_snapshot(request, selection):
    tenant, actor, context, service = _archive_scope(request)
    if not selection:
        return Snapshot(digest([context, "no-request"]), "Finished knowledge requests",
                        "Select a finished request in Knowledge.",
                        blocked="Select a finished rights request in Knowledge first.")
    request_id = _archive_selection(selection)
    record = native.call_native(service.get_request, tenant, request_id)
    blocked = ("This request is already in the retained archive." if record["archived_at"] is not None else
               "This request is not yet ready for the finished archive." if not record["archive_ready"] else "")
    return Snapshot(digest([context, request_id, record["revision"], record["status"],
                            record["archive_ready"], record["archived_at"]]),
                    "Finished knowledge request", "Retain this completed rights review in the finished archive."
                    " Its source restrictions and audit evidence stay in force.",
                    details={"id": request_id, "status": record["status"], "revision": record["revision"]},
                    blocked=blocked)


def archive_prepare(request, selection, arguments):
    _, _, context, _, request_id, record = _archive_record(request, selection)
    if record["archived_at"] is not None or not record["archive_ready"]:
        raise HTTPException(409, "This request is not ready for the finished archive. Refresh Knowledge.")
    return Preview("Move this completed rights request to the retained archive. The original source,"
                   " source restrictions and audit evidence stay in place.",
                   changes=[{"label": "Request", "before": request_id, "after": "Retained in finished archive"},
                            {"label": "Active request capacity", "before": "Uses one place", "after": "Frees one place"}],
                   native={"context": context, "selection": selection, "request_id": request_id,
                           "expected_revision": record["revision"]})


def _archive_outcome(status, record):
    return Outcome(status, "This finished request is retained in the archive. Its source restrictions remain in force.",
                   {"id": record["id"], "status": record["status"], "revision": record["revision"],
                    "archived_at": record["archived_at"]})


def archive_recover(request, selection, arguments, prepared, operation):
    _, _, context, _, request_id, record = _archive_record(request, selection)
    if context != prepared["context"] or selection != prepared["selection"] or request_id != prepared["request_id"]:
        raise HTTPException(409, "Account, workspace or request selection changed. Review again.")
    if record["archived_at"] is None:
        return None
    if record["revision"] != prepared["expected_revision"]:
        raise HTTPException(409, "This request changed after review. Refresh Knowledge.")
    return _archive_outcome("replayed", record)


def archive_execute(request, selection, arguments, prepared, operation):
    with authority_effect_fence():
        tenant, actor, context, service, request_id, record = _archive_record(request, selection)
        if (context != prepared["context"] or selection != prepared["selection"]
                or request_id != prepared["request_id"]
                or record["revision"] != prepared["expected_revision"]
                or record["archived_at"] is not None or not record["archive_ready"]):
            raise HTTPException(409, "This request changed after review. Refresh Knowledge.")
        payload = native.ArchiveIn(context=context, confirm=True, expected_revision=prepared["expected_revision"])
        native._binding(request, Response(), payload, administrator=True)
        result = native.call_native(service.archive_request, tenant, actor, request_id,
                                    expected_revision=payload.expected_revision)
        if result["id"] != request_id or result["revision"] != payload.expected_revision or result["archived_at"] is None:
            return Outcome("unconfirmed", "The archive result could not be confirmed. Refresh Knowledge before retrying.")
        return _archive_outcome("confirmed", result)


class BrowseRequests(StrictInput):
    view: Literal["active", "archive", "ready"]
    page: Literal["current", "first", "next"]


def _batch_selection(selection):
    if selection.get("kind") != "knowledge_request_batch":
        return "active", ""
    if (set(selection) != {"kind", "view", "cursor"}
            or selection.get("view") not in {"active", "archive", "ready"}
            or not isinstance(selection.get("cursor"), str)
            or len(selection["cursor"]) > 2048):
        raise HTTPException(422, "Select a request batch from Knowledge again.")
    return selection["view"], selection["cursor"]


def browse_snapshot(request, selection):
    from .knowledge_request_browse import VIEWS, browse

    view, cursor = _batch_selection(selection)
    page = browse(request, view=view, cursor=cursor, limit=25)
    choices = [{"value": "current", "label": "Selected batch"},
               {"value": "first", "label": "Start this view again"}]
    if not page["complete"]:
        choices.append({"value": "next", "label": "Next batch"})
    return Snapshot(digest([page["context"], view, cursor, page["items"], page["complete"]]),
                    "Current retained knowledge requests",
                    ("Read one batch with current source restrictions and legal holds." if page["can_review"] else
                     "Read your own submissions and status. Other employees' requests and administrative evidence are withheld.") +
                    " This read never applies a change.",
                    fields=[{"name": "view", "label": "Request view", "kind": "select", "required": True,
                             "value": view, "choices": [{"value": key, "label": label} for key, label in VIEWS.items()
                                                         if page["can_review"] or key != "ready"]},
                            {"name": "page", "label": "Which batch", "kind": "select", "required": True,
                             "value": "current", "choices": choices}])


def browse_prepare(request, selection, arguments):
    from datetime import datetime, timezone

    from .knowledge_request_browse import VIEWS, browse

    selected_view, cursor = _batch_selection(selection)
    view = arguments["view"]
    if view != selected_view or arguments["page"] == "first":
        cursor = ""
    elif arguments["page"] == "next":
        previous = browse(request, view=view, cursor=cursor, limit=25)
        cursor = previous["next_cursor"]
        if cursor is None:
            raise HTTPException(409, "This view reached its last batch. Start the view again to check new requests.")
    page = browse(request, view=view, cursor=cursor, limit=25)
    rows = [{"request": row["request_type"].replace("_", " ").capitalize() + " — " + row["reason"],
             "status": row["status"].replace("_", " "),
             "source_use": row["source_use_status"].replace("_", " "),
             "retention_review": row["retention_review_status"].replace("_", " "),
             **({"legal_hold": (row["retention_hold"]["effective_status"].replace("_", " ")
                                if row["retention_hold"] else "No hold")} if page["can_review"] else {}),
             "updated": datetime.fromtimestamp(row["updated_at"], timezone.utc).strftime("%b %d, %Y at %H:%M UTC")}
            for row in page["items"]]
    return Preview("Showing " + VIEWS[view].lower() + ". " +
                   ("This is the last batch currently found. " if page["complete"] else "More records can be checked with Next batch. ") + page["notice"],
                   native={"requests": rows, "knowledge_request_page": {"view": view, "cursor": cursor}})


def feedback_entries():
    return (Adapter("knowledge.feedback", "Report an exact source correction or concern", "learning", "/knowledge-access", ("/knowledge-access",),
                    Feedback, feedback_snapshot, feedback_prepare, feedback_execute),
            Adapter("knowledge.my_feedback", "Review my knowledge requests", "learning", "/knowledge-access", ("/knowledge-access",),
                    EmptyInput, status_snapshot, status_prepare),
            Adapter("knowledge.browse_requests", "Browse retained knowledge requests", "learning", "/knowledge-access", ("/knowledge-access",),
                    BrowseRequests, browse_snapshot, browse_prepare),
            Adapter("knowledge.archive_request", "Move a finished rights request to the retained archive", "learning", "/knowledge-access", ("/knowledge-access",),
                    EmptyInput, archive_snapshot, archive_prepare, archive_execute, archive_recover))
