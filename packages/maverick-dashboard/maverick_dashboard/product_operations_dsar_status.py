"""Read the selected privacy request through its native page authority."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest

from . import auth
from .plain_labels import datetime_text
from .privacy_access import privacy_ops_or_403 as _privacy_ops_or_403
from .product_operations import Adapter, EmptyInput, Preview, Snapshot
from .product_operations_dsar_handoff import _id

KINDS = {
    "access": "Copy of their data", "portability": "Move their data",
    "erasure": "Delete their data", "rectification": "Correct their data",
    "correction": "Correct their data", "objection": "Stop using their data",
    "restriction": "Limit use of their data", "opt_out": "Opt out of sale or sharing",
    "limit_sensitive": "Limit use of sensitive data", "withdraw_consent": "Withdraw consent",
}
STATUSES = {
    "open": "Open", "unverified": "Waiting for email confirmation",
    "awaiting_erasure": "Waiting for deletion", "fulfilled": "Answered", "closed": "Closed",
}


def _state(request, selection):
    auth.require_permission(request, "operate")
    service = _privacy_ops_or_403()
    identifier = _id(selection)
    record = service.get_dsar(identifier)
    if record is None or "status" not in record:
        raise HTTPException(404, "This privacy request is no longer available.")
    clock = service.dsar_clock(record)
    status = STATUSES.get(record["status"], "Review the current request")
    if record["status"] == "fulfilled" and record.get("kind") in {"access", "portability"}:
        status = "Data collected"
    elif record["status"] == "fulfilled" and service.dsar_answer(record) is None:
        status = "Action and response not documented"
    details = {
        "Request": KINDS.get(record.get("kind"), "Other privacy request"),
        "Current state": status,
        "Response still needed": clock["response_pending"],
        "Response deadline": datetime_text(clock["effective_due_at"], date_only=True),
    }
    if clock["response_pending"]:
        days = clock["days_left"]
        details["Time remaining"] = (
            "Deadline passed today" if clock["overdue"] and days == 0 else
            "Due today" if days == 0 else
            f"{abs(days)} day{'s' if abs(days) != 1 else ''} overdue" if clock["overdue"] else
            f"{days} day{'s' if days != 1 else ''} left"
        )
        details["Receipt confirmation overdue"] = clock["acknowledge_overdue"]
    if record.get("acknowledge_by"):
        details["Receipt confirmation deadline"] = datetime_text(record["acknowledge_by"], date_only=True)
    if record.get("extended_until"):
        details["Extension recorded"] = "The response deadline includes the recorded extension."
    answer = service.dsar_answer(record)
    details["Answer on record"] = (
        "Refusal recorded" if answer and answer["kind"] == "refused" else
        "Answer recorded" if answer else "No answer recorded"
    )
    details["Scope"] = (
        "Current saved request and its UTC calendar deadline. Collected data is separate from answering "
        "the request. These records do not independently verify a recipient's receipt or deletion "
        "by another service."
    )
    details["open"] = {"label": "Open this complete privacy request", "href": "/privacy/dsar/" + identifier}
    return digest({"record": record, "clock": clock}), details


def snapshot(request, selection):
    revision, details = _state(request, selection)
    return Snapshot(revision, "The selected native privacy request and its current deadline",
                    "Read the current request, response work and recorded answer without changing them.", details)


def prepare(request, selection, _arguments):
    _, details = _state(request, selection)
    return Preview("Current privacy request status. Nothing was changed, sent or deleted.", native=details)


def entries():
    return (Adapter("artifacts.privacy_request_status", "Read this privacy request and its deadline",
                    "artifacts", "/privacy", ("/privacy/dsar/*",), EmptyInput, snapshot, prepare,
                    aliases=("when is this privacy request due", "read this privacy request",
                             "is this privacy request overdue", "has this privacy request been answered")),)
