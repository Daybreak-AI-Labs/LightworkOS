"""Copilot delivery actions use the same authorized service as Settings."""
from __future__ import annotations

import hashlib
import json
from uuid import UUID

from fastapi import HTTPException
from pydantic import Field

from . import notification_health as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

PAGES = ("/settings", "/settings/*", "/notifications", "/preferences")


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _state(request):
    native._guard(request)
    return native._state()


def _configuration():
    # Secrets bind the preparation without appearing in its source details.
    return _digest(native._config())


def _safe(record):
    return (record.get("kind") == "test" and record.get("state") == "failed"
            and record.get("safe_to_retry") is True and record.get("attempts", 3) < 3)


def _record(state, ident):
    return next((row for row in state["receipts"] if row["id"] == ident), None)


def _snapshot(request, _selection, *, action="status"):
    state = _state(request)
    blocked = ""
    if action != "status":
        if not state["enabled"]:
            blocked = "Enable delivery history in All settings before testing."
        elif state["backend"] not in {"ntfy", "pushover", "slack", "discord"}:
            blocked = "Save a supported notification channel in All settings."
    eligible = [row for row in state["receipts"] if _safe(row)]
    fields = []
    if action == "retry":
        if not eligible:
            blocked = "There are no safely retryable failed tests. Accepted and uncertain deliveries cannot be replayed."
        fields = [{"name": "receipt_id", "label": "Failed test to retry", "kind": "select", "required": True,
                   "value": "", "choices": [{"value": row["id"], "label": row["backend"] + " test (attempt " + str(row["attempts"]) + ")"} for row in eligible]}]
    return Snapshot(revision=_digest({"config": _configuration(), "receipts": state["receipts"]}),
        source="Current saved notification configuration and local delivery receipts",
        summary="Notification service acceptance is separate from whether a person saw the message.",
        details=state, fields=fields, blocked=blocked)


def _prepare_status(request, selection, _arguments):
    state = _snapshot(request, selection)
    return Preview(summary=state.summary)


def _prepare_test(request, _selection, _arguments):
    state = _state(request)
    native._enabled()
    return Preview(summary="Send one content-free test to the currently saved organization notification destination.",
        changes=[{"field": "Test destination", "before": "No new test", "after": state["backend"]},
                 {"field": "Message", "before": "", "after": "Lightwork delivery test; no task content"}],
        native={"configuration": _configuration(), "backend": state["backend"]})


def _check(request, prepared):
    native._guard(request)
    if _configuration() != prepared["configuration"]:
        raise HTTPException(409, "Notification configuration changed. Prepare a fresh test review.")


def _outcome(record, *, replay=False):
    state = record["state"]
    status = ("queued" if state in {"queued", "sending"} else
              "replayed" if replay and state in {"delivered", "failed"} else
              "confirmed" if state in {"delivered", "failed"} else "unconfirmed")
    return Outcome(status=status, message=record["message"], details={"receipt": record, "seen": "unknown"})


def _test_record(prepared, operation_id):
    from maverick.notification_receipts import DeliveryReceipts
    receipts = DeliveryReceipts()
    ident = receipts.key(str(UUID(hex=operation_id)), prepared["backend"])
    return next((row for row in receipts.recent() if row["id"] == ident), None)


def _execute_test(request, _selection, _arguments, prepared, operation_id):
    _check(request, prepared)
    native._test(request, str(UUID(hex=operation_id)), backend=prepared["backend"])
    record = _test_record(prepared, operation_id)
    if record is None:
        raise HTTPException(503, "The test outcome is unavailable. Review notification status before another test.")
    return _outcome(record)


def _recover_test(request, _selection, _arguments, prepared, operation_id):
    _check(request, prepared)
    record = _test_record(prepared, operation_id)
    return _outcome(record, replay=True) if record else None


class RetryInput(StrictInput):
    receipt_id: str = Field(pattern=r"^[0-9a-f]{64}$")


def _prepare_retry(request, _selection, arguments):
    state = _state(request)
    record = _record(state, arguments["receipt_id"])
    if record is None or not _safe(record):
        raise HTTPException(409, "This test cannot safely be retried. Refresh delivery status.")
    if record["backend"] != state["backend"]:
        raise HTTPException(409, "This test used a different channel. Prepare a new test for the saved channel.")
    return Preview(summary="Retry one refused test once. Accepted or uncertain deliveries will never be resent.",
        changes=[{"field": "Test attempt", "before": str(record["attempts"]), "after": str(record["attempts"] + 1)}],
        native={"configuration": _configuration(), "backend": record["backend"],
                "record": record})


def _execute_retry(request, _selection, arguments, prepared, _operation_id):
    _check(request, prepared)
    record = _record(_state(request), arguments["receipt_id"])
    if record != prepared["record"] or record is None or not _safe(record):
        raise HTTPException(409, "This delivery changed after review. Refresh its status.")
    native._test(request, record["request_id"], retry=True, backend=record["backend"])
    result = _record(_state(request), record["id"])
    if result is None:
        raise HTTPException(503, "The retry outcome is unavailable. Check delivery history before another attempt.")
    return _outcome(result)


def _recover_retry(request, _selection, arguments, prepared, _operation_id):
    _check(request, prepared)
    record = _record(_state(request), arguments["receipt_id"])
    if record and record["attempts"] > prepared["record"]["attempts"]:
        return _outcome(record, replay=True)
    return None


def entries() -> tuple[Adapter, ...]:
    from .product_operations_personal_notifications import entries as personal_entries
    shared = {"family": "notifications", "direct_ui": "/settings/notifications", "pages": PAGES}
    return (
        Adapter(id="notifications.delivery_status", label="Show notification delivery status", input_model=EmptyInput,
                snapshot=_snapshot, prepare=_prepare_status, **shared),
        Adapter(id="notifications.send_test", label="Send a notification test", input_model=EmptyInput,
                snapshot=lambda request, selection: _snapshot(request, selection, action="test"),
                prepare=_prepare_test, execute=_execute_test, recover=_recover_test, **shared),
        Adapter(id="notifications.retry_test", label="Retry a refused notification test", input_model=RetryInput,
                snapshot=lambda request, selection: _snapshot(request, selection, action="retry"),
                prepare=_prepare_retry, execute=_execute_retry, recover=_recover_retry, **shared),
    ) + personal_entries()
