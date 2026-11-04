"""Owner-bound companion status and reviewed history clearing for Copilot."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.ediscovery import LegalHoldApplies
from maverick.employee_companion import (
    CompanionConflictError,
    CompanionError,
    CompanionPolicyDenied,
    EmployeeCompanionStore,
)

from . import employee_companion_api as native
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot


def _current(request):
    actor, _tenant, _context = native._authority(request)
    try:
        return actor, EmployeeCompanionStore().history_review(actor)
    except CompanionError as exc:
        raise HTTPException(503, "Your companion history is unavailable. Refresh before deciding what to clear.") from exc


def snapshot(request, _selection, *, clear=False):
    _actor, state = _current(request)
    count = state["saved_exchanges"]
    pending = state["reply_pending"]
    summary = (f"{count} saved conversation exchange{'s' if count != 1 else ''}. "
               + ("A reply is being prepared. " if pending else "")
               + ("New messages are not saved." if state["retention_days"] == 0
                  else f"Saved messages expire after {state['retention_days']} day{'s' if state['retention_days'] != 1 else ''}."))
    return Snapshot(state["revision"], "Your private companion conversation", summary,
                    {"saved_exchanges": count, "reply_pending": pending,
                     "retention_days": state["retention_days"]},
                    blocked="There is no saved conversation or pending reply to clear." if clear and not (count or pending) else "")


def inspect(request, _selection, _arguments):
    _current(request)
    return Preview("These are current counts and retention for your own companion. Conversation text was not shared with Copilot.")


def prepare(request, _selection, _arguments):
    _actor, state = _current(request)
    if not state["saved_exchanges"] and not state["reply_pending"]:
        raise HTTPException(409, "There is no saved conversation or pending reply to clear. Refresh the companion.")
    return Preview("Clear your saved companion conversation and cancel a pending reply. Tasks and companion policy stay in place. AI processing already sent to a provider may still be billed. Activity records are kept separately.",
                   [{"saved_exchanges": state["saved_exchanges"], "after": 0,
                     "pending_reply": "Cancelled" if state["reply_pending"] else "None"}],
                   {"revision": state["revision"]})


def execute(request, _selection, _arguments, prepared, operation_id):
    actor, _state = _current(request)
    try:
        receipt = EmployeeCompanionStore().clear_history(
            actor, actor=actor, expected_revision=prepared["revision"], operation_id=operation_id)
    except CompanionConflictError as exc:
        raise HTTPException(409, "Your companion conversation changed. Refresh and review it again.") from exc
    except CompanionPolicyDenied as exc:
        raise HTTPException(403, "Only you can clear your companion conversation.") from exc
    except LegalHoldApplies as exc:
        raise HTTPException(409, str(exc)) from exc
    except CompanionError as exc:
        raise HTTPException(503, "The clear result could not be confirmed. Check your companion before trying again.") from exc
    return Outcome("confirmed", "Your saved companion conversation was cleared and any pending reply was cancelled. Tasks and policy were unchanged. Earlier provider processing may still be billed.",
                   {"recorded_at": receipt["time"]})


def recover(request, _selection, _arguments, _prepared, operation_id):
    actor, _state = _current(request)
    try:
        receipt = EmployeeCompanionStore().history_clear_receipt(actor, operation_id)
    except CompanionError as exc:
        raise HTTPException(503, "The clear result could not be confirmed. Check your companion before trying again.") from exc
    if receipt:
        return Outcome("replayed", "This exact clear request was already recorded. Refresh your companion for its current conversation.",
                       {"recorded_at": receipt["time"]})
    return None


def entries():
    shared = {"family": "preferences", "direct_ui": "/companion", "pages": ("/companion",)}
    return (
        Adapter("companion.status", "Check my companion conversation", input_model=EmptyInput,
                snapshot=snapshot, prepare=inspect, **shared),
        Adapter("companion.clear_history", "Clear my companion conversation", input_model=EmptyInput,
                snapshot=lambda request, selection: snapshot(request, selection, clear=True),
                prepare=prepare, execute=execute, recover=recover, **shared),
    )
