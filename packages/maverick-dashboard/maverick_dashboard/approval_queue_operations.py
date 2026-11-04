"""Access-checked queue reviews and exact native vote receipts for Copilot."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException
from maverick.approval_cards import ApprovalCardError, decode_approval_detail, digest
from maverick.approval_vote_review import approval_review_identity
from maverick.channel_approvals import card_content
from maverick.safety.secret_detector import redact

from . import _shared, auth
from .approval_authority import require_approval_authority
from .content_access import require_approval_content
from .identity_format import humanize_principal, role_label


def selected_id(selection: dict) -> int:
    value = selection.get("id")
    if (set(selection) != {"kind", "id"} or selection.get("kind") != "approval"
            or type(value) is not int or value < 1):
        raise ValueError("Choose a request's Review with Copilot button in Approvals.")
    return value


def actor(request) -> str:
    return auth.caller_principal(request) or "operator"


def owned(request, approval_id: int, *, status: str | None = None):
    from . import api

    # Reading is subject to the queue's decision-key scope as well as content
    # privacy. An installation key cannot substitute for an employee owner.
    if auth.api_key_permissions(request) is not None:
        auth.require_api_key_scope(request, "approvals:decide")
    else:
        auth.require_permission(request, "operate")
    world = _shared._world()
    row = require_approval_content(request, approval_id, world)
    if status is not None:
        require_approval_authority(request, action="approval." + ("approve" if status == "approved" else "deny"),
                                   resource=str(approval_id))
        api._require_settings_decider(request, world, approval_id, actor(request), approving=status == "approved")
        from . import agent_publish_bypass
        agent_publish_bypass.require_decider(request, world.get_approval(approval_id), actor(request),
                                             approving=status == "approved")
    return world, row


def identity(row) -> str:
    # All queued material and ownership are private commitments. Normal vote
    # state may change after acceptance; a changed card or undo round may not.
    return approval_review_identity(row)


def revision(world, row, who: str) -> str:
    return digest({"identity": identity(row), "state": world.approval_state(row.id),
                   "content_owner": content_owner(world, row),
                   "approve_event": world.approval_audit_event_id(row.id, "approved", who),
                   "deny_event": world.approval_audit_event_id(row.id, "denied", who), "actor": who})


def content_owner(world, row) -> str:
    if not row.goal_id:
        return row.requested_by or ""
    goal = world.get_goal(row.goal_id)
    if goal is None:
        raise HTTPException(409, "The request's original task is unavailable. Read its current status before deciding.")
    return goal.owner or ""


def safe(value: object) -> str:
    try:
        text, _matches = redact(" ".join(str(value or "").split()))
        return text[:2000]
    except Exception:
        return "Details unavailable; open the full review."


def public(world, row, who: str) -> dict:
    # The shared card projection omits exact commands and credential/input
    # commitments. Redact each displayed field; model guidance receives none.
    card, state = card_content(row), world.approval_state(row.id) or {}
    try:
        exact = decode_approval_detail(row.detail) or {}
    except ApprovalCardError:
        exact = {}
    receipts = []
    for status in ("approved", "denied"):
        event = world.get_approval_audit_event(world.approval_audit_event_id(row.id, status, who))
        if event is not None:
            if not event.matches(row.id, status, who):
                raise HTTPException(503, "The original decision record could not be verified. Do not submit it again.")
            receipts.append(receipt(world, event))
    return {"Request": safe(card["action"]), "Risk": safe(card["risk_label"]),
            "Current decision": str(row.status).capitalize(), "Your original decisions": receipts,
            "Applies to": safe(card["scope"]),
            "Description": safe(card["summary"]),
            "What it will do": [safe(text) for text in card["what_it_will_do"]],
            "Spending": safe(card["spending"]), "Cannot be undone": bool(card["irreversible"]),
            "Known effects": [safe(text) for text in card.get("known_effects", [])],
            "Open questions": [safe(text) for text in (exact.get("consequences") or {}).get("unresolved_assumptions", [])],
            "Before": safe((exact.get("preview") or {}).get("before")),
            "After": safe((exact.get("preview") or {}).get("after")),
            "Review validity": {"current": "Ready for review", "expired": "Expired; request a fresh review",
                                "legacy": "An older request; approval requires a fresh review",
                                "invalid": "Details failed verification; approval requires a fresh review",
                                "decided": "A decision has been made"}.get(card["status"], "Check full review"),
            "Approvals received": int(state.get("approved_count", 0)),
            "Approvals needed": int(state.get("approvals_required", 1)),
            "Next step": {"label": "Open this request's full review", "href": f"/approvals#approval-{row.id}"},
            "Meaning": "Authorization, execution and external verification are separate. This decision does not prove an action ran."}


def private_review(request, approval_id: int, *, status: str | None = None) -> dict:
    """The native private card, never the shared/channel or model projection.

    Recheck the same queue/content/decision authority before opening exact
    display text. Validated cards already redact secrets while preserving
    command lines; do not shorten them or reuse the shared summary here.
    """
    world, row = owned(request, approval_id, status=status)
    try:
        exact = decode_approval_detail(row.detail)
    except ApprovalCardError as exc:
        if status == "approved":
            raise HTTPException(409, "This request's complete details could not be verified. Open its full review in Approvals before deciding.") from exc
        exact = None
    if exact is None:
        if status == "approved":
            raise HTTPException(409, "This older request needs its full review in Approvals before deciding.")
        try:
            description, _matches = redact(row.detail or "")
        except Exception as exc:
            raise HTTPException(409, "This request's full description is unavailable. Open its protected review in Approvals before deciding.") from exc
        return {**public(world, row, actor(request)), "Complete saved description": description,
                "Review limit": "These older or unverified details cannot authorize an action. You may reject this request and ask for a fresh verified review."}
    result = public(world, row, actor(request))
    result.update({"Request": exact["action"], "Description": exact["summary"],
                   "Applies to": exact["target"]["label"],
                   "Requested by": humanize_principal(exact["authority"]["actor"]).name,
                   "Requesting role": role_label(exact["authority"]["role"]),
                   "Workspace": exact["authority"]["workspace"],
                   "Decide by": datetime.fromtimestamp(exact["expires_at"], timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC"),
                   "What it will do": exact["parameters"]["summary"],
                   "Before": exact["preview"]["before"], "After": exact["preview"]["after"],
                   "Cannot be undone": exact["consequences"]["irreversible"],
                   "Known effects": exact["consequences"]["known_effects"],
                   "Open questions": exact["consequences"]["unresolved_assumptions"],
                   "Recorded connection versions": exact["credentials"],
                   "Recorded spending allowance": exact["budget"]})
    if exact.get("display"):
        result["Command it will run"] = exact["display"]["command"]
    return result


def receipt(world, event) -> dict:
    state = world.approval_state(event.approval_id) or {}
    return {"Decision": "Approved" if event.status == "approved" else "Rejected",
            "Recorded at": datetime.fromtimestamp(event.created_at, timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
            "Audit delivery": "Delivered" if event.delivered_at is not None else "Pending delivery",
            "Current request decision": str(state.get("status") or "unavailable").capitalize(),
            "Approvals received": int(state.get("approved_count", 0)),
            "Approvals needed": int(state.get("approvals_required", 1)),
            "Decision reference": event.event_id,
            "Meaning": "Your recorded vote authorizes no execution until quorum and audit delivery are complete. It is not an execution receipt."}


def reviewed(request, approval_id: int, status: str) -> dict:
    world, row = owned(request, approval_id, status=status)
    who = actor(request)
    event_id = world.approval_audit_event_id(approval_id, status, who)
    if world.get_approval_audit_event(event_id) is not None:
        raise HTTPException(409, "Your decision is already recorded. Read this request's original decision instead of submitting it again.")
    if row.status != "pending":
        raise HTTPException(409, "This request has already been decided. Read its current status.")
    card = card_content(row)
    if status == "approved":
        from .approval_decisions import require_current_decision_card

        require_current_decision_card(world, approval_id, str(card.get("binding") or ""))
    return guard(world, row, who, status, str(card.get("binding") or ""))


def guard(world, row, who: str, status: str, binding: str, *, bind_state: bool = True) -> dict:
    # The direct queue sends a card binding, not a quorum snapshot. Its native
    # voter checks quorum atomically; don't make a diagnostic state read a new
    # prerequisite for that existing route. Copilot seals its reviewed state.
    return {"actor": who, "approval_id": row.id, "status": status,
            "identity": identity(row), "revision": revision(world, row, who) if bind_state else "",
            "event_id": world.approval_audit_event_id(row.id, status, who),
            "content_owner": content_owner(world, row),
            "binding": binding, "state": world.approval_state(row.id) if bind_state else None}


def require_review(request, world, approval_id: int, status: str, review: dict) -> None:
    # This runs inside the same native decision handler immediately before its
    # audited vote, even if callers bypass a stale catalog precheck.
    current = reviewed(request, approval_id, status)
    if current != review:
        raise HTTPException(409, "This exact request or your review authority changed. Read its current status and review it again.")


def recover(request, approval_id: int, status: str, review: dict):
    world, row = owned(request, approval_id, status=status)
    who = actor(request)
    if (review.get("actor") != who or review.get("approval_id") != approval_id
            or review.get("status") != status or review.get("identity") != identity(row)
            or review.get("content_owner") != content_owner(world, row)
            or review.get("event_id") != world.approval_audit_event_id(approval_id, status, who)):
        raise HTTPException(409, "The request, account or original decision changed. Open the full review to check status.")
    event = world.get_approval_audit_event(review["event_id"])
    if event is None:
        return None
    if not event.matches(approval_id, status, who):
        raise HTTPException(503, "The original decision record could not be verified. Do not submit it again.")
    # Read only: do not repeat a vote, acknowledgement, reason or audit delivery.
    return receipt(world, event)
