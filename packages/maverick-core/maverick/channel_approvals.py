"""Human approval decisions: the ONE implementation every surface shares.

The Approvals page (``maverick_dashboard.api``), the Microsoft Teams cards
(``maverick_channels.teams`` through ``maverick_dashboard.approval_decisions``)
and the Slack cards (``maverick.slack_interactive``) all record a decision with
the functions here, so a vote from chat is exactly as accountable as one from
the dashboard:

* :func:`card_content` turns an approval row into plain-language card content
  (what it will do, risk, spending, "can't be undone", decide-by).
* :func:`require_current_card` is the approve-time card check (expired, stale,
  legacy or corrupted cards are refused).
* :func:`require_acknowledgement` is the confirmation rule: a High or Critical
  request is approved only after a second, explicit step, and -- when
  ``[approval] require_acknowledgement`` is on -- an acknowledgement that the
  person read what it will do, plus the typed word ``APPROVE`` for Critical.
  Every surface writes the same ``approval_confirmation`` audit event, tagged
  with the channel.
* :func:`separate_approver_refusal` says when the person who asked for a High
  or Critical action must leave the approval to someone else (``[approval]
  separate_approver``); :func:`require_separate_approver` refuses such a vote
  before its confirmation is recorded, and :func:`record_vote` again.
* :func:`record_vote` applies one approver's vote through
  ``WorldModel.decide_approval_audited`` and reconciles a lost commit
  acknowledgement by the vote's stable outbox id.
* :func:`audit_approval_decision` / :func:`deliver_approval_audit_event`
  deliver the queued votes to the signed audit chain in order.
* :func:`decide_from_channel` strings those together for a chat channel and
  returns whether the vote is already effective.
* :func:`undo_decision` returns a just-decided request to pending while the
  undo window (``[approval] undo_grace_seconds``) is open; the next decision
  is a new audit round (``WorldModel.undo_approval_decision``).

The policy knobs live in :mod:`maverick.safety.consent`; this module only
reads them. HTTP status mapping and role checks are the dashboard's job
(:mod:`maverick_dashboard.approval_decisions`): a refusal here is a
:class:`ChannelApprovalRefused` with a stable ``reason`` and a plain sentence.

Nothing here talks to a network except :func:`announce_new_approval`, which
posts a new card best-effort. Identity linking (channel user id ->
Lightwork principal) lives in :mod:`maverick.channel_identities`.
"""
from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from typing import Any

from .constant_time import text_equals

log = logging.getLogger(__name__)

CHANNELS = ("slack", "teams", "email", "dashboard")
CONFIRM_RISKS = frozenset({"high", "critical"})
TYPED_CONFIRMATION = "approve"
_RISK_LABELS = {
    "low": "Low risk",
    "medium": "Medium risk",
    "high": "High risk",
    "critical": "Critical risk",
}
# Protected-settings requests are decided by a global administrator on the
# dashboard (settings_quorum enforces who may decide); a chat channel cannot
# prove that role, so it never decides them.
SETTINGS_PROVENANCE = "settings_quorum"
# Publishing changed instructions without a passing test run (the dashboard's agent_publish_bypass.PROVENANCE): the
# person who asked may never approve it, on any surface and whatever [approval] separate_approver says.
ALWAYS_SEPARATE_PROVENANCES = frozenset({"agent_publish.bypass.four_eyes.v1"})

# The HTTP status each refusal maps to when a surface speaks HTTP.
_STATUS_CODES: dict[str, int] = {
    "unlinked": 403,
    "not_permitted": 403,
    "not_pending": 404,
    "not_found": 404,
    "dashboard_only": 403,
    "confirm_required": 428,
    "acknowledgement_required": 422,
    "typed_confirmation_required": 422,
    "expired": 409,
    "stale_card": 409,
    "vote_not_accepted": 403,
    "separate_approver": 403,
    "pending_finalization": 409,
    "not_decided": 409,
    "too_late": 409,
    "final": 409,
    "outcome_uncertain": 503,
    "outbox_integrity_error": 500,
    "audit_failed": 503,
}

# ``authorize(principal, approval_id)`` may raise ChannelApprovalRefused.
Authorizer = Callable[[str, int], None]


class ChannelApprovalRefused(Exception):
    """A decision the shared path will not record.

    ``reason`` is a stable code (see ``_STATUS_CODES``), ``message`` a plain
    sentence for the person, ``status_code`` the HTTP status a web surface
    answers with. ``decision_id`` / ``retry_safe`` are set for the two
    commit-reconciliation outcomes of :func:`record_vote`.
    """

    def __init__(self, reason: str, message: str, *, status_code: int | None = None,
                 decision_id: str | None = None, retry_safe: bool | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.status_code = status_code if status_code is not None else _STATUS_CODES.get(reason, 409)
        self.decision_id = decision_id
        self.retry_safe = retry_safe

    @property
    def detail(self) -> str:
        return self.message


def needs_confirmation(risk: str | None) -> bool:
    """High and Critical requests need a second confirmation on every channel."""
    return str(risk or "").strip().lower() in CONFIRM_RISKS


# ----------------------------------------------------------------------------
# The acknowledgement and undo policy: owned by maverick.safety.consent.
# ----------------------------------------------------------------------------

def approval_requires_acknowledgement() -> bool:
    """Whether approving a High/Critical request needs an explicit acknowledgement
    (``MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT``, else ``[approval]
    require_acknowledgement``; default on). Read from the kernel's consent module."""
    from .safety.consent import approval_requires_acknowledgement as kernel_value

    return bool(kernel_value())


def approval_undo_grace_seconds() -> float:
    """How long (seconds) a decision can still be undone
    (``MAVERICK_APPROVAL_UNDO_GRACE_SECONDS``, else ``[approval]
    undo_grace_seconds``; default 30; 0 disables undo). Read from the kernel's
    consent module."""
    from .safety.consent import approval_undo_grace_seconds as kernel_value

    return float(kernel_value())


def safe_action_label(approval: Any) -> str:
    """The queued action as plain, redacted text for audit summaries."""
    from .safety.secret_detector import redact

    try:
        text, _matches = redact(" ".join(str(getattr(approval, "action", "") or "").split()))
    except Exception:  # noqa: BLE001 -- the label is decoration, never authority
        return "the reviewed action"
    return (text[:200] or "the reviewed action").replace(".", " ").replace("_", " ")


def decision_summary(world: Any, event: Any) -> str:
    """One plain sentence for the audit log: who decided what."""
    try:
        approval = world.get_approval(int(event.approval_id))
    except Exception:  # noqa: BLE001 -- the summary is decoration, never authority
        approval = None
    label = safe_action_label(approval) if approval is not None else "the reviewed action"
    risk = str(getattr(approval, "risk", "") or "").strip() or "unrated"
    verb = "approved" if event.status == "approved" else "rejected"
    if event.final_status is None:
        return (
            f"{event.decided_by} {verb} '{label}' ({risk} risk); "
            "more approvers are needed before it takes effect."
        )
    return f"{event.decided_by} {verb} '{label}' ({risk} risk)."


def _plain_action(action: str | None) -> str:
    text = " ".join(str(action or "").replace("_", " ").replace(".", " ").split())
    return (text[:1].upper() + text[1:]) if text else "Reviewed action"


def _amount_text(budget: Any) -> str:
    if not isinstance(budget, dict):
        return ""
    maximum = budget.get("maximum")
    if isinstance(maximum, (int, float)) and not isinstance(maximum, bool):
        currency = str(budget.get("currency") or "USD")
        amount = f"${maximum:.2f}" if currency == "USD" else f"{currency} {maximum:.2f}"
        minutes = budget.get("minutes")
        return f"Up to {amount}" + (f" · {minutes} minutes" if minutes else "")
    return ""


def spending_text(budget: dict[str, Any] | None) -> str:
    """The spending line people read on every approval surface.

    A card's budget is a plain cap (``maximum``), a promise to check again
    when it runs (``state``), or an exact-operation card's pair of commitments
    (``runtime`` and ``operation``). Fingerprints and raw field names never
    show here; they belong under technical details.
    """
    if not isinstance(budget, dict) or not budget:
        return "Not stated"
    amount = _amount_text(budget)
    if amount:
        return amount
    if budget.get("state"):
        return "Checked again when it runs"
    operation, runtime = budget.get("operation"), budget.get("runtime")
    for part in (operation, runtime):
        amount = _amount_text(part)
        if amount:
            return amount
    if isinstance(operation, dict) and operation.get("state") not in (None, "", "not_applicable"):
        return "Checked again when it runs"
    if isinstance(runtime, dict) and runtime.get("external_effect_cost") == "unmeasured":
        return ("No separate amount for this step. The task's spending limit still applies, "
                "and costs outside Lightwork aren't measured.")
    return "No separate amount for this step."


_spending_text = spending_text


def card_content(approval: Any, *, now: float | None = None) -> dict[str, Any]:
    """Plain-language content for an approval card on any channel.

    Never exposes a malformed structured envelope; a corrupted card becomes
    ``status="invalid"`` with a fixed sentence, like the dashboard row.
    """
    from .approval_cards import ApprovalCardError, decode_approval_detail

    current = time.time() if now is None else float(now)
    risk = str(getattr(approval, "risk", "") or "medium").lower()
    content: dict[str, Any] = {
        "id": int(approval.id),
        "action": _plain_action(approval.action),
        "risk": risk,
        "risk_label": _RISK_LABELS.get(risk, risk.capitalize() + " risk"),
        "scope": " ".join(str(getattr(approval, "scope", "") or "").split())[:300]
        or "The item described",
        "summary": " ".join(str(getattr(approval, "detail", "") or "").split())[:600],
        "what_it_will_do": [],
        "spending": "Not stated",
        "irreversible": False,
        "decide_by": None,
        "requested_by": getattr(approval, "requested_by", None) or "",
        "status": "legacy",
        "binding": None,
        "needs_confirmation": needs_confirmation(risk),
        "needs_typed_confirmation": risk == "critical",
        "approval_status": str(getattr(approval, "status", "pending") or "pending"),
        "decided_by": getattr(approval, "decided_by", None) or "",
        "decided_at": getattr(approval, "decided_at", None),
    }
    if content["approval_status"] != "pending":
        content["status"] = "decided"
    try:
        card = decode_approval_detail(getattr(approval, "detail", None))
    except ApprovalCardError:
        content["summary"] = "Structured approval details failed their integrity check."
        content["status"] = "invalid"
        return content
    if card is None:
        return content
    what_it_will_do = list(card["parameters"]["summary"])
    if card.get("display"):
        # The exact command stays on the access-checked Approvals page; shared
        # chat rooms and summaries say where to read it.
        what_it_will_do.append("The exact command is shown on the Approvals page.")
    content.update({
        "summary": card["summary"],
        "scope": card["target"]["label"],
        "what_it_will_do": what_it_will_do,
        "spending": _spending_text(card.get("budget")),
        "irreversible": bool(card["consequences"]["irreversible"]),
        "decide_by": float(card["expires_at"]),
        "requested_by": card["authority"]["actor"],
        "binding": card["binding_sha256"],
        "known_effects": list(card["consequences"]["known_effects"]),
    })
    if content["status"] != "decided":
        content["status"] = "expired" if current >= card["expires_at"] else "current"
    return content


def held_for_undo(approval: Any) -> bool:
    """Whether a person's decision on ``approval`` can be undone at all: only
    a request the consent wait holds for the undo window. Every other
    requester acts on a decision at once (``WorldModel.undo_approval_decision``)."""
    from .world_model import approval_held_open

    return approval_held_open(approval)


def undo_seconds_left(approval: Any, *, now: float | None = None) -> float:
    """Seconds the decision on ``approval`` can still be undone (0 when it cannot)."""
    from .world_model import approval_undo_refusal

    if approval is None or getattr(approval, "status", "pending") == "pending":
        return 0.0
    if approval_undo_refusal(approval.status, getattr(approval, "decided_by", None),
                             getattr(approval, "undo_hold", None)) is not None:
        return 0.0
    decided_at = getattr(approval, "decided_at", None)
    if not isinstance(decided_at, (int, float)) or isinstance(decided_at, bool):
        return 0.0
    current = time.time() if now is None else float(now)
    return max(0.0, float(decided_at) + approval_undo_grace_seconds() - current)


# ----------------------------------------------------------------------------
# Signed-audit delivery: the ONE implementation the dashboard and channels share.
# ----------------------------------------------------------------------------

def _self_approval(world, event) -> dict[str, bool]:
    """``{"self_approval": True}`` when the requester approved their own request."""
    if event.status != "approved":
        return {}
    try:
        approval = world.get_approval(int(event.approval_id))
    except Exception:  # noqa: BLE001 -- the flag is evidence detail, never authority
        return {}
    requester = str(getattr(approval, "requested_by", "") or "").strip()
    if requester and requester == str(event.decided_by or "").strip():
        return {"self_approval": True}
    return {}


def deliver_approval_audit_event(world, event, *, effect_guard=None) -> bool:
    """Deliver exactly one queued vote and persist its delivery marker."""
    if event.delivered_at is not None:
        return True

    from .audit import AuditRefused, EventKind, audit_event

    if effect_guard is not None:
        effect_guard()
    try:
        written = audit_event(
            EventKind.APPROVAL_DECISION,
            approval_event_id=event.event_id,
            approval_id=int(event.approval_id),
            status=event.status,
            decided_by=event.decided_by,
            occurred_at=float(event.created_at),
            summary=decision_summary(world, event),
            **_self_approval(world, event),
        )
    except AuditRefused as exc:
        # Not refusal swallowing: no approval becomes effective. The exact event
        # stays in the durable outbox for a policy/key repair and idempotent retry.
        log.error(
            "approval audit refused; decision remains non-effective (event_id=%s): %s",
            event.event_id, exc,
        )
        return False
    if not written:
        log.error(
            "approval audit write failed; decision remains non-effective (event_id=%s)",
            event.event_id,
        )
        return False
    try:
        return bool(world.mark_approval_audit_delivered(event.event_id,
            **({"effect_guard": effect_guard} if effect_guard is not None else {})))
    # The signed append may have succeeded while the delivery-marker commit
    # acknowledgement failed. Reconcile instead of inviting a differently-keyed retry.
    # failure-policy: fail_soft_with_audit
    except Exception:
        log.exception(
            "approval audit was written but delivery finalization failed (event_id=%s)",
            event.event_id,
        )
        try:
            reconciled = world.get_approval_audit_event(event.event_id)
        except Exception:
            return False
        return bool(reconciled and reconciled.delivered_at is not None)


def audit_approval_decision(world, event, *, effect_guard=None) -> bool:
    """Deliver an approval's queued votes in durable occurrence order.

    The world-model outbox is the authority seam: an audit refusal leaves every
    later vote durable but non-effective. A retry uses stable event ids and
    resumes at the oldest undelivered row, so a quorum-reaching vote cannot
    overtake an earlier sign-off in the signed chain.
    """
    try:
        pending = world.pending_approval_audit_events(
            approval_id=event.approval_id, limit=1000,
        )
    # failure-policy: fail_soft_with_audit
    except Exception:
        log.exception("approval audit outbox could not be read (event_id=%s)", event.event_id)
        return False
    for queued in pending:
        if not deliver_approval_audit_event(world, queued,
                **({"effect_guard": effect_guard} if effect_guard is not None else {})):
            return False
    try:
        current = world.get_approval_audit_event(event.event_id)
    except Exception:
        return False
    return bool(current and current.delivered_at is not None)


# ----------------------------------------------------------------------------
# A second person approves high-risk actions when one is available.
# ----------------------------------------------------------------------------

_SEPARATE_APPROVER_WORDS = {
    "always": "You asked for this, so someone else must approve it.",
    "when_available": "Another approver is available, so someone else must approve this.",
}


def other_approver_available(world: Any, approval: Any, requester: str) -> bool:
    """Whether someone other than ``requester`` could decide ``approval`` now.

    The people who can decide are the dashboard's to name (its roles, content
    access and linked chat accounts); the kernel without the dashboard has no
    such roster, so nobody else is known there."""
    try:
        from maverick_dashboard.approval_decisions import other_eligible_approvers
    except ImportError:
        return False
    return bool(other_eligible_approvers(world, approval, requester))


def separate_approver_refusal(world: Any, approval: Any, who: str) -> str:
    """Why ``who`` may not approve ``approval`` themselves, or ``""``.

    Only the person who asked is ever refused, only for a High or Critical
    request with one approver, and only as ``[approval] separate_approver``
    says: always, or (the default) whenever another person could decide it.
    A publication bypass (``ALWAYS_SEPARATE_PROVENANCES``) is always refused.
    Rejecting is never refused. Every surface asks this one question: the
    Approvals page disables its Approve button with the sentence, and
    :func:`record_vote` refuses the vote with it."""
    requester = " ".join(str(getattr(approval, "requested_by", "") or "").split())
    if not requester or requester != " ".join(str(who or "").split()):
        return ""
    from .safety.dual_control import separate_approver_applies, separate_approver_mode

    if not separate_approver_applies(getattr(approval, "risk", ""),
                                     getattr(approval, "approvals_required", 1)):
        return ""
    mode = separate_approver_mode()
    if getattr(approval, "provenance", None) in ALWAYS_SEPARATE_PROVENANCES:
        mode = "always"
    if mode == "never":
        return ""
    if mode == "when_available" and not other_approver_available(world, approval, requester):
        return ""
    return _SEPARATE_APPROVER_WORDS.get(mode, _SEPARATE_APPROVER_WORDS["always"])


def require_separate_approver(world: Any, approval_id: int, who: str) -> None:
    """Refuse the requester's own approval when someone else must give it.

    Surfaces call this before they record the confirmation step, and
    :func:`record_vote` calls it again before the vote. A retry of a vote that
    was already accepted keeps its original outcome."""
    approval = world.get_approval(int(approval_id))
    if approval is None or approval.status != "pending":
        return  # the decision path answers "already decided"
    refusal = separate_approver_refusal(world, approval, who)
    if refusal and world.get_approval_audit_event(
            world.approval_audit_event_id(int(approval_id), "approved", who)) is None:
        raise ChannelApprovalRefused("separate_approver", refusal)


# ----------------------------------------------------------------------------
# The vote itself (shared by the dashboard routes and every channel).
# ----------------------------------------------------------------------------

def record_vote(world: Any, approval_id: int, status: str, who: str, *,
                reviewed_card: dict | None = None, effect_guard=None) -> Any:
    """Apply one approver's vote and return its outbox event.

    The person who asked may be told to leave a High or Critical approval to
    someone else (``separate_approver``, see :func:`separate_approver_refusal`).
    Under N-of-M dual control a vote can be refused for segregation-of-duties
    reasons (the requester can't self-approve, or an approver identity is
    needed) -- ``vote_not_accepted`` -- which is distinct from an unknown or
    already-decided approval (``not_pending``) and from a final decision that
    is still awaiting signed audit delivery (``pending_finalization``).

    A commit acknowledgement can be lost after both the vote and its outbox
    row are durable: the vote's stable id lets us prove that outcome before
    deciding whether this request failed (``outcome_uncertain`` is safe to
    retry; ``outbox_integrity_error`` is not).
    """
    if status == "approved":
        require_separate_approver(world, approval_id, who)
    event_id = world.approval_audit_event_id(approval_id, status, who)
    try:
        options = {"reviewed_card": reviewed_card} if reviewed_card is not None else {}
        if effect_guard is not None:
            options["effect_guard"] = effect_guard
        event = world.decide_approval_audited(approval_id, status, decided_by=who, **options)
    except ChannelApprovalRefused:
        # A known atomic review refusal is not a lost commit acknowledgement.
        # Never replace it with an unrelated pre-existing vote's readback.
        raise
    except Exception as decision_error:
        try:
            event = world.get_approval_audit_event(event_id)
        except Exception as reconcile_error:
            log.exception("approval decision outcome is uncertain (event_id=%s)", event_id)
            raise ChannelApprovalRefused(
                "outcome_uncertain",
                "The decision's outcome is uncertain; it is safe to try again.",
                decision_id=event_id, retry_safe=True,
            ) from reconcile_error
        if event is not None and not event.matches(approval_id, status, who):
            log.critical(
                "approval outbox identity mismatch during commit reconciliation (event_id=%s)",
                event_id,
            )
            raise ChannelApprovalRefused(
                "outbox_integrity_error",
                "The decision could not be recorded consistently; do not retry it.",
                decision_id=event_id, retry_safe=False,
            ) from decision_error
        if event is None:
            raise decision_error
    if event is not None:
        return event

    st = world.approval_state(approval_id)
    if st is None or st.get("status") != "pending":
        raise ChannelApprovalRefused(
            "not_pending", "This request was already decided or no longer exists.",
        )
    if world.approval_has_pending_finalization(approval_id):
        raise ChannelApprovalRefused(
            "pending_finalization",
            "a final decision is accepted and awaiting signed audit delivery",
        )
    raise ChannelApprovalRefused(
        "vote_not_accepted",
        "vote not accepted: the requester can't approve their own request "
        "(segregation of duties), or an approver identity is required for "
        "multi-party approval",
    )


def require_current_card(approval: Any, *, binding: str | None, now: float | None = None) -> None:
    """Reject a stale page or card, an expired card, or a corrupted or legacy
    structured approval before an approval vote is recorded."""
    from .approval_cards import (
        ApprovalCardError,
        decode_approval_detail,
        require_current_approval_card,
    )

    try:
        card = decode_approval_detail(approval.detail)
        if card is None:
            raise ApprovalCardError(
                "this approval predates exact-operation review; reject it and "
                "ask the requester to prepare a fresh review"
            )
        # Any character, even a lone surrogate from a JSON escape, is a mismatch, not an error.
        if not text_equals(str(card["action"]), str(approval.action)):
            raise ApprovalCardError(
                "the approval card does not match the queued action; request a fresh review"
            )
        if not binding:
            raise ApprovalCardError(
                "review the current approval card before submitting this decision"
            )
        require_current_approval_card(card, expected_binding=binding, now=now)
    except ApprovalCardError as exc:
        reason = "expired" if "expired" in str(exc) else "stale_card"
        raise ChannelApprovalRefused(reason, str(exc)) from exc


def require_acknowledgement(approval: Any, *, who: str, channel: str, decision: str = "approved",
                            confirmed: bool = False, acknowledged: bool | None = None,
                            typed_confirmation: str | None = None) -> None:
    """The confirmation step for High and Critical risk, on every surface.

    Approving needs the second step (``confirmed``: the dashboard's
    confirmation panel, a chat confirm card or dialog) and, while
    ``[approval] require_acknowledgement`` is on, the acknowledgement that the
    person read what the action will do (``acknowledged``; the dashboard and
    Teams send it as a field, Slack's confirm dialog is the acknowledgement,
    so ``None`` means "the same as confirmed") plus the typed word ``APPROVE``
    for Critical risk. Rejecting never needs the second step; a confirmed
    rejection is still recorded. The outcome is written to the audit log as
    ``approval_confirmation`` with the channel.
    """
    from . import audit

    risk = str(getattr(approval, "risk", "") or "").lower()
    if risk not in CONFIRM_RISKS:
        return
    approving = decision == "approved"
    if approving and not confirmed:
        raise ChannelApprovalRefused(
            "confirm_required",
            f"This is a {risk} risk action. Confirm it before it is approved.",
        )
    if not approval_requires_acknowledgement():
        return
    if approving:
        if not (confirmed if acknowledged is None else bool(acknowledged)):
            raise ChannelApprovalRefused(
                "acknowledgement_required",
                "Confirm you have read what this action will do before approving it.",
            )
        typed = " ".join(str(typed_confirmation or "").split()).lower()
        if risk == "critical" and typed != TYPED_CONFIRMATION:
            raise ChannelApprovalRefused(
                "typed_confirmation_required",
                "Type APPROVE to confirm this critical action.",
            )
    elif not confirmed:
        return
    label = safe_action_label(approval)
    where = "" if channel == "dashboard" else f" on {channel}"
    recorded = audit.audit_event(
        audit.EventKind.CONSENT_RESULT,
        agent=who,
        actor=who,
        action="approval_confirmation",
        approval_id=int(approval.id),
        risk=risk,
        acknowledged=True,
        typed_confirmation=(risk == "critical" and approving),
        channel=channel,
        summary=(
            f"{who} confirmed reading what '{label}' will do ({risk} risk) before "
            f"{'approving' if approving else 'rejecting'} it{where}."
        ),
    )
    if not recorded:
        log.warning("approval confirmation audit write failed (approval_id=%s)", approval.id)


def decide_from_channel(
    world: Any,
    approval_id: int,
    decision: str,
    *,
    principal: str,
    channel: str,
    binding: str | None = None,
    confirmed: bool = False,
    acknowledged: bool | None = None,
    typed_confirmation: str | None = None,
    channel_user: str = "",
    authorize: Authorizer | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Record one approver's vote from ``channel`` and deliver its signed audit.

    ``decision`` is ``"approved"`` or ``"denied"``. ``authorize`` is the
    surface's permission check (the dashboard's ``operate`` role rule), run
    once the request is known to be pending. Raises
    :class:`ChannelApprovalRefused` when nothing was recorded: not linked to a
    Lightwork user, a protected-settings change (dashboard only), an expired,
    stale or legacy card, a High or Critical risk without the confirmation
    step or the acknowledgement, an already-decided request, or a
    segregation-of-duties refusal. A decision made after an undo is a new
    signed audit round, exactly as on the Approvals page.

    The returned mapping says whether the vote is already effective (audit
    delivered), the approval's status afterwards and how long it can still be
    undone.
    """
    from . import audit

    if decision not in ("approved", "denied"):
        raise ValueError("decision must be 'approved' or 'denied'")
    if channel not in CHANNELS:
        raise ValueError(f"unknown channel {channel!r}")
    who = " ".join(str(principal or "").split())
    if not who:
        raise ChannelApprovalRefused(
            "unlinked", "Your chat account isn't linked to a Lightwork user yet.",
        )
    current = time.time() if now is None else float(now)
    approval = world.get_approval(int(approval_id))
    if approval is None or approval.status != "pending":
        raise ChannelApprovalRefused(
            "not_pending", "This request was already decided or no longer exists.",
        )
    from .approval_vote_review import channel_vote_review

    review = channel_vote_review(world, approval, status=decision, actor=who, binding=binding)
    if authorize is not None:
        authorize(who, int(approval_id))
    if approval.provenance == SETTINGS_PROVENANCE:
        raise ChannelApprovalRefused(
            "dashboard_only",
            "Changes to protected settings are decided in the Lightwork dashboard, "
            "not from chat.",
        )
    if decision == "approved":
        require_current_card(approval, binding=binding, now=current)
        if channel != "dashboard":
            from .approval_cards import decode_approval_detail

            card = decode_approval_detail(approval.detail)
            if card and card.get("display"):
                raise ChannelApprovalRefused(
                    "dashboard_only",
                    "Review and approve the full operation on the Lightwork Approvals page.",
                )
        require_separate_approver(world, int(approval_id), who)
    require_acknowledgement(approval, who=who, channel=channel, decision=decision,
                            confirmed=confirmed, acknowledged=acknowledged,
                            typed_confirmation=typed_confirmation)
    event = record_vote(world, int(approval_id), decision, who, reviewed_card=review)
    delivered = audit_approval_decision(world, event)
    try:
        state = world.approval_state(int(approval_id)) or {}
    except Exception:  # noqa: BLE001 -- the vote is durable; the read is diagnostic
        state = {}
    # An unreadable state is not evidence that the vote settled the request: a
    # multi-approver request is still pending after one approval.
    status = str(state.get("status") or "pending")
    effective = bool(delivered and status != "pending")
    try:
        # The signed APPROVAL_DECISION above is the authority; this note says
        # which channel (and which chat account) carried the decision.
        audit.audit_event(
            audit.EventKind.CHANNEL_APPROVAL_DECISION,
            agent=who,
            action="approval_decided_via_channel",
            approval_id=int(approval_id),
            decision=decision,
            channel=channel,
            channel_user=str(channel_user or ""),
            decided_by=who,
            effective=effective,
            decision_id=event.event_id,
            approval_event_id=event.event_id,
        )
    except Exception:  # noqa: BLE001 -- the signed decision chain above is the authority
        log.warning("channel approval audit note failed", exc_info=True)
    return {
        "approval_id": int(approval_id),
        "decision": decision,
        "status": status,
        "effective": effective,
        "decided_by": who,
        "channel": channel,
        "risk": str(approval.risk),
        "audit": "delivered" if delivered else "pending",
        "approvals_required": int(state.get("approvals_required") or 1),
        "approved_count": int(state.get("approved_count") or 0),
        "decision_id": event.event_id,
        # The card offers Undo for this long; the agent-side consumer waits
        # the same window before acting. Nothing waits on other requests.
        "undo_seconds": approval_undo_grace_seconds() if effective and held_for_undo(approval) else 0.0,
        "decided_at": time.time(),
    }


def undo_decision(world: Any, approval_id: int, *, undone_by: str, channel: str,
                  channel_user: str = "", authorize: Authorizer | None = None) -> dict[str, Any]:
    """Undo a decision made moments ago, returning the request to pending.

    Allowed only while the decision can still be undone (``[approval]
    undo_grace_seconds``, default 30): the agent-side consumer waits that long
    before acting, so nothing has run yet. After that the answer is a plain
    ``too_late``. The undo is written to the audit log with the channel; the
    original decision stays in the signed chain and the next decision is a
    new audit round (``WorldModel.undo_approval_decision``).
    """
    from . import audit

    who = " ".join(str(undone_by or "").split())
    if not who:
        raise ChannelApprovalRefused(
            "unlinked", "Your chat account isn't linked to a Lightwork user yet.",
        )
    before = world.get_approval(int(approval_id))
    if before is None:
        raise ChannelApprovalRefused("not_found", "This request no longer exists.")
    if authorize is not None:
        authorize(who, int(approval_id))
    outcome = world.undo_approval_decision(
        int(approval_id), undone_by=who, within_seconds=approval_undo_grace_seconds(),
    )
    if outcome == "not_found":
        raise ChannelApprovalRefused("not_found", "This request no longer exists.")
    if outcome == "not_decided":
        raise ChannelApprovalRefused("not_decided", "There is no decision to undo yet.")
    if outcome == "final":
        raise ChannelApprovalRefused(
            "final",
            "This decision can't be undone: it took effect when it was made. "
            "Ask for a new request if it should not go ahead.",
        )
    if outcome != "undone":
        raise ChannelApprovalRefused(
            "too_late",
            "Too late to undo: the agent has already been told about this decision. "
            "Ask for a new request if it should not go ahead.",
        )
    label = safe_action_label(before)
    previous = "approval" if before.status == "approved" else "rejection"
    where = "" if channel == "dashboard" else f" on {channel}"
    try:
        recorded = audit.audit_event(
            audit.EventKind.CONSENT_RESULT,
            agent=who,
            actor=who,
            action="approval_decision_undone",
            approval_id=int(approval_id),
            previous_status=before.status,
            previously_decided_by=before.decided_by or "",
            channel=channel,
            channel_user=str(channel_user or ""),
            summary=(
                f"{who} undid the {previous} of '{label}'{where}; it is waiting for a decision again."
            ),
        )
    except audit.AuditRefused:
        # The undo is already applied; report it as every other unrecorded
        # undo is reported, not as a server error.
        recorded = False
    if not recorded:
        raise ChannelApprovalRefused(
            "audit_failed",
            "The decision was undone but could not be recorded in the audit log.",
        )
    return {"approval_id": int(approval_id), "status": "pending",
            "previous_status": before.status, "undone_by": who, "channel": channel,
            "audited": True}


# ----------------------------------------------------------------------------
# Announcing a new request on chat channels (best-effort, never blocks consent)
# ----------------------------------------------------------------------------

_announcers: dict[str, Any] = {}


def register_approval_announcer(channel: str, announcer) -> None:
    """``announcer(approval, content) -> bool`` posts a new card on ``channel``
    (the Teams adapter registers here; Slack is built in). ``None`` removes it."""
    if announcer is None:
        _announcers.pop(channel, None)
    else:
        _announcers[channel] = announcer


def slack_announcements_configured() -> bool:
    """Whether a Slack approvals channel and bot token are set."""
    try:
        from .config import load_config
        from .slack_interactive import slack_bot_token

        section = (load_config().get("channels") or {}).get("slack") or {}
    except Exception:  # noqa: BLE001 -- config never blocks an approval
        return False
    if not isinstance(section, dict):
        return False
    room = str(section.get("approvals_channel") or os.environ.get("SLACK_APPROVALS_CHANNEL") or "").strip()
    return bool(room and slack_bot_token())


def registered_announcers() -> tuple[str, ...]:
    """The channels adapters registered with :func:`register_approval_announcer`."""
    return tuple(_announcers)


def _slack_announcer(approval, content: dict[str, Any]) -> bool:
    from .config import load_config
    from .daily_digest import dashboard_url
    from .slack_interactive import approval_blocks, post_message, slack_bot_token

    section = (load_config().get("channels") or {}).get("slack") or {}
    if not isinstance(section, dict):
        return False
    room = str(section.get("approvals_channel") or os.environ.get("SLACK_APPROVALS_CHANNEL") or "").strip()
    token = slack_bot_token()
    if not room or not token:
        return False
    blocks = approval_blocks(content, dashboard_url=dashboard_url())
    return post_message(token, room, f"Approval needed: {content['action']} (#{content['id']})",
                        blocks) is not None


def announce_new_approval(world, approval_id: int) -> dict[str, bool]:
    """Post a freshly parked request to every configured chat channel.

    ``maverick.approval_notify`` calls this on a background thread right after
    ``WorldModel.create_approval`` commits the row (the one call site).
    Failures are logged by type only and never delay or change the approval.
    """
    try:
        approval = world.get_approval(int(approval_id))
    except Exception:  # noqa: BLE001
        return {}
    if approval is None:
        return {}
    content = card_content(approval)
    outcomes: dict[str, bool] = {}
    for name, announcer in {"slack": _slack_announcer, **_announcers}.items():
        try:
            outcomes[name] = bool(announcer(approval, content))
        except Exception as exc:  # noqa: BLE001 -- best-effort by design
            log.warning("approval announcement on %s failed: %s", name, type(exc).__name__)
            outcomes[name] = False
    return outcomes


__all__ = [
    "CHANNELS",
    "CONFIRM_RISKS",
    "SETTINGS_PROVENANCE",
    "TYPED_CONFIRMATION",
    "ChannelApprovalRefused",
    "announce_new_approval",
    "approval_requires_acknowledgement",
    "approval_undo_grace_seconds",
    "audit_approval_decision",
    "card_content",
    "decide_from_channel",
    "decision_summary",
    "deliver_approval_audit_event",
    "needs_confirmation",
    "other_approver_available",
    "record_vote",
    "register_approval_announcer",
    "registered_announcers",
    "require_acknowledgement",
    "require_current_card",
    "require_separate_approver",
    "safe_action_label",
    "separate_approver_refusal",
    "slack_announcements_configured",
    "spending_text",
    "undo_decision",
    "held_for_undo",
    "undo_seconds_left",
]
