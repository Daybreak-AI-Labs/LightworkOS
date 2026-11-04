"""The dashboard's layer over the shared approval decision path.

The primitives (card check, acknowledgement rule, audited vote with undo
rounds, signed audit delivery, undo) live in :mod:`maverick.channel_approvals`
so the Approvals page, the Microsoft Teams cards and the Slack cards share ONE
implementation. This module adds only what the dashboard owns: the HTTP
error mapping the ``/api/v1/approvals/{id}/approve|deny|undo`` routes answer
with, the role check for a chat vote (the linked person needs ``operate``,
like a dashboard voter), the "send back for changes" form of a denial, the
queue-row projection the Teams cards render, and who else could decide a
request (:func:`eligible_approvers`), which the shared separate-approver rule
asks before the person who asked may approve their own high-risk request.
"""
from __future__ import annotations

import logging

from fastapi import HTTPException
from maverick.channel_approvals import (
    CONFIRM_RISKS,
    SETTINGS_PROVENANCE,
    ChannelApprovalRefused,
    approval_requires_acknowledgement,
    approval_undo_grace_seconds,
    audit_approval_decision,
    deliver_approval_audit_event,
    record_vote,
    require_acknowledgement,
    require_current_card,
    require_separate_approver,
    safe_action_label,
    separate_approver_refusal,
)
from maverick.channel_approvals import decide_from_channel as _decide_shared
from maverick.channel_approvals import undo_decision as _undo_shared

log = logging.getLogger(__name__)

# The routes and their tests reach the shared functions through these names.
_audit_approval_decision = audit_approval_decision
_deliver_approval_audit_event = deliver_approval_audit_event
_safe_action_label = safe_action_label


class ApprovalDecisionRefused(ChannelApprovalRefused):
    """A vote was not accepted; ``detail`` is a plain sentence for the person."""

    def __init__(self, detail: str, *, status_code: int = 409, reason: str = "refused") -> None:
        super().__init__(reason, detail, status_code=status_code)


def _refused(exc: ChannelApprovalRefused) -> ApprovalDecisionRefused:
    if isinstance(exc, ApprovalDecisionRefused):
        return exc
    return ApprovalDecisionRefused(exc.message, status_code=exc.status_code, reason=exc.reason)


# ------------------------------------------------------------ HTTP mapping


def require_current_decision_card(world, approval_id: int, binding: str) -> None:
    """Reject a stale card, expired card, or corrupted structured approval (409)."""
    approval = world.get_approval(approval_id)
    if approval is None or approval.status != "pending":
        return
    try:
        require_current_card(approval, binding=binding)
    except ChannelApprovalRefused as exc:
        raise HTTPException(status_code=409, detail=exc.message) from exc


def _require_separate_approver(world, approval_id: int, who: str) -> None:
    """The person who asked may have to leave a high-risk approval to someone
    else (403 with the plain reason), checked before any confirmation is
    recorded. The shared vote checks it again."""
    try:
        require_separate_approver(world, approval_id, who)
    except ChannelApprovalRefused as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def _require_acknowledgement(world, approval_id: int, payload: dict, who: str, *,
                             channel: str = "dashboard") -> None:
    """High and critical risk approvals need an explicit acknowledgement.

    The Approvals page collects it in its confirmation step; API callers send
    ``{"acknowledged": true}`` and, for critical risk, ``"confirmation":
    "approve"`` typed by the person; the Teams confirm card sends the same
    payload. Off via ``[approval] require_acknowledgement = false``. The outcome
    is written to the audit log as ``approval_confirmation`` with the channel.
    """
    approval = world.get_approval(approval_id)
    if approval is None or approval.status != "pending":
        return
    payload = payload if isinstance(payload, dict) else {}
    try:
        require_acknowledgement(
            approval, who=who, channel=channel, decision="approved", confirmed=True,
            acknowledged=payload.get("acknowledged") is True,
            typed_confirmation=str(payload.get("confirmation") or ""),
        )
    except ChannelApprovalRefused as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def _record_vote_or_raise(world, approval_id: int, status: str, who: str, *,
                          reviewed_card: dict | None = None, effect_guard=None):
    """Apply one approver's vote, mapping a refusal to the right HTTP error.

    Segregation-of-duties refusals are 403, an unknown/already-decided approval
    404, a final decision awaiting signed audit delivery 409; the two
    commit-reconciliation outcomes keep their stable decision id in the
    response so a retry is keyed exactly."""
    try:
        options = {"effect_guard": effect_guard} if effect_guard is not None else {}
        if reviewed_card is not None:
            options["reviewed_card"] = reviewed_card
        return record_vote(world, approval_id, status, who, **options)
    except ChannelApprovalRefused as exc:
        if exc.reason in ("outcome_uncertain", "outbox_integrity_error"):
            state = "uncertain" if exc.reason == "outcome_uncertain" else "integrity_error"
            headers = {
                "X-Lightwork-Decision-Id": exc.decision_id or "",
                "X-Lightwork-Approval-State": state,
            }
            if exc.retry_safe:
                headers["Retry-After"] = "1"
            raise HTTPException(
                status_code=exc.status_code,
                detail={
                    "decision": exc.reason,
                    "decision_id": exc.decision_id,
                    "retry_safe": bool(exc.retry_safe),
                },
                headers=headers,
            ) from exc
        if exc.reason == "not_pending":
            raise HTTPException(status_code=404, detail="no such pending approval") from exc
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc


def undo_from_dashboard(world, approval_id: int, *, who: str) -> dict:
    """The ``/approvals/{id}/undo`` route's undo, through the shared rule."""
    try:
        result = _undo_shared(world, int(approval_id), undone_by=who, channel="dashboard")
    except ChannelApprovalRefused as exc:
        if exc.reason == "not_found":
            raise HTTPException(status_code=404, detail="no such approval") from exc
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    return {"status": "pending", "previous_status": result["previous_status"],
            "undone_by": result["undone_by"], "approval_id": int(approval_id)}


# ----------------------------------------------------------------- channels


def _audit_channel_denial(principal: str, *, channel: str, approval_id: int, reason: str) -> None:
    """Record a refused chat decision the way ``require_approval_authority`` records a refused one."""
    from maverick import audit
    from maverick.approval_cards import digest
    from maverick.paths import current_tenant_id_strict

    audit.audit_event(
        audit.EventKind.CAPABILITY_DENIED,
        agent=principal,
        action="approval.decide",
        principal=principal,
        channel=channel,
        tenant=current_tenant_id_strict() or "",
        resource_sha256=digest({"kind": "approval", "resource": str(approval_id)}),
        reason=reason,
    )


def _channel_authority(principal: str, *, channel: str, approval_id: int) -> None:
    """The linked Lightwork user must hold ``operate``, like a dashboard voter.

    A denial is audited the same way ``require_approval_authority`` audits one.
    """
    from . import rbac
    from .auth import role_for_principal

    role = role_for_principal(principal)
    if "operate" in rbac.permissions_for(role):
        return
    _audit_channel_denial(principal, channel=channel, approval_id=approval_id, reason="approval_authority_missing")
    raise ApprovalDecisionRefused(
        "Your Lightwork account can't decide approvals. Ask an administrator for "
        "the operator role.", status_code=403, reason="not_permitted",
    )


def _bypass_authority(principal: str, *, channel: str, approval_id: int) -> None:
    """A publication bypass is decided by a pack editor, in chat as on the Approvals page.

    The linked person must be on the same pack-editor roster the dashboard checks. Only the
    approval itself is refused here; the requester's own approval is refused by the shared rule.
    """
    from . import agent_publish_bypass
    from ._shared import _world

    approval = _world().get_approval(int(approval_id))
    if not agent_publish_bypass.is_bypass(approval) or agent_publish_bypass.pack_editor(principal):
        return
    _audit_channel_denial(principal, channel=channel, approval_id=approval_id, reason="pack_editing_missing")
    raise ApprovalDecisionRefused(
        "Only an administrator who can edit agents can decide this publication. Ask one to decide it "
        "on the Approvals page or in chat.", status_code=403, reason="not_permitted",
    )


def _authority_for(channel: str):
    def authorize(principal: str, approval_id: int) -> None:
        _channel_authority(principal, channel=channel, approval_id=approval_id)
        _bypass_authority(principal, channel=channel, approval_id=approval_id)
    return authorize


def decide_from_channel(*, approval_id: int, status: str, principal: str, binding: str,
                        channel: str, channel_user: str = "", confirmed: bool = False,
                        acknowledgement: dict | None = None, world=None) -> dict:
    """Record a vote that arrived through a chat channel.

    Returns ``{"status", "effective", "decided_by", "risk", "audit", ...}``.
    Raises :class:`ApprovalDecisionRefused` with a plain sentence when the vote
    cannot be accepted: not linked to a permitted user (the linked person needs
    the ``operate`` role, like a dashboard voter), a protected-settings change
    (dashboard only), a high or critical risk without the confirmation step
    (``confirmed``) or without the acknowledgement the dashboard also demands
    (``acknowledgement={"acknowledged": True, "confirmation": "approve"}``, the
    typed word only for critical risk), an expired or already-decided card, or
    a segregation-of-duties refusal. A decision made after an undo is a new
    signed audit round, exactly as on the Approvals page.
    """
    from ._shared import _world

    world = world if world is not None else _world()
    ack = acknowledgement if isinstance(acknowledgement, dict) else {}
    try:
        return _decide_shared(
            world, int(approval_id), status, principal=principal, channel=channel,
            binding=binding, confirmed=confirmed,
            acknowledged=ack.get("acknowledged") is True,
            typed_confirmation=str(ack.get("confirmation") or ""),
            channel_user=channel_user, authorize=_authority_for(channel),
        )
    except ChannelApprovalRefused as exc:
        raise _refused(exc) from exc


def undo_from_channel(*, approval_id: int, principal: str, channel: str,
                      channel_user: str = "", world=None) -> dict:
    """Undo a decision made moments ago from a chat card (the dashboard's
    ``/approvals/{id}/undo``): the request returns to pending while the grace
    window is open, and the undo is written to the audit log with the channel.
    """
    from ._shared import _world

    world = world if world is not None else _world()
    try:
        result = _undo_shared(world, int(approval_id), undone_by=principal, channel=channel,
                              channel_user=channel_user, authorize=_authority_for(channel))
    except ChannelApprovalRefused as exc:
        raise _refused(exc) from exc
    return {"status": "pending", "previous_status": result["previous_status"],
            "undone_by": result["undone_by"], "approval_id": int(approval_id)}


def send_back_from_channel(*, approval_id: int, principal: str, rationale: str,
                           channel: str, channel_user: str = "", world=None) -> dict:
    """The chat form of "Send back for changes": a denial plus the note.

    Mirrors ``/api/v1/approvals/{id}/revise`` so the requester gets the same
    superseded record and rationale.
    """
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail

    text = " ".join(str(rationale or "").split())
    if not text:
        raise ApprovalDecisionRefused("Type the question or note to send back.", status_code=422)
    if len(text) > 2_000:
        raise ApprovalDecisionRefused("The note is too long.", status_code=422)
    try:
        from maverick.safety.secret_detector import redact

        text, _matches = redact(text)
    except Exception:  # noqa: BLE001
        text = "Revision requested; rationale was removed because redaction failed."
    from ._shared import _world

    world = world if world is not None else _world()
    row = world.get_approval(int(approval_id))
    if row is None or row.status != "pending":
        raise ApprovalDecisionRefused(
            "This request was already decided or no longer exists.", status_code=404,
        )
    old_binding = ""
    try:
        card = decode_approval_detail(row.detail)
        old_binding = str(card["binding_sha256"]) if card is not None else ""
    except (ApprovalCardError, KeyError, TypeError, ValueError):
        pass
    result = decide_from_channel(approval_id=approval_id, status="denied", principal=principal,
                                 binding="", channel=channel, channel_user=channel_user,
                                 world=world)
    if not result["effective"]:
        return {**result, "rationale": text}
    from maverick import audit

    recorded = audit.audit_event(
        audit.EventKind.CONSENT_RESULT,
        agent=result["decided_by"],
        actor=result["decided_by"],
        action="approval_revision_requested",
        approval_id=int(approval_id),
        channel=channel,
        superseded_binding_sha256=old_binding,
        producer=row.provenance or "consent",
        original_action=row.action,
        rationale=text,
    )
    if not recorded:
        raise ApprovalDecisionRefused(
            "The request was sent back but the note could not be recorded.", status_code=503,
        )
    return {**result, "status": "superseded", "rationale": text}


# ------------------------------------------------------ who can decide a request


def _may_decide(principal: str) -> bool:
    """Holds ``operate`` in this workspace and is not deprovisioned."""
    from . import rbac, scim_groups
    from .auth import role_for_principal

    try:
        if "operate" not in rbac.permissions_for(role_for_principal(principal)):
            return False
        return scim_groups.active_for_principal(principal) is not False
    except Exception:  # an unreadable roster lets nobody decide, so nobody counts
        return False


def _chat_approvers(approval) -> set[str]:
    """People linked in a chat app where this request's card is posted.

    Slack posts every card to its approvals channel and Teams to each linked
    approver; protected-settings requests are decided in the dashboard only.
    With company sign-in (OIDC) a chat decision is resolved through the sign-in
    bridge instead of these links, so nobody is counted from them."""
    if getattr(approval, "provenance", None) == SETTINGS_PROVENANCE:
        return set()
    try:
        from maverick.oidc import oidc_enabled

        if oidc_enabled():
            return set()
    except Exception:  # unreadable sign-in settings count nobody from chat
        return set()
    people: set[str] = set()
    try:
        from maverick.channel_approvals import slack_announcements_configured

        if slack_announcements_configured():
            from maverick.channel_identities import all_links

            people.update(principal for principal, links in all_links().items()
                          if any(link.get("channel") == "slack" for link in links))
    except Exception:  # an unreadable link store adds nobody
        pass
    try:
        from maverick.approval_notify import teams_approvals_enabled

        if teams_approvals_enabled():
            from maverick.teams_identity import approver_links

            people.update(str(link.get("principal") or "") for link in approver_links())
    except Exception:  # an unreadable link store adds nobody
        pass
    return {person for person in people if person}


def eligible_approvers(world, approval) -> set[str]:
    """Everyone who could decide ``approval`` now, by the rules each surface
    already enforces.

    On the Approvals page: people holding ``operate`` in this workspace who
    can open the request -- its owner, or a current, reviewed read grant for
    exactly this card (:func:`content_access.approval_readers`). In Slack or
    Teams, where its card is posted: linked people holding ``operate``. A
    deprovisioned person never counts. Nobody here is invented: no new role,
    and a store that can't be read adds nobody."""
    from .content_access import approval_readers

    candidates = approval_readers(approval, world) | _chat_approvers(approval)
    return {person for person in candidates if _may_decide(person)}


def other_eligible_approvers(world, approval, requester: str) -> list[str]:
    """The eligible approvers other than ``requester``, sorted."""
    who = " ".join(str(requester or "").split())
    return sorted(person for person in eligible_approvers(world, approval) if person != who)


def own_request_note(world, approval, viewer: str) -> str:
    """What the person who asked is told when their approval can't settle it.

    ``""`` for anyone else, or when the requester may approve. With one
    approver, the separate-approver rule (``[approval] separate_approver``);
    with two or more, the requester's vote counts only when ``[security]
    allow_self_approval`` is on."""
    who = " ".join(str(viewer or "").split())
    if not who or who != " ".join(str(getattr(approval, "requested_by", "") or "").split()):
        return ""
    if max(1, int(getattr(approval, "approvals_required", 1) or 1)) > 1:
        from maverick.safety.dual_control import allow_self_approval

        return "" if allow_self_approval() else "You asked for this, so other people must approve it."
    return separate_approver_refusal(world, approval, who)


def approval_view(approval_id: int, *, world=None) -> dict | None:
    """The queue row as the dashboard shows it: safe labels, decoded card, source.

    ``None`` when the approval does not exist. ``card`` is ``None`` for a legacy
    or corrupted structured detail, which a channel must refuse to approve just
    as the dashboard disables its Approve button.
    """
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail
    from maverick.safety.secret_detector import redact

    from ._shared import _world

    world = world if world is not None else _world()
    approval = world.get_approval(int(approval_id))
    if approval is None:
        return None

    def safe(value: object, *, fallback: str = "") -> str:
        try:
            text, _matches = redact(" ".join(str(value or "").split()))
            return text[:2000]
        except Exception:  # noqa: BLE001 -- the fallback is a plain label
            return fallback

    card = None
    card_status = "legacy"
    detail = safe(approval.detail)
    try:
        card = decode_approval_detail(approval.detail)
    except ApprovalCardError:
        detail = "Structured approval details failed their integrity check."
        card_status = "invalid"
    if card is not None:
        import time as _time

        card_status = "expired" if _time.time() >= card["expires_at"] else "current"
        if card_status == "expired":
            card = None
            # ``detail`` is the stored envelope, which carries the exact
            # command; an expired request shows a sentence, never that.
            detail = "This request's decide-by time has passed. Reject it and ask for a new request."
    try:
        from .app import _approval_source

        source = _approval_source(approval.provenance)
    except Exception:  # noqa: BLE001 -- the label is decoration, never authority
        source = None
    return {
        "approval": {
            "id": approval.id,
            "action": safe(approval.action, fallback="reviewed operation"),
            "risk": str(approval.risk),
            "scope": safe(approval.scope, fallback="reviewed target"),
            "detail": detail,
            "status": approval.status,
            "provenance": approval.provenance,
            "requested_by": approval.requested_by,
        },
        "card": card,
        "card_status": card_status,
        "source_label": source,
    }


__all__ = [
    "CONFIRM_RISKS",
    "ApprovalDecisionRefused",
    "approval_requires_acknowledgement",
    "approval_undo_grace_seconds",
    "approval_view",
    "decide_from_channel",
    "eligible_approvers",
    "other_eligible_approvers",
    "own_request_note",
    "require_current_decision_card",
    "send_back_from_channel",
    "undo_from_channel",
    "undo_from_dashboard",
]
