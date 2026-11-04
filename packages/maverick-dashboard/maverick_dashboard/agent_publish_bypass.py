"""Four-eyes approval for publishing changed instructions without a passing run.

With ``[agent_tests] bypass_requires_second_person`` on, the reasoned bypass of
a failing or missing run is not enough by itself. The publication waits for a
different administrator to approve it on the Approvals page. The request is an
ordinary approval in the world model (the same path the data-use four-eyes
gate uses): its card binds the exact complete draft and the reason, the person
who asked cannot approve it, and one approval covers one publication.
"""
from __future__ import annotations

from fastapi import HTTPException

ACTION = "agent_publish.bypass_passing_tests"
PROVENANCE = "agent_publish.bypass.four_eyes.v1"
TTL_SECONDS = 24 * 3600
WAITING = ("This publication without passing tests is waiting for another administrator to approve its reason "
           "on the Approvals page. Publish again with the same reason once it is approved. Nothing was changed.")
REQUESTED = ("Publishing without passing tests needs another administrator to approve the reason first. "
             "The request is on the Approvals page; publish again with the same reason once it is approved. "
             "Nothing was changed.")


def is_bypass(approval) -> bool:
    return approval is not None and approval.action == ACTION and approval.provenance == PROVENANCE


def _parameters(profile: dict, reason: str) -> dict:
    from maverick.approval_cards import digest

    return {"profile_sha256": digest(profile), "reason_sha256": digest(reason)}


def _card(detail: str | None) -> dict | None:
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail

    try:
        return decode_approval_detail(detail)
    except (ApprovalCardError, TypeError, ValueError):
        return None


def _card_current(detail: str | None) -> bool:
    from maverick.approval_cards import ApprovalCardError, require_current_approval_card

    card = _card(detail)
    if card is None:
        return False
    try:
        require_current_approval_card(card)
    except (ApprovalCardError, KeyError, TypeError, ValueError):
        return False
    return True


def second_person_approval(request, name: str, profile: dict, reason: str, *, used) -> dict:
    """The approval a different administrator gave for exactly this publication, or a 409.

    ``profile`` is the complete draft being published and ``used(approval_id)``
    tells whether an earlier publication already spent that approval. When there
    is none, a request is queued on the Approvals page and the publication is
    refused until someone else approves it.
    """
    from maverick.approval_cards import digest, encode_operation_approval_detail
    from maverick.audit import AuditRefused, EventKind, audit_event

    from . import auth
    from ._shared import _world

    requester = auth.caller_principal(request)
    if not requester:
        raise HTTPException(status_code=403, detail=(
            "A second person must approve publishing without passing tests, so sign in with your own "
            "account first. Nothing was changed."))
    world = _world()
    wanted_target = digest({"specialist": name})
    wanted_parameters = digest(_parameters(profile, reason))
    newest = None
    for row in world.list_approvals(limit=5000):  # newest first
        if row.action != ACTION or row.provenance != PROVENANCE or row.requested_by != requester:
            continue
        card = _card(row.detail)
        if card is None or card["target"]["sha256"] != wanted_target or card["parameters"]["sha256"] != wanted_parameters:
            continue
        newest = row
        break
    if newest is not None:
        if newest.status == "pending":
            raise HTTPException(status_code=409, detail=WAITING)
        if (newest.status == "approved" and newest.decided_by and newest.decided_by != requester
                and not used(newest.id) and _card_current(newest.detail)):
            return {"approval": newest.id, "requested_by": requester, "approved_by": newest.decided_by}
    try:
        recorded = audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard",
                               verb="agent_publish_bypass_requested", actor=requester, specialist=name, reason=reason)
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail="The activity record is unavailable; nothing was requested.") from exc
    if not recorded:
        raise HTTPException(status_code=503, detail="The activity record is unavailable; nothing was requested.")
    detail = encode_operation_approval_detail(
        action=ACTION,
        summary="Publish changed instructions without passing tests",
        target_label=f"Specialist {name}"[:500],
        target={"specialist": name},
        parameters=_parameters(profile, reason),
        parameter_summary=[f"Specialist: {name}", f"Reason given: {reason}"[:500]],
        actor=requester,
        role="admin",
        known_effects=["Once approved, the person who asked can publish these exact changes once, "
                       "without a passing test run."],
        unresolved_assumptions=[],
        before="The specialist keeps the definition it has now.",
        after="The reviewed complete draft is published without a passing test run.",
        irreversible=False,
        ttl_seconds=TTL_SECONDS,
    )
    world.create_approval(ACTION, risk="high", scope=name, detail=detail, provenance=PROVENANCE,
                          approvals_required=1, requested_by=requester)
    raise HTTPException(status_code=409, detail=REQUESTED)


def may_decide(request) -> bool:
    """Whether this caller may read and decide a bypass request: the same pack-editing check publishing makes."""
    from . import auth
    from .editor_policy import pack_editing_denial

    return auth.has_permission(request, "admin") and pack_editing_denial(request) is None


def pack_editor(principal: str) -> bool:
    """:func:`may_decide` for a chat decision, which has a linked person but no request: the pack-editor roster
    and the pack-editing switch, as the dashboard's own check reads them."""
    from maverick.config import get_features

    from . import auth

    if not principal or not auth.is_dashboard_admin(principal):
        return False
    return bool(get_features().get("pack_editing", True))


def require_decider(request, approval, who: str, *, approving: bool) -> None:
    """Only a person who may publish decides a bypass request (the same check publishing makes),
    and never the person who asked for it."""
    if not is_bypass(approval):
        return
    from .editor_policy import require_pack_editing as _require_pack_editing

    _require_pack_editing(request)
    if approving and approval.requested_by and who == approval.requested_by:
        raise HTTPException(status_code=403, detail=(
            "You asked for this publication without passing tests, so another administrator must approve it."))


__all__ = ["ACTION", "PROVENANCE", "is_bypass", "may_decide", "require_decider", "second_person_approval"]
