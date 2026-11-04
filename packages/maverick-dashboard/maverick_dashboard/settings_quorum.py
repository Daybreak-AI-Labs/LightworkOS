"""Several approvers for changes to protected settings ([safety] quorum_*).

When an operator sets ``[safety] quorum_required`` (2 or more; the
environment's ``MAVERICK_QUORUM_REQUIRED`` wins), a save on Settings > All
settings that touches a protected setting (``[safety] quorum_protected_keys``,
by default every safety, governance and add-on setting and the spending limit
per task) is not written. It becomes a request in the dashboard's Approvals,
through the same approvals path agents use: N distinct approvers, never the
person who asked. Saving exactly the same change again once it is approved
applies it; the approval is then used up. A change whose values differ from
what was approved, a denied request or one older than
``[safety] quorum_ttl_days`` starts a new request.

What approvers see are the settings' names with their old and new values as
the activity record shows them (a secret only as "set" or "not set"). The
approval is also bound to the exact new values through a keyed fingerprint
(HMAC with a key derived from this installation's at-rest key), so an
approved secret can't be swapped for another one; neither the value nor an
unkeyed hash of it is stored. The request carries an approval card, so it is
decided on the Approvals page, by global administrators only (the permission
needed to save the setting) and never by the person who asked.
Unset, nothing here runs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
from typing import Any

from fastapi import HTTPException

log = logging.getLogger(__name__)

ACTION = "settings_change"
PROVENANCE = "settings_quorum"


def _shown(value: object) -> str:
    text = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    return text if len(text) <= 120 else text[:117] + "..."


def _rows(changes: list[dict], shown) -> list[tuple[str, str, str, str]]:
    return sorted(
        (c["setting"].id, c["setting"].label,
         _shown(shown(c["setting"], c["old"])), _shown(shown(c["setting"], c["new"])))
        for c in changes
    )


def _binding_key() -> bytes:
    """A key for value fingerprints, derived from the installation's at-rest key."""
    from maverick.crypto_at_rest import _load_or_create_key

    return hashlib.sha256(b"lightwork-settings-quorum-values/v1\x00"
                          + _load_or_create_key()).digest()


def _keyed_values(changes: list[dict]) -> list[tuple[str, str]]:
    """Each change's exact new value as a keyed fingerprint (sealed values
    are opened first, so re-sealing the same secret gives the same print)."""
    from maverick import config

    key = _binding_key()
    out = []
    for c in changes:
        value = config._unseal_config_tree(c["new"])
        raw = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
        out.append((c["setting"].id,
                    hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()))
    return sorted(out)


def fingerprint(changes: list[dict], shown) -> str:
    """The id a request is stored under: the exact change set as shown, bound
    to the exact new values by their keyed fingerprints."""
    body = json.dumps([[(sid, old, new) for sid, _label, old, new in _rows(changes, shown)],
                       _keyed_values(changes)], ensure_ascii=False)
    return "settings:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _card(changes: list[dict], shown, actor: str, change_id: str, ttl_days: float) -> str:
    """The approval card the Approvals page shows and the approve route checks."""
    from maverick.approval_cards import encode_operation_approval_detail

    lines = [f"{label}: {old} -> {new}" for _sid, label, old, new in _rows(changes, shown)]
    if len(lines) > 24:
        lines = lines[:23] + [f"and {len(lines) - 23} more settings"]
    lines = [line if len(line) <= 500 else line[:497] + "..." for line in lines]
    return encode_operation_approval_detail(
        action=ACTION, summary="Change protected settings",
        target_label="Settings for the whole installation",
        target={"settings": sorted(c["setting"].id for c in changes)},
        parameters={"change_id": change_id}, parameter_summary=lines,
        actor=actor, role="admin",
        known_effects=["Once approved, the person who asked can save exactly these "
                       "changes once."],
        unresolved_assumptions=[],
        before="The settings keep their current values.",
        after="The listed settings change for the whole installation.",
        irreversible=False, ttl_seconds=ttl_days * 86_400,
    )


def is_settings_approval(approval) -> bool:
    return (approval is not None and approval.action == ACTION
            and approval.provenance == PROVENANCE)


def _proposal_binds_approval(proposal, approval) -> bool:
    """Only a native proposal grants administrators this redacted card read."""
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail, digest
    from maverick.paths import current_tenant_id_strict

    if not is_settings_approval(approval) or approval.goal_id is not None or approval.scope != "settings":
        return False
    saved = proposal.new
    if (not isinstance(saved, dict) or type(saved.get("approval")) is not int
            or saved["approval"] != approval.id or proposal.proposer != approval.requested_by
            or proposal.required != approval.approvals_required):
        return False
    try:
        card = decode_approval_detail(approval.detail)
        settings = sorted(proposal.key.split(","))
        return bool(card and card["action"] == ACTION
                    and card["binding_sha256"] == saved.get("card_binding")
                    and card["parameters"]["sha256"] == digest({"change_id": proposal.change_id})
                    and card["target"]["sha256"] == digest({"settings": settings})
                    and card["authority"]["actor"] == proposal.proposer
                    and card["authority"]["role"] == "admin"
                    and card["authority"]["workspace"] == (current_tenant_id_strict() or "local"))
    except (ApprovalCardError, KeyError, TypeError, ValueError):
        return False


def has_bound_admin_review(approval) -> bool:
    """Verify the independent proposal ledger, never caller-selected labels."""
    if not is_settings_approval(approval) or approval.goal_id is not None:
        return False
    from maverick import quorum

    try:
        proposals = quorum.ProposalStore().all()
    except (OSError, KeyError, TypeError, ValueError):
        return False
    return len(proposals) <= 10000 and any(_proposal_binds_approval(proposal, approval) for proposal in proposals)


def require_decider(request, approval, who: str, *, approving: bool) -> None:
    """Only a global administrator decides a settings request, and never the
    person who asked approves it (whatever self-approval allows elsewhere)."""
    if not is_settings_approval(approval):
        return
    from .auth import require_global_permission

    require_global_permission(request, "admin")
    if approving and approval.requested_by and who == approval.requested_by:
        raise HTTPException(status_code=403, detail=(
            "You asked for this change, so another administrator must approve it."))


def _held(approval_id: int, required: int, votes: int, fresh: bool) -> dict[str, Any]:
    need = "approval" if required == 1 else "approvals"
    if fresh:
        message = (f"Not saved yet: this change needs {required} {need} from other "
                   "administrators. It was sent to Approvals; save it again once it is "
                   "approved.")
    else:
        message = (f"Not saved yet: waiting for approval ({votes} of {required} so far). "
                   "Save it again once it is approved.")
    return {"approval_id": approval_id, "required": required, "approvals": votes,
            "message": message}


def _votes(world, approval_id: int) -> int:
    try:
        state = world.approval_state(approval_id) or {}
        return int(state.get("approved_count") or 0)
    except Exception:  # noqa: BLE001 -- the count is only shown
        return 0


def review(changes: list[dict], actor: str, shown) -> tuple[dict | None, str | None]:
    """Decide one save.

    Returns ``(hold, None)`` when the save must wait (``hold`` is what the
    page shows), ``(None, change_id)`` when an approved request covers it
    (call :func:`settle` after writing), and ``(None, None)`` when no
    quorum applies.
    """
    from maverick import quorum

    policy = quorum.configured_policy()
    if policy is None or not any(quorum.is_protected(c["setting"].id, policy)
                                 for c in changes):
        return None, None
    from ._shared import _world

    world = _world()
    store = quorum.ProposalStore()
    change_id = fingerprint(changes, shown)
    proposal = store.get(change_id)
    if proposal is not None:
        approval_id = int((proposal.new or {}).get("approval", 0))
        approval = world.get_approval(approval_id) if approval_id else None
        expired = quorum.status(change_id, store=store, policy=policy) == quorum.EXPIRED
        bound = approval is not None and _proposal_binds_approval(proposal, approval)
        if bound and not expired and approval.status == "approved":
            return None, change_id
        if bound and not expired and approval.status == "pending":
            return _held(approval_id, approval.approvals_required,
                         _votes(world, approval_id), fresh=False), None
        store.delete([change_id])  # denied, gone or too old: ask again
    from maverick.approval_cards import decode_approval_detail

    detail = _card(changes, shown, actor, change_id, policy.ttl_days)
    card_binding = decode_approval_detail(detail)["binding_sha256"]
    approval_id = world.create_approval(
        ACTION, risk="high", scope="settings",
        detail=detail,
        provenance=PROVENANCE, approvals_required=policy.required, requested_by=actor,
    )
    try:
        quorum.propose(change_id, ",".join(sorted(c["setting"].id for c in changes)),
                       None, {"approval": approval_id, "card_binding": card_binding}, actor, policy=policy, store=store)
    except quorum.QuorumError:
        # The same change was requested at the same moment: keep that request.
        log.info("settings quorum: request %s already open", change_id)
    return _held(approval_id, policy.required, 0, fresh=True), None


def settle(change_id: str | None) -> None:
    """Use up an approved request once its change is written."""
    if not change_id:
        return
    from maverick import quorum

    quorum.ProposalStore().delete([change_id])


__all__ = ["ACTION", "PROVENANCE", "fingerprint", "is_settings_approval", "require_decider",
           "review", "settle"]
