"""Decision cards for waiting requests the viewer can't open.

A request from a colleague's private task stays private: its summary, target,
command, preview and fingerprints are read only through the exact-read flow
(``content_access``). The Approvals page still shows each one as a card with
the few facts that are already visible on My work or are routing facts --
who asked, the kind of action and its risk, the agent or specialist, when it
expires -- and why the viewer sees it. Nothing here widens who may decide:
the card has no decision buttons, because deciding on the Approvals page
needs the card read. People linked in Slack or Teams, where the rules already
let them decide, are told to decide there.
"""
from __future__ import annotations

from typing import Any

_RISK_LABELS = {"low": "Low risk", "medium": "Medium risk", "high": "High risk",
                "critical": "Critical risk"}


def decides_in_chat(approval, viewer: str) -> bool:
    """Whether ``viewer`` may decide ``approval`` in Slack or Teams by the rules
    already enforced there (:func:`approval_decisions.eligible_approvers`)."""
    from .approval_decisions import _chat_approvers, _may_decide

    who = " ".join(str(viewer or "").split())
    if not who or who == " ".join(str(getattr(approval, "requested_by", "") or "").split()):
        return False
    try:
        return who in _chat_approvers(approval) and _may_decide(who)
    except Exception:  # an unreadable link store lets nobody decide from chat
        return False


def _worker(goal) -> dict[str, str]:
    """The agent or specialist working on the task, by name only."""
    from .identity_format import humanize

    domain = str(getattr(goal, "domain", "") or "").strip()
    if domain:
        try:
            from maverick.domain import builtin_domains

            builtin = domain in builtin_domains()
        except Exception:  # unknown catalog: never claim it is ours
            builtin = False
        return {"noun": "Specialist" if builtin else "Agent", "name": humanize(domain)}
    principal = str(getattr(goal, "execution_principal", "") or "")
    if principal.startswith("agent:") and len(principal) > 6:
        return {"noun": "Agent", "name": humanize(principal[6:].rsplit(".", 1)[-1])}
    return {"noun": "Agent", "name": "Lightwork's general agent"}


def _expires_at(approval) -> float | None:
    from maverick.approval_cards import ApprovalCardError, decode_approval_detail

    try:
        card = decode_approval_detail(getattr(approval, "detail", None))
    except ApprovalCardError:
        return None
    return float(card["expires_at"]) if card is not None else None


def private_card(world, approval, viewer: str) -> dict[str, Any]:
    """The facts one private request's card shows, and nothing else."""
    from maverick.channel_approvals import _plain_action

    goal = None
    if getattr(approval, "goal_id", None):
        try:
            goal = world.get_goal(int(approval.goal_id))
        except Exception:  # a vanished task still shows who asked
            goal = None
    owner = (getattr(goal, "owner", "") if goal is not None else "") or approval.requested_by or ""
    risk = str(approval.risk or "medium").lower()
    return {
        "id": approval.id,
        "action": _plain_action(approval.action),
        "risk": risk,
        "risk_label": _RISK_LABELS.get(risk, risk.capitalize() + " risk"),
        "requested_by": owner,
        "worker": _worker(goal),
        "expires_at": _expires_at(approval),
        "in_chat": decides_in_chat(approval, viewer),
    }


def private_cards(world, approvals: list, viewer: str) -> list[dict[str, Any]]:
    return [private_card(world, approval, viewer) for approval in approvals]


def waiting_in_chat(approvals: list, viewer: str) -> int:
    """How many of these unopenable requests wait on ``viewer`` in chat.

    The same rule as :func:`decides_in_chat`, with the chat links and the
    viewer's role read once: neither depends on the request, apart from a
    protected-settings request, which is never decided in chat."""
    from .approval_decisions import SETTINGS_PROVENANCE

    who = " ".join(str(viewer or "").split())
    candidates = [approval for approval in approvals
                  if getattr(approval, "provenance", None) != SETTINGS_PROVENANCE
                  and who != " ".join(str(getattr(approval, "requested_by", "") or "").split())]
    if not candidates or not decides_in_chat(candidates[0], who):
        return 0
    return len(candidates)


__all__ = ["decides_in_chat", "private_card", "private_cards", "waiting_in_chat"]
