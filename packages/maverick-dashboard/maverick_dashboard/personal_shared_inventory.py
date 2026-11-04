"""Bounded own-record metadata for retained local copies, using native ACLs."""
from __future__ import annotations

from urllib.parse import quote

from maverick.authority_effects import authority_effect_fence

from .identity_format import humanize_principal

LIMIT = 100


def _recipient(principal):
    identity = humanize_principal(principal)
    return identity.name + (" (" + identity.detail + ")" if identity.detail else "")


def _source(service, actor, goal_id):
    goal = service.world.get_goal(goal_id)
    if goal is None or goal.owner != actor:
        return {"source": "Original task unavailable; the separately captured copy remains retained."}
    return {"source": "Your original task", "source_href": "/chat/goal/" + str(goal_id)}


def _bundle(service, row, actor):
    payload = row["payload"]
    return {
        "id": row["id"], "name": payload["name"], "owner": actor,
        "owner_label": "You", "recipient": _recipient(payload["recipient"]),
        "state": row["status"], "access_expires_at": row["expires_at"],
        "use": "A separately captured copy of selected evidence for its named recipient.",
        "expiry": "Recipient access expiry is not deletion of the saved copy or previously downloaded files.",
        "dependencies": "Original task, selected evidence and review receipts remain separate records.",
        "source_state": "Source changed or unavailable" if row["stale"] else "Captured source is current",
        "action": "Review or export the selected copy; revoke future recipient access where permitted.",
        "href": "/deliverable-bundles?open=" + quote(row["id"], safe=""),
        **_source(service, actor, payload["source"]["goal_id"]),
    }


def _handoff(service, row, actor):
    preview = row["preview"]
    return {
        "id": row["id"], "name": preview["title"], "owner": actor,
        "owner_label": "You", "recipient": _recipient(row["recipient"]),
        "state": row["state"], "access_expires_at": preview["expires_at"],
        "expiry_label": "Offer expiry",
        "use": "A retained responsibility offer and its acceptance or withdrawal receipt.",
        "expiry": "Offer expiry is not record deletion and does not end an accepted recipient's independent work.",
        "dependencies": "The selected bundle and original task remain separate. Any accepted continuation belongs to its recipient; its private details are not included here.",
        "action": "Review the handoff or withdraw an outstanding offer where permitted. Accepted work cannot be recalled.",
        "href": "/task-handoffs?open=" + quote(row["id"], safe=""),
        "dependency_href": "/deliverable-bundles?open=" + quote(preview["bundle_id"], safe=""),
        **_source(service, actor, preview["source_id"]),
    }


def _one(request, actor, factory, project, *, name, href):
    store = {"name": name, "href": href,
             "use": "Retained local records you own and can currently read; received copies belong to their sender.",
             "expiry": "No automatic physical deletion is promised. Preservation holds and independently retained copies remain separate.",
             "action": "Open each record's governed controls. Revocation or withdrawal ends future access only where supported."}
    try:
        service = factory(request)
        if service.actor != actor:
            raise ValueError("Inventory identity changed.")
        candidates = service.inbox()
        items = []
        # Native inboxes enforce their own 1,000-record bound and membership
        # checks. Inspect at most 100 currently authorized entries; never use a
        # raw store scan to bypass a disabled feature or source ACL.
        for candidate in candidates[:LIMIT]:
            row = service.get(candidate["id"])
            if row["owner"] == actor:
                items.append(project(service, row, actor))
        return {**store, "state": "current-authorized-only", "items": items,
                "visible_count": len(items), "partial": len(candidates) > LIMIT,
                "coverage": "Only currently readable owned records are counted. Unavailable records and received copies are not counted as your owned data."}
    except Exception:
        # Missing authority, disabled policy, a bound exceeded or storage failure
        # must never become a fabricated empty/fully erased store.
        return {**store, "state": "unavailable",
                "action": "This local inventory could not be confirmed. Check the feature and workspace permissions in its governed controls; no zero count or deletion is claimed."}


def inventory(request, actor):
    from .deliverable_bundles_api import service as bundles
    from .task_handoffs_api import service as handoffs

    with authority_effect_fence():
        return [
            _one(request, actor, bundles, _bundle, name="Owned selected-result bundles", href="/deliverable-bundles"),
            _one(request, actor, handoffs, _handoff, name="Owned responsibility handoffs", href="/task-handoffs"),
        ]
