"""Current, access-scoped discovery of paused flow approvals.

The flow checkpoint and its existing approval service remain the authority.
This module only projects currently reviewable pauses into dashboard inboxes.
"""
from __future__ import annotations

from maverick import flow
from maverick.flow import store

from .auth import api_key_permissions, caller_principal, goal_owner_filter, has_permission

SOURCE_LIMIT = 2000


def _actor(request) -> str:
    from .auth import auth_genuinely_off

    return caller_principal(request) or ("local:dashboard" if auth_genuinely_off() else "")


def _assigned_to_actor(run, actor: str) -> bool:
    """Use the same verdict/assignee check as the queue's decision reservation."""
    if not actor or not str((run.human or {}).get("assignee") or "").strip():
        return False
    from . import automation_queue as aq

    try:
        aq._validate_approval_actor(run, decision="approved", decided_by=actor)
        return True
    except store.FlowSnapshotError:
        return False


def _assignee_fields_current(run) -> bool:
    """The decision UI still matches the published pause, for page and alerts."""
    if run.cursor == "teaching_review":
        # Its generated question can contain the owner's private observations.
        return False
    try:
        # The card binds the immutable release, but the checkpoint's human
        # fields are separate. They must still match its published approval
        # node before we expose the decision controls to another person.
        published = store.load_flow_snapshot(run.definition_digest)
        node = published.node(run.cursor)
        human = run.human or {}
        if (node is None or node.kind != "approval"
                or human.get("assignee") != node.assignee
                or human.get("choices") != list(node.choices)
                or human.get("form") != [dict(field) for field in node.form]):
            return False
    except Exception:
        return False
    return True


def assigned_review_allowed(request, run) -> bool:
    """A named assignee may see only the current approval, never the owner's run."""
    allowed = (has_permission(request, "operate", api_scope="approvals:decide")
               if api_key_permissions(request) is not None
               else has_permission(request, "operate"))
    if (run is None or run.status != "paused_approval"
            or not allowed):
        return False
    # Local auth-off access already uses the ordinary owner/legacy path.
    actor = caller_principal(request)
    if not _assigned_to_actor(run, actor or ""):
        return False
    from . import automation_queue as aq

    try:
        aq.current_flow_approval_card(run)
        aq.flow_approval_binding(run)
    except Exception:
        return False
    return _assignee_fields_current(run)


def pending_for_request(request, *, limit: int = SOURCE_LIMIT) -> dict:
    """Return only pauses this caller can actually review, with honest coverage."""
    allowed = (has_permission(request, "operate", api_scope="approvals:decide")
               if api_key_permissions(request) is not None
               else has_permission(request, "operate"))
    if not allowed:
        return {"items": [], "coverage": "unavailable"}
    if not flow.enabled():
        return {"items": [], "coverage": "current"}
    actor = _actor(request)
    if not actor:
        # A principal-less installation token can inspect some local work,
        # but cannot produce an attributable human approval decision.
        return {"items": [], "coverage": "current"}
    owner = goal_owner_filter(request)
    return _pending_for_actor(actor, owner=owner, request=request, limit=limit)


def pending_for_observer(actor: str, *, limit: int = SOURCE_LIMIT) -> dict:
    """Read the named alert recipient under current identity and role policy."""
    from maverick.paths import current_tenant_id_strict
    from maverick.personal_identity import principal_current

    from . import auth, rbac

    if not actor.startswith("user:") or not principal_current(actor):
        return {"items": [], "coverage": "unavailable"}
    tenant = current_tenant_id_strict()
    role = rbac.get_tenant_role(tenant, actor) if tenant else auth.global_role_for_principal(actor)
    if "operate" not in rbac.permissions_for(role):
        return {"items": [], "coverage": "unavailable"}
    if not flow.enabled():
        return {"items": [], "coverage": "current"}
    return _pending_for_actor(actor, owner=actor, request=None, limit=limit)


def _pending_for_actor(actor: str, *, owner: str, request, limit: int) -> dict:
    from . import automation_queue as aq

    try:
        metadata = store.list_run_metadata(
            statuses={"paused_approval"}, limit=limit + 1,
        )
        items = []
        for meta in metadata[:limit]:
            assignee = str((meta.human or {}).get("assignee") or "").strip()
            owns = meta.owner == owner
            if (request is not None and not owns and owner == ""
                    and meta.owner in {"operator", "local:dashboard"}):
                from .api import _legacy_local_flow_run

                owns = _legacy_local_flow_run(request, meta)
            assigned = _assigned_to_actor(meta, actor) if assignee else False
            if not owns and not assigned:
                continue
            # Metadata is an index preview. Recheck the canonical checkpoint
            # before disclosing any card or promising a decision.
            run = store.load_run(meta.run_id, owner=meta.owner)
            if run is None or run.status != "paused_approval":
                continue
            assigned = _assigned_to_actor(run, actor) if assignee else False
            if not owns and not assigned:
                continue
            if not owns and not _assignee_fields_current(run):
                continue
            status, card, binding = "current", None, ""
            try:
                card = aq.current_flow_approval_card(run)
                binding = aq.flow_approval_binding(run)
            except Exception:
                status = "unavailable"
                # An assigned reviewer must not receive a card whose authority
                # could not be verified. The owner can inspect their own run.
                if not owns:
                    continue
            if status == "current" and assignee and not assigned:
                # A healthy assigned request belongs in the assignee's inbox,
                # while a broken one needs the owner's recovery attention.
                continue
            if not owns and request is not None and not assigned_review_allowed(request, run):
                continue
            items.append({
                "run_id": run.run_id, "flow_id": run.flow_id,
                "title": card["summary"] if card else "Flow approval needs fresh review",
                "href": f"/flows/{run.flow_id}/runs/{run.run_id}?approval_review=1",
                "owner": run.owner, "assignee": assignee,
                "updated_at": run.updated, "due_at": run.resume_at,
                "approval_card": card, "approval_card_status": status,
                "approval_binding_sha256": binding,
            })
        return {"items": items, "coverage": "partial" if len(metadata) > limit else "current"}
    except Exception:
        return {"items": [], "coverage": "unavailable"}
