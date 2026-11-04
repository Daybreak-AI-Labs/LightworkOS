"""Employee departure inventory, deactivation and explicitly retained handoff.

Local credential removal is never described as provider revocation. The case
stays open while running work, pending review or external closure is unresolved.
No content is erased and no private-read authority is granted to a custodian.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import contextmanager

from fastapi import HTTPException
from maverick.governed_records import GovernedRecordStore

STORE = GovernedRecordStore("employee_departures", "EDP", "employee_departure",
                            authority_scope="deployment_global")


@contextmanager
def _tenant(tenant):
    from maverick.paths import reset_tenant, set_tenant
    token = set_tenant(tenant)
    try:
        yield
    finally:
        reset_tenant(token)


def enabled():
    from maverick.config import get_features
    return get_features().get("employee_departures") is True


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def candidates():
    """Everyone a departure can name: the people the Users page lists (role
    holders, accepted invitations into the installation or a workspace,
    administrators, people who signed in) plus anyone who already has a case.

    ``departed`` marks a person who has a case and is no longer active; they
    stay known so their case can be reviewed and closed, but are not offered
    for a new departure."""
    from . import admin_pages, auth, invites, rbac, scim_groups
    from .identity_format import humanize_principal
    people, _labels = admin_pages.known_people(rbac.list_users(), invites.list_invites())
    labels = {person["principal"]: person["label"] for person in people}
    cased = {row["principal"] for row in STORE.list() if isinstance(row.get("principal"), str)}
    result = []
    for principal in sorted(set(labels) | cased):
        if not principal.startswith("user:"):
            continue
        active = scim_groups.active_for_principal(principal) is not False
        result.append({"principal": principal, "label": labels.get(principal) or humanize_principal(principal).name,
                       "active": active, "departed": principal in cased and not active,
                       "admin": "admin" in rbac.permissions_for(auth.global_role_for_principal(principal))})
    return result


def _item_key(item):
    return _digest([item.get("tenant"), item["kind"], item["id"], item.get("owner", "")])


def _owned_work(world, owner):
    goals = world.list_goals(owner=owner, limit=5001)
    rows = [{"kind": "task", "id": str(goal.id), "status": goal.status,
             "owner": owner, "followup": goal.status not in {"done", "completed", "failed", "cancelled", "error"}}
            for goal in goals[:5000]]
    for project in world.list_projects(owner=owner):
        rows.append({"kind": "project", "id": str(project["id"]), "status": project.get("status", ""),
                     "owner": owner, "followup": True})
    return rows, len(goals) > 5000


def _workspace_inventory(principal):
    from maverick import connections
    from maverick.job_queue import JobQueue
    from maverick.personal_identity import recorded_channels
    from maverick.project_reviews import _PACKETS
    from maverick.schedule_definitions import list_definitions
    from maverick.world_model import close_world_if_owned, open_world

    links = recorded_channels(principal)
    owners = {principal} | {"user:" + link["channel"] + ":" + link["user_id"] for link in links}
    rows, partial = [], False
    world = open_world()
    try:
        for owner in sorted(owners):
            owned, truncated = _owned_work(world, owner)
            rows.extend(owned)
            partial = partial or truncated
        for approval in world.pending_approvals():
            if owners.intersection({approval.requested_by, approval.claimed_by}):
                rows.append({"kind": "approval", "id": str(approval.id), "status": "pending", "followup": True})
    finally:
        close_world_if_owned(world)
    queue = JobQueue()
    for owner in sorted(owners):
        for connection in connections.list_connections(owner=owner):
            rows.append({"kind": "connection", "id": connection["name"], "revision": connection["revision"],
                         "owner": owner, "status": "connected", "followup": True, "provider": connection["connector"]})
        for definition in list_definitions(queue, owner=owner):
            if definition["state"] != "retired":
                rows.append({"kind": "schedule", "id": definition["definition_id"], "revision": definition["revision"],
                             "owner": owner, "status": definition["state"], "followup": True})
    for job in queue.iter_pending(include_running=True):
        if (job.payload or {}).get("owner") in owners:
            rows.append({"kind": "scheduled_work", "id": str(job.id), "status": job.status,
                         "owner": job.payload["owner"], "job_kind": job.kind,
                         "payload_digest": _digest(job.payload), "followup": True})
    for packet in _PACKETS.list():
        if owners.intersection({packet.get("owner"), packet.get("reviewer")}) and packet.get("status") == "pending":
            rows.append({"kind": "review", "id": packet["id"], "status": packet["status"],
                         "revision": packet["revision"], "followup": True})
    for link in links:
        rows.append({"kind": "channel_link", "id": link["id"], "status": "verified_binding_retained",
                     "channel": link["channel"], "followup": True})
    return rows[:10000], partial or len(rows) > 10000


def preview(principal):
    from maverick.tenant.registry import list_tenants

    from . import rbac, scim_groups

    if principal not in {row["principal"] for row in candidates()}:
        raise HTTPException(404, "Choose a known signed-in employee.")
    scopes = [None] + [record.id for record in list_tenants()]
    items, truncated = [], False
    for tenant in scopes:
        with _tenant(tenant):
            rows, partial = _workspace_inventory(principal)
            items.extend({**row, "tenant": tenant} for row in rows)
            truncated = truncated or partial
            role = rbac.get_tenant_role(tenant, principal) if tenant else rbac.get_stored_role(principal)
            if role:
                items.append({"kind": "membership", "id": tenant or "installation", "tenant": tenant,
                              "status": role, "followup": False})
    result = {"principal": principal, "active": scim_groups.active_for_principal(principal) is not False,
              "items": items, "truncated": truncated,
              "coverage": "Exact named and verified-channel tasks, projects, approvals, project reviews, all owned queued job kinds, recurring schedule definitions, identity links and owned connections across registered workspaces. Unlinked identities, provider-side grants and external systems require a named retained obligation; no ownership is inferred.",
              "preservation": "All existing data and preservation holds are retained. Custodian assignment does not grant access to private employee content."}
    result["snapshot"] = _digest(result)
    return result


def begin(principal, custodian, expected_snapshot, actor, authorize):
    from maverick import connections
    from maverick.authority_effects import authority_effect_fence
    from maverick.job_queue import JobQueue

    from . import auth, rbac, scim

    with authority_effect_fence():
        authorize()
        if principal == actor or "admin" in rbac.permissions_for(auth.global_role_for_principal(principal)):
            raise HTTPException(409, "Assign another administrator and explicitly change this account's administrator role before departure. You cannot deactivate your own account here.")
        if custodian == principal or not any(row["principal"] == custodian and row["active"] and row["admin"] for row in candidates()):
            raise HTTPException(422, "Choose a different, active installation administrator as handoff owner.")
        inventory = preview(principal)
        if inventory["snapshot"] != expected_snapshot:
            raise HTTPException(409, "This employee's work changed. Review a fresh inventory before deactivating.")
        if inventory["truncated"]:
            raise HTTPException(409, "The inventory exceeds this view's supported window. Do not treat it as complete.")
        case_id = "EDP-" + _digest([principal, expected_snapshot, actor])[:32]
        existing = STORE.get(case_id)
        if existing:
            return existing
        row = STORE.create({"id": case_id, "principal": principal, "custodian": custodian,
                            "status": "prepared", "inventory": inventory, "steps": [],
                            "retained_data_owner": custodian}, action="departure_reviewed", actor=actor)
        if row.get("_audit_pending"):
            return row  # No identity or credential effect before audit acknowledgement.
        def checkpoint(step):
            nonlocal row
            def mutate(current):
                current["steps"].append(step)
                current["status"] = "handoff_required"
            row = STORE.update(row["id"], mutate, expected_revision=row["revision"], action="departure_progress", actor=actor)
            if row.get("_audit_pending"):
                raise HTTPException(503, "Departure progress is saved but its activity receipt is pending. Review the saved case before any further action.")
        checkpoint({"kind": "identity", "status": "dispatching"})
        scim._retire_user_identity({"externalId": principal.removeprefix("user:")})
        checkpoint({"kind": "identity", "status": "deactivated", "sessions": "revoked"})
        for item in sorted(inventory["items"], key=lambda item: item["kind"] != "schedule"):
            authorize()
            with _tenant(item["tenant"]):
                if item["kind"] == "connection":
                    checkpoint({"kind": "connection", "tenant": item["tenant"], "id": item["id"], "status": "dispatching"})
                    removed = connections.delete_connection(item["id"], owner=item.get("owner", principal), expected_revision=item["revision"])
                    checkpoint({"kind": "connection", "tenant": item["tenant"], "id": item["id"],
                                "status": "removed_from_lightwork" if removed else "needs_review",
                                "provider_revocation": "unconfirmed"})
                elif item["kind"] == "schedule":
                    from maverick.schedule_definitions import change_definition
                    checkpoint({"kind": "schedule", "tenant": item["tenant"], "id": item["id"], "status": "dispatching"})
                    try:
                        change_definition(JobQueue(), item["id"], expected_revision=item["revision"], state="retired",
                                          actor=actor, owner=item.get("owner", principal), rationale="Reviewed employee departure")
                        state = "retired"
                    except (KeyError, ValueError):
                        state = "needs_review"
                    checkpoint({"kind": "schedule", "tenant": item["tenant"], "id": item["id"], "status": state})
                elif item["kind"] == "scheduled_work" and item["status"] == "pending":
                    checkpoint({"kind": "scheduled_work", "tenant": item["tenant"], "id": item["id"], "status": "dispatching"})
                    queue = JobQueue()
                    current = queue.get(int(item["id"]))
                    cancelled = bool(current and (current.status == "cancelled" or (current.status == "pending" and _digest(current.payload) == item["payload_digest"] and queue.cancel(current.id))))
                    checkpoint({"kind": "scheduled_work", "tenant": item["tenant"], "id": item["id"],
                                "status": "cancelled" if cancelled else "needs_review"})
        # Closing requires a separate fresh inventory and explicit per-item
        # retained responsibility; deactivation alone never completes a case.
        return row


def record_handoff(case_id, revision, *, item_key, owner, disposition, evidence, actor, authorize):
    """Record a person's explicit handoff responsibility, never a content grant.

    External evidence is a reviewed human attestation, not provider verification.
    Closure must separately recheck the complete current local inventory and
    retain explicit responsibility for external or unverified authorities.
    """
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        authorize()
        if disposition not in {"retained", "transfer_reported", "revocation_reported"} or not isinstance(evidence, str) or not 10 <= len(evidence) <= 1000:
            raise HTTPException(422, "Record a supported disposition and a bounded evidence reference.")
        if not any(row["principal"] == owner and row["active"] and row["admin"] for row in candidates()):
            raise HTTPException(422, "Choose an active installation administrator as the responsible handoff owner.")
        def mutate(row):
            items = row["inventory"]["items"]
            if item_key != "external" and item_key not in {_item_key(item) for item in items} | {_digest(item) for item in items}:
                raise HTTPException(404, "This item does not belong to the reviewed departure inventory.")
            row.setdefault("handoffs", {})[item_key] = {"owner": owner, "disposition": disposition,
                "evidence": evidence, "recorded_by": actor, "verification": "human_attestation"}
            row["status"] = "handoff_required"
        return STORE.update(case_id, mutate, expected_revision=revision, action="departure_handoff", actor=actor)


def public(row):
    from .identity_format import humanize_principal
    result = {key: row.get(key) for key in ("id", "revision", "principal", "custodian", "status", "steps", "handoffs", "closure")}
    result["person"] = humanize_principal(row["principal"]).name
    result["audit_pending"] = bool(row.get("_audit_pending"))
    result["inventory"] = {**row["inventory"], "items": [{**item, "key": _item_key(item)} for item in row["inventory"]["items"]]}
    return result


def _case(case_id, revision):
    row = STORE.get(case_id)
    if row is None:
        raise HTTPException(404, "No such departure case.")
    if row["revision"] != revision:
        raise HTTPException(409, "This departure case changed. Refresh before reviewing closure.")
    if row.get("_audit_pending"):
        raise HTTPException(409, "Record the pending activity receipt before reviewing departure closure.")
    return row


def refresh_inventory(case_id, revision, actor, authorize):
    """Append newly found obligations, retaining original reviewed evidence."""
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        authorize()
        row = _case(case_id, revision)
        current = preview(row["principal"])
        if current["truncated"]:
            raise HTTPException(409, "Current inventory is incomplete. Closure remains blocked.")
        def mutate(saved):
            known = {_item_key(item) for item in saved["inventory"]["items"]}
            saved["inventory"]["items"].extend(item for item in current["items"] if _item_key(item) not in known)
            saved["inventory"]["coverage"] = current["coverage"]
            saved["status"] = "handoff_required"
            saved.pop("closure", None)
        return STORE.update(case_id, mutate, expected_revision=revision,
                            action="departure_inventory_refreshed", actor=actor)


def closure_preview(case_id, revision):
    row = _case(case_id, revision)
    current = preview(row["principal"])
    known = {_item_key(item) for item in row["inventory"]["items"]}
    new_items = [_item_key(item) for item in current["items"] if _item_key(item) not in known]
    active_owners = {person["principal"] for person in candidates() if person["active"] and person["admin"]}
    missing = []
    for item in row["inventory"]["items"]:
        handoff = row.get("handoffs", {}).get(_item_key(item)) or row.get("handoffs", {}).get(_digest(item))
        if not handoff or handoff.get("owner") not in active_owners:
            missing.append(_item_key(item))
    external = row.get("handoffs", {}).get("external", {})
    # External outcomes cannot be automatically verified. The closure explicitly
    # retains an accountable owner even when that person reports revocation.
    if external.get("owner") not in active_owners:
        missing.append("external")
    blockers = []
    if current["active"]:
        blockers.append("The named identity is still active.")
    if current["truncated"]:
        blockers.append("The current inventory is incomplete.")
    if new_items:
        blockers.append("New work was found. Refresh the case inventory and assign responsibility.")
    if missing:
        blockers.append("Each reviewed item and external boundary needs an active responsible administrator.")
    # Pending dispatch can be retained as an unknown result only after explicit
    # item handoff. Never translate an ambiguous dispatch into a success.
    return {"case_id": case_id, "revision": revision, "snapshot": current["snapshot"],
            "can_close": not blockers, "blockers": blockers, "missing_handoffs": missing,
            "new_items": new_items, "current_inventory": current,
            "outcome": "closed_with_retained_obligations",
            "notice": "Closure records named responsibility for retained work, data, holds and external or uncertain outcomes. It does not verify provider revocation, terminate running work, erase data or grant private-content access."}


def close_case(case_id, revision, expected_snapshot, actor, authorize):
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        authorize()
        review = closure_preview(case_id, revision)
        if review["snapshot"] != expected_snapshot:
            raise HTTPException(409, "The current work or identity changed. Review closure again.")
        if not review["can_close"]:
            raise HTTPException(409, " ".join(review["blockers"]))
        def mutate(row):
            row["status"] = review["outcome"]
            row["closure"] = {"reviewed_by": actor, "snapshot": expected_snapshot,
                              "notice": review["notice"], "external_verification": "human_attestation",
                              "preservation": "retained", "private_content_access": "unchanged"}
        return STORE.update(case_id, mutate, expected_revision=revision,
                            action="departure_closed_with_retained_obligations", actor=actor)
