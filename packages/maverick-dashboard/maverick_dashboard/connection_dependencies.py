"""Permission-scoped connection attention and explicit dependency review."""
from __future__ import annotations

import hashlib
import json
import time

from fastapi import HTTPException

from .auth import has_permission


def require_connections() -> None:
    """Reject connection operations while the installation has disabled them."""
    from maverick import connections

    if not connections.enabled():
        raise HTTPException(
            status_code=403,
            detail={"code": "connections_disabled", "message": "Connections are turned off. An administrator can enable them in Settings."},
        )


def owned_connections(request):
    from maverick.connections import list_connections

    from .request_identity import request_identity as _request_identity

    actor = _request_identity(request)
    rows = list_connections(owner=actor)
    # An auth-off local session does not inherit credentials owned by named
    # employees from a prior authenticated session.
    return [row for row in rows if row.get("owner") == actor or (actor is None and not row.get("owner"))]


def connection_attention(request):
    from maverick import connections

    if not has_permission(request, "operate"):
        return {"items": [], "coverage": "unavailable"}
    if not connections.enabled():
        return {"items": [], "coverage": "disabled"}
    try:
        items = []
        for record in owned_connections(request):
            oauth = record.get("oauth") or {}
            test = record.get("last_test") or {}
            reason = None
            if oauth and oauth.get("renewal_state") != "ready":
                reason = oauth.get("recovery_action") or "Reconnect this account before using it."
            elif oauth.get("expires_at") and float(oauth["expires_at"]) <= time.time() and not oauth.get("available"):
                reason = "This authorization expired. Reconnect the account before using it."
            elif test.get("revision") == record.get("revision") and test.get("outcome") in {"sign_in_refused", "blocked_by_policy", "unreachable", "address_missing"}:
                reason = "The current connection check failed. Review its result in Connections."
            if reason:
                items.append({"name": record["name"], "title": record["name"], "revision": record["revision"],
                              "reason": reason, "href": "/connections"})
        return {"items": items, "coverage": "current"}
    except (connections.ConnectionStoreUnavailable, ValueError, TypeError):
        return {"items": [], "coverage": "unavailable"}


def _references(value, name):
    """Only declared named-credential references; do not mine prose for names."""
    if isinstance(value, str):
        if value.startswith("lwconn1."):
            from maverick.template_connections import decode
            try:
                return decode(value)["name"] == name
            except ValueError:
                return False
        return value.startswith("connection:" + name + ":")
    if isinstance(value, dict):
        if set(value) == {"name", "revision", "owner", "tenant", "connector"}:
            return value["name"] == name
        return any(_references(item, name) for item in value.values())
    if isinstance(value, list):
        return any(_references(item, name) for item in value)
    return False


def _tools(value):
    if isinstance(value, dict):
        found = {value["tool"]} if isinstance(value.get("tool"), str) else set()
        return found | set().union(*(_tools(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_tools(item) for item in value))
    return set()


def _active_flow_impact(request, name, record, owner, items, coverage):
    from fastapi import HTTPException
    from maverick.flow import store

    from .flows_api import _assert_flow_access

    try:
        count = 0
        for run in store.iter_run_metadata(owner=owner):
            if run.status in {"done", "failed", "cancelled"}:
                continue
            count += 1
            if count > 2000:
                break
            # Approval authority binds the credential inventory. Any connection
            # generation change can invalidate an owner's pending approval,
            # even when a dynamic tool selection has not happened yet.
            flow = store.load_flow_snapshot(run.definition_digest) if run.definition_digest else store.load_flow(run.flow_id)
            if flow is None:
                continue
            try:
                _assert_flow_access(request, flow)
            except HTTPException:
                continue
            if run.owner == record.get("owner") or _references(flow.to_dict(), name) or record["connector"] in _tools(flow.to_dict()):
                items.append({"kind": "active_flow", "id": run.run_id, "title": flow.name,
                              "revision": str(run.updated), "owner": run.owner,
                              "binding": "run authority includes saved credential inventory", "state": run.status,
                              "external_outcome": "unknown; never replayed by connection repair", "href": "/flows"})
        coverage.append({"kind": "active flows and approvals", "state": "partial" if count > 2000 else "current"})
    except Exception:
        coverage.append({"kind": "active flows and approvals", "state": "unavailable"})


def impact(request, name):
    """Review authorized exact references and explicitly labelled fallback use.

    Provider credentials selected dynamically by an agent cannot be inferred
    from prose. Coverage states keep that uncertainty visible during review.
    """
    from fastapi import HTTPException
    from maverick import connections
    from maverick.flow import store
    from maverick.job_queue import JobQueue
    from maverick.schedule_definitions import list_definitions

    from .auth import goal_owner_filter, has_global_permission, require_permission
    from .draft_api import context_for
    from .flows_api import _assert_flow_access

    require_permission(request, "operate")
    record = next((row for row in owned_connections(request) if row["name"] == name), None)
    if record is None:
        raise HTTPException(404, "Connection is unavailable in your account.")
    items, coverage = [], []
    owner = goal_owner_filter(request)
    try:
        for flow in store.list_flows():
            try:
                _assert_flow_access(request, flow)
            except HTTPException:
                continue
            graph = flow.to_dict()
            exact = _references(graph, name)
            if exact or record["connector"] in _tools(graph):
                items.append({"kind": "flow", "id": flow.id, "title": flow.name, "revision": flow.revision,
                              "version": flow.version, "owner": flow.owner,
                              "binding": "exact reference" if exact else "possible connector fallback; environment credentials may take precedence",
                              "state": "needs-review after a credential change", "href": "/flows"})
                if flow.schedule:
                    items.append({"kind": "flow_schedule", "id": flow.id, "title": flow.name,
                                  "revision": flow.revision, "version": flow.version, "owner": flow.owner,
                                  "binding": "scheduled flow", "state": "review its published release", "href": "/flows"})
        coverage.append({"kind": "saved flows", "state": "current"})
    except Exception:
        coverage.append({"kind": "saved flows", "state": "unavailable"})
    _active_flow_impact(request, name, record, owner, items, coverage)
    try:
        from .app import _world
        from .auth import can_access_goal

        world = _world()
        goals = world.list_goals(owner=owner, limit=2001, order="desc")
        for goal in goals[:2000]:
            if goal.status in {"done", "failed", "cancelled"} or not can_access_goal(request, goal):
                continue
            if connections._may_use(record, getattr(goal, "owner", None)):
                items.append({"kind": "active_task", "id": str(goal.id), "title": goal.title,
                              "revision": str(getattr(goal, "updated_at", "")), "owner": getattr(goal, "owner", ""),
                              "binding": "possible dynamic selection by an authorized task owner", "state": goal.status,
                              "external_outcome": "unknown; repair never replays task work", "href": "/chat/goal/" + str(goal.id)})
        coverage.append({"kind": "tasks with possible dynamic use", "state": "partial" if len(goals) > 2000 else "current"})
    except Exception:
        coverage.append({"kind": "tasks with possible dynamic use", "state": "unavailable"})
    try:
        queue = JobQueue()
        definitions = {item["definition_id"]: item for item in list_definitions(queue, owner=owner)}
        with queue._conn() as connection:
            for row in connection.execute("SELECT id,payload FROM schedule_definitions"):
                payload = json.loads(row["payload"])
                if row["id"] in definitions and _references(payload, name):
                    definition = definitions[row["id"]]
                    items.append({"kind": "schedule", "id": row["id"], "title": definition["title"],
                                  "revision": str(definition["revision"]), "owner": definition["owner"],
                                  "binding": "exact reference", "state": definition["state"], "href": "/automations"})
        coverage.append({"kind": "declared schedule references", "state": "current"})
    except Exception:
        coverage.append({"kind": "declared schedule references", "state": "unavailable"})
    if has_global_permission(request, "admin"):
        try:
            from .privacy_data_discovery_api import _authority

            _, tenant, discovery = _authority(request)
            sources = discovery.list_sources(tenant, limit=2000)
            for source in sources:
                if _references(source.credential_env, name):
                    items.append({"kind": "discovery_source", "id": source.source_id, "title": source.resource_ref,
                                  "revision": source.revision, "owner": "Workspace administrator",
                                  "binding": "exact reference", "state": source.state if source.credential_env.endswith(":" + record["revision"]) else "needs-review",
                                  "href": "/privacy/data-discovery", "reference": source.credential_env})
            coverage.append({"kind": "discovery sources", "state": "partial" if len(sources) == 2000 else "current"})
        except HTTPException as exc:
            coverage.append({"kind": "discovery sources", "state": "disabled" if exc.status_code == 403 else "unavailable"})
        except Exception:
            coverage.append({"kind": "discovery sources", "state": "unavailable"})
    else:
        coverage.append({"kind": "discovery sources", "state": "administrator-only"})
    coverage.append({"kind": "agent-selected tools and unstructured instructions", "state": "not statically knowable; review affected owners before rotation"})
    material = {"connection": record["revision"], "items": items, "coverage": coverage}
    return {"name": name, "revision": record["revision"], "items": items, "coverage": coverage,
            "context": context_for(request), "impact_version": hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest(),
            "receipts": record.get("test_history", []) + ([record["last_test"]] if record.get("last_test") else []),
            "note": "Credential changes invalidate pinned source and approval authority. Review and rebind explicitly; uncertain effects remain unknown. Local removal does not revoke provider consent."}


def require_review(request, name, expected_revision, reviewed, *, expected_context=None, rotation=False):
    import hmac

    from fastapi import HTTPException

    current = impact(request, name)
    if (expected_context is not None and not hmac.compare_digest(expected_context, current["context"])) or current["revision"] != expected_revision or not reviewed or not hmac.compare_digest(reviewed, current["impact_version"]):
        raise HTTPException(409, "Connection or affected work changed. Review the current impact before changing it.")
    if rotation and any(item["kind"] == "active_task" and item["state"] in {"running", "blocked"} for item in current["items"]):
        raise HTTPException(409, "An active task may select this connection dynamically. Finish or cancel the listed active tasks before rotating it; an uncertain effect must not receive replacement credentials.")
    return current
