"""Bounded task-content search with current authority and readable continuation."""
from __future__ import annotations

import hmac
import json
import math
import time
from urllib.parse import urlencode

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.governed_operations import digest
from maverick.paths import current_tenant_id_strict

from . import auth, rbac
from .api_flow_operator_review import _workspace_authority
from .draft_api import context_for

WINDOW = 250
TTL = 3600
NOTICE = (
    "Your own currently readable tasks, newest first. Search title, request and saved result. "
    "Search older work to continue beyond this part. New tasks and later edits need a fresh search."
)


def context(request):
    auth.require_permission(request, "view")
    tenant, owner = current_tenant_id_strict(), auth.goal_owner_filter(request)
    role = auth.caller_role(request)
    departments = auth.caller_suites(request)
    key_permissions, scopes = auth.api_key_permissions(request), auth.api_key_scopes(request)
    return digest([context_for(request), owner, role, sorted(rbac.permissions_for(role)),
                   sorted(departments) if departments is not None else None,
                   sorted(key_permissions) if key_permissions is not None else None,
                   sorted(scopes) if scopes is not None else None,
                   _workspace_authority(request, owner, tenant) if tenant else None])


def _position(token, query, current):
    if not token:
        return None
    try:
        if len(token) > 1536 or not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if (set(value) != {"purpose", "context", "query", "before", "expires"}
                or value["purpose"] != "task-search.v1"
                or value["context"] != current or value["query"] != digest(query)
                or type(value["before"]) is not int or not 0 < value["before"] < 2**63
                or type(value["expires"]) not in (int, float)
                or not math.isfinite(value["expires"]) or value["expires"] <= time.time()):
            raise ValueError
        return value["before"]
    except Exception as exc:
        raise HTTPException(409, "This older search no longer matches your words, account or access. Search from the newest work again.") from exc


def validate_cursor(request, query, cursor):
    """Validate a named continuation before advertising it in Copilot."""
    if not cursor or not 1 <= len(query.strip()) <= 256:
        raise HTTPException(409, "Choose a current older-search position.")
    _position(cursor, query.strip(), context(request))


def _continuation(current, query, before):
    value = {"purpose": "task-search.v1", "context": current, "query": digest(query),
             "before": before, "expires": time.time() + TTL}
    try:
        result = crypto_at_rest.seal_to_str(json.dumps(value, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(result):
            raise ValueError
        return result
    except Exception as exc:
        raise HTTPException(503, "The older-search position could not be protected. Your search words remain; try again when storage protection is available.") from exc


def _identity(goal):
    return digest([goal.id, goal.owner, goal.domain, goal.title, goal.description,
                   goal.result, goal.status, goal.updated_at])


def check(request, goals, expected):
    from maverick.world_model import goals_by_id

    from ._shared import _world

    world = _world()
    # One read for the page's goals; every goal still passes its own access
    # check and identity comparison.
    current = goals_by_id(world, [goal.id for goal in goals])
    for goal in goals:
        latest = current.get(goal.id)
        if not auth.can_access_goal(request, latest) or _identity(latest) != _identity(goal):
            raise HTTPException(409, "A matching task or its access changed during search. Search again to read current results.")
    if not hmac.compare_digest(expected, context(request)):
        raise HTTPException(409, "Your account, workspace or access changed during search. Reload Tasks.")


def page(request, query, *, cursor="", limit=100, expected="", allow_empty=False):
    """A continuation is a position, never a grant or evidence of a complete scan."""
    query = query.strip()
    if len(query) > 256 or not query and not allow_empty:
        raise HTTPException(422, "Enter up to 256 characters to search your tasks.")
    current = context(request)
    if expected and not auth.constant_time_equals(expected, current):
        raise HTTPException(409, "Your signed-in account, workspace or access changed. Reload Tasks before reading private results.")
    before = _position(cursor, query, current)
    limit = max(1, min(int(limit), 100))
    from ._shared import _world

    world = _world()
    rows = world.list_goals(owner=auth.goal_owner_filter(request), order="desc",
                            before_id=before, limit=WINDOW + 1)
    matched, consumed = [], 0
    folded = query.casefold()
    for goal in rows[:WINDOW]:
        consumed += 1
        if auth.can_access_goal(request, goal) and any(
            folded in (text or "").casefold() for text in (goal.title, goal.description, goal.result)
        ):
            matched.append(goal)
            if len(matched) >= limit:
                break
    # Ownership, department mappings and the displayed content must still be
    # current after collecting a page; never release an older private projection.
    more = consumed < len(rows)
    next_cursor = _continuation(current, query, rows[consumed - 1].id) if more else ""
    check(request, matched, current)
    return {"goals": matched, "context": current, "continuation": next_cursor,
            "complete": not more, "checked_at": time.time(), "notice": NOTICE}


def initial(request, *, limit=50):
    return page(request, "", limit=limit, allow_empty=True)


def present(goal):
    from .plain_labels import risk_label

    risk = risk_label(goal) or {}
    return {"id": str(goal.id), "title": goal.title, "description": (goal.description or "")[:160],
            "status": goal.status, "created_at": goal.created_at, "updated_at": goal.updated_at,
            "risk_tier": risk.get("tier"), "risk_reasons": risk.get("reasons")}


def link(query, cursor=""):
    parameters = {"q": query}
    if cursor:
        parameters["search_after"] = cursor
    return "/goals?" + urlencode(parameters)
