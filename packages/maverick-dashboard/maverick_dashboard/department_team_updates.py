"""Exact saved-team previews and original-actor receipts; no work is dispatched."""
from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, replace

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.departments import (
    EntitlementError,
    deploy_department,
    fleet_name_for,
    get_department,
    merge_department_fleet,
)
from maverick.file_lock import cross_process_lock
from maverick.fleet import fleets_dir, load_fleet, save_fleet
from maverick.governed_operations import digest

from . import auth
from .draft_api import context_for

TTL = 600
PURPOSE = "lightwork.department-team-review.v1"


def context(request):
    suites = auth.caller_suites(request)
    scopes = auth.api_key_scopes(request)
    return digest({"account": context_for(request), "role": auth.caller_role(request),
                   "departments": sorted(suites) if suites is not None else None,
                   "key_scopes": sorted(scopes) if scopes is not None else None})


def authorize(request, key):
    from . import api
    auth.require_permission(request, "operate")
    auth.require_suite(request, key)
    dept = get_department(key)
    if dept is None:
        raise HTTPException(404, "This department is unavailable. Choose a current department.")
    tenant = api._department_request_tenant()
    if tenant is None and api._has_managed_tenant_roster():
        raise HTTPException(402, "Choose your workspace before setting up this department.")
    if not api._department_entitled_for_request(key):
        raise HTTPException(402, "This department needs an add-on. Ask your administrator to review your plan.")
    return dept, auth.caller_principal(request) or "", tenant or "__active__"


def _current(name, owner, tenant):
    current = load_fleet(name, tenant=tenant)
    if current is not None and current.owner != owner:
        raise HTTPException(404, "This team is unavailable.")
    if current is None and (fleets_dir(tenant=tenant) / (name + ".json")).exists():
        raise HTTPException(503, "The saved team could not be verified. Nothing will be overwritten; ask your administrator to review this team's storage.")
    return current


def _material(fleet):
    value = fleet.to_dict()
    value.pop("department_update_receipts", None)
    return value


def _plan(request, key, current):
    from maverick.domain_edit import list_agents

    dept, owner, tenant = authorize(request, key)
    by_name = {row["name"]: row for row in list_agents()}
    from maverick.suite_grants import DepartmentAccessError
    try:
        candidate = deploy_department(key, owner, save=False, tenant=tenant if tenant != "__active__" else None)
    except EntitlementError as exc:
        raise HTTPException(402, "This department needs an add-on. Ask your administrator to review your plan.") from exc
    except DepartmentAccessError as exc:
        raise HTTPException(403, "Your department access changed. Ask your administrator to review your access.") from exc
    if candidate is None:
        raise HTTPException(409, "This department changed. Choose a current department before reviewing again.")
    ready = {name for name in dept.members if by_name.get(name, {}).get("readiness", {}).get("state") == "action_ready"}
    candidate = replace(candidate, agents=tuple(row for row in candidate.agents if row.name in ready))
    if not candidate.agents and current is None:
        raise HTTPException(409, "No specialist in this department passed its action setup check. Open View team to review setup before creating the team.")
    after, added = merge_department_fleet(candidate, current, known_members=dept.members)
    from maverick.domain import enabled_domains
    profiles = enabled_domains()
    revision = digest({"profiles": {name: asdict(profiles[name]) for name in dept.members if name in profiles}, "context": context(request), "before": current.to_dict() if current else None,
                       "candidate": [row.to_dict() for row in candidate.agents], "catalog": dept.members,
                       "readiness": [by_name.get(name, {}).get("readiness", {}) for name in dept.members]})
    skipped = [{"name": name, "reason": by_name.get(name, {}).get("readiness", {}).get("label") or "Setup check unavailable",
                "fix_url": by_name.get(name, {}).get("readiness", {}).get("fix_url") or "/agents"}
               for name in dept.members if name not in ready]
    return after, revision, {"created": current is None, "added_count": added,
        "deployed_count": len(after.agents), "baseline_created": current is not None and not current.department_members_added,
        "skipped_count": len(skipped), "skipped_specialists": skipped}


def _roster(fleet):
    from .approval_queue_operations import safe
    from .identity_format import role_label
    from .plain_labels import pack_display_name
    return [{"Specialist": pack_display_name(row.name), "Job role": role_label(row.role),
             "What it does": safe(row.description) or "No description"} for row in (fleet.agents if fleet else ())]


def review(request, key):
    original = context(request)
    _dept, owner, tenant = authorize(request, key)
    name = fleet_name_for(key, owner)
    with authority_effect_fence(), cross_process_lock(fleets_dir(tenant=tenant) / (name + ".json"), strict=True):
        before = _current(name, owner, tenant)
        after, revision, result = _plan(request, key, before)
    if context(request) != original:
        raise HTTPException(409, "Your account, workspace or access changed. Review the current team again.")
    from .plain_labels import pack_display_name
    existing_names = {row.name for row in before.agents} if before else set()
    public = {"Team": get_department(key).title, "Before": _roster(before), "After": _roster(after),
              "New specialists": [pack_display_name(row.name) for row in after.agents if row.name not in existing_names],
              "Preserved": "Existing manual additions, removals, job roles and descriptions are retained.",
              "Setup still needed": [{"Specialist": pack_display_name(row["name"]), "Reason": row["reason"],
                  "Next step": {"label": "Review setup", "href": row["fix_url"]}} for row in result["skipped_specialists"]],
              "Meaning": "Saving this team does not run tasks, test connections or prove the AI service is available.",
              "Recovery history": "The team keeps the latest 32 save receipts. An older missing receipt cannot confirm a save; checking never repeats it.",
              "Older team": "This first update records the current catalog as already offered. No removed specialist is recreated; future newly offered specialists can be added." if result["baseline_created"] else "No older-team baseline change."}
    material = {"key": key, "context": original, "revision": revision, "expires_at": time.time() + TTL}
    return material, public


def token_review(request, key):
    material, public = review(request, key)
    material.update(purpose=PURPOSE, operation_id=secrets.token_hex(16))
    token = crypto_at_rest.seal_to_str(json.dumps(material, sort_keys=True, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "A secure review could not be prepared. No team was changed.")
    return {"token": token, "context": material["context"], "preview": public}


def open_token(token, *, recovery=False):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if (set(value) != {"key", "context", "revision", "expires_at", "purpose", "operation_id"}
                or value["purpose"] != PURPOSE or not isinstance(value["expires_at"], float)
                or (not recovery and not time.time() < value["expires_at"] <= time.time() + TTL)):
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This team review expired or could not be verified. Prepare a new review; no team was changed.") from exc


def receipt(request, material, operation_id):
    _dept, owner, tenant = authorize(request, material["key"])
    if context(request) != material["context"]:
        raise HTTPException(409, "Your account, workspace or access changed. Return to the original account to check this result.")
    current = _current(fleet_name_for(material["key"], owner), owner, tenant)
    if current is None:
        return None
    actor = owner or "local:dashboard"
    for row in current.department_update_receipts:
        if row.get("operation_id") == operation_id and row.get("actor") == actor:
            if row.get("review_revision") != material["revision"]:
                raise HTTPException(409, "This request belongs to a different review. No save was repeated.")
            if context(request) != material["context"]:
                raise HTTPException(409, "Your account, workspace or access changed. Return to the original account to check this result.")
            return {**row, "current_team_matches": digest(_material(current)) == row["after_revision"],
                    "team_href": "/fleets#team-" + current.name}
    return None


def apply(request, material, operation_id):
    with authority_effect_fence():
        _dept, owner, tenant = authorize(request, material["key"])
        name = fleet_name_for(material["key"], owner)
        with cross_process_lock(fleets_dir(tenant=tenant) / (name + ".json"), strict=True):
            prior = receipt(request, material, operation_id)
            if prior is not None:
                return prior, True
            if not time.time() < material["expires_at"] <= time.time() + TTL:
                raise HTTPException(409, "This review expired. Review the current team before saving.")
            current = _current(name, owner, tenant)
            after, revision, result = _plan(request, material["key"], current)
            if revision != material["revision"] or context(request) != material["context"]:
                raise HTTPException(409, "The saved team, ready specialists or your access changed after review. Nothing was saved. Review the current before and after again.")
            from maverick.audit import audit_event
            if audit_event("department_team_update_reviewed", agent="dashboard", actor=owner or "local:dashboard",
                           department=material["key"], operation_id=operation_id, added=result["added_count"], created=result["created"]) is not True:
                raise HTTPException(503, "The review could not be recorded. No team was changed.")
            accepted = {"operation_id": operation_id, "actor": owner or "local:dashboard", "review_revision": revision,
                        "after_revision": digest(_material(after)), "recorded_at": time.time(),
                        **{key: result[key] for key in ("created", "added_count", "deployed_count", "baseline_created")}}
            history = (*after.department_update_receipts, accepted)[-32:]
            save_fleet(replace(after, department_update_receipts=history), tenant=tenant)
            confirmed = receipt(request, material, operation_id)
            if confirmed is None:
                raise HTTPException(503, "The save response could not be confirmed. Check the original result before another save.")
            return confirmed, False
