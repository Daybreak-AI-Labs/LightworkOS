"""Current permission explanations and reviewed requests, never automatic grants."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException
from maverick.authority_effects import authority_effect_fence
from maverick.governed_records import GovernedRecordStore

from . import auth, rbac
from .access_explanations import role as explain_role

STORE = GovernedRecordStore("permission_access_requests", "PAR", "permission_access_request")
PERMISSIONS = {"operate", "audit", "admin"}


def enabled():
    from maverick.config import get_features
    return get_features().get("permission_access_requests") is True


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _layer(name, layer, tool, *, role=False):
    from maverick.safety.tool_risk import RISK_LEVELS, risk_rank, tool_risk
    allow = layer.get("allow_tools" if role else "allowed_tools") or []
    deny = layer.get("deny_tools" if role else "denied_tools") or []
    reason = ""
    if tool in deny:
        reason = "Explicitly denied by this policy."
    elif allow and tool not in allow:
        reason = "Outside this policy's allowed tool set."
    elif layer.get("max_risk") in RISK_LEVELS and risk_rank(tool_risk(tool)) > risk_rank(layer["max_risk"]):
        reason = "Tool risk exceeds this policy's " + layer["max_risk"] + " ceiling."
    return {"source": name, "allowed": not reason, "reason": reason or "No denial from this layer."}


def tool_explanation(principal, name):
    from maverick.capability import capability_from_config, role_for_principal
    from maverick.config import config_source_errors, load_config
    from maverick.runtime_overrides import denied_tools
    from maverick.safety.tool_risk import tool_risk
    config = load_config()
    if config_source_errors():
        raise ValueError("Permission policy is unavailable; no effective grant is claimed.")
    user_id = principal.removeprefix("user:")
    cap = capability_from_config(principal, channel="dashboard", user_id=user_id)
    security = config.get("security") or {}
    layers = [_layer("Organization/workspace tool ACL", security, name),
              _layer("Dashboard channel ACL", (security.get("channels") or {}).get("dashboard") or {}, name),
              _layer("Your exact execution-user ACL", (security.get("users") or {}).get(user_id) or {}, name)]
    blocked = name in denied_tools()
    layers.append({"source": "Runtime tool controls", "allowed": not blocked,
                   "reason": "Disabled by an administrator." if blocked else "No runtime block."})
    assigned = role_for_principal(principal)
    if assigned:
        layers.append(_layer("Assigned capability role: " + assigned, (config.get("roles") or {}).get(assigned) or {}, name, role=True))
    allowed = cap.permits(name)
    if not allowed and all(layer["allowed"] for layer in layers):
        reason = ("Effective policy denied all tools because its authority could not be resolved."
                  if any("\x00" in value for value in cap.allow_tools) else
                  "Effective capability excludes this tool; regulatory attenuation, expiration and secure default ceilings also apply.")
        layers.append({"source": "Effective capability envelope", "allowed": False, "reason": reason})
    return {"allowed": allowed, "risk": tool_risk(name), "ceiling": cap.max_risk,
            "layers": layers, "owner": "Installation administrator", "approver_scope": "installation",
            "limit": "This is the current dashboard root tool grant. Task roles, resource boundaries, consent and provider access are separately checked at use time."}


def explain(principal, kind, capability):
    from maverick.personal_identity import principal_current
    if kind not in {"permission", "tool"} or not isinstance(capability, str) or not capability or len(capability) > 80:
        raise ValueError("Choose a supported permission or tool name.")
    current = explain_role(principal)
    if kind == "permission":
        if capability not in PERMISSIONS:
            raise ValueError("Choose operate, audit or admin permission.")
        value = {"allowed": capability in rbac.permissions_for(auth.role_for_principal(principal)),
                 "source": current["source"], "owner": current["owner"],
                 "approver_scope": "workspace" if current["source"] == "Current workspace membership" else "installation",
                 "layers": [{"source": current["source"], "role": current["role"]}],
                 "limit": "This checks the current dashboard permission; it does not grant another person's private content."}
    else:
        value = tool_explanation(principal, capability)
        if "operate" not in rbac.permissions_for(auth.role_for_principal(principal)):
            value["allowed"] = False
            value["layers"].insert(0, {"source": current["source"], "allowed": False,
                                      "reason": "Current dashboard role does not permit tool actions."})
    if not principal_current(principal):
        value["allowed"] = False
        value["layers"].insert(0, {"source": "Current named membership", "allowed": False, "reason": "No current active named workspace membership."})
    value.update(kind=kind, capability=capability)
    value["snapshot"] = digest(value)
    return value


def can_review(request, row):
    if auth.caller_principal(request) == row["owner"]:
        return False
    return (auth.has_global_permission(request, "admin") if row["approver_scope"] == "installation"
            else auth.has_permission(request, "admin"))


def visible(request, row):
    return auth.caller_principal(request) == row["owner"] or can_review(request, row)


def public(request, row):
    if not visible(request, row):
        raise HTTPException(404, "No such access request.")
    current = explain(row["owner"], row["kind"], row["capability"])
    return {**{key: row.get(key) for key in ("id", "revision", "owner", "kind", "capability", "reason", "approver_scope", "status", "decision_note", "reviewed_by")},
            "current": current, "can_review": can_review(request, row), "audit_pending": bool(row.get("_audit_pending"))}


def submit(request, kind, capability, reason, snapshot, *, operation_id=None):
    from .permission_requests_api import authority
    with authority_effect_fence():
        actor = authority(request, write=True)
        current = explain(actor, kind, capability)
        if snapshot != current["snapshot"]:
            raise HTTPException(409, "Your permissions changed. Review the current explanation first.")
        if current["allowed"]:
            raise HTTPException(409, "This root permission is already allowed. Review task/resource/consent restrictions separately.")
        if not isinstance(reason, str) or not 10 <= len(reason) <= 1000:
            raise ValueError("Describe the business need in 10 to 1,000 characters without private task content or secrets.")
        for row in STORE.list(limit=10001):
            if row["owner"] == actor and row["kind"] == kind and row["capability"] == capability and row["status"] in {"requested", "reviewing"}:
                return public(request, row)
        row = STORE.create({"id": STORE.new_id(), "owner": actor, "kind": kind, "capability": capability,
                            "reason": reason, "approver_scope": current["approver_scope"],
                            "reviewed_explanation": current, "status": "requested", "operation_id": operation_id},
                           action="access_requested", actor=actor, max_records=10000)
        return public(request, row)


def decide(request, identifier, revision, decision, note, *, operation_id=None):
    from .permission_requests_api import authority
    with authority_effect_fence():
        actor = authority(request, write=True)
        if decision not in {"reviewing", "deny", "confirm_effective"} or not isinstance(note, str) or not 10 <= len(note) <= 1000:
            raise ValueError("Choose a review result and record a bounded explanation.")
        def mutate(row):
            if not can_review(request, row):
                raise HTTPException(403, "A different administrator with authority over the governing policy must review this request.")
            current = explain(row["owner"], row["kind"], row["capability"])
            if decision == "confirm_effective" and not current["allowed"]:
                raise HTTPException(409, "The requested permission is still blocked. Change the actual policy through its existing controls, then check again.")
            row.update(status={"reviewing": "reviewing", "deny": "denied", "confirm_effective": "effective"}[decision],
                       decision_note=note, reviewed_by=actor, reviewed_explanation=current, decision_operation_id=operation_id)
        row = STORE.update(identifier, mutate, expected_revision=revision, action="access_reviewed", actor=actor)
        if row is None:
            raise HTTPException(404, "No such access request.")
        return public(request, row)
