"""Employee requests to the actual policy owner; reviews never change grants."""
from __future__ import annotations

import re
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import permission_requests as service
from .draft_api import context_for

router = APIRouter(tags=["permission-access-requests"])


class ExplainIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: Literal["permission", "tool"]
    capability: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_.:-]{0,79}$")


class SubmitIn(ExplainIn):
    reason: str = Field(min_length=10, max_length=1000)
    snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")
    confirm_shared_with_reviewer: Literal[True]


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    expected_revision: int = Field(ge=1)
    decision: Literal["reviewing", "deny", "confirm_effective"]
    note: str = Field(min_length=10, max_length=1000)


def authority(request, *, write=False):
    auth.require_permission(request, "view")
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(403, "Use your named account for permission requests.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
        if not service.enabled():
            raise HTTPException(403, "Permission requests are disabled by your administrator.")
    return actor


def _call(operation):
    from maverick.privacy_ops import RecordConflict
    try:
        return operation()
    except RecordConflict as exc:
        raise HTTPException(409, "This request changed. Refresh before reviewing it.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(503, "The current policy or saved outcome could not be confirmed. Refresh before retrying.") from exc


_PERMISSION_LABELS = {"operate": "Carry out work", "audit": "Review activity and evidence", "admin": "Manage people and settings"}
_CAPABILITY = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,79}\Z")


def action_label(kind, capability):
    if kind == "permission":
        return _PERMISSION_LABELS.get(capability, "Dashboard action")
    from .tool_summary import plain_tool_summary
    text = plain_tool_summary(capability, None).removesuffix(". No description given.").rstrip(".")
    return re.sub(r"[_.:-]+", " ", text)


def policy_layers(value):
    from .identity_format import role_label
    labels = {"Organization/workspace tool ACL": "Organization and workspace policy",
              "Dashboard channel ACL": "Dashboard policy", "Your exact execution-user ACL": "Your individual work policy",
              "Runtime tool controls": "Administrator action controls", "Effective capability envelope": "Overall work restrictions",
              "Pinned installation administrator": "Installation administrator assignment"}
    reasons = {"Outside this policy's allowed tool set.": "Not among the actions this policy permits.",
               "No denial from this layer.": "This policy does not block the action.",
               "No runtime block.": "The administrator has not stopped this action.",
               "Current dashboard role does not permit tool actions.": "Your current role does not allow work actions.",
               "Effective policy denied all tools because its authority could not be resolved.": "Actions are blocked because current authority could not be confirmed.",
               "Effective capability excludes this tool; regulatory attenuation, expiration and secure default ceilings also apply.": "The overall work permissions block this action. Other policy restrictions, expiration and deployment safety rules also apply."}
    rows = []
    for layer in value.get("layers", []):
        source = layer["source"]
        if source.startswith("Assigned capability role: "):
            source = "Assigned work role: " + re.sub(r"[_.:-]+", " ", source.removeprefix("Assigned capability role: "))
        result = layer.get("reason") or (role_label(layer["role"]) if layer.get("role") else "No active role")
        if result.startswith("Tool risk exceeds this policy's "):
            result = "This action has more risk than the policy permits (highest permitted risk: " + result.removeprefix("Tool risk exceeds this policy's ").removesuffix(" ceiling.") + ")."
        rows.append({"source": labels.get(source, source), "reason": reasons.get(result, result)})
    return rows


def public_explanation(value):
    return {**value, "label": action_label(value["kind"], value["capability"]), "layers": policy_layers(value),
            "limit": ("This checks whether your current policy allows this action. Each task still checks its assigned responsibilities, data boundaries, consent and connected service access when it runs."
                      if value["kind"] == "tool" else value["limit"])}


def _binding(request):
    with auth.fresh_configuration():
        return service.digest([context_for(request), authority(request), auth.caller_role(request)])


def action_choices(request):
    """Built-in and current owned generated names; no add-on loading/probing."""
    from maverick.tools import base_tool_names
    bound = _binding(request)
    names = base_tool_names(configured_optional=True, include_plugins=False)
    if names is not None:
        from maverick import self_learning
        if self_learning.enabled():
            names |= self_learning.generated_tool_names(owner=authority(request))
    available = names is not None and len(names) <= 10000
    tools = [{"value": name, "label": action_label("tool", name)} for name in sorted(names or ())
             if _CAPABILITY.fullmatch(name)] if available else []
    if _binding(request) != bound:
        raise HTTPException(409, "Your account or workspace changed. Reload the current permission choices.")
    return {"permission": [{"value": name, "label": label} for name, label in _PERMISSION_LABELS.items()],
            "tool": tools, "tools_available": available,
            "tools_notice": ("These are built-in actions and your currently permitted created actions. Add-on action names are not loaded here. Current policy and other work restrictions still apply."
                             if available else "Tool choices could not be loaded completely. Refresh to try again. Dashboard actions and saved requests remain available.")}


def state(request, *, include_choices=False):
    bound, actor = _binding(request), authority(request)
    value = {"enabled": service.enabled(), "actor": actor, "context": bound,
             "examples": [public_explanation(service.explain(actor, "permission", name)) for name in sorted(service.PERMISSIONS)] +
                         [public_explanation(service.explain(actor, "tool", name)) for name in ("read_file", "write_file", "shell")],
             "records": [service.public(request, row) for row in service.STORE.list(limit=10001) if service.visible(request, row)]}
    if include_choices:
        value["choices"] = action_choices(request)
    for row in value["records"]:
        row["label"] = action_label(row["kind"], row["capability"])
        row["current"] = public_explanation(row["current"])
    if _binding(request) != bound:
        raise HTTPException(409, "Your account or workspace changed. Reload the current permission requests.")
    return value


@router.get("/access-requests", response_class=HTMLResponse)
def page(request: Request):
    authority(request)
    from .app import templates
    return templates.TemplateResponse(request, "permission_requests.html", {})


@router.get("/api/v1/access-requests")
def status(request: Request):
    return _call(lambda: state(request, include_choices=True))


@router.post("/api/v1/access-requests/explain")
def explain(request: Request, body: ExplainIn):
    actor = authority(request)
    def read():
        bound = _binding(request)
        value = service.explain(actor, body.kind, body.capability)
        if _binding(request) != bound:
            raise HTTPException(409, "Your account or workspace changed. Check the current policy again.")
        return {**public_explanation(value), "context": bound}
    return _call(read)


@router.post("/api/v1/access-requests")
def submit(request: Request, body: SubmitIn):
    return _call(lambda: service.submit(request, body.kind, body.capability, body.reason, body.snapshot))


@router.post("/api/v1/access-requests/{identifier}/decision")
def decide(request: Request, identifier: str, body: DecisionIn):
    auth.require_api_key_scope(request, "approvals:decide")
    return _call(lambda: service.decide(request, identifier, body.expected_revision, body.decision, body.note))
