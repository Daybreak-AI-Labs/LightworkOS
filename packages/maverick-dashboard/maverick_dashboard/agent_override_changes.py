"""Review exact agent definitions before the existing native override removal."""
from __future__ import annotations

import json
import math
import re
import time
from dataclasses import asdict

from fastapi import HTTPException
from maverick import config, domain, domain_edit
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import tools_ops_api
from .auth import caller_principal, caller_suites, is_dashboard_admin, require_permission
from .draft_api import context_for
from .plain_labels import EFFORT_LABELS, agent_role_title, capability_label, model_label

PAGE = "/agents#agent-override-change"
TTL = 600
ACTIONS = {"remove_custom", "reset_builtin"}
NOTICE = ("This changes the saved definition used for new work. Tasks already in progress can retain their earlier instructions. "
          "Past tasks, department rosters, schedules and saved workflows are kept; references to a removed agent may need to be changed separately.")


def authority(request, context=None, *, write=False):
    from .editor_policy import require_pack_editing as _require_pack_editing

    require_permission(request, "view")
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Reload Agent Factory before continuing.")
    if write:
        _require_pack_editing(request)
        tools_ops_api.same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current settings could not be checked. Nothing was changed.")
    return current


def _store():
    return GovernedRecordStore("agent-override-removal-requests", "AOR", "agent_override_removal_request")


def _snapshot(request, name, *, locked=False):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name):
        raise HTTPException(422, "Choose a current agent by name.")
    view = domain_edit._resolved_view(name) if locked else domain_edit.resolved_view(name)
    profile = domain.available_domains().get(name)
    if view is None or profile is None:
        return _damaged_snapshot(request, name)
    allowed = caller_suites(request)
    if allowed is not None and not set(view["suites"]) <= allowed:
        raise HTTPException(403, "Your current access does not include this agent's department.")
    raw = domain_edit.read_override(name)
    built = domain.builtin_domains().get(name)
    material = {"definition": asdict(profile), "saved_changes": raw, "view": view,
                "builtin": asdict(built) if built is not None else None}
    if len(json.dumps(material, ensure_ascii=False, allow_nan=False).encode()) > 1024 * 1024:
        raise HTTPException(409, "This complete definition exceeds the review limit. Shorten its instructions in Agent Factory before reviewing its removal or reset.")
    return material


def _damaged_snapshot(request, name):
    rejected = domain_edit.rejected_override_view(name)
    if rejected is None or not rejected["generation"]:
        raise HTTPException(409, "The saved setup is unavailable for a safe review. Nothing was changed.")
    principal = caller_principal(request)
    if (principal is not None and not is_dashboard_admin(principal)) or caller_suites(request) is not None:
        raise HTTPException(403, "An installation administrator with access to all departments must review this damaged setup.")
    built = domain.builtin_domains().get(name)
    return {"view": rejected, "definition": None, "saved_changes": {"damaged": True}, "damaged": True,
            "builtin": asdict(built) if built is not None else None}


def _refuse_while_trial_live(name):
    """A live trial keeps the saved definition as it is; a reset or removal waits until it is promoted or rolled back."""
    from .editor_policy import refuse_while_trial_live as refuse

    refuse(name)


def prepare(request, name, action, *, context=None):
    current = authority(request, context, write=True)
    if action not in ACTIONS:
        raise HTTPException(422, "Choose Remove custom agent or Reset to built-in.")
    material = _snapshot(request, name)
    _refuse_while_trial_live(name)
    expected = "reset_builtin" if material["view"]["is_builtin"] else "remove_custom"
    if action != expected:
        raise HTTPException(409, "This agent's origin changed. Review its current removal or reset controls.")
    if not material["saved_changes"]:
        raise HTTPException(409, "This agent has no saved changes to reset. Its built-in definition is already in use.")
    authority(request, current, write=True)
    return {"name": name, "action": action, "source_kind": "damaged" if material.get("damaged") else "loaded",
            "generation": material["view"]["generation"], "source": digest(material),
            "actor": tools_ops_api.actor(request), "context": current, "expires": time.time() + TTL}


PROFILE_LABELS = {"name": "Agent", "compartment": "Work separation", "description": "Description", "persona": "Full instructions",
    "allow_tools": "Permitted actions", "deny_tools": "Excluded actions", "max_risk": "Risk limit", "allow_paths": "Files it may use",
    "allow_hosts": "Web addresses it may use", "mcp_servers": "Connected tool services", "models": "AI choices",
    "knowledge_sources": "Company knowledge", "authoring": "How it was created", "effort": "Answer effort",
    "refuse": "Requests it must refuse", "extends": "Inherited definition", "workflow": "Full work instructions",
    "output": "Expected deliverable", "autonomy": "Saved independence choices"}
NESTED_LABELS = {
    "workflow": {"name": "Step", "instruction": "Full instructions", "tools": "Suggested actions", "gate": "Declared review requirement"},
    "output": {"shape": "Presentation", "deliverable": "Deliverable", "consumers": "People who use it", "cadence": "Frequency", "gate": "Required review"},
    "autonomy": {"default": "Default independence", "low": "Low-risk work", "medium": "Medium-risk work", "high": "High-risk work",
        "onboarding": "Setup review required", "levels_enabled": "Independence controls enabled", "config_override": "Separate workforce settings apply",
        "pack_default": "Agent's default independence", "pack": "Agent's saved independence", "effective": "Independence actually in use"},
}
INDEPENDENCE = {"observe": "Observe only", "suggest": "Suggest work", "request": "Request permission", "auto": "Act within permitted limits"}
CHOICE_LABELS = {"max_risk": {"low": "Low", "medium": "Medium", "high": "High"}, "effort": EFFORT_LABELS,
    "authoring": {"manual": "Manually entered", "generated": "AI drafted"},
    "gate": {"review": "Review required", "approval": "Approval required"},
    "shape": {"prose": "Written response", "report": "Report", "table": "Table", "forecast": "Forecast"}}


def _details(value, labels, kind):
    if not isinstance(value, dict) or not set(value) <= set(labels):
        raise HTTPException(409, "This definition contains an unsupported review detail. Nothing was changed.")
    return [{labels[key]: _readable(child, key if kind != "autonomy" else "autonomy_value")}
            for key, child in value.items()]


def _readable(value, kind):
    if value is None:
        return None
    if kind == "definition":
        return _details(value, PROFILE_LABELS, kind)
    if kind == "workflow":
        if not isinstance(value, list):
            raise HTTPException(409, "The saved work instructions cannot be reviewed completely. Nothing was changed.")
        return [_details(step, NESTED_LABELS[kind], kind) for step in value]
    if kind in {"output", "autonomy"}:
        return _details(value, NESTED_LABELS[kind], kind)
    if kind == "models":
        if not isinstance(value, dict) or any(not isinstance(key, str) or not key.strip()
                or not isinstance(child, str) or not child.strip() for key, child in value.items()):
            raise HTTPException(409, "The complete saved AI choices cannot be read safely. Nothing was changed.")
        return [{"Part": agent_role_title(key).replace(".", " ").replace("-", " "), "AI choice": model_label(child)} for key, child in value.items()]
    if kind == "autonomy_value":
        if isinstance(value, dict):
            return _details(value, NESTED_LABELS["autonomy"], "autonomy")
        if isinstance(value, str):
            if value not in INDEPENDENCE:
                raise HTTPException(409, "This definition includes an unsupported independence choice. Nothing was changed.")
            return INDEPENDENCE[value]
    if kind in {"allow_tools", "deny_tools", "tools"}:
        if not isinstance(value, list):
            raise HTTPException(409, "The saved action choices cannot be reviewed completely. Nothing was changed.")
        return [capability_label(tool) for tool in value]
    if kind in CHOICE_LABELS and isinstance(value, str):
        return CHOICE_LABELS[kind].get(value, value)
    if isinstance(value, dict):
        raise HTTPException(409, "This definition contains an unsupported review detail. Nothing was changed.")
    return value


def changes(request, prepared):
    authority(request, prepared["context"], write=True)
    material = _snapshot(request, prepared["name"])
    if digest(material) != prepared["source"]:
        raise HTTPException(409, "This definition changed. Review its current version before deciding.")
    if material.get("damaged"):
        rows = [{"label": "Saved setup to discard", "after": prepared["name"]},
                {"label": "Damaged setup", "after": "This saved setup cannot be loaded safely, so its work instructions are unavailable for review. "
                    "You are explicitly discarding this exact damaged saved file, not approving or correcting its contents. A changed file will stop this request."}]
    else:
        rows = [{"label": label, "after": value} for row in _readable(material["definition"], "definition") for label, value in row.items()]
        rows.append({"label": "Saved changes being discarded", "after": _readable(material["saved_changes"], "definition")})
        rows.append({"label": "Current independence", "after": _readable(material["view"]["autonomy"], "autonomy")})
    rows.append({"label": "Effect", "after": ("Remove this custom agent. It has no built-in version to restore." if prepared["action"] == "remove_custom" else
        "Remove its saved changes and restore the built-in definition. Its built-in policy may allow more than the current saved limits.") + " " + NOTICE})
    if prepared["action"] == "reset_builtin":
        rows.append({"label": "Full built-in definition after reset", "after": _readable(material["builtin"], "definition")})
    authority(request, prepared["context"], write=True)
    return rows


def owned(request, operation, *, prepared=None):
    context = authority(request)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original agent change is unavailable.")
    store = _store()
    row = store.get("AOR-" + operation)
    if row and (row["actor"] != tools_ops_api.actor(request) or row["context"] != context):
        raise HTTPException(404, "This original change is unavailable to this account and workspace.")
    if row and prepared is not None and row["binding"] != digest([operation, prepared]):
        raise HTTPException(409, "This original request belongs to another reviewed change.")
    if row and row.get("_audit_pending"):
        row = store._flush(row)
    authority(request, context)
    return row


def original(request, operation, *, prepared=None):
    context = authority(request)
    row = owned(request, operation, prepared=prepared)
    result = {"context": context, "operation": operation, "confirmed": False, "notice": NOTICE,
              "message": "The original change is unconfirmed. Matching current settings or a missing agent do not confirm who changed it. Nothing was repeated."}
    if row:
        confirmed = row["state"] == "confirmed" and not row.get("_audit_pending")
        result.update(name=row["name"], action=row["action"], confirmed=confirmed, recorded_at=row["updated_at"], source_kind=row["source_kind"])
        if confirmed:
            result["message"] = "Your original reviewed " + ("custom agent removal" if row["action"] == "remove_custom" else "reset to the built-in definition") + " is confirmed. Nothing was repeated."
        try:
            current = domain_edit.resolved_view(row["name"])
        except (OSError, ValueError):
            current = None
        allowed = caller_suites(request)
        readable = current is not None and (allowed is None or set(current["suites"]) <= allowed)
        result["current"] = "A current definition is present. Read its latest settings separately." if readable else "No current definition is available to this account. This does not establish the original outcome."
        result["current_generation"] = current["generation"] if readable else None
    authority(request, context)
    return result


def catalog(request):
    context = authority(request)
    from .editor_policy import pack_editing_denial

    allowed = caller_suites(request)
    builtins = domain.builtin_domains()
    editing = pack_editing_denial(request) is None
    choices = [{"value": row["name"], "label": row["description"] or row["name"].replace("_", " "),
                "action": "reset_builtin" if row["name"] in builtins else "remove_custom"}
               for row in domain_edit.list_agents() if editing and row["is_override"] and (allowed is None or set(row["suites"]) <= allowed)] if editing else []
    principal = caller_principal(request)
    if editing and (principal is None or is_dashboard_admin(principal)) and allowed is None:
        for name in domain.rejected_workspace_domains():
            rejected = domain_edit.rejected_override_view(name)
            if rejected is not None and rejected["generation"]:
                choices.append({"value": name, "label": name.replace("_", " ") + " — damaged saved setup",
                                "action": "reset_builtin" if rejected["is_builtin"] else "remove_custom"})
    rows = _store().list(limit=10001)
    if len(rows) > 10000:
        raise HTTPException(409, "The retained change history exceeds its supported limit. Nothing was changed.")
    rows = sorted((row for row in rows if row["actor"] == tools_ops_api.actor(request) and row["context"] == context),
                  key=lambda row: (row["created_at"], row["id"]), reverse=True)
    authority(request, context)
    return {"context": context, "editing": editing, "choices": choices, "requests": [{"value": row["id"][4:], "label": row["name"].replace("_", " ") +
            " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in rows], "notice": NOTICE}


def apply(request, prepared, operation):
    context = authority(request, prepared["context"], write=True)
    actor = tools_ops_api.actor(request)
    with authority_effect_fence():
        if owned(request, operation, prepared=prepared):
            return original(request, operation, prepared=prepared)
        claim = None

        def guard():
            nonlocal claim
            authority(request, context, write=True)
            _refuse_while_trial_live(prepared["name"])
            expires = prepared.get("expires")
            if digest(_snapshot(request, prepared["name"], locked=True)) != prepared["source"]:
                raise HTTPException(409, "This definition changed. Review its current version; nothing was changed.")
            authority(request, context, write=True)
            if actor != prepared["actor"] or type(expires) not in {float, int} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
                raise HTTPException(409, "This review expired or the account changed. Review the current definition again; nothing was changed.")
            if claim is None:
                claim = _store().create({"id": "AOR-" + operation, "actor": actor, "context": context, "name": prepared["name"],
                    "action": prepared["action"], "source_kind": prepared["source_kind"], "binding": digest([operation, prepared]), "state": "started"},
                    action="agents.override_removal.started", actor=actor, max_records=10000)
                if claim.get("_audit_pending"):
                    raise HTTPException(503, "The activity record could not confirm this request. No agent change was attempted.")
                guard()

        try:
            removed = domain_edit.remove_override(prepared["name"], expected_generation=prepared["generation"], effect_guard=guard)
            if not removed:
                raise HTTPException(409, "No saved definition was removed. Current state is not an original receipt.")
            _store().update(claim["id"], lambda row: row.update(state="confirmed"), expected_revision=claim["revision"],
                            action="agents.override_removal.completed", actor=actor)
            from . import agent_changelog
            agent_changelog.record(prepared["name"], ["Removed this custom agent" if prepared["action"] == "remove_custom" else "Reset to the built-in version"], by=actor)
        except Exception as exc:
            if claim is not None or owned(request, operation, prepared=prepared) is not None:
                return original(request, operation, prepared=prepared)
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(409, "This exact definition could not be changed safely. Read the original result before a new decision.") from exc
        return original(request, operation, prepared=prepared)
