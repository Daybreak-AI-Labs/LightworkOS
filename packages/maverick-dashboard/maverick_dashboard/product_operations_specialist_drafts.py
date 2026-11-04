"""Typed Copilot controls for the same full specialist draft service."""
from __future__ import annotations

from dataclasses import asdict
from typing import Literal
from urllib.parse import urlencode

from fastapi import HTTPException
from maverick import domain
from maverick.governed_operations import digest
from pydantic import Field

from . import specialist_drafts as native
from .plain_labels import agent_role_title, capability_label, model_label, pack_display_name
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class NameInput(StrictInput):
    name: str = Field(min_length=1, max_length=128)


class OriginalInput(StrictInput):
    selected: str = Field(pattern=r"^SPD-[a-f0-9]{32}$")


class SelectedInput(NameInput):
    selected: str = Field(pattern=r"^SPD-[a-f0-9]{32}$")
    acknowledge_previous: bool = False


class TryInput(SelectedInput):
    task: str = Field(min_length=8, max_length=4000)


class PublishInput(SelectedInput):
    reason: str = Field(default="", max_length=300)


class SaveInput(NameInput):
    title: str = Field(default="", max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    persona: str = Field(min_length=8, max_length=16000)
    allow_tools: list[str] = Field(min_length=1, max_length=5000)
    deny_tools: list[str] = Field(default_factory=list, max_length=5000)
    max_risk: Literal["low", "medium", "high"]
    model_role: str = Field(default="", max_length=128)
    model: str = Field(default="", max_length=200)
    mcp_servers: list[str] | None = Field(default=None, max_length=5000)
    acknowledge_previous: bool = False


def _unpublished_drafts(request):
    actor, context = native.authority(request)
    active_names = set(domain.available_domains())
    rows = native.STORE.list(limit=native.MAX_RECORDS + 1)
    if len(rows) > native.MAX_RECORDS:
        raise HTTPException(409, "The complete retained draft history exceeds its supported limit. No choices were silently omitted.")
    current = {}
    for row in sorted(rows, key=lambda item: (item["created_at"], item["id"]), reverse=True):
        if row.get("actor") != actor or row.get("context") != context or row.get("action") != "save" or row.get("state") != "confirmed" or row.get("_audit_pending"):
            continue
        name = row["name"]
        if name in current or name in active_names:
            continue
        try:
            saved = native.saved_draft(request, row["id"])
            if native._source(request, name)["profile"] is None:
                current[name] = saved
        except HTTPException as exc:
            if exc.status_code not in {403, 404, 409}:
                raise
    native.authority(request, context)
    return current


def _profiles(request):
    from .workforce_ops_api import _test_profiles
    native.authority(request)
    profiles = _test_profiles(request)
    unpublished = {name: domain._coerce(name, row["profile"]) for name, row in _unpublished_drafts(request).items() if name not in profiles}
    return {**unpublished, **profiles}


def _profile_choices(request, selection):
    profiles = _profiles(request)
    names = [{"value": name, "label": pack_display_name(name, profile.persona, profile.description)} for name, profile in sorted(profiles.items())]
    chosen = selection.get("name") or selection.get("specialist") or selection.get("agent")
    return profiles, names, chosen if chosen in profiles else next(iter(profiles), "")


def _chosen_name(request, selection, arguments=None):
    _, names, chosen = _profile_choices(request, {**selection, **(arguments or {})})
    return names, chosen


def name_snapshot(request, selection):
    native.authority(request)
    profiles, names, name = _profile_choices(request, selection)
    states = [(row["value"], digest(asdict(profiles[row["value"]]))) for row in names]
    return Snapshot(digest([native.authority(request), states]), "Current specialist definitions in this account and workspace", native.NOTICE,
        fields=[{"name": "name", "label": "Specialist or agent", "kind": "select", "required": True, "value": name, "choices": names}],
        blocked="No specialist is available to this account." if not names else "")


def _editor_link(request, state):
    parameters = {"name": state["name"]}
    if state["current"] is None:
        row = _unpublished_drafts(request).get(state["name"])
        if row is None:
            raise HTTPException(409, "This unpublished draft is no longer available. Choose a current owned draft again.")
        parameters = {"new": "1", "specialist_draft": row["id"]}
    return {"href": "/agents?" + urlencode(parameters) + "#specialist-drafts", "label": "Open complete specialist editor"}


def author_prepare(request, _selection, arguments):
    state = native.inventory(request, arguments["name"])
    if state["current"] is None:
        return Preview("Open your owned unpublished draft in the blank editor, then choose Load draft. Nothing is published and entered work is kept.",
            native={"Open complete editor": _editor_link(request, state)})
    return Preview("Open the complete specialist editor. Any work already entered there is kept; nothing is saved or published.",
        native={"specialist_draft_author": {"context": state["context"], "binding": state["binding"], "name": state["name"]}})


def read_prepare(request, _selection, arguments):
    state = native.inventory(request, arguments["name"])
    return Preview("Read the current specialist and choose a named retained draft or original decision in Agent Factory.", native={
        "Current specialist": native._readable(state["current"], "definition") if state["current"] else "No active custom agent",
        "Saved drafts": [row["label"] for row in state["drafts"]], "Earlier definitions": [row["label"] for row in state["earlier"]],
        "Original decisions": [row["label"] for row in state["originals"]], "Limits": native.NOTICE,
        "Open complete editor": _editor_link(request, state)})


def selection_snapshot(action):
    def snapshot(request, selection):
        state = name_snapshot(request, selection)
        names, name = _chosen_name(request, selection)
        groups = _choice_groups(request, names, "earlier" if action == "restore" else "drafts")
        choices = groups.get(name, [])
        fields = state.fields + [{"name": "selected", "label": "Earlier definition" if action == "restore" else "Saved draft", "kind": "select",
            "required": True, "depends_on": "name", "choices": choices, "choices_by": groups}]
        fields.append(_ack_field())
        if action == "try":
            fields.append({"name": "task", "label": "Fictional sample request", "kind": "textarea", "required": True, "max_length": 4000})
        if action in {"publish", "restore"}:
            fields.append({"name": "reason", "label": "Reason for proceeding without a complete passing check (optional)", "kind": "textarea", "max_length": 300})
        return Snapshot(digest([state.revision, groups]), state.source, native.NOTICE, fields=fields,
            blocked="Save a complete draft in Agent Factory first." if not any(groups.values()) else state.blocked)
    return snapshot


def save_snapshot(request, selection):
    state = name_snapshot(request, selection)
    profiles, _names, name = _profile_choices(request, selection)
    profile = asdict(profiles[name]) if name else {}
    profile = profile or {}
    from maverick.tools import base_tool_names
    # The editor remains the complete form. This typed edit changes at most one
    # model entry and preserves the complete map and every other retained field.
    known = base_tool_names(configured_optional=True, include_plugins=False)
    if known is None or len(known) > 10000:
        raise HTTPException(503, "The complete built-in action choices could not be read. Open the complete editor to review retained actions.")
    known |= set(profile.get("allow_tools", [])) | set(profile.get("deny_tools", []))
    choices = [{"value": action, "label": capability_label(action)} for action in sorted(known)]
    from maverick.role_edit import ROLES

    from .app import model_picker_options
    models = model_picker_options()
    role_choices = {}
    retained_models = set()
    for item_name, item_profile in profiles.items():
        labels = [{"value": "", "label": "Keep every AI choice"}, {"value": item_name, "label": "This specialist or agent"}]
        labels += [{"value": role, "label": agent_role_title(role).replace(".", " ").replace("-", " ")}
                   for role in dict.fromkeys((*ROLES, *item_profile.models)) if role != item_name]
        role_choices[item_name] = labels
        retained_models.update(item_profile.models.values())
    model_choices = [{"value": "", "label": "Use the workspace choice"}]
    model_choices += [{"value": spec, "label": model_label(spec)} for spec, _label in models]
    available = {spec for spec, _label in models}
    model_choices += [{"value": spec, "label": "Saved choice · " + model_label(spec)} for spec in sorted(retained_models - available)]
    services = native._server_state([server for item in profiles.values() for server in item.mcp_servers])
    server_choices = [{"value": row["value"], "label": row["label"]} for row in services["choices"]]
    return Snapshot(digest([state.revision, role_choices, model_choices, services]), state.source, "Save a draft of these changes while preserving its other complete settings. Use Open complete specialist editor to change every field. Tool services connect only for new work; risk limits and the caller's permissions still apply.",
        fields=state.fields + [{"name": "title", "label": "Draft name (optional)", "kind": "text", "max_length": 120},
            {"name": "description", "label": "Name people see", "kind": "text", "required": True, "max_length": 1000, "value": profile.get("description", "")},
            {"name": "persona", "label": "What should it do?", "kind": "textarea", "required": True, "max_length": 16000, "value": profile.get("persona", "")},
            {"name": "allow_tools", "label": "Permitted actions", "kind": "multiselect", "required": True, "choices": choices, "value": profile.get("allow_tools", [])},
            {"name": "deny_tools", "label": "Actions it must never use", "kind": "multiselect", "choices": choices, "value": profile.get("deny_tools", [])},
            {"name": "max_risk", "label": "Highest risk", "kind": "select", "required": True, "value": profile.get("max_risk", "low"),
                "choices": [{"value": level, "label": level.capitalize()} for level in ("low", "medium", "high")]},
            {"name": "model_role", "label": "Change the AI for (optional)", "kind": "select", "value": "", "depends_on": "name",
                "choices": role_choices.get(name, []), "choices_by": role_choices},
            {"name": "model", "label": "AI choice (used only when a part is selected above)", "kind": "select", "value": "", "choices": model_choices},
            {"name": "mcp_servers", "label": "Connected tool services", "kind": "multiselect", "choices": server_choices, "value": profile.get("mcp_servers", [])},
            _ack_field()], blocked=state.blocked)


def _ack_field():
    return {"name": "acknowledge_previous", "label": "I read any earlier unconfirmed original and acknowledge that earlier work may already exist", "kind": "select",
        "value": False, "choices": [{"value": False, "label": "No earlier unknown outcome, or not acknowledged"}, {"value": True, "label": "Yes, this is a separately reviewed new intent"}]}


def prepare_for(action):
    def prepare(request, _selection, arguments):
        if action == "save":
            profile = native.inventory(request, arguments["name"])["current"]
            saved = _unpublished_drafts(request).get(arguments["name"]) if profile is None else None
            if profile is None and saved is None:
                raise HTTPException(409, "This unpublished draft is no longer available. Choose a current owned draft again.")
            retained = saved["patch"] if saved else {}
            entered = {**retained, **{key: arguments[key] for key in ("description", "persona", "allow_tools", "deny_tools", "max_risk")}}
            if arguments.get("mcp_servers") is not None:
                entered["mcp_servers"] = arguments["mcp_servers"]
            role = arguments.get("model_role", "")
            model = arguments.get("model", "")
            if role:
                from maverick.llm import ModelNotAllowedError, require_model_allowed
                from maverick.role_edit import ROLES
                models = dict((saved["profile"] if saved else profile).get("models", {}))
                if role not in {*ROLES, arguments["name"], *models}:
                    raise HTTPException(422, "Choose this specialist or one of its supporting parts before changing an AI choice.")
                if model:
                    try:
                        models[role] = require_model_allowed(model)
                    except ModelNotAllowedError as exc:
                        raise HTTPException(409, "This AI choice is no longer permitted by the current workspace policy. Choose an allowed AI and review the draft again.") from exc
                else:
                    models.pop(role, None)
                entered["models"] = models
            elif model:
                raise HTTPException(422, "Choose which part should use this AI before reviewing the draft.")
            prepared = native.prepare(request, arguments["name"], action, title=arguments["title"],
                entered=entered, acknowledge_previous=arguments["acknowledge_previous"])
        else:
            prepared = native.prepare(request, arguments["name"], action, selected=arguments["selected"],
                task=arguments.get("task", ""), reason=arguments.get("reason", ""), acknowledge_previous=arguments["acknowledge_previous"])
        return Preview("Review every setting and consequence before confirming this specialist decision.", native.changes(request, prepared), prepared)
    return prepare


def _outcome(result):
    details = {"Decision": result["action"], "Recorded": result["recorded_at"], "Limits": result["notice"],
        "Read original decision": {"href": "/agents?draft_original=" + result["operation"] + "#specialist-drafts", "label": "Read original specialist decision"}}
    if result.get("run"):
        run = result["run"]
        details.update({"Answer check": {"done": "Finished", "running": "Checking answers", "prepared": "Waiting to start",
            "stopped": "Stopped", "unknown": "Result unconfirmed"}.get(run["state"], "Result unconfirmed"),
            "Answers received": len(run["results"]), "Questions passed": run["passed"],
            "Recorded model spend": f"${run['spent_dollars']:.6f}",
            "Answers": [{"Question": item["task"], "Answer": item["answer"], "Passing conditions met": "Sample only; none declared" if item.get("sample") else "Yes" if item["passed"] else "No"} for item in run["results"]]})
    return Outcome("confirmed" if result["confirmed"] else "unconfirmed", result["message"], details)


def execute(request, _selection, arguments, prepared, operation):
    if arguments["name"] != prepared["name"]:
        raise HTTPException(409, "The selected specialist changed. Review it again.")
    return _outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    native.authority(request, prepared["context"])
    if native.STORE.get("SPD-" + operation) is None:
        if not read_only:
            return None
        return Outcome("unconfirmed", "No original receipt is available. Nothing was repeated; do not treat current settings as confirmation.")
    return _outcome(native.original(request, operation, prepared=prepared))


def original_snapshot(request, selection):
    import time
    actor, context = native.authority(request)
    rows = native.STORE.list(limit=native.MAX_RECORDS + 1)
    if len(rows) > native.MAX_RECORDS:
        raise HTTPException(409, "The complete original history exceeds its supported limit. No choices were silently omitted.")
    rows = [row for row in rows if row.get("actor") == actor and row.get("context") == context]
    choices = [{"value": row["id"], "label": native.ACTIONS[row["action"]] + " · " + time.strftime("%b %d, %Y %H:%M", time.localtime(row["created_at"]))}
               for row in sorted(rows, key=lambda item: (item["created_at"], item["id"]), reverse=True)]
    native.authority(request, context)
    return Snapshot(digest([actor, context, [(row["id"], row["revision"]) for row in rows]]), "Your original specialist decisions",
        "Read the retained outcome without another answer request or publication. Source names and answers are withheld when current source access is unavailable.",
        fields=[{"name": "selected", "label": "Original decision", "kind": "select", "required": True, "choices": choices}],
        blocked="No original specialist decision is recorded." if not choices else "")


def _choice_groups(request, names, kind):
    import time
    actor, context = native.authority(request)
    rows = native.STORE.list(limit=native.MAX_RECORDS + 1)
    if len(rows) > native.MAX_RECORDS:
        raise HTTPException(409, "The complete retained draft history exceeds its supported limit. No choices were silently omitted.")
    groups = {row["value"]: [] for row in names}
    for row in sorted(rows, key=lambda item: (item["created_at"], item["id"]), reverse=True):
        if row.get("actor") != actor or row.get("context") != context or row.get("name") not in groups:
            continue
        wanted = kind == "originals" or (kind == "drafts" and row["action"] == "save" and row["state"] == "confirmed" and not row.get("_audit_pending"))
        wanted = wanted or (kind == "earlier" and row["action"] in {"publish", "restore"} and row.get("before", {}).get("profile"))
        if wanted:
            label = (row.get("title") or native.ACTIONS[row["action"]]) if kind == "drafts" else native.ACTIONS[row["action"]]
            if kind == "earlier":
                label = "Before " + label.lower()
            groups[row["name"]].append({"value": row["id"], "label": label + " · " + time.strftime("%b %d, %Y %H:%M", time.localtime(row["created_at"]))})
    native.authority(request, context)
    return groups


def original_prepare(request, _selection, arguments):
    result = native.original(request, arguments["selected"])
    return Preview(result["message"], native=_outcome(result).details)


def entries():
    common = {"family": "models", "pages": ("/agents", "/workforce"), "direct_ui": native.PAGE}
    writes = {"execute": execute, "recover": recover,
        "read_recovery": lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True)}
    return (
        Adapter("specialists.drafts.author", "Open complete specialist editor", input_model=NameInput, snapshot=name_snapshot, prepare=author_prepare, **common),
        Adapter("specialists.drafts.read", "Read specialist drafts and versions", input_model=NameInput, snapshot=name_snapshot, prepare=read_prepare, **common),
        Adapter("specialists.drafts.save", "Save a specialist draft", input_model=SaveInput, snapshot=save_snapshot, prepare=prepare_for("save"), **writes, **common),
        Adapter("specialists.drafts.try", "Try a saved specialist draft", input_model=TryInput, snapshot=selection_snapshot("try"), prepare=prepare_for("try"), **writes, **common),
        Adapter("specialists.drafts.check", "Check every saved question on a draft", input_model=SelectedInput, snapshot=selection_snapshot("check"), prepare=prepare_for("check"), **writes, **common),
        Adapter("specialists.drafts.publish", "Publish a saved specialist draft", input_model=PublishInput, snapshot=selection_snapshot("publish"), prepare=prepare_for("publish"), **writes, **common),
        Adapter("specialists.drafts.restore", "Restore an earlier specialist definition", input_model=PublishInput, snapshot=selection_snapshot("restore"), prepare=prepare_for("restore"), **writes, **common),
        Adapter("specialists.drafts.original", "Read an original specialist decision", input_model=OriginalInput, snapshot=original_snapshot, prepare=original_prepare, **common),
    )
