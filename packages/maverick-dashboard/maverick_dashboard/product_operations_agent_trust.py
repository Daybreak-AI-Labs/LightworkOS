"""Copilot reads the Agent trust page and makes its changes through the
page's own functions in ``trust_page_api``: the same permission checks, the
same setting record and the same saved result, read back afterwards.
Partner request limits are in ``product_operations_partner_limits``. Adding,
blocking, unblocking and removing an agent (the ``/api/v1/trust/agents``
routes in ``api.py``) have no Copilot operation yet."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import trust_page_api as native
from .identity_format import humanize
from .plain_labels import money
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput

_PAGES = ("/trust", "/external-agents")
_FAMILY = "connections"
_BLOCKING = "Blocking unlisted agents"
_DIRECTION = {"inbound": "It may contact us", "outbound": "We may contact it", "both": "Both ways"}
_RISK = {"low": "Low-risk only", "medium": "Up to medium risk", "high": "Any risk", "unbounded": "Any risk"}
_STATUS = {"expired": "Expired", "not_yet_valid": "Not started yet"}
_UNREADABLE = "The list of outside agents can't be read right now. Open the page to check it."


class Enforcement(StrictInput):
    enforced: bool
    confirmed: bool = False


class Check(StrictInput):
    agent: str = Field(min_length=1, max_length=128)
    direction: Literal["inbound", "outbound"] = "inbound"
    tool: str = Field(default="", max_length=128)
    risk: Literal["low", "medium", "high"] | None = None


class Limits(StrictInput):
    agent: str = Field(min_length=1, max_length=128)
    direction: Literal["inbound", "outbound", "both"] = "both"
    allow_tools: list[str] = Field(default_factory=list, max_length=256)
    deny_tools: list[str] = Field(default_factory=list, max_length=256)
    max_risk: Literal["low", "medium", "high"] | None = None
    max_dollars: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    max_minutes: float | None = Field(default=None, ge=0, le=525_600, allow_inf_nan=False)
    data_scopes: list[str] = Field(default_factory=list, max_length=256)


def _names(values) -> str:
    return ", ".join(humanize(v) for v in values)


def _words(row: dict) -> dict:
    """One agent's limits in the page's words."""
    tools = row["allow_tools"]
    minutes = row["max_wall_seconds"]
    return {"Direction": _DIRECTION.get(row["direction"], humanize(row["direction"])),
            "Tools it may use": "All tools" if tools in ([], ["*"]) else _names(tools),
            "Tools it may never use": _names(row["deny_tools"]) or "None",
            "Highest-risk actions allowed": _RISK.get(row["max_risk"] or "unbounded", humanize(row["max_risk"])),
            "Spending limit per task": "No limit" if row["max_dollars"] is None else money(row["max_dollars"]),
            "Time limit per task": "No limit" if minutes is None else f"{round(minutes / 60, 1):g} minutes",
            "Data it may read": _names(row["data_scopes"]) or "None"}


def _status(row: dict) -> str:
    if row["revoked"]:
        return "Blocked"
    return "Active" if row["active"] else _STATUS.get(row["status"], "Not active")


def _state() -> dict:
    """What the page shows: blocking, and each agent with its limits."""
    from maverick import agent_trust

    from .control_plane import trust_overview

    overview = trust_overview()
    try:
        keys = {str(e.get("id") or ""): str(e.get("pubkey") or "") for e in agent_trust._load_managed()}
    except Exception:
        keys = {}
    return {"available": overview.get("available", False), "enforced": overview.get("enforced", False),
            "agents": overview.get("agents", []), "keys": keys}


def _details(state: dict) -> dict:
    return {_BLOCKING: "On" if state["enforced"] else "Off",
            "Outside agents": [{"Agent": humanize(row["id"]), "Status": _status(row), **_words(row),
                                "Set up by": "This app" if row["id"] in state["keys"] else "Your installation",
                                "Security key on file": "Yes" if row["has_key"] else "No"}
                               for row in state["agents"]]}


def _summary(state: dict) -> str:
    count = len(state["agents"])
    listed = "No outside agents are on the list." if not count else (
        "1 outside agent is on the list." if count == 1 else f"{count} outside agents are on the list.")
    return listed + (" Agents not on the list are turned away." if state["enforced"]
                     else " Blocking is off, so every outside agent is let in.")


def _snapshot(state: dict, *, fields=(), blocked="") -> Snapshot:
    if not state["available"]:
        blocked = _UNREADABLE
    return Snapshot(digest(state), "Current outside agents and their limits", _summary(state),
                    details=_details(state), fields=list(fields), blocked=blocked)


def _agent_choices(state: dict, *, managed_only: bool) -> list[dict]:
    return [{"value": row["id"], "label": humanize(row["id"])} for row in state["agents"]
            if not managed_only or row["id"] in state["keys"]]


def _row(state: dict, agent: str, *, managed_only: bool) -> dict:
    row = next((r for r in state["agents"] if r["id"] == agent
                and (not managed_only or agent in state["keys"])), None)
    if row is None:
        raise HTTPException(404, "Choose an agent from the list. Agents set up by your installation can't be edited here."
                            if managed_only else "Choose an agent from the list.")
    return row


# -- show -------------------------------------------------------------------

def show_snapshot(request, _selection):
    auth.require_page_permission(request, "/trust")
    return _snapshot(_state())


def show_prepare(request, selection, _arguments):
    from maverick import agent_trust

    shown = show_snapshot(request, selection)
    # The page reads the key only when someone asks for it; so does Copilot.
    key = agent_trust.local_pubkey()
    return Preview(shown.summary, native={**shown.details, "Our security key": key or "None yet"})


# -- blocking ---------------------------------------------------------------

def enforcement_snapshot(request, _selection):
    from . import settings_catalog as catalog

    native.require_global_permission(request, "admin")
    state = _state()
    on = bool(state["enforced"])
    return _snapshot(state, fields=[
        {"name": "enforced", "label": _BLOCKING, "kind": "select", "value": not on,
         "choices": [{"value": True, "label": "On"}, {"value": False, "label": "Off"}]},
        {"name": "confirmed", "label": catalog.BY_ID["agent_trust.enforce"].warning, "kind": "boolean",
         "value": False}])


def enforcement_prepare(request, _selection, arguments):
    native.require_global_permission(request, "admin")
    on = bool(_state()["enforced"])
    if arguments["enforced"] is on:
        raise HTTPException(422, f"Blocking is already {'on' if on else 'off'}. Nothing was changed.")
    if on and not arguments["confirmed"]:
        raise HTTPException(409, "Confirm that every outside agent may then work with Lightwork. Nothing was changed.")
    summary = ("Turn on blocking. Agents not on the list are turned away from their next contact." if not on else
               "Turn off blocking. Any outside agent can then work with Lightwork, even one not on the list.")
    return Preview(summary, changes=[{"field": _BLOCKING, "before": "On" if on else "Off",
                                      "after": "Off" if on else "On"}])


def enforcement_execute(request, _selection, arguments, _review, _operation):
    try:
        native.apply_enforcement(request, arguments["enforced"], confirm=arguments["confirmed"])
    except native.ConfirmationNeeded as exc:
        raise HTTPException(409, "Confirm that every outside agent may then work with Lightwork. "
                                 "Nothing was changed.") from exc
    on = native._enforced_now()
    words = "On" if on else "Off"
    return Outcome("confirmed", f"Blocking is now {words.lower()}.", {_BLOCKING: words})


# -- check access -----------------------------------------------------------

def check_snapshot(request, _selection):
    native.require_permission(request, "view")
    state = _state()
    choices = _agent_choices(state, managed_only=False)
    tools = sorted({t for row in state["agents"] for t in row["allow_tools"] + row["deny_tools"] if t != "*"})
    return _snapshot(state, blocked="" if choices else "No outside agents are on the list.", fields=[
        {"name": "agent", "label": "Agent", "kind": "select", "value": choices[0]["value"] if choices else "",
         "choices": choices},
        {"name": "direction", "label": "Who starts the conversation", "kind": "select", "value": "inbound",
         "choices": [{"value": "inbound", "label": "The agent contacts us"},
                     {"value": "outbound", "label": "We contact the agent"}]},
        {"name": "tool", "label": "Tool it wants to use", "kind": "select", "value": "",
         "choices": [{"value": "", "label": "No particular tool"},
                     *({"value": t, "label": humanize(t)} for t in tools)]},
        {"name": "risk", "label": "Riskiest action it wants to take", "kind": "select", "value": None,
         "choices": [{"value": None, "label": "Not stated"},
                     *({"value": k, "label": humanize(k)} for k in ("low", "medium", "high"))]}])


def check_prepare(request, _selection, arguments):
    agent = arguments["agent"]
    decision = native.check_access(request, agent, native.CheckIn(
        direction=arguments["direction"], tools=[arguments["tool"]] if arguments["tool"] else [],
        risk=arguments["risk"]))
    return Preview(decision["reason"], native={"Agent": humanize(agent), "Allowed": decision["allowed"],
                                               "Reason": decision["reason"]})


# -- edit limits ------------------------------------------------------------

def _limits_row(arguments: dict) -> dict:
    """The arguments as the saved agent row reads them back."""
    minutes = arguments["max_minutes"]
    return {"direction": arguments["direction"], "allow_tools": arguments["allow_tools"] or ["*"],
            "deny_tools": arguments["deny_tools"], "max_risk": arguments["max_risk"] or "unbounded",
            "max_dollars": arguments["max_dollars"],
            "max_wall_seconds": None if minutes is None else round(minutes * 60),
            "data_scopes": arguments["data_scopes"]}


def edit_snapshot(request, _selection):
    from .app import _trust_context

    native.require_permission(request, "admin")
    state = _state()
    choices = _agent_choices(state, managed_only=True)
    first = _row(state, choices[0]["value"], managed_only=True) if choices else None
    page = _trust_context(request)
    tools = [{"value": value, "label": label} for value, label in page["tool_choices"]]
    areas = page["area_choices"]
    scopes = {value: label for value, label in areas.get("recent", [])}
    for group in areas.get("groups", []):
        scopes.update({value: label for value, label in group.get("options", [])})
    minutes = first["max_wall_seconds"] if first else None
    fields = [
        {"name": "agent", "label": "Agent", "kind": "select", "value": first["id"] if first else "",
         "choices": choices},
        {"name": "direction", "label": "Direction", "kind": "select", "value": first["direction"] if first else "both",
         "choices": [{"value": k, "label": v} for k, v in _DIRECTION.items()]},
        {"name": "allow_tools", "label": "Tools it may use (choose none for all tools)", "kind": "multiselect",
         "value": [t for t in first["allow_tools"] if t != "*"] if first else [], "choices": tools},
        {"name": "deny_tools", "label": "Tools it may never use", "kind": "multiselect",
         "value": first["deny_tools"] if first else [], "choices": tools},
        {"name": "max_risk", "label": "Highest-risk actions allowed", "kind": "select",
         "value": (first["max_risk"] if first and first["max_risk"] != "unbounded" else "high"),
         "choices": [{"value": k, "label": _RISK[k]} for k in ("low", "medium", "high")]},
        {"name": "max_dollars", "label": "Spending limit per task in dollars (empty means no limit)",
         "kind": "number", "value": first["max_dollars"] if first else None},
        {"name": "max_minutes", "label": "Time limit per task in minutes (empty means no limit)",
         "kind": "number", "value": None if minutes is None else round(minutes / 60, 1)},
        {"name": "data_scopes", "label": "Data it may read (none chosen means no access)", "kind": "multiselect",
         "value": first["data_scopes"] if first else [],
         "choices": [{"value": k, "label": v} for k, v in scopes.items()]}]
    return _snapshot(state, fields=fields, blocked="" if choices else
                     "No agent on the list was added in this app, so none can be edited here.")


def edit_prepare(request, _selection, arguments):
    native.require_permission(request, "admin")
    row = _row(_state(), arguments["agent"], managed_only=True)
    before, after = _words(row), _words(_limits_row(arguments))
    changes = [{"field": name, "before": before[name], "after": after[name]}
               for name in before if before[name] != after[name]]
    if not changes:
        raise HTTPException(422, "These limits are the same as now. Nothing was changed.")
    return Preview(f"Change the limits for {humanize(row['id'])}. Its connection, security key and block "
                   "state stay as they are. Changes apply from its next task.", changes=changes)


def edit_execute(request, _selection, arguments, _review, _operation):
    agent = arguments["agent"]
    limits = _limits_row(arguments)
    native.apply_agent_limits(request, agent, native.AgentLimitsIn(
        pubkey=_state()["keys"].get(agent, ""), direction=limits["direction"],
        allow_tools=arguments["allow_tools"], deny_tools=limits["deny_tools"],
        max_risk=arguments["max_risk"], max_dollars=limits["max_dollars"],
        max_wall_seconds=limits["max_wall_seconds"], data_scopes=limits["data_scopes"]))
    saved = _row(_state(), agent, managed_only=True)
    return Outcome("confirmed", f"The limits for {humanize(agent)} are saved.", _words(saved))


def entries():
    return (
        Adapter("trust.agents.show", "Show outside agents and their limits", _FAMILY, "/trust", _PAGES,
                EmptyInput, show_snapshot, show_prepare,
                aliases=("which outside agents are allowed", "is blocking on", "show our security key")),
        Adapter("trust.agents.check", "Check whether an outside agent would be let in", _FAMILY, "/trust",
                _PAGES, Check, check_snapshot, check_prepare,
                aliases=("check agent access", "would this agent be let in")),
        Adapter("trust.agents.edit", "Change an outside agent's limits", _FAMILY, "/trust", _PAGES,
                Limits, edit_snapshot, edit_prepare, edit_execute,
                aliases=("edit agent limits", "change what an outside agent may do")),
        Adapter("trust.enforcement.set", "Turn blocking of unlisted agents on or off", _FAMILY, "/trust",
                _PAGES, Enforcement, enforcement_snapshot, enforcement_prepare, enforcement_execute,
                aliases=("turn on blocking", "turn off blocking", "block unlisted agents")),
    )
