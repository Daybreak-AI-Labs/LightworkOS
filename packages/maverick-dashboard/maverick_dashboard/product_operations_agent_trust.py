"""Copilot reads the Agent trust page and makes its changes through the
page's own functions in ``trust_page_api``: the same permission checks, the
same setting record and the same saved result, read back afterwards.
Partner request limits are in ``product_operations_partner_limits``. Every
change to the list writes its audit row before it is saved."""
from __future__ import annotations

import re
import unicodedata
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


class _LimitFields(StrictInput):
    direction: Literal["inbound", "outbound", "both"] = "both"
    allow_tools: list[str] = Field(default_factory=list, max_length=256)
    deny_tools: list[str] = Field(default_factory=list, max_length=256)
    max_risk: Literal["low", "medium", "high"] | None = None
    max_dollars: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    max_minutes: float | None = Field(default=None, ge=0, le=525_600, allow_inf_nan=False)
    data_scopes: list[str] = Field(default_factory=list, max_length=256)


class Limits(_LimitFields):
    agent: str = Field(min_length=1, max_length=128)


class NewAgent(_LimitFields):
    name: str = Field(min_length=1, max_length=60)
    pubkey: str = Field(default="", max_length=64)
    max_risk: Literal["low", "medium", "high"] | None = "low"


class Chosen(StrictInput):
    agent: str = Field(min_length=1, max_length=128)


class Confirmed(Chosen):
    confirmed: bool = False


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


def _limit_fields(request, first: dict | None) -> list[dict]:
    """The page's limit controls, filled from ``first`` (an agent row) or
    the page's defaults for a new agent."""
    from .app import _trust_context

    page = _trust_context(request)
    tools = [{"value": value, "label": label} for value, label in page["tool_choices"]]
    areas = page["area_choices"]
    scopes = {value: label for value, label in areas.get("recent", [])}
    for group in areas.get("groups", []):
        scopes.update({value: label for value, label in group.get("options", [])})
    minutes = first["max_wall_seconds"] if first else None
    return [
        {"name": "direction", "label": "Direction", "kind": "select", "value": first["direction"] if first else "both",
         "choices": [{"value": k, "label": v} for k, v in _DIRECTION.items()]},
        {"name": "allow_tools", "label": "Tools it may use (choose none for all tools)", "kind": "multiselect",
         "value": [t for t in first["allow_tools"] if t != "*"] if first else [], "choices": tools},
        {"name": "deny_tools", "label": "Tools it may never use", "kind": "multiselect",
         "value": first["deny_tools"] if first else [], "choices": tools},
        {"name": "max_risk", "label": "Highest-risk actions allowed", "kind": "select",
         "value": (first["max_risk"] if first and first["max_risk"] != "unbounded" else "high") if first else "low",
         "choices": [{"value": k, "label": _RISK[k]} for k in ("low", "medium", "high")]},
        {"name": "max_dollars", "label": "Spending limit per task in dollars (empty means no limit)",
         "kind": "number", "value": first["max_dollars"] if first else None},
        {"name": "max_minutes", "label": "Time limit per task in minutes (empty means no limit)",
         "kind": "number", "value": None if minutes is None else round(minutes / 60, 1)},
        {"name": "data_scopes", "label": "Data it may read (none chosen means no access)", "kind": "multiselect",
         "value": first["data_scopes"] if first else [],
         "choices": [{"value": k, "label": v} for k, v in scopes.items()]}]


def edit_snapshot(request, _selection):
    native.require_permission(request, "admin")
    state = _state()
    choices = _agent_choices(state, managed_only=True)
    first = _row(state, choices[0]["value"], managed_only=True) if choices else None
    fields = [{"name": "agent", "label": "Agent", "kind": "select", "value": first["id"] if first else "",
               "choices": choices}, *_limit_fields(request, first)]
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
        direction=limits["direction"],
        allow_tools=arguments["allow_tools"], deny_tools=limits["deny_tools"],
        max_risk=arguments["max_risk"], max_dollars=limits["max_dollars"],
        max_wall_seconds=limits["max_wall_seconds"], data_scopes=limits["data_scopes"]))
    saved = _row(_state(), agent, managed_only=True)
    return Outcome("confirmed", f"The limits for {humanize(agent)} are saved.", _words(saved))


# -- add, block, unblock, remove -------------------------------------------

def _slug(name: str) -> str:
    """The page's id for a new agent's name (``slug`` in trust.html)."""
    text = unicodedata.normalize("NFKD", name.lower())
    return re.sub(r"[^a-z0-9]+", "-", text).strip("-")[:60] or "agent"


def add_snapshot(request, _selection):
    native.require_permission(request, "admin")
    fields = [{"name": "name", "label": "Name", "kind": "text", "value": "", "max_length": 60},
              *_limit_fields(request, None),
              {"name": "pubkey", "label": "Security key from the agent's provider (optional)", "kind": "text",
               "value": "", "max_length": 64}]
    return _snapshot(_state(), fields=fields)


def add_prepare(request, _selection, arguments):
    from maverick import agent_trust

    native.require_permission(request, "admin")
    agent = _slug(arguments["name"])
    if any(row["id"] == agent for row in _state()["agents"]):
        raise HTTPException(409, "An agent with this name is already on the list. Change its limits instead.")
    if arguments["pubkey"].strip() and not agent_trust._PUBKEY_RE.fullmatch(arguments["pubkey"].strip()):
        raise HTTPException(422, "That security key is not valid. Nothing was changed.")
    after = _words(_limits_row(arguments))
    return Preview(f"Add {humanize(agent)} to the list. While blocking is on, it may work with Lightwork "
                   "only within these limits.", changes=[{"field": name, "before": "", "after": value}
                                                         for name, value in after.items()])


def add_execute(request, _selection, arguments, _review, _operation):
    from .api_schemas import TrustAgentIn

    limits = _limits_row(arguments)
    agent = native.register_agent(request, TrustAgentIn(
        id=_slug(arguments["name"]), pubkey=arguments["pubkey"].strip(), direction=limits["direction"],
        allow_tools=arguments["allow_tools"], deny_tools=limits["deny_tools"], max_risk=arguments["max_risk"],
        max_dollars=limits["max_dollars"], max_wall_seconds=limits["max_wall_seconds"],
        data_scopes=limits["data_scopes"]))
    row = _row(_state(), agent, managed_only=True)
    return Outcome("confirmed", f"{humanize(agent)} is on the list.",
                   {"Agent": humanize(agent), "Status": _status(row), **_words(row)})


def _choose_snapshot(request, *, revoked: bool | None, confirm: str = "", empty: str):
    native.require_permission(request, "admin")
    state = _state()
    choices = [c for c in _agent_choices(state, managed_only=True)
               if revoked is None or _row(state, c["value"], managed_only=True)["revoked"] is revoked]
    fields = [{"name": "agent", "label": "Agent", "kind": "select",
               "value": choices[0]["value"] if choices else "", "choices": choices}]
    if confirm:
        fields.append({"name": "confirmed", "label": confirm, "kind": "boolean", "value": False})
    return _snapshot(state, fields=fields, blocked="" if choices else empty)


def _chosen(request, arguments, *, revoked: bool | None, needs_confirming: str = "") -> dict:
    native.require_permission(request, "admin")
    row = _row(_state(), arguments["agent"], managed_only=True)
    if revoked is not None and row["revoked"] is not revoked:
        raise HTTPException(409, f"{humanize(row['id'])} is {'not ' if revoked else 'already '}blocked. "
                                 "Nothing was changed.")
    if needs_confirming and not arguments.get("confirmed"):
        raise HTTPException(409, needs_confirming)
    return row


_CONFIRM_BLOCK = "Confirm that this agent is turned away from its next contact. Nothing was changed."
_CONFIRM_REMOVE = "Confirm that this agent's limits and connection details are deleted. Nothing was changed."


def block_snapshot(request, _selection):
    return _choose_snapshot(request, revoked=False, empty="No agent added in this app can be blocked now.",
                            confirm="I understand this agent is turned away from its next contact.")


def block_prepare(request, _selection, arguments):
    row = _chosen(request, arguments, revoked=False, needs_confirming=_CONFIRM_BLOCK)
    name = humanize(row["id"])
    return Preview(f"Block {name}. It is turned away from its next contact, and we stop contacting it. "
                   "Its limits and connection details are kept, so you can unblock it later.",
                   changes=[{"field": name, "before": _status(row), "after": "Blocked"}])


def _blocked_outcome(agent: str, message: str) -> Outcome:
    return Outcome("confirmed", message, {"Status": _status(_row(_state(), agent, managed_only=True))})


def block_execute(request, _selection, arguments, _review, _operation):
    if not arguments["confirmed"]:
        raise HTTPException(409, _CONFIRM_BLOCK)
    native.set_agent_blocked(request, arguments["agent"], True)
    return _blocked_outcome(arguments["agent"], f"{humanize(arguments['agent'])} is blocked.")


def unblock_snapshot(request, _selection):
    return _choose_snapshot(request, revoked=True, empty="No agent added in this app is blocked.")


def _unblocked_status(row: dict) -> str:
    """A blocked row hides whether its access has also run out."""
    import time

    expires = row.get("expires_at")
    return "Expired" if isinstance(expires, (int, float)) and time.time() >= expires else "Active"


def unblock_prepare(request, _selection, arguments):
    row = _chosen(request, arguments, revoked=True)
    name = humanize(row["id"])
    return Preview(f"Unblock {name}. It can work with Lightwork again within its limits.",
                   changes=[{"field": name, "before": "Blocked", "after": _unblocked_status(row)}])


def unblock_execute(request, _selection, arguments, _review, _operation):
    native.set_agent_blocked(request, arguments["agent"], False)
    return _blocked_outcome(arguments["agent"], f"{humanize(arguments['agent'])} is unblocked.")


def remove_snapshot(request, _selection):
    return _choose_snapshot(request, revoked=None, empty="No agent on the list was added in this app.",
                            confirm="I understand this agent's limits and connection details are deleted.")


def remove_prepare(request, _selection, arguments):
    row = _chosen(request, arguments, revoked=None, needs_confirming=_CONFIRM_REMOVE)
    name = humanize(row["id"])
    return Preview(f"Remove {name} from the list. Its limits and connection details are deleted. "
                   "While blocking is on, it is turned away from its next contact.",
                   changes=[{"field": name, "before": "On the list", "after": "Removed"}])


def remove_execute(request, _selection, arguments, _review, _operation):
    if not arguments["confirmed"]:
        raise HTTPException(409, _CONFIRM_REMOVE)
    native.remove_managed_agent(request, arguments["agent"])
    listed = any(row["id"] == arguments["agent"] for row in _state()["agents"])
    return Outcome("confirmed", f"{humanize(arguments['agent'])} was removed.", {"On the list": "Yes" if listed else "No"})


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
        Adapter("trust.agents.add", "Add an outside agent", _FAMILY, "/trust", _PAGES,
                NewAgent, add_snapshot, add_prepare, add_execute, aliases=("add an outside agent", "add an agent")),
        Adapter("trust.agents.block", "Block an outside agent", _FAMILY, "/trust", _PAGES,
                Confirmed, block_snapshot, block_prepare, block_execute, aliases=("block an agent", "block agent")),
        Adapter("trust.agents.unblock", "Unblock an outside agent", _FAMILY, "/trust", _PAGES,
                Chosen, unblock_snapshot, unblock_prepare, unblock_execute, aliases=("unblock an agent",)),
        Adapter("trust.agents.remove", "Remove an outside agent from the list", _FAMILY, "/trust", _PAGES,
                Confirmed, remove_snapshot, remove_prepare, remove_execute, aliases=("remove an agent",)),
        Adapter("trust.enforcement.set", "Turn blocking of unlisted agents on or off", _FAMILY, "/trust",
                _PAGES, Enforcement, enforcement_snapshot, enforcement_prepare, enforcement_execute,
                aliases=("turn on blocking", "turn off blocking", "block unlisted agents")),
    )
