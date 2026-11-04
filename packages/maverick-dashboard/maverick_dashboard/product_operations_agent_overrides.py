"""Typed Copilot shares complete native agent removal/reset and original read."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import agent_override_changes as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class AgentInput(StrictInput):
    name: str = Field(min_length=1, max_length=128)


class OriginalInput(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")


def snapshot_for(action):
    def snapshot(request, _selection):
        state = native.catalog(request)
        choices = [choice for choice in state["choices"] if choice["action"] == action]
        versions = [(choice["value"], digest(native._snapshot(request, choice["value"]))) for choice in choices]
        native.authority(request, state["context"])
        return Snapshot(digest([state, versions]), "Current saved definitions and their exact built-in origin", native.NOTICE,
                        fields=[{"name": "name", "label": "Saved agent", "kind": "select", "required": True, "choices": choices}],
                        blocked="No saved definition is available for this change." if not choices else "")
    return snapshot


def prepare_for(action):
    def prepare(request, _selection, arguments):
        prepared = native.prepare(request, arguments["name"], action)
        return Preview("Review the exact damaged saved setup to discard and its effect; its instructions cannot be loaded safely." if prepared["source_kind"] == "damaged" else
                       "Review the complete current definition and the exact effect before confirming.", changes=native.changes(request, prepared), native=prepared)
    return prepare


def outcome(result):
    return Outcome("confirmed" if result["confirmed"] else "unconfirmed", result["message"],
                   {"Current definition": result.get("current", "Current state does not establish the original outcome."), "Scope": native.NOTICE,
                    "Open original change": {"href": "/agents?agent_change=" + result["operation"] + "#agent-override-change", "label": "Read original agent change"}})


def execute(request, _selection, arguments, prepared, operation):
    if arguments["name"] != prepared["name"]:
        raise HTTPException(409, "The selected agent changed. Review it again.")
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if not read_only and native.owned(request, operation, prepared=prepared) is None:
        return None
    return outcome(native.original(request, operation, prepared=prepared))


def original_snapshot(request, _selection):
    state = native.catalog(request)
    return Snapshot(digest(state), "Your retained original agent removal and reset requests", "Read the original outcome without changing a definition again.",
                    fields=[{"name": "request", "label": "Original change", "kind": "select", "required": True, "choices": state["requests"]}],
                    blocked="No original change is recorded for this account and workspace." if not state["requests"] else "")


def read_prepare(request, _selection, arguments):
    result = native.original(request, arguments["request"])
    return Preview(result["message"], native=outcome(result).details)


def entries():
    common = {"family": "preferences", "pages": ("/agents",), "direct_ui": native.PAGE}
    mutations = {"input_model": AgentInput, "execute": execute, "recover": recover,
                 "read_recovery": lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True)}
    return (
        Adapter("agents.custom_remove", "Remove a custom agent", snapshot=snapshot_for("remove_custom"), prepare=prepare_for("remove_custom"), **common, **mutations),
        Adapter("agents.builtin_reset", "Reset an agent to its built-in definition", snapshot=snapshot_for("reset_builtin"), prepare=prepare_for("reset_builtin"), **common, **mutations),
        Adapter("agents.override_change_read", "Read an original agent change", input_model=OriginalInput,
                snapshot=original_snapshot, prepare=read_prepare, **common),
    )
