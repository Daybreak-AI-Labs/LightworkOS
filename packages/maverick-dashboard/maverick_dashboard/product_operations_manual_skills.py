"""Copilot uses the same manual skill review, effect and original receipt."""
from __future__ import annotations

from fastapi import HTTPException
from maverick.governed_operations import digest
from pydantic import Field

from . import manual_skill_removal as native
from .product_operations import Adapter, Outcome, Preview, Snapshot, StrictInput


class SkillInput(StrictInput):
    name: str = Field(min_length=1, max_length=96)


class OriginalInput(StrictInput):
    request: str = Field(pattern=r"^[a-f0-9]{32}$")


def snapshot(request, _selection):
    state = native.catalog(request)
    versions = [(choice["value"], native._snapshot(choice["value"])[1]) for choice in state["choices"]]
    native.authority(request, state["context"])
    return Snapshot(digest([state, versions]), "Current manually installed skills and their exact saved versions", native.NOTICE,
                    fields=[{"name": "name", "label": "Saved skill", "kind": "select", "required": True, "choices": state["choices"]}],
                    blocked="There are no manually installed skills to remove. Learned suggestions have separate source-reviewed controls." if not state["choices"] else "")


def prepare(request, _selection, arguments):
    prepared = native.prepare(request, arguments["name"])
    return Preview("Review this full saved version before removing it from new tasks.", changes=native.changes(request, prepared), native=prepared)


def outcome(result):
    return Outcome("confirmed" if result["confirmed"] else "unconfirmed", result["message"],
                   {"Current skills": result.get("current", "Current state does not establish the original outcome."), "Scope": native.NOTICE,
                    "Open original removal": {"href": "/skills?manual_removal=" + result["operation"] + "#manual-skill-removal", "label": "Read original removal"}})


def execute(request, _selection, arguments, prepared, operation):
    if arguments["name"] != prepared["name"]:
        raise HTTPException(409, "The selected skill changed. Review it again.")
    return outcome(native.apply(request, prepared, operation))


def recover(request, _selection, _arguments, prepared, operation, *, read_only=False):
    if not read_only and native.owned(request, operation, prepared=prepared) is None:
        return None
    return outcome(native.original(request, operation, prepared=prepared))


def original_snapshot(request, _selection):
    state = native.catalog(request)
    return Snapshot(digest(state), "Your original manual skill removal requests", "Read the original outcome without removing anything again.",
                    fields=[{"name": "request", "label": "Original removal", "kind": "select", "required": True, "choices": state["requests"]}],
                    blocked="No original manual skill removal is recorded for this account and workspace." if not state["requests"] else "")


def read_prepare(request, _selection, arguments):
    result = native.original(request, arguments["request"])
    return Preview(result["message"], native=outcome(result).details)


def entries():
    common = {"family": "learning", "pages": ("/skills",), "direct_ui": native.PAGE}
    return (
        Adapter("skills.manual_remove", "Remove a saved skill", input_model=SkillInput, snapshot=snapshot, prepare=prepare,
                execute=execute, recover=recover, read_recovery=lambda r, s, a, p, o: recover(r, s, a, p, o, read_only=True), **common),
        Adapter("skills.manual_removal_read", "Read an original saved skill removal", input_model=OriginalInput,
                snapshot=original_snapshot, prepare=read_prepare, **common),
    )
