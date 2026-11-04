"""Remove one exact manually installed skill; absence is never a receipt."""
from __future__ import annotations

import math
import re
import time

from fastapi import HTTPException
from maverick import config, skills
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import tools_ops_api as native
from .auth import require_permission
from .draft_api import context_for

PAGE = "/skills#manual-skill-removal"
TTL = 600
NOTICE = "Remove only this reviewed saved version from new tasks. Work already in progress can retain its earlier instructions. Past task records remain. This does not remove a built-in skill or a learned suggestion."


def authority(request, context=None, *, write=False):
    require_permission(request, "admin")
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Reload the Skills page before continuing.")
    if write:
        native.same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current settings could not be checked. No skill was removed.")
    return current


def _store():
    return GovernedRecordStore("manual-skill-removal-requests", "MSR", "manual_skill_removal_request")


def _snapshot(name):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", name):
        raise HTTPException(422, "Choose a current saved skill by name.")
    try:
        return skills.manual_skill_snapshot(name)
    except FileNotFoundError as exc:
        raise HTTPException(409, "This skill is no longer installed. Its absence does not confirm your removal request.") from exc
    except (ValueError, OSError) as exc:
        raise HTTPException(409, str(exc) if isinstance(exc, ValueError) else "This saved skill could not be read safely. Nothing was removed.") from exc


def prepare(request, name, *, context=None):
    current = authority(request, context, write=True)
    _item, revision = _snapshot(name)
    authority(request, current, write=True)
    return {"name": name, "revision": revision, "actor": native.actor(request), "context": current,
            "expires": time.time() + TTL}


def changes(request, prepared):
    authority(request, prepared["context"])
    item, revision = _snapshot(prepared["name"])
    if revision != prepared["revision"]:
        raise HTTPException(409, "This saved skill changed. Review its current version before deciding.")
    from .plain_labels import capability_label
    rows = [{"label": "Saved skill", "after": item.name.replace("-", " ")},
            {"label": "Used when", "after": item.triggers},
            {"label": "Tools requested", "after": [capability_label(tool) for tool in item.tools_needed] or ["None"]},
            {"label": "Full current instructions", "after": item.body}, {"label": "Effect", "after": NOTICE}]
    authority(request, prepared["context"])
    return rows


def owned(request, operation, *, prepared=None):
    current = authority(request)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original removal request is unavailable.")
    row = _store().get("MSR-" + operation)
    if row and (row["actor"] != native.actor(request) or row["context"] != current):
        raise HTTPException(404, "This original removal is unavailable to this account and workspace.")
    if row and prepared is not None and row["binding"] != digest([operation, prepared, native.actor(request)]):
        raise HTTPException(409, "This original request belongs to another reviewed removal.")
    authority(request, current)
    return row


def original(request, operation, *, prepared=None):
    context = authority(request)
    row = owned(request, operation, prepared=prepared)
    result = {"operation": operation, "context": context, "confirmed": False, "notice": NOTICE,
              "message": "The original removal is unconfirmed. A missing skill does not confirm who removed it. Nothing was repeated."}
    if row:
        # A completion whose activity record is still pending is not confirmed.
        result.update(name=row["name"], recorded_at=row["updated_at"],
                      confirmed=row["state"] == "confirmed" and not row.get("_audit_pending"))
        if result["confirmed"]:
            result["message"] = "Your original reviewed skill version was removed. Nothing was repeated."
        try:
            _item, revision = skills.manual_skill_snapshot(row["name"])
            result["current_state"] = "installed"
            result["current"] = "The reviewed version is currently installed." if revision == row["reviewed_revision"] else "A different version is currently installed. It was not removed by this request."
        except FileNotFoundError:
            result["current_state"] = "absent"
            result["current"] = "No manually installed skill with this name is currently present. Current absence does not establish the original outcome."
        except (ValueError, OSError):
            result["current_state"] = "unavailable"
            result["current"] = "The reviewed version is not currently readable as a manually installed skill. This does not establish the original outcome."
    authority(request, context)
    return result


def catalog(request):
    context = authority(request)
    choices = [{"value": item.name, "label": item.name.replace("-", " ")} for item in skills.load_skills()
               if not item.source.startswith("auto-distilled")]
    rows = [row for row in _store().list(limit=10000) if row["actor"] == native.actor(request) and row["context"] == context]
    rows.sort(key=lambda row: (row["created_at"], row["id"]), reverse=True)
    authority(request, context)
    return {"context": context, "choices": choices, "requests": [{"value": row["id"][4:],
            "label": row["name"].replace("-", " ") + " / " + time.strftime("%b %d, %H:%M", time.localtime(row["created_at"]))} for row in rows[:20]], "notice": NOTICE}


def apply(request, prepared, operation):
    actor = native.actor(request)
    context = authority(request, prepared["context"], write=True)
    with authority_effect_fence():
        if owned(request, operation, prepared=prepared):
            return original(request, operation, prepared=prepared)

        def guard():
            authority(request, context, write=True)
            expires = prepared.get("expires")
            if actor != prepared["actor"] or type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
                raise HTTPException(409, "This review expired or the account changed. Review the current skill again; nothing was removed.")

        guard()
        claim = None

        def reserve(_item):
            nonlocal claim
            guard()
            native.record(request, "manual_skill_remove_reviewed", installation=False, name=prepared["name"], operation=operation, phase="prepared")
            guard()
            claim = _store().create({"id": "MSR-" + operation, "actor": actor, "context": context, "name": prepared["name"],
                "binding": digest([operation, prepared, actor]), "reviewed_revision": prepared["revision"], "state": "started"},
                action="skills.manual_remove.started", actor=actor, max_records=10000)
            if claim.get("_audit_pending"):
                raise HTTPException(503, "The original removal record is unconfirmed. No further removal was attempted.")
            guard()

        try:
            removed = skills.remove_skill(prepared["name"], expected_revision=prepared["revision"], before_delete=reserve, effect_guard=guard)
            if not removed:
                raise HTTPException(409, "This saved skill is no longer installed. Its absence does not confirm your request.")
            _store().update(claim["id"], lambda row: row.update(state="confirmed"), expected_revision=claim["revision"],
                            action="skills.manual_remove.completed", actor=actor)
        except Exception as exc:
            if claim is not None:
                return original(request, operation, prepared=prepared)
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(409, str(exc) if isinstance(exc, ValueError) else "This saved skill could not be removed safely. Read the original result before a new decision.") from exc
        return original(request, operation, prepared=prepared)
