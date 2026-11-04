"""Exact reviewed learned-skill changes and read-only original results.

A matching file is current state, never evidence that a particular request
completed. Reserve each request before the native file effect; a reservation
without its completion remains unknown and cannot authorize another effect.
"""
from __future__ import annotations

import json
import math
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import tools_ops_api as native
from .auth import require_permission
from .draft_api import context_for

TTL = 600
PURPOSE = "lightwork.learned-skill-review.v1"


def authority(request, context=None, *, write=False):
    require_permission(request, "admin")
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Reload the Skills page before continuing.")
    if write:
        native.same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current settings could not be checked. Your review is kept; no skill was changed.")
    return current


def _store():
    return GovernedRecordStore("learned-skill-change-requests", "LSC", "learned_skill_change_request")


def prepare(request, name, action, fingerprint, publish_name=""):
    context = authority(request, write=True)
    if action not in {"admit", "withdraw"} or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        raise HTTPException(422, "Choose a current suggested skill and review its exact version.")
    state = native._learned_candidates()
    if action == "admit":
        row = next((r for r in state["suggestions"] if r["name"] == name and r["fingerprint"] == fingerprint and r["ok"]), None)
        if not state["can_add"]:
            raise HTTPException(409, state["blocked"])
        if row is None:
            raise HTTPException(409, "This suggestion changed or is unavailable. Refresh before reviewing it.")
        chosen = publish_name or name
        if len(chosen) > 96 or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", chosen):
            raise HTTPException(422, "Choose a short name using letters, numbers and dashes.")
        from maverick.skills import load_builtin_skills, skills_dir
        if chosen in {s.name for s in load_builtin_skills()} or (skills_dir() / (chosen + ".md")).exists():
            raise HTTPException(409, "A skill already has this name. Choose another name before reviewing.")
        sources = list(row["source_tasks"])
        changes = [{"label": "Save as", "after": chosen.replace("-", " ")},
                   {"label": "Used when", "after": ", ".join(row["triggers"])},
                   {"label": "Tools requested", "after": ", ".join(row["tools"]) or "None"},
                   {"label": "Source tasks", "after": ", ".join("Task " + str(n) for n in sources)},
                   {"label": "Full instructions", "after": row["instructions"]}]
        message = "Read every instruction and its source tasks. Adding this skill lets agents use it on matching new tasks."
    else:
        from maverick.skills import admitted_learned_skills
        row = next((r for r in admitted_learned_skills() if r.name == name and r.fingerprint == fingerprint), None)
        if row is None:
            raise HTTPException(409, "This saved skill changed or is unavailable. Refresh before reviewing removal.")
        chosen, sources = name, list(row.source_goal_ids)
        changes = [{"label": "Saved skill", "after": name.replace("-", " ")},
                   {"label": "Change", "after": "Remove this exact saved version from new tasks. Past task records remain."}]
        message = "Remove this reviewed skill from new tasks. Work already in progress can retain its earlier instructions."
    authority(request, context, write=True)
    return {"action": action, "name": name, "fingerprint": fingerprint, "publish_name": chosen,
            "context": context, "actor": native.actor(request), "source_tasks": sources,
            "changes": changes, "message": message}


def sealed_review(request, name, action, fingerprint, publish_name=""):
    with authority_effect_fence():
        value = prepare(request, name, action, fingerprint, publish_name)
        material = {"purpose": PURPOSE, "prepared": value, "operation": secrets.token_hex(16),
                    "expires": time.time() + TTL}
        token = crypto_at_rest.seal_to_str(json.dumps(material, sort_keys=True, allow_nan=False))
        if not crypto_at_rest.is_sealed_str(token):
            raise HTTPException(503, "This review could not be saved securely. No skill was changed.")
        authority(request, value["context"], write=True)
        return {"token": token, "operation": material["operation"], "context": value["context"],
                "expires": material["expires"], "changes": value["changes"], "message": value["message"]}


def open_review(request, token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if (set(value) != {"purpose", "prepared", "operation", "expires"} or value["purpose"] != PURPOSE
                or not re.fullmatch(r"[a-f0-9]{32}", value["operation"])):
            raise ValueError
        authority(request, value["prepared"]["context"], write=True)
        if value["prepared"]["actor"] != native.actor(request):
            raise ValueError
        return value
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(409, "This skill review is unavailable. Read the original result or prepare a fresh review.") from exc


def _owned(request, operation):
    context = authority(request)
    if not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original skill change is unavailable.")
    row = _store().get("LSC-" + operation)
    if row and (row["actor"] != native.actor(request) or row["context"] != context):
        raise HTTPException(404, "This original skill change is unavailable to your account.")
    return row


def original(request, operation):
    context = authority(request)
    with authority_effect_fence():
        row = _owned(request, operation)
        result = {"operation": operation, "context": context, "confirmed": False,
                  "message": "The original change is not confirmed. Absence does not establish failure. Nothing was repeated."}
        if row:
            # A completion whose activity record is still pending is not confirmed.
            confirmed = row["state"] == "confirmed" and not row.get("_audit_pending")
            result.update(confirmed=confirmed, action=row["action"], name=row["name"],
                          recorded_at=row["updated_at"], result=row.get("result"),
                          message=("Your original reviewed skill was added." if row["action"] == "admit" else
                                   "Your original reviewed skill was removed.") if confirmed else
                          "The original change started, but completion is unconfirmed. Nothing was repeated. Review the current skill list separately.")
            # The original receipt is stable even when today's file differs.
            try:
                from maverick.skills import admitted_learned_skills
                current = next((r for r in admitted_learned_skills() if r.name == row["name"]), None)
                expected = row.get("result", {}).get("fingerprint") if isinstance(row.get("result"), dict) else None
                result["current"] = ("This saved version is still installed." if current and expected == current.fingerprint else
                                     "A saved skill with this name is currently installed; its version differs from this receipt." if current else
                                     "No reviewed suggested skill with this name is currently installed.")
            except Exception:
                result["current"] = "Current installed skills could not be checked. This does not change the original receipt."
        authority(request, context)
        return result


def recent(request):
    context = authority(request)
    actor = native.actor(request)
    rows = [r for r in _store().list(limit=10000) if r.get("actor") == actor and r.get("context") == context]
    rows.sort(key=lambda r: (r["created_at"], r["id"]), reverse=True)
    authority(request, context)
    return {"context": context, "requests": [{"operation": r["id"][4:], "name": r["name"], "action": r["action"],
             "confirmed": r["state"] == "confirmed" and not r.get("_audit_pending"), "created_at": r["created_at"]} for r in rows[:20]]}


def original_for_review(request, prepared, operation):
    row = _owned(request, operation)
    if row is None:
        return None
    if row["binding"] != digest([operation, prepared, native.actor(request)]):
        raise HTTPException(409, "This original request belongs to a different reviewed skill change.")
    return original(request, operation)


def apply(request, prepared, operation, *, expires):
    context = authority(request, prepared["context"], write=True)
    actor = native.actor(request)
    binding = digest([operation, prepared, actor])
    with authority_effect_fence():
        row = _owned(request, operation)
        if row:
            if row["binding"] != binding:
                raise HTTPException(409, "This request belongs to a different review. Read its original result.")
            return original(request, operation)

        def guard():
            authority(request, context, write=True)
            if actor != prepared["actor"]:
                raise HTTPException(409, "The signed-in account changed. Reload before continuing.")
            if type(expires) not in (int, float) or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
                raise HTTPException(409, "This review expired before the skill change. Prepare a fresh review; nothing was repeated.")
            if prepared["action"] == "admit":
                from maverick.learning_guard import check_learning_halt
                check_learning_halt("skill_distillation", "admit")
                allowed, reason = native._learned_admission_allowed()
                if not allowed:
                    raise HTTPException(409, reason)

        guard()
        if prepare(request, prepared["name"], prepared["action"], prepared["fingerprint"], prepared["publish_name"]) != prepared:
            raise HTTPException(409, "The reviewed skill or its source changed. Refresh before a new decision.")
        claim = None

        def reserve(item):
            nonlocal claim
            guard()
            native._record_learned_change(request, "learned_skill_" + prepared["action"],
                name=prepared["publish_name"], fingerprint=prepared["fingerprint"], source_tasks=item.source_goal_ids, phase="prepared")
            guard()
            claim = _store().create({"id": "LSC-" + operation, "actor": actor, "context": context,
                "binding": binding, "state": "started", "action": prepared["action"],
                "name": prepared["publish_name"], "reviewed_fingerprint": prepared["fingerprint"],
                "source_tasks": prepared["source_tasks"]}, action="skills.reviewed_change.started", actor=actor, max_records=10000)
            guard()

        try:
            if prepared["action"] == "admit":
                from maverick.skills import admit_learned_skill
                skill = admit_learned_skill(prepared["name"], prepared["fingerprint"],
                    publish_name=prepared["publish_name"], before_save=reserve, effect_guard=guard)
                if skill._runtime_binding is None:
                    raise ValueError("Saved learned skill has no exact native content binding")
                result = {"name": skill.name, "fingerprint": skill._runtime_binding[2]}
            else:
                from maverick.skills import withdraw_admitted_learned_skill
                skill = withdraw_admitted_learned_skill(prepared["name"], prepared["fingerprint"],
                    before_delete=reserve, effect_guard=guard)
                result = {"name": skill.name, "fingerprint": skill.fingerprint, "removed": True}
            _store().update(claim["id"], lambda value: value.update(state="confirmed", result=result),
                            expected_revision=claim["revision"], action="skills.reviewed_change.completed", actor=actor)
        except Exception as exc:
            if claim is not None:
                # Never infer completion from the current file, or repeat a
                # reserved effect after its completion publication was lost.
                return original(request, operation)
            if isinstance(exc, HTTPException):
                raise
            from maverick.learning_guard import Halted
            if isinstance(exc, Halted):
                raise HTTPException(409, "Learning is paused. This suggestion was not added.") from exc
            if isinstance(exc, ValueError):
                raise HTTPException(409, str(exc)) from exc
            raise HTTPException(503, "The original skill result could not be read. Check the original change before a new decision.") from exc
        return original(request, operation)
