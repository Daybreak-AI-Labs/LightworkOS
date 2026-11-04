"""Exact, reviewed local encryption maintenance shared by Settings and Copilot."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from contextlib import contextmanager

from fastapi import HTTPException
from maverick import config
from maverick import crypto_at_rest as crypto
from maverick.file_lock import cross_process_lock, prepare_private_directory
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import maverick_home

from . import auth, step_up
from .draft_api import context_for

PURPOSE = "lightwork.encryption-maintenance.v1"


def store():
    return GovernedRecordStore("encryption-maintenance", "EMR", "encryption_maintenance",
                               required_backend="local", authority_scope="deployment_global")


def authority(request):
    auth.require_global_permission(request, "admin")
    actor = auth.caller_principal(request) or "local administrator"
    return actor, context_for(request)


@contextmanager
def fence():
    path = maverick_home() / "keys" / "encryption-maintenance.lock"
    prepare_private_directory(path.parent)
    with cross_process_lock(path, strict=True):
        yield


def current(request):
    authority(request)
    from .system_checks_api import _encryption, _world_db
    state = _encryption()
    db = _world_db()
    key_state = crypto.key_rotation_version()
    blocked = ""
    if config.config_source_errors(include_tenant=True):
        blocked = "Installation settings could not be verified. Refresh before changing encryption."
    elif not state["enabled"]:
        blocked = "Turn on stored-data protection in All settings before maintaining encrypted records."
    local_rotation = not crypto.shared_authority_key_identity_required() and not crypto.per_tenant_at_rest()
    # Externally injected material is coordinated by its original custodian.
    local_rotation = local_rotation and not bool(os.environ.get("MAVERICK_ENCRYPTION_KEY"))
    revision = digest({"state": state, "keys": key_state, "database": str(db),
                       "strict": crypto.strict_at_rest(), "local_rotation": local_rotation})
    return {**state, "revision": revision, "key_revision": key_state, "context": context_for(request),
            "can_rotate": local_rotation and not blocked,
            "can_protect": db is not None and state["older_unprotected"] is not None and not blocked,
            "blocked": blocked}


def prepare(request, action):
    actor, context = authority(request)
    if action not in {"protect", "rotate"}:
        raise HTTPException(422, "Choose an encryption action.")
    if action == "rotate":
        step_up.require_recent_mfa(request, "rotate_keys")
    state = current(request)
    if state["blocked"]:
        raise HTTPException(409, state["blocked"])
    if not state["can_" + ("protect" if action == "protect" else "rotate")]:
        raise HTTPException(409, "This installation's shared or externally managed keys and records cannot be changed by this local control.")
    # A first installation may not have created its protected local key yet.
    # Establish that native key before pinning the history used by this review.
    if not crypto.is_sealed_str(crypto.seal_to_str("encryption-maintenance-review")):
        raise HTTPException(503, "This review could not be protected. No maintenance change was made.")
    state = current(request)
    if state["blocked"]:
        raise HTTPException(409, state["blocked"])
    if not state["can_" + ("protect" if action == "protect" else "rotate")]:
        raise HTTPException(409, "This installation's shared or externally managed keys and records cannot be changed by this local control.")
    material = {"purpose": PURPOSE, "actor": actor, "context": context, "action": action,
                "revision": state["revision"], "key_revision": state["key_revision"], "expires": time.time() + 600}
    token = crypto.seal_to_str(json.dumps(material, sort_keys=True))
    if not crypto.is_sealed_str(token):
        raise HTTPException(503, "This review could not be protected. No change was made.")
    count = state["older_unprotected"]
    summary = (f"Protect the supported older records in this workspace (currently {count} fields). Newer edits are preserved. Other workspaces, backups and shared storage stay outside this check."
               if action == "protect" else
               "Create one new local key for new records. Every earlier key is retained so existing records stay readable. Keep a separate key backup afterward.")
    return {"token": token, "summary": summary, "revision": state["revision"], "context": context}


def _open(request, token):
    actor, context = authority(request)
    try:
        if not crypto.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto.unseal_from_str(token))
        if (set(value) != {"purpose", "actor", "context", "action", "revision", "key_revision", "expires"}
                or value["purpose"] != PURPOSE or value["actor"] != actor
                or not hmac.compare_digest(value["context"], context)
                or value["action"] not in {"rotate", "protect"}
                or not time.time() < value["expires"] <= time.time() + 600):
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or the account or workspace changed. Review the action again.") from exc


def _identity(actor, context, operation):
    if not isinstance(operation, str) or re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "The original action reference is missing. Review the action again.")
    bound = hashlib.sha256((actor + "|" + context + "|" + operation).encode()).hexdigest()
    return "EMR-" + bound[:48], bound


def _result(row):
    pending = bool(row.get("_audit_pending"))
    state = "receipt_pending" if pending else row["state"]
    message = ("The original change completed, but its activity entry is still waiting to be recorded. Read the original result again; the change will not repeat."
               if pending and row["state"] == "confirmed" else
               "The original authorization is still waiting to be recorded. No maintenance change was started."
               if pending else row.get("message", ""))
    return {"operation": row["operation"], "action": row["action"], "state": state, "context": row["context"],
            "protected": row.get("protected", 0), "message": message,
            "recorded_at": row["created_at"]}


def receipt(request, operation):
    actor, context = authority(request)
    identity, bound = _identity(actor, context, operation)
    row = store().get(identity)
    if not row:
        return None
    if row["actor"] != actor or row["context"] != context:
        raise HTTPException(403, "This action belongs to a different account or workspace.")
    if row.get("_audit_pending"):
        row = store()._flush(row)  # Retry only original outbox entries, never the maintenance effect.
    if row["action"] == "rotate" and row["state"] != "confirmed" and crypto.rotation_receipt(bound):
        # The exact native intent proves the original additive key was created.
        row = store().update(identity, lambda value: value.update(state="confirmed",
             message="The original new key was created. No second key change was performed. Keep a separate key backup."),
             expected_revision=row["revision"], action="original_rotation_confirmed", actor=actor)
    return _result(row)


def execute(request, action, token, operation):
    material = _open(request, token)
    if material["action"] != action:
        raise HTTPException(409, "Review this exact encryption action before continuing.")
    actor, context = authority(request)
    identity, bound = _identity(actor, context, operation)
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence(), fence():
        original = receipt(request, operation)
        if original:
            return original  # Never repeat an unknown migration or an original rotation.
        if current(request)["revision"] != material["revision"]:
            raise HTTPException(409, "The encryption settings, key history or record counts changed. Check again and prepare a fresh review.")
        if action == "rotate":
            step_up.require_recent_mfa(request, "rotate_keys")
        row = store().create({"id": identity, "actor": actor, "context": context,
              "action": action, "operation": operation, "state": "unconfirmed"},
              action="maintenance_authorized", actor=actor)
        if row.get("_audit_pending"):
            raise HTTPException(503, "The authorization could not be recorded. No encryption change was started.")
        try:
            if action == "rotate":
                crypto.rotate_at_rest_key(operation_id=bound, expected_version=material["key_revision"])
                count = 0
                message = "One new key was created. Earlier keys are retained. Keep a separate key backup."
            else:
                from maverick.encryption_migrate import migrate_world_db

                from .system_checks_api import _world_db
                db = _world_db()
                if db is None:
                    raise ValueError("shared database")
                count = sum(migrate_world_db(db, backup=False).values())
                remaining = current(request)["older_unprotected"]
                message = (f"{count} older fields were protected. " +
                           ("No remaining unprotected supported fields were found."
                            if remaining == 0 else "Check encryption again for the remaining or newly edited records."))
            row = store().update(identity, lambda value: value.update(
                state="confirmed", protected=count, message=message),
                expected_revision=row["revision"], action="maintenance_completed", actor=actor)
            return _result(row)
        except Exception as exc:
            recovered = receipt(request, operation)
            if recovered and recovered["state"] == "confirmed":
                return recovered
            raise HTTPException(503, "The original result is unconfirmed. Read its saved result before considering another action; this request will not run again automatically.") from exc
