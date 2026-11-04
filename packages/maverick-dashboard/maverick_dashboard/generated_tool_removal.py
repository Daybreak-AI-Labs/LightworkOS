"""Exact, owner-bound stopping and cleanup of native generated tools."""
from __future__ import annotations

import contextlib
import hmac
import json
import math
import re
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest, self_learning
from maverick import generated_tool_removal as engine
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import auth
from .draft_api import context_for
from .tools_ops_api import actor, same_origin

PAGE, API, TTL = "/learned#generated-tools", "/api/v1/generated-tool-removals", 600
STORE = GovernedRecordStore("generated-tool-removals", "GTR", "generated_tool_removal", required_backend="local")
NOTICE = "Stop this exact owned tool's permission for future calls and remove its retained files. Work already started can finish; completed work and connected-service actions are not undone. No tool is enabled, learned or granted new permission."
ACTIONS = {"remove": "Stop and remove the reviewed tool", "cleanup": "Acknowledge the unknown earlier result and clean up the current reviewed files"}


def budget():
    return Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)


def authority(request, context=None, *, write=False):
    auth.require_permission(request, "admin")
    current = context_for(request)
    if context is not None and not hmac.compare_digest(current, context):
        raise HTTPException(409, "Your account or workspace changed. Refresh before reviewing a tool.")
    if write:
        same_origin(request)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Current settings are unavailable. No further tool change was admitted.")
    return actor(request), current, auth.goal_owner_filter(request) or ""


def _seal(row, value):
    raw = json.dumps({"identity": [row["id"], row["actor"], row["context"], row["tool_key"]], "payload": value}, allow_nan=False, separators=(",", ":"))
    if len(raw.encode()) > 512000:
        raise HTTPException(413, "The complete original history exceeds its retained bound. Nothing was shortened.")
    row["envelope"] = crypto_at_rest.seal_to_str(raw)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(503, "Stored-data protection must be available before retaining this private removal.")


def _open(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if value["identity"] != [row["id"], row["actor"], row["context"], row["tool_key"]]:
        raise HTTPException(409, "This retained removal's owner could not be verified.")
    return value["payload"]


def _id(context, key):
    return "GTR-" + digest([context, key])[:48]


def _owned(request, identifier):
    who, context, _owner = authority(request)
    row = STORE.get(identifier) if isinstance(identifier, str) and re.fullmatch(r"GTR-[a-f0-9]{48}", identifier) else None
    if row is None or (row["actor"], row["context"]) != (who, context):
        raise HTTPException(404, "This original tool decision is unavailable to this account and workspace.")
    if row.get("_audit_pending"):
        allowance = budget()
        with authority_effect_fence(), cross_process_lock(STORE._backend()._store._path(identifier), strict=True):
            who, current, _owner = authority(request, context)
            row = STORE.get(identifier)
            if row is None or (row["actor"], row["context"]) != (who, current):
                raise HTTPException(404, "This original tool decision is unavailable to this account and workspace.")
            allowance.check()
            row = STORE._flush(row)
            authority(request, context)
            allowance.check()
    return row


def _inspect(name, owner, allowance, *, absent_record=None):
    try:
        return engine.inspect(name, owner, allowance, absent_record=absent_record)
    except (PermissionError, FileNotFoundError) as exc:
        raise HTTPException(404, "This owned tool's current retained files are unavailable.") from exc
    except (ValueError, OSError, RuntimeError) as exc:
        raise HTTPException(409, "The exact tool files could not be checked safely. No source text was read into the page.") from exc


def _label(source):
    return source["name"].removeprefix("gen_").replace("_", " ") if source["source_permitted"] else "Tool from unavailable earlier work"


def _state(source):
    if source["source_file"] is None:
        return "No tool source file is present. This observation does not establish any original result."
    if source["consent"] is None:
        return "Runtime permission could not be verified. No stopped or active state is claimed; retained files remain available for a reviewed cleanup."
    if source["consent"] is False:
        return "Runtime permission is stopped; retained files still need removal."
    if not source["source_permitted"]:
        return "Source use is withdrawn or unavailable. The retained owner can stop and remove this tool without reading its body."
    return "Runtime permission is currently present. This does not establish that the tool works correctly."


def history(request):
    allowance = budget()
    who, context, _owner = authority(request)
    rows = STORE.list(limit=513)
    if len(rows) > 512:
        raise HTTPException(409, "The complete removal history exceeds 512 entries. Nothing was omitted.")
    choices = []
    for row in rows:
        allowance.check()
        if (row.get("actor"), row.get("context")) != (who, context):
            continue
        for operation, receipt in _open(row)["operations"].items():
            choices.append({"value": row["id"] + "|" + operation, "label": ACTIONS[receipt["action"]] + " · " +
                            time.strftime("%b %d, %H:%M", time.localtime(receipt["recorded_at"])) + " · " +
                            ("Original recorded" if receipt["state"] == "confirmed" and not row.get("_audit_pending") else "Original remains unknown")})
    authority(request, context)
    allowance.check()
    return {"context": context, "choices": list(reversed(choices)), "notice": NOTICE}


def listing(request):
    allowance = budget()
    _who, context, owner = authority(request)
    try:
        sources = engine.inventory(owner, allowance)
    except (ValueError, OSError, RuntimeError) as exc:
        raise HTTPException(409, "The complete owned tool inventory could not be checked. Refresh or read your original decisions; no empty inventory is claimed.") from exc
    choices = []
    for source in sources:
        allowance.check()
        row = STORE.get(_id(context, source["key"]))
        payload = _open(row) if row is not None else None
        pending = payload["pending"] if payload else None
        choices.append({"value": source["key"], "label": _label(source), "state": _state(source), "pending": bool(pending),
                        "original": row["id"] + "|" + pending if pending else None})
    for row in STORE.list(limit=513):
        allowance.check()
        if (row.get("actor"), row.get("context")) != authority(request)[:2]:
            continue
        payload = _open(row)
        if payload["pending"] and not any(item["value"] == row["tool_key"] for item in choices):
            choices.append({"value": row["tool_key"], "label": "Earlier tool removal waiting for an original result", "state": "Current files are absent or unavailable. The original remains unknown.",
                            "pending": True, "original": row["id"] + "|" + payload["pending"]})
    for source in sources:
        current = _inspect(source["name"], owner, allowance)
        if current["binding"] != source["binding"]:
            raise HTTPException(409, "Current tool files or source permission changed while the inventory was read. Refresh before continuing.")
    authority(request, context)
    allowance.check()
    return {"context": context, "choices": choices, "notice": NOTICE,
            "identity_notice": "Only the exact current owner's stamped tools are shown. Older files stamped with another or unverified local identity remain withheld; an empty list does not claim that those files are absent."}


def _select(request, key, allowance):
    who, context, owner = authority(request)
    if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{64}", key):
        raise HTTPException(404, "Choose a current owned tool.")
    identifier = _id(context, key)
    row = STORE.get(identifier)
    if row is not None:
        if (row["actor"], row["context"]) != (who, context):
            raise HTTPException(404, "This tool decision is unavailable.")
        payload = _open(row)
        source = _inspect(payload["name"], owner, allowance, absent_record=payload["ownership"])
    else:
        payload = None
        try:
            source = next((item for item in engine.inventory(owner, allowance) if item["key"] == key), None)
        except (ValueError, OSError, RuntimeError) as exc:
            raise HTTPException(409, "Current owned tool files could not be verified.") from exc
        if source is None:
            raise HTTPException(404, "This current owned tool is unavailable.")
    return source, row, payload


def prepare(request, key, action, *, context=None, acknowledge_unknown=False):
    allowance = budget()
    who, current, _owner = authority(request, context, write=True)
    if action not in ACTIONS:
        raise HTTPException(422, "Choose a supported tool change.")
    source, row, payload = _select(request, key, allowance)
    pending = payload["pending"] if payload else None
    if action == "remove" and pending:
        raise HTTPException(409, "The earlier original remains unknown. Read it, then separately review intentional cleanup.")
    if action == "cleanup" and (not pending or acknowledge_unknown is not True):
        raise HTTPException(409, "Acknowledge the exact unknown earlier result before a separate cleanup review.")
    if action == "remove" and source["source_file"] is None:
        raise HTTPException(409, "No current tool source is present. Absence does not establish an earlier removal.")
    if payload and (len(payload["operations"]) >= 64 or row.get("_audit_pending")):
        raise HTTPException(409, "Original custody is full or its activity record remains unconfirmed. Nothing was repeated.")
    value = {"id": _id(current, key), "key": key, "actor": who, "context": current, "source": source,
             "action": action, "prior": pending, "before": digest(payload), "revision": row["revision"] if row else 0,
             "expires": time.time() + TTL}
    authority(request, current, write=True)
    allowance.check()
    return value


def changes(prepared):
    return [{"label": "Reviewed change", "after": ACTIONS[prepared["action"]]},
            {"label": "Current owned tool", "after": _label(prepared["source"])},
            {"label": "Current permission and retained files", "after": _state(prepared["source"])},
            {"label": "Source privacy", "after": "No generated code, private task body or withdrawn source name is disclosed. Original ownership permits only stopping and cleanup; it grants no use or training."},
            {"label": "Earlier unknown result", "after": "The earlier attempt may already have stopped or removed the tool. It stays unknown; this is a separate intentional cleanup, and its prior history is kept." if prepared["prior"] else "No earlier unresolved attempt is being repeated."},
            {"label": "Effect and limits", "after": NOTICE},
            {"label": "Review expires", "after": time.strftime("%b %d, %Y %H:%M:%S", time.localtime(prepared["expires"]))}]


def _guard(request, prepared, allowance, *, exact=False):
    who, _context, owner = authority(request, prepared["context"], write=True)
    expires = prepared["expires"]
    if who != prepared["actor"] or type(expires) not in {int, float} or not math.isfinite(expires) or not time.time() < expires <= time.time() + TTL:
        raise HTTPException(409, "This complete review expired or its account changed. No further change was admitted.")
    current = _inspect(prepared["source"]["name"], owner, allowance, absent_record=prepared["source"]["ownership"])
    if exact and current["binding"] != prepared["source"]["binding"]:
        raise HTTPException(409, "Current files or permission changed. Review the complete current tool again.")
    if current["ownership"] != prepared["source"]["ownership"] or (current["source_file"] is not None and current["source_file"] != prepared["source"]["source_file"]):
        raise HTTPException(409, "The exact owned tool changed. This request cannot remove another saved version.")
    allowance.check()
    if time.time() >= expires:
        raise HTTPException(409, "The complete review expired while its current files were being checked.")


@contextlib.contextmanager
def _writer(prepared):
    with authority_effect_fence(), cross_process_lock(engine.target(prepared["source"]["name"]), strict=True):
        backend = STORE._backend()
        with cross_process_lock(backend._store._dir() / ".namespace-admission", strict=True), cross_process_lock(backend._store._path(prepared["id"]), strict=True):
            yield


def _reserve(request, prepared, operation, allowance):
    receipt = {"action": prepared["action"], "binding": digest(prepared), "state": "unconfirmed", "stopped": False, "recorded_at": time.time()}
    row = STORE.get(prepared["id"])
    if row is None:
        row = {"id": prepared["id"], "actor": prepared["actor"], "context": prepared["context"], "tool_key": prepared["key"]}
        payload = {"name": prepared["source"]["name"], "ownership": prepared["source"]["ownership"], "pending": operation, "operations": {operation: receipt}}
        _seal(row, payload)
        _guard(request, prepared, allowance, exact=True)
        return STORE.create(row, action="generated_tool_removal_reserved", actor=prepared["actor"], max_records=512)
    def mutate(current):
        _guard(request, prepared, allowance, exact=True)
        payload = _open(current)
        if digest(payload) != prepared["before"] or current.get("_audit_pending") or len(payload["operations"]) >= 64:
            raise HTTPException(409, "The retained original decisions changed. Refresh before another intentional review.")
        payload.update(name=prepared["source"]["name"], ownership=prepared["source"]["ownership"], pending=operation)
        payload["operations"][operation] = receipt
        _seal(current, payload)
        _guard(request, prepared, allowance, exact=True)
    return STORE.update(row["id"], mutate, expected_revision=prepared["revision"], action="generated_tool_removal_reserved", actor=prepared["actor"])


def _progress(request, prepared, operation, allowance, *, complete=False):
    row = _owned(request, prepared["id"])
    def mutate(current):
        _guard(request, prepared, allowance)
        payload = _open(current)
        if payload["pending"] != operation or payload["operations"][operation]["binding"] != digest(prepared) or current.get("_audit_pending"):
            raise HTTPException(409, "The original stopping record changed. Nothing was repeated.")
        payload["operations"][operation]["stopped"] = True
        if complete:
            payload["operations"][operation]["state"] = "confirmed"
            payload["pending"] = None
        _seal(current, payload)
        _guard(request, prepared, allowance)
    return STORE.update(row["id"], mutate, expected_revision=row["revision"], action="generated_tool_removal_completed" if complete else "generated_tool_stop_recorded", actor=prepared["actor"])


def _owned_absence(request, prepared, operation, allowance):
    _guard(request, prepared, allowance)
    payload = _open(_owned(request, prepared["id"]))
    if (prepared["action"] != "cleanup" or prepared["source"]["source_file"] is not None
            or prepared["source"]["ownership_file"] is not None or not prepared["prior"]
            or payload["pending"] != operation or payload["ownership"] != prepared["source"]["ownership"]
            or payload["operations"][operation]["binding"] != digest(prepared)):
        raise HTTPException(409, "Original-owner absent-file custody could not be verified. Nothing was repeated.")


def apply(request, prepared, operation):
    allowance = budget()
    authority(request, prepared["context"], write=True)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(422, "This original request could not be verified.")
    with _writer(prepared):
        existing = STORE.get(prepared["id"])
        if existing and operation in _open(existing)["operations"]:
            return original(request, prepared["id"] + "|" + operation, prepared=prepared)
        claim = _reserve(request, prepared, operation, allowance)
        if claim is None or claim.get("_audit_pending"):
            return original(request, prepared["id"] + "|" + operation, prepared=prepared)
        try:
            _guard(request, prepared, allowance)
            source = prepared["source"]
            self_learning.delete_generated_tool(source["name"], actor=prepared["actor"], owner=source["owner"], expected_digest=source["source_sha256"],
                metadata_stop=True, allow_absent=prepared["action"] == "cleanup",
                effect_guard=lambda: _guard(request, prepared, allowance),
                owned_absence_guard=lambda: _owned_absence(request, prepared, operation, allowance),
                after_revoke=lambda: _progress(request, prepared, operation, allowance))
            _progress(request, prepared, operation, allowance, complete=True)
        except Exception:
            return original(request, prepared["id"] + "|" + operation, prepared=prepared)
        return original(request, prepared["id"] + "|" + operation, prepared=prepared)


def original(request, reference, *, prepared=None):
    if not isinstance(reference, str) or not re.fullmatch(r"GTR-[a-f0-9]{48}\|[a-f0-9]{32}", reference):
        raise HTTPException(404, "This original tool decision is unavailable.")
    identifier, operation = reference.split("|")
    row = _owned(request, identifier)
    payload = _open(row)
    receipt = payload["operations"].get(operation)
    if receipt is None:
        raise HTTPException(404, "This exact original tool decision is unavailable.")
    if prepared is not None and receipt["binding"] != digest(prepared):
        raise HTTPException(409, "This original belongs to a different complete review.")
    confirmed = receipt["state"] == "confirmed" and not row.get("_audit_pending")
    stopped = receipt["stopped"] and not row.get("_audit_pending")
    value = {"context": row["context"], "reference": reference, "confirmed": confirmed, "stopped": stopped,
             "message": "Your exact reviewed stopping and cleanup decision was recorded. Nothing was repeated." if confirmed else
                        "Your original remains unconfirmed. Nothing was repeated. A current missing file cannot confirm this original.",
             "notice": NOTICE, "action": ACTIONS[receipt["action"]], "recorded_at": receipt["recorded_at"]}
    if stopped and not confirmed:
        value["message"] = "Your original stop is recorded, but complete file cleanup is unconfirmed. Nothing was repeated. Review current files before a separate intentional cleanup."
    try:
        source = _inspect(payload["name"], authority(request)[2], budget(), absent_record=payload["ownership"])
        value["current"] = _state(source)
    except HTTPException:
        value["current"] = "Current retained files are unavailable. This does not establish the original result."
    authority(request, row["context"])
    return value
