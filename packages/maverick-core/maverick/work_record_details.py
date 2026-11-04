"""Reviewed business fields beside native work; never an execution transition.

The existing governed record store supplies tenant custody, CAS and audit delivery.
Each record retains its latest twenty exact operation outcomes; pruning that window
does not prevent later edits and matching current values never proves an original.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import math
import re
import uuid

from . import config
from .file_lock import cross_process_lock
from .governed_operations import digest
from .governed_records import GovernedMutationFence, GovernedRecordStore, RecordConflict
from .paths import data_dir
from .privacy_ops import _validated_audit_queue

KINDS = {
    "task": "Tasks", "control": "Safeguards", "evidence": "Evidence",
    "risk": "Risks", "poam": "Improvement plans", "vendor": "Vendors",
    "policy": "Policies", "incident": "Incidents", "audit_engagement": "Audits",
    "regulatory_clock": "Notification deadlines",
}
HISTORY = 20
ORIGINAL_NOTICE = "Original results are retained for the latest 20 saves of each record or field setup. Older originals may no longer be available. Removing a field from the category does not delete its previously saved business value."
NOTICE = "Business stages and fields organize your work. They do not start work, change execution status, approve evidence or make a compliance decision."
_ID = re.compile(r"[0-9a-f]{32}\Z")
_TYPES = {"text", "number", "boolean", "date", "choice"}


def enabled():
    if config.config_source_errors(include_tenant=True):
        raise ValueError("Business details settings could not be read.")
    value = (config.load_config() or {}).get("work_details", {})
    if not isinstance(value, dict) or type(value.get("enable", True)) is not bool:
        raise ValueError("Business details settings could not be read.")
    return value.get("enable", True)


def store():
    return GovernedRecordStore("work-record-details", "WRD", "work_record_details")


def record_id(kind, target=""):
    if kind not in KINDS:
        raise ValueError("Choose a supported kind of work.")
    return "WRD-" + (digest([kind, target])[:32] if target else "schema-" + kind)


def _label(value):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 100:
        raise ValueError("Give each field, choice and business stage a name of up to 100 characters.")
    return value.strip()


def _identifier(value):
    if value == "":
        return uuid.uuid4().hex
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("A field or choice no longer matches the current setup. Refresh it.")
    return value


def _named(rows, maximum):
    if not isinstance(rows, list) or len(rows) > maximum:
        raise ValueError(f"Choose at most {maximum} named items.")
    result, names, ids = [], set(), set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "label"}:
            raise ValueError("A named choice is incomplete.")
        value = {"id": _identifier(row["id"]), "label": _label(row["label"])}
        if value["id"] in ids or value["label"].casefold() in names:
            raise ValueError("Give each item a different name.")
        ids.add(value["id"])
        names.add(value["label"].casefold())
        result.append(value)
    return result


def normalize_schema(draft):
    if not isinstance(draft, dict) or set(draft) != {"fields", "stages"}:
        raise ValueError("Choose the fields and business stages for this kind of work.")
    fields = draft["fields"]
    if not isinstance(fields, list) or len(fields) > 20:
        raise ValueError("Choose at most 20 fields for each kind of work.")
    result, names, ids = [], set(), set()
    for row in fields:
        if not isinstance(row, dict) or set(row) != {"id", "label", "type", "required", "options"}:
            raise ValueError("A field is incomplete.")
        if row["type"] not in _TYPES or type(row["required"]) is not bool:
            raise ValueError("Choose a supported field type and whether it is required.")
        value = {"id": _identifier(row["id"]), "label": _label(row["label"]),
                 "type": row["type"], "required": row["required"],
                 "options": _named(row["options"], 20)}
        if value["type"] == "choice" and not value["options"]:
            raise ValueError("Add at least one named choice to a choice field.")
        if value["type"] != "choice" and value["options"]:
            raise ValueError("Only choice fields have named choices.")
        if value["id"] in ids or value["label"].casefold() in names:
            raise ValueError("Give each field a different name.")
        names.add(value["label"].casefold())
        ids.add(value["id"])
        result.append(value)
    return {"fields": result, "stages": _named(draft["stages"], 12)}


def normalize_details(draft, schema):
    if not isinstance(draft, dict) or set(draft) != {"values", "stage"} or not isinstance(draft["values"], dict):
        raise ValueError("Enter this record's business fields and stage.")
    fields = {row["id"]: row for row in schema["fields"]}
    if set(draft["values"]) - fields.keys():
        raise ValueError("A field was changed or removed. Refresh the field setup before reviewing.")
    values = {}
    for key, field in fields.items():
        value = draft["values"].get(key)
        if value is None or value == "" and field["type"] != "text":
            value = None
        if field["required"] and (value is None or value == ""):
            raise ValueError(f"Enter {field['label']} before reviewing.")
        if value is not None:
            valid = {
                "text": isinstance(value, str) and len(value) <= 4000,
                "number": type(value) in (int, float) and math.isfinite(value),
                "boolean": type(value) is bool,
                "choice": isinstance(value, str) and value in {row["id"] for row in field["options"]},
                "date": isinstance(value, str) and len(value) == 10,
            }[field["type"]]
            if not valid:
                raise ValueError(f"Enter a valid value for {field['label']}.")
            if field["type"] == "date":
                try:
                    dt.date.fromisoformat(value)
                except ValueError as exc:
                    raise ValueError(f"Choose a valid date for {field['label']}.") from exc
        values[key] = value
    stage = draft["stage"]
    if stage is not None and stage not in {row["id"] for row in schema["stages"]}:
        raise ValueError("The chosen business stage changed. Choose a current stage.")
    return {"values": values, "stage": stage}


def read(kind, target="", *, storage=None):
    storage = storage or store()
    schema = storage.get(record_id(kind))
    detail = storage.get(record_id(kind, target)) if target else None
    return schema, detail


def schema_public(schema):
    return {"revision": int((schema or {}).get("revision", 0)),
            "fields": (schema or {}).get("fields", []), "stages": (schema or {}).get("stages", [])}


def details_public(detail, schema):
    entries = (detail or {}).get("entries", [])
    current = {row["id"]: row for row in schema["fields"]}
    values, retained = {}, []
    for entry in entries:
        field, value = entry["field"], entry["value"]
        definition = current.get(field["id"])
        if (definition and field["type"] == definition["type"]
                and (definition["type"] != "choice" or value is None
                     or value in {option["id"] for option in definition["options"]})):
            values[field["id"]] = value
        else:
            retained.append(entry)
    saved_stage = (detail or {}).get("saved_stage")
    stage = saved_stage["id"] if saved_stage in schema["stages"] else None
    return {"revision": int((detail or {}).get("revision", 0)), "values": values,
            "stage": stage, "retained": retained, "saved_stage": saved_stage}


def _text(value, field=None):
    if value is None:
        return "Not set"
    if field and field["type"] == "choice":
        return next((row["label"] for row in field["options"] if row["id"] == value), "Previously saved choice")
    if type(value) is bool:
        return "Yes" if value else "No"
    return str(value)


def changes(mode, draft, schema, detail):
    if mode == "schema":
        before = schema_public(schema)
        def field_text(row):
            types = {"text": "Text", "number": "Number", "boolean": "Yes or no", "date": "Date", "choice": "Choose one"}
            return row["label"] + " · " + types[row["type"]] + (" · required" if row["required"] else " · optional") + (
                " · " + ", ".join(option["label"] for option in row["options"]) if row["options"] else "")
        return [{"label": "Fields", "before": "\n".join(map(field_text, before["fields"])) or "None",
                 "after": "\n".join(map(field_text, draft["fields"])) or "None"},
                {"label": "Business stages", "before": "\n".join(row["label"] for row in before["stages"]) or "None",
                 "after": "\n".join(row["label"] for row in draft["stages"]) or "None"}]
    saved = {row["field"]["id"]: row for row in (detail or {}).get("entries", [])}
    result = [{"label": field["label"],
               "before": _text(saved.get(field["id"], {}).get("value"), saved.get(field["id"], {}).get("field")),
               "after": _text(draft["values"].get(field["id"]), field)} for field in schema["fields"]]
    old_stage = (detail or {}).get("saved_stage")
    stage = next((row for row in schema["stages"] if row["id"] == draft["stage"]), None)
    return result + [{"label": "Business stage", "before": old_stage["label"] if old_stage else "Not set",
                      "after": stage["label"] if stage else "Not set"}]


def original(kind, target, operation, request_hash, actor, owner, *, storage=None):
    row = (storage or store()).get(record_id(kind, target))
    for result in (row or {}).get("originals", []):
        if result["operation"] == operation:
            if (result["request_hash"], result["actor"], result["owner"]) != (request_hash, actor, owner):
                raise RecordConflict("This original does not match your reviewed request.")
            # The record outbox may still include this operation. A later audit
            # acknowledgment releases the historical result without another edit.
            pending = any(item.get("revision") == result["revision"] for item in _validated_audit_queue(row))
            return {"confirmed": True, "state": "audit_pending" if pending else "confirmed",
                    "heading": result["heading"], "changes": result["changes"]}
    return None


def save(*, kind, target, mode, draft, expected_schema, expected_details,
         operation, request_hash, actor, owner, heading, review_changes, effect_guard):
    storage = store()
    backend = storage._backend()
    lock = contextlib.nullcontext() if backend.shared else cross_process_lock(
        data_dir("work-record-details", "definition-authority"), strict=True)
    with lock:
        effect_guard()
        prior = original(kind, "" if mode == "schema" else target, operation, request_hash, actor, owner, storage=storage)
        if prior is not None:
            return prior
        schema, detail = read(kind, target, storage=storage)
        if int((schema or {}).get("revision", 0)) != expected_schema:
            raise RecordConflict("The field setup changed. Refresh it and review your preserved draft again.")
        if mode == "details" and not schema:
            raise RecordConflict("An administrator needs to set up fields or business stages first.")
        destination = schema if mode == "schema" else detail
        expected = expected_schema if mode == "schema" else expected_details
        if int((destination or {}).get("revision", 0)) != expected:
            raise RecordConflict("This record's business details changed. Read them before reviewing another save.")
        normalized = normalize_schema(draft) if mode == "schema" else normalize_details(draft, schema)
        if normalized != draft:
            raise ValueError("The reviewed fields changed. Review them again.")
        receipt = {"operation": operation, "request_hash": request_hash, "actor": actor, "revision": expected + 1,
                   "owner": owner, "heading": heading, "changes": review_changes}
        def mutate(row):
            if mode == "schema":
                row.update(normalized)
            else:
                current_ids = {field["id"] for field in schema["fields"]}
                retained = [entry for entry in row.get("entries", []) if entry["field"]["id"] not in current_ids]
                row["entries"] = retained + [{"field": field, "value": normalized["values"][field["id"]]}
                                             for field in schema["fields"]]
                row["saved_stage"] = next((stage for stage in schema["stages"] if stage["id"] == normalized["stage"]), None)
            row["originals"] = (row.get("originals", []) + [receipt])[-HISTORY:]
        def validate_definition(row, _now):
            if row.get("revision") != expected_schema or digest(schema_public(row)) != digest(schema_public(schema)):
                raise RecordConflict("The field setup changed before this save.")
        fence = GovernedMutationFence(storage.namespace, storage.prefix, record_id(kind), "tenant", validate_definition) if backend.shared and mode == "details" else None
        identity = record_id(kind, "" if mode == "schema" else target)
        if destination:
            saved = storage.update(identity, mutate, expected_revision=expected,
                                   action="business_details_saved", actor=actor, fence=fence, effect_guard=effect_guard)
        else:
            value = {"id": identity, "kind": kind, "target": "" if mode == "schema" else target}
            mutate(value)
            saved = storage.create(value, action="business_details_saved", actor=actor, fence=fence, effect_guard=effect_guard)
        if saved is None:
            raise RecordConflict("This record disappeared before the save.")
        effect_guard()
        return original(kind, "" if mode == "schema" else target, operation, request_hash, actor, owner, storage=storage)
