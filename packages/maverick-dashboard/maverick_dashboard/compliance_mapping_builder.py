"""Business choices compiled into the existing immutable action catalog.

Only current finalized scope facts supply control identities. This creates a
mapping awaiting independent review, never a provider task or an approval.
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import time
import zlib
from dataclasses import asdict

from fastapi import HTTPException
from maverick import crypto_at_rest
from maverick.governed_operations import digest
from pydantic import Field

from . import auth
from . import compliance_scope_actions_api as native
from . import compliance_scoping_api as scoping
from .draft_api import context_for
from .product_operations import StrictInput

PAGE = "/compliance/scope-actions/mapping"
PURPOSE = "lightwork.compliance-mapping-review.v1"
TTL = 600
STATES = {"not_started": "Not started", "not_implemented": "Not in place yet", "planned": "Planned"}
ROLES = {"second_line": "Risk and compliance owner", "control_owner": "Control owner", "evidence_owner": "Evidence owner"}
KINDS = {"none": "No evidence task", "collect": "Collect evidence", "refresh": "Refresh evidence", "review": "Review evidence"}
CADENCES = {"one_time": "Once", "monthly": "Every month", "quarterly": "Every quarter", "annual": "Every year", "continuous": "Continuously"}


class Choices(StrictInput):
    scope: str = Field(min_length=1, max_length=128, pattern=native._ID_PATTERN)
    name: str = Field(min_length=1, max_length=80)
    control_state: native.DesiredControlState = "planned"
    control_owner: native.ControlOwnerRole = "control_owner"
    evidence_kind: str = Field(pattern=r"^(none|collect|refresh|review)$")
    evidence_owner: native.EvidenceOwnerRole = "evidence_owner"
    cadence: native.EvidenceCadence = "one_time"


class EvidenceChoice(StrictInput):
    saved_work: str = Field(default="", max_length=64)
    work: native.EvidenceTaskKind = "collect"
    responsibility: native.EvidenceOwnerRole = "evidence_owner"
    frequency: native.EvidenceCadence = "one_time"


class ControlChoice(StrictInput):
    control: str = Field(pattern=r"^[a-f0-9]{64}$")
    control_status: native.DesiredControlState
    control_responsibility: native.ControlOwnerRole
    evidence_work: list[EvidenceChoice] = Field(max_length=64)


class GuidedChoices(Choices):
    mapping: str = Field(default="", max_length=140)
    mapping_revision: str = Field(default="", max_length=64)
    controls: list[ControlChoice] = Field(default_factory=list, max_length=2000)


def control_key(row):
    return digest([row["framework_ref"], row["control_ref"]])


def work_key(item, row, task):
    return digest([item.definition_sha256, row["entry_id"], task["evidence_mapping_ref"]])


def latest(store, tenant, catalog_id):
    with store._connect() as connection:
        row = connection.execute("SELECT MAX(version) FROM action_catalog_definitions WHERE tenant_id=? AND catalog_id=?", (tenant, catalog_id)).fetchone()
    return int(row[0] or 0)


def edit_source(request, scope, choices):
    if not choices.mapping:
        if choices.mapping_revision:
            raise HTTPException(409, "Choose the saved mapping again. Your draft is kept.")
        return None
    _module, tenant, store, item = mapping(request, choices.mapping)
    if item.version != latest(store, tenant, item.catalog_id) or item.definition_sha256 != choices.mapping_revision:
        raise HTTPException(409, "A newer mapping is available or the saved choices changed. Your draft is kept; load the current mapping before a new review.")
    source_contracts = {(row["framework_ref"], row["control_ref"]) for row in scope.control_applicability}
    saved_contracts = {(row["framework_ref"], row["scope_control_ref"]) for row in item.entries}
    if len(source_contracts) != len(scope.control_applicability) or len(saved_contracts) != len(item.entries) or source_contracts != saved_contracts:
        raise HTTPException(409, "This mapping and final scope have different control lists. Choose its matching scope; no saved entries will be omitted or replaced.")
    return item


def business(row, item=None):
    return {"control_status": row["desired_control_state"], "control_responsibility": row["control_owner_role"],
            "evidence_work": [{"saved_work": work_key(item, row, task) if item else "", "work": task["task_kind"],
                               "responsibility": task["owner_role"], "frequency": task["cadence"]} for task in row["evidence_tasks"]]}


def editor(request, scope_id, key="", *, offset=0):
    _module, _tenant, _store, scope = source(request, scope_id)
    item = None
    if key:
        _module, tenant, store, item = mapping(request, key)
        if latest(store, tenant, item.catalog_id) != item.version:
            raise HTTPException(409, "Choose the latest saved version. Your draft is kept.")
        edit_source(request, scope, GuidedChoices(scope=scope_id, name="Mapping", evidence_kind="none", mapping=key, mapping_revision=item.definition_sha256))
    original = {(row["framework_ref"], row["scope_control_ref"]): row for row in item.entries} if item else {}
    rows = []
    for index, row in enumerate(scope.control_applicability[offset:offset + 8]):
        old = original.get((row["framework_ref"], row["control_ref"]))
        rows.append({"value": control_key(row), "label": readable(row["control_ref"], f"Control {offset + index + 1}") + " · " + readable(row["framework_ref"], "Framework"),
                     "choices": business(old, item) if old else None,
                     "saved_work": [{"value": work_key(item, old, task), "label": f"Saved work {i + 1}: {KINDS[task['task_kind']]} · {ROLES[task['owner_role']]} · {CADENCES[task['cadence']]}"} for i, task in enumerate(old["evidence_tasks"])] if old else []})
    return {"context": context_for(request), "revision": source_revision(scope), "mapping_revision": item.definition_sha256 if item else "",
            "name": readable(item.catalog_id, "Task mapping") if item else "", "version": item.version if item else 0,
            "total": len(scope.control_applicability), "rows": rows,
            "next_offset": offset + len(rows) if offset + len(rows) < len(scope.control_applicability) else None}


def readable(value, fallback="Control"):
    value = str(value or "")
    if re.search(r"[a-f0-9]{24,}", value, re.IGNORECASE):
        return fallback
    value = re.sub(r"^(?:ref:|framework[-_:]|control[-_:]|questionnaire[-_:]|mapping[-_:])", "", value)
    value = re.sub(r"-[a-f0-9]{12}$", "", value)
    return re.sub(r"[-_:]+", " ", value).strip().capitalize() or fallback


def authority(request, *, write=False, approval=False):
    auth.require_permission(request, "operate" if write or approval else "view",
                            api_scope="approvals:decide" if approval else None)
    if approval:
        auth.require_global_permission(request, "admin")
    return native.authority(request)


def call(module, function, *args, **kwargs):
    prefix = "ComplianceScopeAction" if hasattr(module, "ComplianceScopeActionError") else "ComplianceScoping"
    try:
        return function(*args, **kwargs)
    except getattr(module, prefix + "NotFound") as exc:
        raise HTTPException(404, "This record is no longer available. Refresh and choose a current record.") from exc
    except getattr(module, prefix + "PermissionDenied") as exc:
        raise HTTPException(403, "This action needs another authorized person. A mapping cannot be approved by its creator.") from exc
    except getattr(module, prefix + "Conflict") as exc:
        raise HTTPException(409, "The record changed or its retention period ended. Refresh and review the current record.") from exc
    except getattr(module, prefix + "Error") as exc:
        raise HTTPException(503, "The compliance record could not be verified. Check saved mappings before preparing another change.") from exc


def scopes(request):
    authority(request)
    module, tenant, store = scoping.authority(request)
    listed = call(module, store.list_records, tenant, limit=200)
    assessments = {item.assessment_id: item for item in listed["assessments"]}
    result = []
    for item in listed["scopes"]:
        if item.status != "finalized" or item.retained_until <= time.time():
            continue
        assessment = assessments.get(item.assessment_id)
        name = readable(assessment.questionnaire_id, "Assessment") if assessment else "Assessment"
        count = len(item.control_applicability)
        # 2,000 is the native immutable catalog's actual entry limit.
        result.append({"value": item.scope_id, "label": f"{name} · {time.strftime('%d %b %Y', time.gmtime(item.created_at))} · {count} controls",
                       "controls": count, "supported": 0 < count <= 2000,
                       "binding": digest([asdict(item), asdict(assessment) if assessment else None])})
    return result


def source(request, scope_id):
    module, tenant, store = authority(request)
    scope = call(module, store._resolved_scope, tenant, scope_id)
    call(module, store._assert_scope_active, scope, time.time())
    if not 0 < len(scope.control_applicability) <= 2000:
        raise HTTPException(409, "Choose a scope with 1 to 2,000 controls, the supported size of a task mapping. No controls were omitted.")
    return module, tenant, store, scope


def source_revision(scope):
    return digest(asdict(scope))


def controls(request, scope_id, *, offset=0):
    _module, _tenant, _store, scope = source(request, scope_id)
    rows = scope.control_applicability[offset:offset + 100]
    return {"context": context_for(request), "revision": source_revision(scope), "total": len(scope.control_applicability),
            "next_offset": offset + len(rows) if offset + len(rows) < len(scope.control_applicability) else None,
            "controls": [{"control": readable(row["control_ref"], f"Control {offset + index + 1}"),
                          "framework": readable(row["framework_ref"], "Framework"),
                          "reason": ", ".join(readable(reason, "Recorded requirement") for reason in row["reason_codes"][:8])
                                    + (f" and {len(row['reason_codes']) - 8} other recorded requirements" if len(row["reason_codes"]) > 8 else "")} for index, row in enumerate(rows)],
            "responsibilities": {key: readable(value, "Assigned team") for key, value in scope.responsibility_assignments.items()}}


def state(request):
    module, tenant, store = authority(request)
    listed = call(module, store.list_records, tenant, limit=200)
    choices = scopes(request)
    mappings = [{"value": f"{item.catalog_id}/{item.version}", "name": readable(item.catalog_id, "Task mapping"),
                 "label": f"{readable(item.catalog_id, 'Task mapping')} · version {item.version} · {len(item.entries)} controls",
                 "status": "Ready to use" if item.status == "published" else "Waiting for another administrator",
                 "latest": item.version == latest(store, tenant, item.catalog_id),
                 "can_approve": auth.has_global_permission(request, "admin") and item.status == "pending_review" and item.created_by != native._principal(request, tenant)} for item in listed["catalogs"]]
    return {"context": context_for(request), "revision": digest([context_for(request), choices, [asdict(c) for c in listed["catalogs"]]]),
            "scopes": choices, "mappings": mappings,
            "listing_notice": "Up to 200 scopes and saved mapping versions are shown.",
            "notice": "A mapping describes proposed work. Another administrator must approve it before a task plan can use it. This page creates no tasks and contacts no outside system."}


def entries(scope, choices, original=None):
    result = []
    overrides = {row.control: row for row in getattr(choices, "controls", [])}
    available = {control_key(row) for row in scope.control_applicability}
    if len(overrides) != len(getattr(choices, "controls", [])) or not set(overrides).issubset(available):
        raise HTTPException(409, "Some selected controls changed or were repeated. Your draft is kept; load the current scope.")
    saved = {(row["framework_ref"], row["scope_control_ref"]): row for row in original.entries} if original else {}
    for index, row in enumerate(scope.control_applicability):
        old = saved.get((row["framework_ref"], row["control_ref"]))
        override = overrides.get(control_key(row))
        if old and not override:
            result.append(dict(old))
            continue
        evidence = []
        if override:
            existing = {work_key(original, old, task): task for task in old["evidence_tasks"]} if old else {}
            used = set()
            for number, task in enumerate(override.evidence_work):
                if task.saved_work and (task.saved_work not in existing or task.saved_work in used):
                    raise HTTPException(409, "Choose each saved evidence job only once from this control. Your draft is kept.")
                used.add(task.saved_work)
                evidence.append({"evidence_mapping_ref": existing[task.saved_work]["evidence_mapping_ref"] if task.saved_work else "evidence-" + digest([original.definition_sha256 if original else "new", old["entry_id"] if old else control_key(row), number, task.work])[:32],
                                 "task_kind": task.work, "owner_role": task.responsibility, "cadence": task.frequency})
        elif choices.evidence_kind != "none":
            evidence = [{"evidence_mapping_ref": "evidence-" + digest([row["control_ref"], choices.evidence_kind])[:32],
                         "task_kind": choices.evidence_kind, "owner_role": choices.evidence_owner, "cadence": choices.cadence}]
        result.append({"entry_id": old["entry_id"] if old else f"entry-{index + 1}", "framework_ref": row["framework_ref"],
                       "scope_control_ref": row["control_ref"], "desired_control_ref": old["desired_control_ref"] if old else row["control_ref"],
                       "desired_control_state": override.control_status if override else choices.control_state,
                       "control_owner_role": override.control_responsibility if override else choices.control_owner, "evidence_tasks": sorted(evidence, key=lambda task: task["evidence_mapping_ref"])})
    controls, work = {}, {}
    for row in result:
        key, contract = row["desired_control_ref"], (row["desired_control_state"], row["control_owner_role"])
        if key in controls and controls[key] != contract:
            raise HTTPException(422, "This control is shared by more than one framework. Give those entries the same status and responsibility; your draft is kept.")
        controls[key] = contract
        for task in row["evidence_tasks"]:
            key, contract = task["evidence_mapping_ref"], (task["task_kind"], task["owner_role"], task["cadence"])
            if key in work and work[key] != contract:
                raise HTTPException(422, "A saved evidence job is shared by multiple controls. Keep its work, responsibility and frequency consistent; your draft is kept.")
            work[key] = contract
    return sorted(result, key=lambda row: row["entry_id"])


def review_rows(body, *, offset=0):
    rows = body[offset:offset + 20]
    return {"total": len(body), "next_offset": offset + len(rows) if offset + len(rows) < len(body) else None,
            "rows": [{"control": readable(row["scope_control_ref"], f"Control {offset + index + 1}"), "framework": readable(row["framework_ref"], "Framework"),
                      "initial_status": STATES[row["desired_control_state"]], "owner": ROLES[row["control_owner_role"]],
                      "evidence": [{"work": KINDS[t["task_kind"]], "owner": ROLES[t["owner_role"]], "frequency": CADENCES[t["cadence"]]} for t in row["evidence_tasks"]]} for index, row in enumerate(rows)]}


def description(choices, count, scope):
    return {"mapping": choices.name, "controls": count, "initial_status": STATES[choices.control_state],
            "control_owner": ROLES[choices.control_owner], "evidence_work": KINDS[choices.evidence_kind],
            "evidence_owner": ROLES[choices.evidence_owner] if choices.evidence_kind != "none" else "No evidence task",
            "frequency": CADENCES[choices.cadence] if choices.evidence_kind != "none" else "No evidence task",
            "control_team_in_selected_scope": readable(scope.responsibility_assignments[choices.control_owner], "Assigned team"),
            "evidence_team_in_selected_scope": readable(scope.responsibility_assignments[choices.evidence_owner], "Assigned team") if choices.evidence_kind != "none" else "No evidence task"}


def review(request, choices, expected_revision):
    authority(request, write=True)
    _module, tenant, _store, scope = source(request, choices.scope)
    if source_revision(scope) != expected_revision:
        raise HTTPException(409, "This scope changed. Your draft is kept; refresh its controls and review again.")
    name = choices.name.strip()
    if not name or any(ord(char) < 32 for char in name):
        raise HTTPException(422, "Give the mapping a short readable name.")
    choices = choices.model_copy(update={"name": name})
    original = edit_source(request, scope, choices) if isinstance(choices, GuidedChoices) else None
    body = entries(scope, choices, original)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:70] or "task-mapping"
    material = {"purpose": PURPOSE, "owner": native._principal(request, tenant), "context": context_for(request),
                "expires": time.time() + TTL, "action": "create", "choices": choices.model_dump(), "source": expected_revision,
                "catalog_id": original.catalog_id if original else slug + "-" + secrets.token_hex(6), "latest": original.version if original else 0,
                "operation": secrets.token_hex(16), "entries": digest(body)}
    details = description(choices, len(body), scope) if not isinstance(choices, GuidedChoices) else {"mapping": readable(original.catalog_id, "Task mapping") if original else name,
               "version_to_save": material["latest"] + 1, "controls": len(body), "individually_edited_controls": len(choices.controls),
               "scope_control_team": readable(scope.responsibility_assignments["control_owner"], "Assigned team"),
               "scope_evidence_team": readable(scope.responsibility_assignments["evidence_owner"], "Assigned team"),
               "scope_compliance_team": readable(scope.responsibility_assignments["second_line"], "Assigned team")}
    if isinstance(choices, GuidedChoices) and not original and not choices.controls:
        details.update(description(choices, len(body), scope))
    return {"token": _seal(material), "context": material["context"], "details": details,
            "control_review": review_rows(body) if isinstance(choices, GuidedChoices) else None,
            "message": "Save these exact choices as an immutable mapping version for independent review. Earlier versions stay unchanged; no task is created or approved."}


def read_review(request, token, *, offset=0):
    value = _open(request, token)
    if value["action"] not in {"create", "approve"}:
        raise HTTPException(409, "Choose a mapping authoring review.")
    if value["action"] == "approve":
        authority(request, write=True, approval=True)
        _module, _tenant, _store, item = mapping(request, value["key"])
        if item.definition_sha256 != value["definition"] or item.revision != value["revision"]:
            raise HTTPException(409, "The mapping changed. Review its current choices before approving.")
        return {"context": value["context"], **review_rows(item.entries, offset=offset)}
    choices = GuidedChoices.model_validate(value["choices"])
    _module, _tenant, _store, scope = source(request, choices.scope)
    original = edit_source(request, scope, choices)
    body = entries(scope, choices, original)
    if source_revision(scope) != value["source"] or digest(body) != value["entries"]:
        raise HTTPException(409, "The source changed. Your draft is kept; review current choices before saving.")
    return {"context": value["context"], **review_rows(body, offset=offset)}


def _seal(material):
    plain = json.dumps(material, sort_keys=True, allow_nan=False)
    token = crypto_at_rest.seal_to_str("z:" + base64.b64encode(zlib.compress(plain.encode("utf-8"))).decode("ascii"))
    if len(token) > 3_000_000:
        raise HTTPException(422, "This protected review is too large. Your draft is kept; reduce the evidence jobs before reviewing.")
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "This review could not be protected. Nothing changed.")
    return token


def _open(request, token):
    _module, tenant, _store = authority(request)
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        plain = crypto_at_rest.unseal_from_str(token)
        if plain.startswith("z:"):
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(base64.b64decode(plain[2:], validate=True), 32_000_000)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError
            plain = decoded.decode("utf-8")
        value = json.loads(plain)
        if (value["purpose"] != PURPOSE or value["owner"] != native._principal(request, tenant)
                or value["context"] != context_for(request) or not time.time() < value["expires"] <= time.time() + TTL):
            raise ValueError
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or your account changed. Refresh and start a new review; existing mappings are kept.") from exc


def _mapping_key(value):
    parts = value.rsplit("/", 1)
    if len(parts) != 2 or not re.fullmatch(native._ID_PATTERN, parts[0]) or not parts[1].isdigit() or not 1 <= int(parts[1]) <= 1_000_000:
        raise HTTPException(404, "Choose a saved mapping.")
    return parts[0], int(parts[1])


def mapping(request, key):
    module, tenant, store = authority(request)
    catalog_id, version = _mapping_key(key)
    item = call(module, store.get_catalog_version, tenant, catalog_id, version)
    return module, tenant, store, item


def mapping_details(item):
    return {"name": readable(item.catalog_id, "Task mapping"), "version": item.version, "controls": len(item.entries),
            "status": "Ready to use" if item.status == "published" else "Waiting for another administrator",
            "open_plan": {"href": "/compliance/scope-actions", "label": "Choose a scope and propose its tasks"}}


def inspect_mapping(request, key, *, offset=0):
    _module, _tenant, _store, item = mapping(request, key)
    # Imported native mappings may have 64 evidence tasks per control. Keep
    # the ordinary readback bounded even for that supported contract.
    rows = item.entries[offset:offset + 20]
    return {"context": context_for(request), **mapping_details(item),
            "next_offset": offset + len(rows) if offset + len(rows) < len(item.entries) else None,
            "rows": [{"control": readable(row["scope_control_ref"], f"Control {offset + index + 1}"),
                      "framework": readable(row["framework_ref"], "Framework"), "initial_status": STATES[row["desired_control_state"]],
                      "owner": ROLES[row["control_owner_role"]],
                      "evidence": [{"work": KINDS[t["task_kind"]], "owner": ROLES[t["owner_role"]], "frequency": CADENCES[t["cadence"]]} for t in row["evidence_tasks"]]} for index, row in enumerate(rows)]}


def review_approval(request, key):
    authority(request, write=True, approval=True)
    _module, tenant, _store, item = mapping(request, key)
    if item.status != "pending_review" or item.created_by == native._principal(request, tenant):
        raise HTTPException(403, "Choose a mapping awaiting review that was created by someone else. Your own mapping needs another administrator.")
    material = {"purpose": PURPOSE, "owner": native._principal(request, tenant), "context": context_for(request), "expires": time.time() + TTL,
                "action": "approve", "key": key, "revision": item.revision, "definition": item.definition_sha256, "operation": secrets.token_hex(16)}
    return {"token": _seal(material), "context": material["context"], "details": mapping_details(item), "control_review": review_rows(item.entries),
            "message": "Approve this exact saved mapping for use. Task plans still need their own independent review. This creates no tasks."}


def readback(request, token):
    value = _open(request, token)
    if value["action"] == "create":
        try:
            _module, _tenant, _store, item = mapping(request, value["catalog_id"] + "/" + str(value.get("latest", 0) + 1))
        except HTTPException as exc:
            if exc.status_code != 404:
                raise
            return {"status": "not_found", "message": "No saved mapping matches this review yet. Nothing was repeated. You may confirm this same review while it is current."}
        if item.created_by != value["owner"] or digest(list(item.entries)) != value["entries"]:
            raise HTTPException(409, "The saved mapping does not match this reviewed request. Nothing was repeated.")
        # Read the original accepted native operation; an identical version saved
        # by another request or by the same person is not this request's receipt.
        request_material = {"action": "create_catalog_version", "catalog_id": value["catalog_id"], "entries": list(item.entries),
                            "expected_latest_version": value.get("latest", 0), "actor_ref": value["owner"]}
        with _store._connect() as connection:
            _sha, receipt = call(_module, _store._operation, connection, _tenant, "guided-" + value["operation"], request_material)
        if receipt is None:
            raise HTTPException(409, "A mapping version exists, but it was not saved by this original request. Your draft is kept; check the current version before a new review.")
        if receipt["result_kind"] != "catalog" or receipt["result_id"] != f"{item.catalog_id}:{item.version}":
            raise HTTPException(409, "The original saved receipt could not be matched. Nothing was repeated.")
        return {"status": "confirmed", "message": "This exact original request saved the mapping version. No save was repeated.", "mapping": f"{item.catalog_id}/{item.version}", "details": mapping_details(item)}
    authority(request, write=True, approval=True)
    _module, _tenant, _store, item = mapping(request, value["key"])
    if item.definition_sha256 != value["definition"]:
        raise HTTPException(409, "The saved mapping differs from this review. Nothing was repeated.")
    if item.status == "published":
        return {"status": "current", "message": "This mapping is currently approved. This check did not repeat an approval or attribute it to an interrupted request.", "details": mapping_details(item)}
    if item.revision != value["revision"]:
        raise HTTPException(409, "The mapping changed. Review it again before approving.")
    return {"status": "not_found", "message": "This mapping still awaits approval. This check did not approve it."}


def apply(request, token, *, confirmed):
    from maverick.authority_effects import authority_effect_fence
    with authority_effect_fence():
        return _apply(request, token, confirmed=confirmed)


def _apply(request, token, *, confirmed):
    if confirmed is not True:
        raise HTTPException(409, "Confirm the exact reviewed mapping before continuing.")
    value = _open(request, token)
    authority(request, write=True, approval=value["action"] == "approve")
    previous = readback(request, token)
    if previous["status"] != "not_found":
        return previous
    module, tenant, store = authority(request, write=True, approval=value["action"] == "approve")
    if value["action"] == "create":
        choices = GuidedChoices.model_validate(value["choices"])
        _module, _tenant, _store, scope = source(request, choices.scope)
        original = edit_source(request, scope, choices)
        body = entries(scope, choices, original)
        if source_revision(scope) != value["source"] or digest(body) != value["entries"]:
            raise HTTPException(409, "The scope changed after your review. No mapping was created; review the current scope.")
        item = call(module, store.create_catalog_version, tenant, value["catalog_id"], entries=body,
                    expected_latest_version=value.get("latest", 0), idempotency_key="guided-" + value["operation"])
        return {"status": "confirmed", "message": "Mapping saved. Another administrator must review it before a task plan can use it. No tasks were created.", "mapping": f"{item.catalog_id}/{item.version}", "details": mapping_details(item)}
    catalog_id, version = _mapping_key(value["key"])
    item = call(module, store.approve_catalog_version, tenant, catalog_id, version,
                expected_revision=value["revision"], idempotency_key="guided-" + value["operation"])
    return {"status": "confirmed", "message": "Mapping approved for use. A task plan still needs separate review before tasks can be created.", "details": mapping_details(item)}
