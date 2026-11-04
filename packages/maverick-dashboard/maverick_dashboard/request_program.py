"""Current native case grants and encrypted original request-local calculations."""
from __future__ import annotations

import json
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget, BudgetExceeded
from maverick.flow import request_program as engine
from maverick.flow import store
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from . import flow_requalification as source
from . import local_flow_promotions as release
from .plain_labels import datetime_text
from .scalar_wire import whole_number

PAGE = "/learning/request-program"
API = "/api/v1/learning/request-program"
NOTICE = "Prepare an answer for this request by combining selected checked rule steps in every order within your limit. Every combination receives all selected original cases and your expected answers. Every combination that passes those cases also receives the current request. An answer is established only when all passing combinations produce the same answer. No AI, connected action or publication is performed."
LIMITS = "This checks explicit expected answers and current inputs, not the meaning of your description or future correctness. All combinations and original comparisons share twenty seconds and 100,000 charged local work units, including source, custody and rule-candidate checks. Calculation time excludes final saving and browser time. Earlier outcomes never repeat automatically. Saving or publishing a general workflow remains a separate independently reviewed operation."
Scalar = StrictBool | StrictInt | StrictStr


class CaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    evidence: str = Field(pattern=r"^FRQ-[a-f0-9]{32}$")
    expected: Scalar


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    flow: str = Field(min_length=1, max_length=128)
    description: str = Field(min_length=1, max_length=500)
    steps: list[str] = Field(min_length=1, max_length=3)
    length: int = Field(default=3, ge=1, le=3)
    result: str = Field(min_length=1, max_length=64)
    cases: list[CaseIn] = Field(min_length=2, max_length=8)
    inputs: dict[str, Scalar] = Field(min_length=1, max_length=6)


def records():
    release._records()
    return GovernedRecordStore("request-specific-programs", "RSP", "request_program", required_backend="local")


def authority(request, context=None, *, write=False):
    return source.authority(request, context, write=write)


def enabled():
    return not config.config_source_errors(include_tenant=True) and config.get_features().get("request_program") is True


def case(request, identifier):
    row = source._owned(request, identifier)
    if (row["kind"] != "retain" or row["state"] != "done" or row.get("reuse_allowed") is not True
            or row.get("_audit_pending") or not row.get("result", {}).get("agreement")):
        raise HTTPException(409, "An original case no longer has confirmed evidence and current use permission. Review and retain current case evidence first.")
    value = {key: row[key] for key in ("kind", "flow_id", "name", "tenant", "owner", "context", "root", "bundle", "version", "flow_revision",
        "candidate_manifest", "baseline", "case", "evidence", "evidence_revision", "policy", "components", "case_use", "deadline")}
    if row.get("semantic_reuse") is True:
        value["semantic_reuse"] = True
    source._guard(request, value, deadline=False)
    return row


def _cases(request, flow):
    tenant, owner, context = authority(request)
    result = []
    for row in source.records().list(limit=1001):
        if (row.get("tenant"), row.get("owner"), row.get("context"), row.get("flow_id"), row.get("kind")) != (tenant, owner, context, flow, "retain"):
            continue
        try:
            row = case(request, row["id"])
        except HTTPException:
            continue
        result.append({"value": row["id"], "label": "Original case " + str(len(result) + 1) + " · " + datetime_text(row["case"]["created"], seconds=True),
                       "inputs": row["case"]["inputs"]})
    if len(result) > 50:
        raise HTTPException(409, "More than fifty eligible cases need a narrower selection. No incomplete case list is shown.")
    return result


def fields(rows):
    observed = {}
    for row in rows:
        for key, value in row["inputs"].items():
            kind = "boolean" if type(value) is bool else "integer" if type(value) is int else "string" if type(value) is str else "unsupported"
            if key in observed and observed[key] != kind:
                raise HTTPException(409, "These cases use different value types. Choose another workflow with consistent named inputs.")
            observed[key] = kind
    if not 1 <= len(observed) <= 6 or "unsupported" in observed.values():
        raise HTTPException(409, "This request supports one to six directly named text, whole-number or Yes/No inputs.")
    return [{"key": key, "label": key.replace("_", " "), "kind": kind} for key, kind in sorted(observed.items())]


def listing(request, flow=""):
    with authority_effect_fence(), store._definitions_lock():
        return _listing(request, flow)


def _listing(request, flow):
    tenant, owner, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(409, "The original request history exceeds this bounded view.")
    flows = source.listing(request)["flows"] if enabled() else []
    value = {"context": context, "enabled": enabled(), "flows": flows, "steps": [], "cases": [], "fields": [], "notice": NOTICE, "limits": LIMITS,
        "history": [{"value": row["id"], "label": row["name"] + " · " + datetime_text(row["created_at"], seconds=True)} for row in rows
                    if (row.get("tenant"), row.get("owner"), row.get("context")) == (tenant, owner, context)]}
    if flow and enabled():
        current = source.cases._current(request, flow, changed=False)
        baseline = current[4]
        value.update(name=baseline.name, version=baseline.version, steps=engine.components(baseline), cases=_cases(request, flow))
        if value["cases"]:
            value["fields"] = fields(value["cases"])
        value["revision"] = engine.digest([current[5:], value["steps"], value["cases"], value["fields"]])
    authority(request, context)
    return value


def material(request, arguments):
    body = Choices.model_validate(arguments)
    tenant, owner, context = authority(request)
    if not enabled():
        raise HTTPException(409, "Request-specific answers are off. An administrator can enable them in Settings. Original history remains available.")
    release._learning_allowed()
    current = source.cases._current(request, body.flow, changed=False)
    native_steps = {row["id"]: row for row in engine.components(current[4])}
    engine.sequences(body.steps, body.length)
    if any(key not in native_steps for key in body.steps):
        raise HTTPException(409, "A selected step no longer has supported checked rules.")
    output_types = {native_steps[key]["kind"] for key in body.steps if native_steps[key]["output"] == body.result}
    if len(output_types) != 1:
        raise HTTPException(422, "Choose a produced result with one consistent answer type.")
    expected_type = next(iter(output_types))
    selected, identities = [], set()
    for index, choice in enumerate(body.cases):
        row = case(request, choice.evidence)
        if row["flow_id"] != body.flow or row["baseline"] != current[5] or row["case"]["run_id"] in identities:
            raise HTTPException(409, "Choose different original cases from this exact published workflow.")
        identities.add(row["case"]["run_id"])
        if expected_type == "integer":
            choice.expected = whole_number(choice.expected)
        source.engine.learned_operator._scalar(choice.expected, expected_type, output=True)
        selected.append({"id": row["id"], "revision": row["revision"], "binding": row["binding"],
            "label": "Original case " + str(index + 1) + " · " + datetime_text(row["case"]["created"], seconds=True),
            "inputs": row["case"]["inputs"], "expected": choice.expected})
    required = fields(selected)
    if set(body.inputs) != {item["key"] for item in required} or body.result in body.inputs:
        raise HTTPException(422, "Enter every named request input, and select a result that was not supplied as an input.")
    for item in required:
        if item["kind"] == "integer":
            body.inputs[item["key"]] = whole_number(body.inputs[item["key"]])
        source.engine.learned_operator._scalar(body.inputs[item["key"]], item["kind"])
    return {"tenant": tenant, "owner": owner, "context": context, "arguments": body.model_dump(), "name": current[4].name,
            "root": current[5]["definition_digest"], "publication": current[5], "draft": list(current[6:]), "policy": source._policy(request),
            "cases": selected, "fields": required, "steps": [native_steps[key] for key in body.steps]}


def prepare(request, arguments, context):
    authority(request, context, write=True)
    with authority_effect_fence(), store._definitions_lock():
        value = material(request, arguments)
        value.update(operation="RSP-" + secrets.token_hex(16), deadline=time.time() + 600)
        body = value["arguments"]
        names = {row["id"]: row["label"] for row in value["steps"]}
        combinations = engine.sequences(body["steps"], body["length"])
        changes = [{"label": "Business request", "after": body["description"]}, {"label": "Current published rules", "after": value["name"]},
            {"label": "Selected checked steps", "after": "\n".join(names[key] for key in body["steps"])},
            {"label": "Complete combinations", "after": str(len(combinations)) + " combinations, including repeated steps, through " + str(body["length"]) + " steps; every chosen original case is checked for every combination.\n" + "\n".join(str(index + 1) + ". " + " → ".join(names[key] for key in sequence) for index, sequence in enumerate(combinations))},
            {"label": "Required result", "after": body["result"].replace("_", " ")}, {"label": "Current request inputs", "after": source._display(body["inputs"])}]
        for row in value["cases"]:
            changes.append({"label": row["label"], "after": "Original inputs:\n" + source._display(row["inputs"]) + "\nYour required answer: " + source._display(row["expected"])})
        changes.extend(source._source_review(store.load_flow_snapshot(value["root"]), value["publication"].get("subflow_digests", {}), "Current checked rules"))
        changes.append({"label": "Permission, allowance and retained outcome", "after": NOTICE + " " + LIMITS})
        if len(changes) > 512 or len(release._bytes(changes)) > 131072:
            raise HTTPException(413, "The complete rule and case review is too large. Choose fewer or smaller rule sources; unseen values cannot be approved.")
        authority(request, context)
        return value, changes


def guard(request, value, *, deadline=True, require_enabled=True):
    authority(request, value["context"])
    if require_enabled:
        fresh = material(request, value["arguments"])
        if fresh != {key: row for key, row in value.items() if key not in {"operation", "deadline"}}:
            raise HTTPException(409, "Rules, original case permission, policy or your account changed. Your entered request is kept; review current sources again.")
    else:
        for row in value["cases"]:
            original = case(request, row["id"])
            if original["revision"] != row["revision"] or original["binding"] != row["binding"]:
                raise HTTPException(409, "Original case permission changed. Private values cannot be displayed.")
    if deadline and time.time() >= value["deadline"]:
        raise HTTPException(409, "This review expired before the native operation. Review the current request again.")


def seal(value):
    result = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
    if not crypto_at_rest.is_sealed_str(result) or len(result) > 2 * 1024 * 1024:
        raise HTTPException(413, "The complete private outcome cannot be retained safely. Nothing will repeat automatically.")
    return result


def owned(request, identifier):
    tenant, owner, context = authority(request)
    if re.fullmatch(r"RSP-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(404, "Choose an original request.")
    row = records().get(identifier)
    if row is None or (row.get("tenant"), row.get("owner"), row.get("context")) != (tenant, owner, context):
        raise HTTPException(404, "This original request is unavailable to the current account and workspace.")
    authority(request, context)
    return row


def original(request, identifier):
    with authority_effect_fence(), store._definitions_lock():
        return _original(request, identifier)


def _original(request, identifier):
    row = owned(request, identifier)
    payload = json.loads(crypto_at_rest.unseal_from_str(row["payload"]))
    if engine.digest(payload["prepared"]) != row["binding"]:
        raise HTTPException(409, "This original request cannot be verified.")
    confirmed = row["state"] == "done" and not row.get("_audit_pending")
    result = {"id": row["id"], "context": row["context"], "confirmed": confirmed, "current": False, "result": None,
        "message": "The original request has no confirmed complete result. Nothing will repeat; review current choices for a separate request."}
    try:
        guard(request, payload["prepared"], deadline=False, require_enabled=False)
        result.update(current=True, result=payload.get("result") if confirmed else None)
        if confirmed:
            result["message"] = "Every declared combination and case is retained with the original current-request answers. Nothing ran again."
    except HTTPException:
        result["message"] = "The original outcome remains retained, but current source permission no longer allows its private values. Nothing ran again."
    authority(request, row["context"])
    return result


def apply(request, value):
    authority(request, value["context"], write=True)
    budget = Budget(max_wall_seconds=20, max_dollars=0, max_tool_calls=100000)
    def charge(count=1):
        for _ in range(count):
            budget.record_tool_call()
        budget.check()
    def checked():
        charge()
        guard(request, value)
        budget.check()
    def dispatch_checked():
        # The same native authority/definition fences remain held throughout
        # this local execution and exclude ordinary case withdrawal, settings,
        # ownership, publication and role writers. Re-reading every immutable
        # source on post-step telemetry would duplicate admission work. The
        # independent learning stop and clock remain current at every check.
        charge()
        release._learning_allowed()
        if not enabled() or time.time() >= value["deadline"]:
            raise HTTPException(409, "This request's current capability or reviewed time window closed. Read its original outcome; nothing repeats.")
        budget.check()
    with authority_effect_fence(), store._definitions_lock():
        service, identifier, binding = records(), value["operation"], engine.digest(value)
        charge()
        existing = service.get(identifier)
        if existing:
            if owned(request, identifier)["binding"] != binding:
                raise HTTPException(409, "This original request belongs to a different review.")
            return original(request, identifier)
        checked()
        try:
            charge()
            row = service.create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "context": value["context"],
                "name": value["arguments"]["description"], "binding": binding, "state": "prepared", "payload": seal({"prepared": value})},
                action="request.rules.reviewed", actor=value["owner"], max_records=1000)
        except RecordConflict:
            if owned(request, identifier)["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another review.") from None
            return original(request, identifier)
        def claim(current):
            checked()
            if current["state"] != "prepared" or current.get("_audit_pending") or current["binding"] != binding:
                raise HTTPException(409, "Original admission is unconfirmed. Check its original result without repeating work.")
            current["state"] = "running"
        charge()
        row = service.update(identifier, claim, expected_revision=row["revision"], action="request.rules.start", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
        charge()
        rules = store.load_flow_snapshot(value["root"])
        checked()
        answer = engine.run(rules, value["arguments"], value["cases"], guard=dispatch_checked, charge=charge, budget=budget, original=identifier)
        def finish(current):
            checked()
            if current["state"] != "running" or current["binding"] != binding:
                raise HTTPException(409, "The original result remains unconfirmed. Nothing will repeat.")
            payload = seal({"prepared": value, "source": rules.to_dict(), "result": answer})
            checked()
            current.update(state="done", payload=payload)
        charge()
        service.update(identifier, finish, expected_revision=row["revision"], action="request.rules.complete", actor=value["owner"])
    return original(request, identifier)


def call(function):
    from maverick.governed_records import GovernedRecordBackendError
    from maverick.learning_guard import Halted
    from maverick.privacy_ops import AuditOutboxError, PrivacyStateError
    try:
        return release._native_call(function)
    except (BudgetExceeded, Halted) as exc:
        raise HTTPException(409, "The full calculation exceeded its allowance. Read the original outcome; no partial result is called an answer.") from exc
    except (ValueError, RecordConflict) as exc:
        raise HTTPException(409, "The complete typed request or original custody could not be qualified. Check every expected answer and current source, or read the original outcome without repeating it.") from exc
    except (OSError, GovernedRecordBackendError, AuditOutboxError, PrivacyStateError) as exc:
        raise HTTPException(503, "The original request could not be confirmed. Read its original outcome; no calculation will repeat automatically.") from exc
