"""Owner-reviewed structural sharing and guarded local rule qualification."""
from __future__ import annotations

import copy
import json
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.candidate_promotion import (
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionUnavailable,
)
from maverick.flow import competence_transport as engine
from maverick.flow import runner, store
from maverick.flow.evolve import attach_learned_operator
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import flow_requalification as source
from . import local_flow_promotions as release
from . import work_restructuring as evidence
from .plain_labels import datetime_text
from .scalar_wire import whole_number

PAGE = "/learning/portable-rules"
API = "/api/v1/learning/portable-rules"
NOTICE = ("Share only the displayed rule structures and anonymous value types. Private input names, values, thresholds, bounds, examples and source identities stay out of the file. "
          "A recipient checks local bindings against their own permitted cases. A qualified result remains an unpublished local rule with no AI, outside action or inherited source accuracy.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: str = Field(pattern=r"^(share|qualify|run)$")
    flow: str = Field(default="", max_length=128, pattern=r"^[A-Za-z0-9_.-]*$")
    evidence: list[str] = Field(default_factory=list, max_length=8)
    expected: list[bool | int | str] = Field(default_factory=list, max_length=8)
    package: dict = Field(default_factory=dict)
    original: str = Field(default="", pattern=r"^(PCR-[a-f0-9]{32})?$")
    inputs: dict = Field(default_factory=dict)


def records():
    release._records()
    return GovernedRecordStore("portable-competence-requests", "PCR", "portable_competence", required_backend="local")


def authority(request, context=None, *, write=False):
    return source.authority(request, context, write=write)


def available(request):
    release._learning_allowed()
    if config.get_features().get("portable_competence") is not True:
        raise HTTPException(409, "Sharing and qualifying local rule structures is off. An administrator can enable it in Settings. Original request history remains available.")
    return source._policy(request)


def _flow(request, identifier, *, finite=False):
    current, _qualified, _left, _right = source._current(request, identifier)
    baseline, publication = current[4], current[5]
    if publication.get("subflow_digests") or len(baseline.nodes) != 1:
        raise HTTPException(409, "Choose a published rule with one taught answer step. Included workflows and outside actions cannot be shared through this bounded journey.")
    node = baseline.nodes[baseline.start]
    if (node.kind != "agent" or node.learned_fallback or not node.learned_operator or node.next
            or node.learned_operator["artifact"].get("schema") != "lightwork.learned-operator.v1"):
        raise HTTPException(409, "Choose one published taught answer step that runs entirely through local rules.")
    if finite:
        engine.domain(node.learned_operator["artifact"]["spec"])
    return current, baseline, publication


def _flows(request, owner):
    rows = store.list_flow_summaries(owner=owner, bounded=True)
    if len(rows) > 100:
        raise HTTPException(409, "The current rule picker supports one hundred owned workflows. Choose a smaller current collection before using this bounded sharing journey.")
    result, targets = [], []
    for row in rows:
        if not row["single_agent"]:
            continue
        try:
            _current, baseline, _publication = _flow(request, row["id"])
        except (HTTPException, ValueError, CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable, store.FlowSnapshotError):
            continue
        choice = {"value": row["id"], "label": row["name"]}
        artifact = baseline.nodes[baseline.start].learned_operator["artifact"]
        if len(artifact["candidates"]) <= 32:
            result.append(choice)
        try:
            engine.domain(artifact["spec"])
        except ValueError:
            continue
        targets.append(choice)
    return result, targets


def listing(request, flow=""):
    tenant, owner, context = authority(request)
    enabled = config.get_features().get("portable_competence") is True
    sources, targets = _flows(request, owner) if enabled else ([], [])
    value = {"context": context, "flows": sources, "target_flows": targets, "cases": [], "notice": NOTICE, "enabled": enabled}
    if flow:
        available(request)
        current, baseline, publication = _flow(request, flow)
        node = baseline.nodes[baseline.start]
        value.update(name=baseline.name, version=baseline.version, output_type=node.learned_operator["artifact"]["spec"]["output_type"], inputs=node.learned_operator["artifact"]["spec"]["inputs"])
        retained = source.records().list(limit=1001)
        if len(retained) > 1000:
            raise HTTPException(409, "The current case picker supports one thousand retained requests. No cases were silently hidden.")
        for row in retained:
            if (row.get("owner"), row.get("tenant"), row.get("context"), row.get("flow_id"), row.get("kind")) != (owner, tenant, context, flow, "retain"):
                continue
            try:
                row = evidence._receipt(request, row["id"])
            except HTTPException:
                continue
            if row["baseline"] != publication:
                continue
            value["cases"].append({"value": row["id"], "label": "Original case " + str(len(value["cases"]) + 1) + " / " + datetime_text(row["case"]["created"], seconds=True), "values": source._display(row["case"]["inputs"])})
        value["source"] = {"publication": publication, "draft": [current[6], current[7]]}
    authority(request, context)
    value["revision"] = engine.digest(value)
    return value


def describe(package):
    labels = {"if": "Choose", "strip": "Remove surrounding spaces from", "lower": "Lowercase", "upper": "Uppercase", "not": "Opposite of", "add": "Sum of", "sub": "Difference of", "mul": "Product of", "min": "Smaller of", "max": "Larger of", "eq": "Equal values", "lt": "Less than", "le": "Less than or equal to"}
    types = {"boolean": "Yes or no", "integer": "Whole number", "string": "Text"}
    def expression(part):
        if part[0] in {"input", "parameter"}:
            return ("Input " if part[0] == "input" else "Local value ") + str(part[1] + 1)
        return labels[part[0]] + " (" + "; ".join(expression(child) for child in part[1:]) + ")"
    return "\n\n".join("Pattern " + str(index + 1) + ": " + expression(item["program"]) + "\n" + "; ".join("Input " + str(i + 1) + ": " + types[kind] for i, kind in enumerate(item["inputs"])) + "\n" + "; ".join("Local value " + str(i + 1) + ": " + types[kind] for i, kind in enumerate(item["parameters"])) + "\nResult: " + types[item["output"]] for index, item in enumerate(package["templates"]))


def material(request, arguments):
    body = Choices.model_validate(arguments)
    if (body.kind == "share" and (body.expected or body.package or body.original or body.inputs)
            or body.kind == "qualify" and (body.original or body.inputs)
            or body.kind == "run" and (body.flow or body.evidence or body.expected or body.package)):
        raise HTTPException(422, "Use only the displayed choices for this local rule action.")
    tenant, owner, context = authority(request)
    policy = available(request)
    value = {"arguments": body.model_dump(), "kind": body.kind, "tenant": tenant, "owner": owner, "context": context, "policy": policy}
    if body.kind == "run":
        row = owned(request, body.original)
        if row is None or row["kind"] != "qualify" or row["state"] != "done" or row.get("_audit_pending"):
            raise HTTPException(409, "Choose your confirmed qualified local rule first.")
        payload = opened(row)
        guard(request, payload["prepared"], deadline=False)
        result = payload.get("result", {})
        if not result.get("qualified"):
            raise HTTPException(409, "This original check has unresolved local behavior and cannot run as a qualified rule.")
        baseline = store.load_flow_snapshot(payload["prepared"]["publication"]["definition_digest"])
        artifact = result["artifact"]
        if set(body.inputs) != set(artifact["spec"]["inputs"]):
            raise HTTPException(422, "Enter every named input for the qualified local rule.")
        from maverick.flow import learned_operator as scalar
        try:
            scalar._inputs(artifact["spec"], body.inputs, exact=True)
        except ValueError as exc:
            raise HTTPException(422, "Enter each named input within its displayed whole-number or yes/no bounds.") from exc
        value.update(name=baseline.name, original=body.original, original_binding=row["binding"], artifact=artifact, publication=payload["prepared"]["publication"], inputs=body.inputs)
        return value
    if len(body.evidence) < 2 or len(set(body.evidence)) != len(body.evidence):
        raise HTTPException(422, "Choose two to eight different original case records with current reuse permission.")
    current, baseline, publication = _flow(request, body.flow, finite=body.kind == "qualify")
    node = baseline.nodes[baseline.start]
    selected, runs, distinct_inputs = [], set(), set()
    if body.kind == "qualify" and len(body.expected) != len(body.evidence):
        raise HTTPException(422, "Enter your expected answer for every selected local case.")
    for index, identifier in enumerate(body.evidence):
        row = evidence._receipt(request, identifier)
        if row["flow_id"] != body.flow or row["baseline"] != publication or row["case"]["run_id"] in runs:
            raise HTTPException(409, "Choose different original cases from this exact published rule.")
        runs.add(row["case"]["run_id"])
        distinct_inputs.add(engine.digest({name: row["case"]["inputs"].get(name) for name in node.learned_operator["artifact"]["spec"]["inputs"]}))
        item = {"id": identifier, "source_revision": row["revision"], "source_binding": row["binding"], "run": row["case"]["run_id"], "inputs": row["case"]["inputs"]}
        if body.kind == "qualify":
            from maverick.flow import learned_operator as scalar
            output_type = node.learned_operator["artifact"]["spec"]["output_type"]
            expected = whole_number(body.expected[index]) if output_type == "integer" else body.expected[index]
            scalar._scalar(expected, output_type, output=True)
            item["expected"] = expected
        selected.append(item)
    if len(distinct_inputs) < 2:
        raise HTTPException(409, "Choose original cases with at least two different declared input combinations. Repeated work cannot manufacture independent support.")
    package = engine.extract(node.learned_operator["artifact"]) if body.kind == "share" else engine.validate(body.package)
    value.update(name=baseline.name, flow=body.flow, publication=publication, draft=[current[6], current[7]], cases=selected, package=package)
    return value


def prepare(request, arguments, *, context=None):
    authority(request, context)
    began = time.perf_counter()
    with authority_effect_fence(), store._definitions_lock():
        value = material(request, arguments)
        value["expires"] = time.time() + 600
        changes = [{"label": "Action", "after": {"share": "Release only this anonymous rule structure", "qualify": "Find and independently check local bindings", "run": "Run this confirmed unpublished local rule"}[value["kind"]]}, {"label": "Current local rule", "after": value["name"]}]
        if value["kind"] != "run":
            changes.append({"label": "Complete shared rule structure", "after": describe(value["package"]) + "\nRepeated input or local-value numbers refer to the same value; different numbers require different bindings. These displayed operations, value types and repeated-value relationships are shared. Private values, bounds and names are omitted."})
            changes.extend({"label": "Original local case " + str(index + 1), "after": source._display(item["inputs"]) + ("\nYour expected answer: " + source._display(item["expected"]) if "expected" in item else "\nCurrent permission permits this local reuse. No case values enter the shared structural file.")} for index, item in enumerate(value["cases"]))
            if value["kind"] == "qualify":
                baseline = store.load_flow_snapshot(value["publication"]["definition_digest"])
                points = engine.domain(baseline.nodes[baseline.start].learned_operator["artifact"]["spec"])
                changes.extend(source._source_review(baseline, {}, "Current target source"))
                changes.append({"label": "Supported input bounds and all work", "after": "Check all " + str(len(points)) + " complete bounded input combinations. Try at most 4,096 local bindings and separately check at most 4,096 possible bindings using the same information. Run every selected case separately through the platform's existing rule runner. The complete calculation has a thirty-second, zero-cost allowance. Different possible results remain unresolved. This rule stays bound to this saved qualification; no independent workflow is created or published."})
        else:
            changes.append({"label": "Complete named input values", "after": source._display(value["inputs"])})
        changes.append({"label": "Scope, permission and meaning", "after": NOTICE + " Current source, case permission, policy, account and this time window are checked again before work and saving. Copies already downloaded cannot be recalled. Matching these cases does not promise correct answers on future business work. Only the displayed input bounds are supported, and differing possible answers remain unresolved. Nothing is published automatically."})
        value["preparation_ms"] = (time.perf_counter() - began) * 1000
        authority(request, value["context"])
        if len(release._bytes(changes)) > 131072:
            raise HTTPException(413, "The complete review is too large. Choose fewer cases.")
        return value, changes


def guard(request, value, *, deadline=True):
    authority(request, value["context"])
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "This complete review expired. The original request will not repeat or resume.")
    current = material(request, value["arguments"])
    if current != {key: item for key, item in value.items() if key not in {"expires", "preparation_ms"}}:
        raise HTTPException(409, "The source rule, original case, local binding, policy or reuse permission changed. Review current choices; the original request will not resume.")
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "The review expired while current permission was checked. No further work will start.")


def seal(value):
    text = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(text) or len(text) > 2 * 1024 * 1024:
        raise HTTPException(413, "The complete private result could not be saved safely. Read the original request without repeating work.")
    return text


def opened(row):
    payload = json.loads(crypto_at_rest.unseal_from_str(row["payload"]))
    if engine.digest(payload["prepared"]) != row["binding"]:
        raise HTTPException(409, "The original request cannot be verified.")
    return payload


def owned(request, identifier):
    tenant, owner, context = authority(request)
    if re.fullmatch(r"PCR-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(422, "Choose an original local rule request.")
    row = records().get(identifier)
    if row and (row["tenant"], row["owner"], row["context"]) != (tenant, owner, context):
        raise HTTPException(404, "This original request is unavailable to the current account and workspace.")
    authority(request, context)
    return row


def apply(request, value, operation):
    authority(request, value["context"], write=True)
    if re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "This original request is invalid.")
    identifier, binding, service = "PCR-" + operation, engine.digest(value), records()
    with authority_effect_fence(), store._definitions_lock():
        prior = owned(request, identifier)
        if prior:
            if prior["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another complete review.")
            return original(request, identifier)
        guard(request, value)
        try:
            row = service.create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "context": value["context"], "kind": value["kind"], "name": value["name"], "binding": binding, "state": "prepared", "payload": seal({"prepared": value})}, action="competence.reviewed", actor=value["owner"], max_records=1000)
        except RecordConflict:
            prior = owned(request, identifier)
            if prior is None or prior["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another complete review.") from None
            return original(request, identifier)
        def claim(current):
            guard(request, value)
            if current["state"] != "prepared" or current.get("_audit_pending"):
                raise HTTPException(409, "This original admission is uncertain. Read it without repeating work.")
            current["state"] = "running"
        row = service.update(identifier, claim, expected_revision=row["revision"], action="competence.start", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
        began = time.perf_counter()
        if value["kind"] == "share":
            guard(request, value)
            result = {"released": True, "patterns": len(value["package"]["templates"]), "preparation_ms": value["preparation_ms"], "native_source_validation": True}
        elif value["kind"] == "qualify":
            flow = store.load_flow_snapshot(value["publication"]["definition_digest"])
            result = engine.qualify(value["package"], flow, value["cases"], guard=lambda: guard(request, value), original=identifier)
            result["preparation_ms"] = value["preparation_ms"]
        else:
            budget = Budget(max_dollars=0, max_tool_calls=0, max_wall_seconds=10)
            flow = store.load_flow_snapshot(value["publication"]["definition_digest"])
            flow = attach_learned_operator(flow, flow.start, value["artifact"])
            def current(*_args):
                budget.check()
                guard(request, value)
                budget.check()
            def refuse(*_args):
                raise ValueError("This qualified local rule cannot call AI or connected actions.")
            current()
            done = runner.run_flow(flow, data=copy.deepcopy(value["inputs"]), run_id=identifier, agent_fn=refuse, action_fn=refuse, on_node=current)
            current()
            result = {"complete": done.status == runner.STATUS_COMPLETED, "answer": done.data.get(flow.nodes[flow.start].output), "elapsed_ms": (time.perf_counter() - began) * 1000, "native_runs": 1}
        def finish(current):
            if current["state"] != "running" or current.get("_audit_pending"):
                raise HTTPException(409, "The original result could not be confirmed. Read its retained request without repeating it.")
            payload = opened(current)
            payload["result"] = result
            retained = seal(payload)
            guard(request, value)
            authority(request, value["context"], write=True)
            current.update(state="done", payload=retained, finished_at=time.time())
        service.update(identifier, finish, expected_revision=row["revision"], action="competence.complete", actor=value["owner"])
    return original(request, identifier)


def original(request, identifier):
    row = owned(request, identifier)
    value = {"id": identifier, "confirmed": False, "current": False, "message": "The original request has no confirmed complete outcome. Missing or interrupted work never resumes automatically."}
    if row:
        value.update(context=row["context"], kind=row["kind"], confirmed=row["state"] == "done" and not row.get("_audit_pending"))
        try:
            payload = opened(row)
            guard(request, payload["prepared"], deadline=False)
            value["current"] = True
            if value["confirmed"]:
                value["result"] = {key: item for key, item in payload["result"].items() if key != "artifact"}
                if row["kind"] == "share":
                    value["structure"] = describe(payload["prepared"]["package"])
                if row["kind"] == "qualify" and payload["result"].get("qualified"):
                    value["inputs"] = payload["result"]["artifact"]["spec"]["inputs"]
                value["message"] = "The exact original result is retained. Nothing ran again."
        except (HTTPException, ValueError, RecordConflict, store.FlowSnapshotError):
            value["message"] = "The original request is retained, but current source permission is unavailable. Private values and downloads are withheld; nothing repeats."
    authority(request)
    return value


def history(request):
    tenant, owner, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(503, "The complete original history exceeds its supported bound. Nothing was omitted; original results remain readable individually.")
    value = {"context": context, "choices": [{"value": row["id"], "kind": row["kind"], "label": {"share": "Shared rule structure", "qualify": "Local rule qualification", "run": "Qualified local answer"}[row["kind"]] + " / " + datetime_text(row["created_at"], seconds=True)} for row in rows if (row.get("tenant"), row.get("owner"), row.get("context")) == (tenant, owner, context)]}
    authority(request, context)
    return value


def download(request, identifier):
    row = owned(request, identifier)
    if row is None or row["kind"] != "share" or row["state"] != "done" or row.get("_audit_pending"):
        raise HTTPException(409, "Only a confirmed original structural release can be downloaded.")
    with authority_effect_fence(), store._definitions_lock():
        payload = opened(row)
        guard(request, payload["prepared"], deadline=False)
        result = json.dumps(payload["prepared"]["package"], ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        guard(request, payload["prepared"], deadline=False)
        return result


def operation():
    return secrets.token_hex(16)
