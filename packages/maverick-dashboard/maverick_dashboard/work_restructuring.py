"""Original custody and current permission for bounded local grouped work."""
from __future__ import annotations

import json
import re
import secrets
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.candidate_promotion import (
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionUnavailable,
)
from maverick.flow import store
from maverick.flow import work_restructuring as engine
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import flow_requalification as source
from . import local_flow_promotions as release
from .plain_labels import datetime_text

PAGE = "/learning/work-restructuring"
API = "/api/v1/learning/work-restructuring"
NOTICE = ("Check two to eight original local rule cases. Share only exact successful preparation within groups you explicitly allow, "
          "and check every case separately against the complete unchanged workflow. Each case keeps its own input, permission and local check deadline. "
          "Both calculations count toward the reviewed work allowance. No AI, connected action, live approval or publication is performed. "
          "A matching result does not establish faster work, future accuracy or a new algorithm.")


class CaseChoice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    evidence: str = Field(pattern=r"^FRQ-[a-f0-9]{32}$")
    group: str = Field(default="", max_length=40, pattern=r"^[A-Za-z0-9 -]*$")
    deadline: float = Field(gt=0)


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    flow: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    cases: list[CaseChoice] = Field(min_length=2, max_length=8)
    max_steps: int = Field(default=512, ge=4, le=1024)
    max_seconds: int = Field(default=15, ge=1, le=30)
    authorize_sharing: bool = False


def records():
    release._records()
    return GovernedRecordStore("local-work-restructuring", "FWR", "work_restructuring", required_backend="local")


def authority(request, context=None, *, write=False):
    return source.authority(request, context, write=write)


def available(request):
    release._learning_allowed()
    if config.get_features().get("work_restructuring") is not True:
        raise HTTPException(409, "Grouping local work is off. An administrator can enable Share preparation safely in Settings. Original request history remains available.")
    return source._policy(request)


def _receipt(request, identifier):
    row = source._owned(request, identifier)
    if (row["kind"] != "retain" or row["state"] != "done" or row.get("reuse_allowed") is not True
            or row.get("_audit_pending") or not row.get("result", {}).get("agreement")):
        raise HTTPException(409, "A selected case has no current permission for its complete successful evidence. Retain or review its case evidence first.")
    value = {key: row[key] for key in ("kind", "flow_id", "name", "tenant", "owner", "context", "root", "bundle", "version", "flow_revision", "candidate_manifest", "baseline", "case", "evidence", "evidence_revision", "policy", "components", "case_use", "deadline")}
    if row.get("semantic_reuse") is True:
        value["semantic_reuse"] = True
    source._guard(request, value, deadline=False)
    return row


def listing(request, flow=""):
    tenant, owner, context = authority(request)
    enabled = config.get_features().get("work_restructuring") is True
    choices = source.listing(request) if enabled else {"flows": []}
    result = {"context": context, "flows": choices["flows"], "cases": [], "notice": NOTICE, "enabled": enabled}
    if flow and enabled:
        available(request)
        current, _qualified, components, _candidate = source._current(request, flow)
        baseline, publication = current[4], current[5]
        retained = source.records().list(limit=1001)
        if len(retained) > 1000:
            raise HTTPException(503, "The complete case collection exceeds its supported bound. Nothing was omitted; narrow or repair the collection before continuing.")
        for row in retained:
            if (row.get("owner"), row.get("tenant"), row.get("context"), row.get("flow_id"), row.get("kind")) != (owner, tenant, context, flow, "retain"):
                continue
            try:
                row = _receipt(request, row["id"])
            except (HTTPException, ValueError, RecordConflict, CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable, store.FlowSnapshotError):
                continue
            result["cases"].append({"value": row["id"], "label": "Original case " + str(len(result["cases"]) + 1) + " / " + datetime_text(row["case"]["created"], seconds=True),
                                    "revision": row["revision"], "values": source._display(row["case"]["inputs"])})
        result.update(name=baseline.name, version=baseline.version, release=publication["release_id"],
                      components=[item["label"] for item in components])
    authority(request, context)
    result["revision"] = engine.digest(result)
    return result


def material(request, arguments):
    body = Choices.model_validate(arguments)
    tenant, owner, context = authority(request)
    policy = available(request)
    current, _qualified, components, _candidate = source._current(request, body.flow)
    baseline, publication = current[4], current[5]
    selected, runs = [], set()
    groups = [item.group.strip() for item in body.cases if item.group.strip()]
    if len(groups) != len(set(groups)) and body.authorize_sharing is not True:
        raise HTTPException(422, "Explicitly allow preparation sharing before using the same group for more than one case.")
    for index, item in enumerate(body.cases):
        row = _receipt(request, item.evidence)
        if row["flow_id"] != body.flow or row["baseline"] != publication or row["case"]["run_id"] in runs:
            raise HTTPException(409, "Choose different original cases from this exact published workflow.")
        runs.add(row["case"]["run_id"])
        selected.append({"id": item.evidence, "label": "Original case " + str(index + 1) + " / " + datetime_text(row["case"]["created"], seconds=True),
            "source_revision": row["revision"], "source_binding": row["binding"], "source_version": row["case"]["version"],
            "run_id": row["case"]["run_id"], "inputs": row["case"]["inputs"], "components": row["result"]["selective"]["components"],
            "group": engine.digest(["explicit", item.group.strip()]) if item.group.strip() else engine.digest(["separate", item.evidence]),
            "group_label": item.group.strip() or "Keep this case separate",
            "deadline": item.deadline})
    value = {"context": context, "tenant": tenant, "owner": owner, "arguments": body.model_dump(),
        "flow": body.flow, "name": baseline.name, "version": baseline.version, "root": publication["definition_digest"],
        "manifest": publication.get("subflow_digests", {}), "publication": publication, "policy": policy,
        "cases": selected, "current_draft": {"root": current[6], "bundle": current[7]}, "components": components}
    engine.obligations(baseline, value["manifest"], selected, source._resolver(value["manifest"]))
    authority(request, context)
    return value


def prepare(request, arguments, *, context=None):
    authority(request, context)
    with authority_effect_fence(), store._definitions_lock():
        value = material(request, arguments)
        now = time.time()
        if any(not now < item["deadline"] <= now + 3600 for item in value["cases"]):
            raise HTTPException(422, "Give every selected case a local check deadline within the next hour.")
        value["expires"] = now + 600
        planned = engine.obligations(store.load_flow_snapshot(value["root"]), value["manifest"], value["cases"], source._resolver(value["manifest"]))
        changes = [{"label": "Unchanged published workflow", "after": value["name"] + " / version " + str(value["version"])},
            {"label": "Work allowance for all grouped calculations and separate comparisons", "after": str(value["arguments"]["max_steps"]) + " local calculation steps; " + str(value["arguments"]["max_seconds"]) + " seconds, including current-source checks and intermediate case receipts; no AI or connected work"},
            {"label": "Planned local order", "after": "\n".join(value["cases"][index]["label"] for index in planned["order"])},
            {"label": "Ordinary batching comparison", "after": str(planned["independent_computations"]) + " original component requests; " + str(planned["invariant_batching_computations"]) + " exact computations after confidentiality-safe batching. " + planned["meaning"]}]
        for item in value["cases"]:
            changes.extend([{"label": item["label"] + " / original values", "after": source._display(item["inputs"])},
                {"label": item["label"] + " / confidentiality", "after": item["group_label"]},
                {"label": item["label"] + " / local check deadline", "after": datetime_text(item["deadline"], seconds=True)},
                {"label": item["label"] + " / current permission", "after": "Current owner-approved complete case evidence permits reuse. Every source and this permission are checked again before each calculation and saved receipt."}])
        changes.extend(source._source_review(store.load_flow_snapshot(value["root"]), value["manifest"], "Exact published source"))
        changes.append({"label": "Scope and consent", "after": NOTICE + " I authorize only the displayed local sharing and comparison within the existing case permissions. No permission or confidentiality group is widened automatically."})
        if len(changes) > 512 or len(release._bytes(changes)) > 131072:
            raise HTTPException(413, "The complete review is too large. Choose fewer cases or a smaller supported workflow.")
        authority(request, value["context"])
        return value, changes


def guard(request, value, *, deadline=True):
    authority(request, value["context"])
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "The reviewed time window has closed. No further local work will start.")
    if material(request, value["arguments"]) != {key: item for key, item in value.items() if key != "expires"}:
        raise HTTPException(409, "The workflow, original case, reuse permission or current policy changed. Review current choices; the original request will not resume.")
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "The reviewed time window closed while current permission was checked. No further work will start.")


def seal(value):
    result = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(result) or len(result) > 2 * 1024 * 1024:
        raise HTTPException(413, "The complete private result could not be retained safely. Check the original request without repeating it.")
    return result


def opened(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["payload"]))
    if engine.digest(value["prepared"]) != row["binding"]:
        raise HTTPException(409, "The original retained request cannot be verified.")
    return value


def owned(request, identifier):
    tenant, owner, context = authority(request)
    if re.fullmatch(r"FWR-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(422, "Choose an original local grouping request.")
    row = records().get(identifier)
    if row and (row["tenant"], row["owner"], row["context"]) != (tenant, owner, context):
        raise HTTPException(404, "This original request is unavailable to the current account and workspace.")
    authority(request, context)
    return row


def apply(request, value, operation):
    authority(request, value["context"], write=True)
    identifier, service = "FWR-" + operation, records()
    binding = engine.digest(value)
    with authority_effect_fence(), store._definitions_lock():
        available(request)
        existing = owned(request, identifier)
        if existing:
            if existing["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another reviewed plan.")
            return original(request, identifier)
        guard(request, value)
        if any(time.time() >= item["deadline"] for item in value["cases"]):
            raise HTTPException(409, "A selected case deadline has closed. Review current local deadlines before starting a new request.")
        try:
            row = service.create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "context": value["context"],
                "flow": value["flow"], "name": value["name"], "binding": binding, "state": "prepared", "completed_cases": 0,
                "payload": seal({"prepared": value, "receipts": []})}, action="work.restructure.reviewed", actor=value["owner"], max_records=1000)
        except RecordConflict as exc:
            if owned(request, identifier)["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another reviewed plan.") from exc
            return original(request, identifier)
        def claim(current):
            guard(request, value)
            if any(time.time() >= item["deadline"] for item in value["cases"]):
                raise HTTPException(409, "A selected case deadline closed before admission. No calculation started.")
            if current["state"] != "prepared" or current.get("_audit_pending"):
                raise HTTPException(409, "The original admission is uncertain. Check its original result; work will not resume.")
            current["state"] = "running"
        row = service.update(identifier, claim, expected_revision=row["revision"], action="work.restructure.start", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
        def save_case(index, receipt):
            nonlocal row
            def save(current):
                guard(request, value)
                payload = opened(current)
                if current["state"] != "running" or any(item["index"] == index for item in payload["receipts"]):
                    raise HTTPException(409, "This original case already has a retained outcome. It will not run again.")
                payload["receipts"].append({"index": index, "result": receipt})
                retained = seal(payload)
                guard(request, value)
                current.update(payload=retained, completed_cases=len(payload["receipts"]))
            row = service.update(identifier, save, expected_revision=row["revision"], action="work.restructure.case", actor=value["owner"])
            if row.get("_audit_pending"):
                raise HTTPException(409, "The saved case receipt is unconfirmed. Further work stopped; nothing will resume automatically.")
        result = engine.run(store.load_flow_snapshot(value["root"]), value["manifest"], value["cases"],
            resolve=source._resolver(value["manifest"]), guard=lambda: guard(request, value), original=identifier,
            max_steps=value["arguments"]["max_steps"], max_seconds=value["arguments"]["max_seconds"], save_case=save_case)
        def finish(current):
            guard(request, value)
            payload = opened(current)
            if len(payload["receipts"]) != len(value["cases"]) or current["state"] != "running":
                raise HTTPException(409, "The complete original result could not be established. No work will resume.")
            payload["result"] = result
            retained = seal(payload)
            guard(request, value)
            current.update(state="done", payload=retained, finished_at=time.time())
        service.update(identifier, finish, expected_revision=row["revision"], action="work.restructure.complete", actor=value["owner"])
    return original(request, identifier)


def original(request, identifier):
    row = owned(request, identifier)
    result = {"id": identifier, "confirmed": False, "current": False, "completed_cases": 0, "cases": [], "notice": NOTICE,
        "message": "The original request has no confirmed complete outcome. Missing or interrupted work never resumes automatically."}
    if row:
        result.update(context=row["context"], completed_cases=row["completed_cases"], name=row["name"],
                      confirmed=row["state"] == "done" and not row.get("_audit_pending"))
        try:
            payload = opened(row)
            guard(request, payload["prepared"], deadline=False)
            result["current"] = True
            result["cases"] = [{"label": payload["prepared"]["cases"][item["index"]]["label"],
                                "group_label": payload["prepared"]["cases"][item["index"]]["group_label"], **item["result"]} for item in payload["receipts"]]
            if result["confirmed"]:
                result["summary"] = {key: item for key, item in payload["result"].items() if key != "cases"}
        except (HTTPException, ValueError, RecordConflict, CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable, store.FlowSnapshotError):
            result["message"] = "The original request is retained, but its current source or reuse permission is unavailable. Private case values are withheld; no work is repeated."
        if result["confirmed"] and result["current"]:
            result["message"] = "Every original case has a retained grouped result and a separate complete comparison. Nothing ran again."
    authority(request)
    return result


def history(request):
    tenant, owner, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(503, "The complete original history exceeds its supported bound. Nothing was omitted; original results remain readable individually.")
    choices = [{"value": row["id"], "label": row["name"] + " / " + datetime_text(row["created_at"], seconds=True)} for row in rows
               if (row.get("tenant"), row.get("owner"), row.get("context")) == (tenant, owner, context)]
    authority(request, context)
    return {"context": context, "choices": choices}


def operation():
    return secrets.token_hex(16)
