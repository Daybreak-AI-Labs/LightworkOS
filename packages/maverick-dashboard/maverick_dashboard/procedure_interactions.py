"""Current-source joint local rule checks with durable original custody."""
from __future__ import annotations

import re
import secrets
import time

from fastapi import HTTPException
from maverick import config
from maverick.authority_effects import authority_effect_fence
from maverick.candidate_promotion import (
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionUnavailable,
)
from maverick.flow import procedure_interactions as engine
from maverick.flow import store
from maverick.governed_records import GovernedRecordStore, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import competence_transport as custody
from . import flow_requalification as source
from . import local_flow_promotions as release
from . import work_restructuring as evidence
from .plain_labels import datetime_text

PAGE = "/learning/rules-together"
API = "/api/v1/learning/rules-together"
NOTICE = ("Check two owned published local rules together. Both rules keep every local result, and each combined order is checked against fresh separate runs. "
          "Only displayed finite starting values are supported. Differing valid final results remain unresolved. No AI, connected action, live approval or publication runs; no outside effect is deduplicated.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: str = Field(pattern=r"^(qualify|run)$")
    first: str = Field(default="", max_length=128, pattern=r"^[A-Za-z0-9_.-]*$")
    second: str = Field(default="", max_length=128, pattern=r"^[A-Za-z0-9_.-]*$")
    evidence: list[str] = Field(default_factory=list, max_length=8)
    original: str = Field(default="", pattern=r"^(PJI-[a-f0-9]{32})?$")
    inputs: dict = Field(default_factory=dict)


def records():
    release._records()
    return GovernedRecordStore("procedure-interaction-requests", "PJI", "procedure_interactions", required_backend="local")


def authority(request, context=None, *, write=False):
    return source.authority(request, context, write=write)


def available(request):
    release._learning_allowed()
    if config.get_features().get("procedure_interactions") is not True:
        raise HTTPException(409, "Checking local rules together is off. An administrator can enable Check local rules together in Settings. Original request history remains available.")
    return source._policy(request)


def domain(flows):
    try:
        return engine.domain(flows)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


def _flow(request, identifier):
    current, _qualified, _left, _right = source._current(request, identifier)
    flow, publication = current[4], current[5]
    if publication.get("subflow_digests"):
        raise HTTPException(409, "Choose a local rule without included workflows for this combined check.")
    engine.procedure(flow)
    return current, flow, publication


def _choices(request, owner):
    rows = store.list_flow_summaries(owner=owner, bounded=True)
    if len(rows) > 100:
        raise HTTPException(409, "This bounded rule picker supports one hundred owned workflows.")
    result = []
    for row in rows:
        try:
            _flow(request, row["id"])
        except (HTTPException, ValueError, CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable, store.FlowSnapshotError):
            continue
        result.append({"value": row["id"], "label": row["name"]})
    return result


def listing(request, first="", second=""):
    tenant, owner, context = authority(request)
    enabled = config.get_features().get("procedure_interactions") is True
    value = {"context": context, "enabled": enabled, "flows": _choices(request, owner) if enabled else [], "rules": [], "notice": NOTICE}
    if enabled:
        for identifier in (first, second):
            if not identifier:
                value["rules"].append(None)
                continue
            available(request)
            current, flow, publication = _flow(request, identifier)
            cases = []
            for row in source.records().list(limit=1000):
                if (row.get("owner"), row.get("tenant"), row.get("context"), row.get("flow_id"), row.get("kind")) != (owner, tenant, context, identifier, "retain"):
                    continue
                try:
                    retained = evidence._receipt(request, row["id"])
                except HTTPException:
                    continue
                if retained["baseline"] == publication:
                    cases.append({"value": row["id"], "label": "Original case / " + datetime_text(row["case"]["created"], seconds=True), "values": source._display(row["case"]["inputs"])})
            value["rules"].append({"flow": identifier, "name": flow.name, "version": flow.version, "source": [publication, current[6], current[7]], "cases": cases})
    authority(request, context)
    value["revision"] = engine.digest(value)
    return value


def owned(request, identifier):
    tenant, owner, context = authority(request)
    if re.fullmatch(r"PJI-[a-f0-9]{32}", identifier) is None:
        raise HTTPException(422, "Choose an original combined rule request.")
    row = records().get(identifier)
    if row and (row["tenant"], row["owner"], row["context"]) != (tenant, owner, context):
        raise HTTPException(404, "This original request is unavailable to the current account and workspace.")
    authority(request, context)
    return row


def material(request, arguments):
    body = Choices.model_validate(arguments)
    if body.kind == "run" and (body.first or body.second or body.evidence) or body.kind == "qualify" and (body.original or body.inputs):
        raise HTTPException(422, "Use only the displayed choices for this combined rule action.")
    tenant, owner, context = authority(request)
    value = {"arguments": body.model_dump(), "kind": body.kind, "tenant": tenant, "owner": owner, "context": context, "policy": available(request)}
    if body.kind == "run":
        row = owned(request, body.original)
        if row is None or row["state"] != "done" or row["kind"] != "qualify" or row.get("_audit_pending"):
            raise HTTPException(409, "Choose your confirmed combined rule check first.")
        payload = custody.opened(row)
        guard(request, payload["prepared"], deadline=False)
        if not payload["result"].get("qualified"):
            raise HTTPException(409, "This combined rule check has no currently usable learned order checks.")
        from maverick.flow import learned_operator as scalar
        try:
            scalar._inputs({"inputs": payload["result"]["inputs"]}, body.inputs, exact=True)
        except ValueError as exc:
            raise HTTPException(422, "Enter every displayed starting value using its shown type and bounds.") from exc
        selected = next((cell for cell in payload["result"]["cells"] if cell["inputs"] == body.inputs), None)
        if selected is None or not selected["unambiguous"]:
            raise HTTPException(409, "These starting values still have different valid results or no safe order. Choose a qualified starting state.")
        value.update(original=body.original, original_binding=row["binding"], sources=payload["prepared"]["sources"], inputs=body.inputs, result=payload["result"])
        return value
    if not body.first or not body.second or body.first == body.second or len(body.evidence) < 4 or len(set(body.evidence)) != len(body.evidence):
        raise HTTPException(422, "Choose two different published local rules and two different original cases for each, up to eight total.")
    sources, flows, cases = [], [], []
    retained = [evidence._receipt(request, identity) for identity in body.evidence]
    if any(row["flow_id"] not in (body.first, body.second) for row in retained):
        raise HTTPException(409, "Every selected original case must belong to one of these two exact published rules.")
    for identifier in (body.first, body.second):
        current, flow, publication = _flow(request, identifier)
        sources.append({"flow": identifier, "name": flow.name, "publication": publication, "draft": [current[6], current[7]]})
        flows.append(flow)
        selected, runs, distinct = [], set(), set()
        for row in retained:
            if row["flow_id"] != identifier:
                continue
            if row["baseline"] != publication or row["case"]["run_id"] in runs:
                raise HTTPException(409, "Choose different complete cases for these exact published versions.")
            runs.add(row["case"]["run_id"])
            distinct.add(engine.digest({name: row["case"]["inputs"].get(name) for name in engine.procedure(flow)["inputs"]}))
            selected.append({"id": row["id"], "revision": row["revision"], "binding": row["binding"], "run": row["case"]["run_id"], "inputs": row["case"]["inputs"], "case": row["case"]})
        if len(distinct) < 2:
            raise HTTPException(422, "Retain two distinct starting-value cases for each selected rule first.")
        cases.append(selected)
    _definitions, inputs, points = domain(flows)
    value.update(sources=sources, cases=cases, inputs=inputs, domain_points=len(points))
    return value


def prepare(request, arguments, *, context=None):
    authority(request, context)
    with authority_effect_fence(), store._definitions_lock():
        value = material(request, arguments)
        value["expires"] = time.time() + 600
        changes = [{"label": "Action", "after": "Check these local rules together" if value["kind"] == "qualify" else "Run this checked local combination"}]
        for index, item in enumerate(value["sources"]):
            changes.append({"label": "Rule " + str(index + 1), "after": item["name"] + " / published version " + str(item["publication"]["definition_version"])})
            changes.extend(source._source_review(store.load_flow_snapshot(item["publication"]["definition_digest"]), {}, "Complete rule " + str(index + 1)))
        if value["kind"] == "qualify":
            for index, rows in enumerate(value["cases"]):
                changes.extend({"label": "Rule " + str(index + 1) + " / permitted original case " + str(number + 1), "after": source._display(row["inputs"])} for number, row in enumerate(rows))
            changes.extend([{"label": "Complete shared starting-value bounds", "after": source._display(value["inputs"])},
                {"label": "Complete work and reference", "after": "Check all " + str(value["domain_points"]) + " starting states. At each state, run both rules separately, each repeated locally, both combined orders and separate full comparisons of both orders. Infer two order checks using every supported matching rule. One shared thirty-second, 8,192-step, zero-cost allowance covers all work and source checks. Repeated local state is not evidence that an outside effect is safe to repeat."}])
        else:
            changes.append({"label": "Complete starting values", "after": source._display(value["inputs"])})
        changes.append({"label": "Scope and current permission", "after": NOTICE + " Every exact source, existing case-use grant, owner, workspace, policy and reviewed time window is checked before each calculation and saved result. This review creates no new source permission. Original uncertain work never resumes."})
        if len(changes) > 512 or len(release._bytes(changes)) > 131072:
            raise HTTPException(413, "The complete review is too large. Choose smaller supported local rules.")
        authority(request, value["context"])
        return value, changes


def guard(request, value, *, deadline=True):
    authority(request, value["context"])
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "This complete joint review expired. No original work will repeat or resume.")
    if material(request, value["arguments"]) != {key: item for key, item in value.items() if key != "expires"}:
        raise HTTPException(409, "A rule, original case, source permission or policy changed. Review current choices; the original request will not resume.")
    if deadline and time.time() >= value["expires"]:
        raise HTTPException(409, "The complete review expired while current permission was checked. No further work starts.")


def _current_boundary(request, value, admitted, flows, terminals):
    # Used only while apply holds both native writer fences. Definitions and
    # grants were fully checked at claim; actual runs can change independently.
    authority(request, value["context"])
    if time.time() >= value["expires"] or available(request) != value["policy"]:
        raise HTTPException(409, "The current permission or review time changed. Further local work stopped; the original will not resume.")
    for index, selected_cases in enumerate(admitted["cases"]):
        for selected in selected_cases:
            actual = source.cases._source(value["owner"], flows[index], value["sources"][index]["publication"], selected["run"], terminals[index], receipt_version=selected["case"].get("receipt_version", 1))
            if engine.digest(actual) != engine.digest(selected["case"]):
                raise HTTPException(409, "An original case changed. Further local work stopped; the original will not resume.")
    authority(request, value["context"])
    if time.time() >= value["expires"]:
        raise HTTPException(409, "The review expired during the current-source check. Further local work stopped.")


def apply(request, value, operation):
    authority(request, value["context"], write=True)
    if re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "This original combined rule request is invalid.")
    identifier, service, binding = "PJI-" + operation, records(), engine.digest(value)
    with authority_effect_fence(), store._definitions_lock():
        prior = owned(request, identifier)
        if prior:
            if prior["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another complete review.")
            return original(request, identifier)
        guard(request, value)
        try:
            row = service.create({"id": identifier, "tenant": value["tenant"], "owner": value["owner"], "context": value["context"], "kind": value["kind"], "binding": binding, "state": "prepared", "payload": custody.seal({"prepared": value, "observations": []})}, action="interactions.reviewed", actor=value["owner"], max_records=1000)
        except RecordConflict:
            prior = owned(request, identifier)
            if prior is None or prior["binding"] != binding:
                raise HTTPException(409, "This original request belongs to another complete review.") from None
            return original(request, identifier)
        def claim(current):
            guard(request, value)
            if current["state"] != "prepared" or current.get("_audit_pending"):
                raise HTTPException(409, "Original admission is uncertain. Read it without repeating work.")
            current["state"] = "running"
        row = service.update(identifier, claim, expected_revision=row["revision"], action="interactions.start", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
        def save_cell(cell):
            nonlocal row
            def save(current):
                payload = custody.opened(current)
                if current["state"] != "running" or current.get("_audit_pending"):
                    raise HTTPException(409, "The original partial result is uncertain. Further work stopped.")
                payload["observations"].append(cell)
                retained = custody.seal(payload)
                guard(request, value)
                current["payload"] = retained
            row = service.update(identifier, save, expected_revision=row["revision"], action="interactions.cell", actor=value["owner"])
            if row.get("_audit_pending"):
                raise HTTPException(409, "An original local result is unconfirmed. Further work stopped.")
        flows = [store.load_flow_snapshot(item["publication"]["definition_digest"]) for item in value["sources"]]
        admitted = value if value["kind"] == "qualify" else custody.opened(owned(request, value["original"]))["prepared"]
        terminals = [engine.procedure(flow)["components"][-1]["writes"][-1] for flow in flows]
        def current_boundary():
            _current_boundary(request, value, admitted, flows, terminals)
        result = engine.qualify(flows, guard=current_boundary, original=identifier, save_cell=save_cell) if value["kind"] == "qualify" else engine.run(flows, value["result"], value["inputs"], guard=current_boundary, original=identifier)
        def finish(current):
            if current["state"] != "running" or current.get("_audit_pending"):
                raise HTTPException(409, "The original complete result is unconfirmed. Read it without repeating work.")
            payload = custody.opened(current)
            payload["result"] = result
            retained = custody.seal(payload)
            guard(request, value)
            authority(request, value["context"], write=True)
            current.update(state="done", payload=retained)
        service.update(identifier, finish, expected_revision=row["revision"], action="interactions.complete", actor=value["owner"])
    return original(request, identifier)


def original(request, identifier):
    row = owned(request, identifier)
    value = {"id": identifier, "confirmed": False, "current": False, "message": "This original request has no confirmed complete outcome. Missing or interrupted work never resumes automatically."}
    if row:
        value.update(context=row["context"], kind=row["kind"], confirmed=row["state"] == "done" and not row.get("_audit_pending"))
        try:
            payload = custody.opened(row)
            guard(request, payload["prepared"], deadline=False)
            value.update(current=True, observations=payload["observations"], rules=[item["name"] for item in payload["prepared"]["sources"]])
            if value["confirmed"]:
                value.update(result={key: item for key, item in payload["result"].items() if key != "guard_rules"}, message="The exact original result is retained. Nothing ran again.")
        except (HTTPException, ValueError, RecordConflict, store.FlowSnapshotError, CandidatePromotionConflict, CandidatePromotionDenied, CandidatePromotionUnavailable):
            value["message"] = "The original request is retained, but current source permission is unavailable. Private values are withheld; nothing repeats."
    authority(request)
    return value


def history(request):
    tenant, owner, context = authority(request)
    rows = records().list(limit=1001)
    if len(rows) > 1000:
        raise HTTPException(409, "The complete original history exceeds its supported bound. Nothing was omitted.")
    value = {"context": context, "choices": [{"value": row["id"], "kind": row["kind"], "label": ("Joint local rule check" if row["kind"] == "qualify" else "Combined local result") + " / " + datetime_text(row["created_at"], seconds=True)} for row in rows if (row.get("tenant"), row.get("owner"), row.get("context")) == (tenant, owner, context)]}
    authority(request, context)
    return value


def operation():
    return secrets.token_hex(16)
