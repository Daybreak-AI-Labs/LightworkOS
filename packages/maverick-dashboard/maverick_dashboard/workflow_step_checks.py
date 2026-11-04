"""One reviewed pure taught step, with durable original outcome custody."""
from __future__ import annotations

import json
import re
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.flow import Flow, learned_operator, operator_artifacts, runner, store
from maverick.flow.request_program import compile_flow, components
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore, RecordConflict
from maverick.learning_guard import check_learning_halt
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import api
from .candidate_promotion_api import _binding
from .recovery_visibility import call

router = APIRouter(prefix="/api/v1/workflow-step-checks")
PURPOSE = "lightwork.workflow-step-check.v1"


class DraftIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    flow: dict = Field(min_length=1, max_length=30)
    step: str = Field(min_length=1, max_length=120)


class ReviewIn(DraftIn):
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    inputs: dict[str, bool | int | str] = Field(max_length=6)


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2 * 1024 * 1024)
    confirmed: bool


def records():
    return GovernedRecordStore("workflow-step-checks", "WSC", "workflow_step_check")


def authority(request, context=None, *, write=False):
    from fastapi import Response
    tenant, owner, current = _binding(request, Response())
    if context is not None and context != current:
        raise HTTPException(409, "Your account or workspace changed. Refresh before continuing.")
    if write:
        from .app import _require_same_origin
        _require_same_origin(request)
    return tenant, owner, current


def material(request, body):
    tenant, owner, context = authority(request)
    if not config.get_features().get("workflow_step_checks") or config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "Trying one step is off. An administrator can enable it in Settings; original results remain readable.")
    api._require_flows()
    check_learning_halt("workflow_step_checks", "check")
    if len(json.dumps(body, ensure_ascii=False).encode("utf-8")) > 2 * 1024 * 1024:
        raise HTTPException(422, "This complete workflow exceeds the supported review size.")
    source = Flow.from_dict(body["flow"])
    saved = store.load_flow(source.id)
    api._assert_flow_access(request, saved)
    source.owner = saved.owner
    available = {row["id"]: row for row in components(source)}
    if body["step"] not in available:
        raise HTTPException(409, "Choose a taught local rule with AI fallback turned off. Connected actions and AI calls cannot be tried through this local calculation.")
    return {"tenant": tenant, "owner": owner, "context": context, "body": body,
            "saved_source": digest(saved.to_dict()), "source": source.to_dict(),
            "fields": available[body["step"]]["inputs"], "label": available[body["step"]]["label"],
            "policy": digest(config.load_config()), "version": implementation()}


def implementation():
    from pathlib import Path

    from maverick.flow import learned_operator
    return digest([Path(module.__file__).read_bytes().hex() for module in
                   (runner, operator_artifacts, learned_operator, store)] + [Path(__file__).read_bytes().hex()])


def guard(request, value):
    authority(request, value["context"], write=True)
    if not time.time() < value["deadline"] <= time.time() + 600:
        raise HTTPException(409, "This review expired before the calculation was admitted. Review current choices again.")
    fresh = material(request, value["body"])
    if fresh != {key: item for key, item in value.items() if key not in {"deadline", "operation", "inputs"}}:
        raise HTTPException(409, "The workflow, permission or safeguards changed. Review current choices again.")


def original(request, identifier, binding=None):
    tenant, owner, context = authority(request)
    row = records().get(identifier) if isinstance(identifier, str) and identifier.startswith("WSC-") and len(identifier) == 36 else None
    if row is None or (row.get("tenant"), row.get("owner"), row.get("context")) != (tenant, owner, context):
        raise HTTPException(404, "This original step check is unavailable to the current account.")
    if binding is not None and row["binding"] != binding:
        raise HTTPException(409, "This original request belongs to another complete review.")
    current = False
    try:
        fresh = material(request, row["body"])
        current = all(fresh[key] == row[key] for key in fresh)
    except (HTTPException, OSError, ValueError):
        pass
    confirmed = row["state"] == "done" and not row.get("_audit_pending")
    authority(request, context)
    return {"context": context, "id": identifier, "confirmed": confirmed, "current": current,
            "message": "The complete original check was retained. Nothing ran again." if confirmed else
                       "This original result is unconfirmed. It will not run again.",
            "result": row["result"] if confirmed and current else None}


def apply(request, value):
    service, identifier, binding = records(), value["operation"], digest(value)
    budget = Budget(max_dollars=0, max_tool_calls=512, max_wall_seconds=20)
    with authority_effect_fence(), store._definitions_lock():
        authority(request, value["context"], write=True)
        if service.get(identifier) is not None:
            return original(request, identifier, binding)
        guard(request, value)
        try:
            row = service.create({**value, "id": identifier, "binding": binding, "state": "prepared"},
                                 action="workflow.step_check.reviewed", actor=value["owner"], max_records=1000)
        except RecordConflict:
            return original(request, identifier, binding)
        def claim(current):
            guard(request, value)
            budget.check()
            if current["state"] != "prepared" or current.get("_audit_pending") or current["binding"] != binding:
                raise HTTPException(409, "The original admission is unconfirmed. Read it without repeating work.")
            current["state"] = "running"
        row = service.update(identifier, claim, expected_revision=row["revision"],
                             action="workflow.step_check.started", actor=value["owner"])
        if row.get("_audit_pending"):
            return original(request, identifier)
        source = Flow.from_dict(value["source"])
        unit = compile_flow(source, [value["body"]["step"]], identifier, 1)
        node = unit.nodes[unit.start]
        for _ in range(1 + operator_artifacts.evaluation_cost(node.learned_operator["artifact"])):
            budget.record_tool_call()
        guard(request, value)
        def refuse(*_args):
            raise ValueError("This local check cannot call AI or connected tools.")
        def observe(*_args):
            authority(request, value["context"])
            check_learning_halt("workflow_step_checks", "check")
            budget.check()
        result = runner.run_flow(unit, data=value["inputs"], agent_fn=refuse, action_fn=refuse,
                                 run_id=identifier, on_node=observe)
        produced = result.status == runner.STATUS_COMPLETED and node.output in result.data
        retained = {"answered": produced, "label": value["label"],
                    "value": (str(result.data[node.output]) if type(result.data[node.output]) is int
                              else result.data[node.output]) if produced else None,
                    "message": "Every retained rule alternative agreed on this answer." if produced else
                               "These values did not establish one supported answer. Review the declared range or teach another permitted example."}
        def finish(current):
            guard(request, value)
            budget.check()
            if current["state"] != "running" or current["binding"] != binding:
                raise HTTPException(409, "The original confirmation changed. Nothing will be repeated.")
            current.update(state="done", result=retained)
        service.update(identifier, finish, expected_revision=row["revision"],
                       action="workflow.step_check.completed", actor=value["owner"])
        return original(request, identifier)


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "no-store, private"})


@router.post("/inputs")
def inputs(request: Request, body: DraftIn):
    def read():
        with authority_effect_fence(), store._definitions_lock():
            value = material(request, body.model_dump())
            fields = {name: {key: str(item) if key in {"min", "max"} else item
                             for key, item in declaration.items()}
                      for name, declaration in value["fields"].items()}
            return {"context": value["context"], "fields": fields, "label": value["label"]}
    return response(call(read))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    def prepare():
        authority(request, body.context, write=True)
        with authority_effect_fence(), store._definitions_lock():
            value = material(request, body.model_dump(exclude={"context", "inputs"}))
            if set(body.inputs) != set(value["fields"]):
                raise HTTPException(422, "Answer each named input exactly once.")
            entered = dict(body.inputs)
            for name, declaration in value["fields"].items():
                if declaration["type"] == "integer" and type(entered[name]) is str:
                    text = entered[name]
                    if len(text) > 24 or not re.fullmatch(r"-?[0-9]+", text):
                        raise HTTPException(422, "Enter a whole number inside the displayed range.")
                    entered[name] = int(text)
            try:
                artifact = Flow.from_dict(value["source"]).nodes[body.step].learned_operator["artifact"]
                learned_operator._inputs(artifact["spec"], entered, exact=True)
            except ValueError as exc:
                raise HTTPException(422, "A value does not match its displayed type or supported range. Entered work is kept.") from exc
            value.update(inputs=entered, deadline=time.time() + 600, operation="WSC-" + secrets.token_hex(16))
            token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "prepared": value}))
            changes = [{"label": "Selected taught step", "after": value["label"]}]
            for name, item in entered.items():
                text = ("Yes" if item else "No") if type(item) is bool else str(item)
                changes.append({"label": name.replace("_", " "), "after": text if type(item) is not str else "Entered text (spaces preserved): «" + text + "»"})
            changes.append({"label": "Consequence", "after": "Only this taught step is calculated. No other workflow step, AI call or connected action runs. All retained alternatives are checked within the shared local work allowance. The original outcome is retained; an uncertain reply never repeats automatically."})
            return {"context": value["context"], "id": value["operation"], "token": token, "changes": changes}
    return response(call(prepare))


@router.post("/apply")
async def apply_endpoint(request: Request, body: ApplyIn):
    authority(request, write=True)
    if body.confirmed is not True:
        raise HTTPException(422, "Review the step and every entered value before continuing.")
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if set(value) != {"purpose", "prepared"} or value["purpose"] != PURPOSE:
            raise ValueError
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This complete step review could not be verified.") from exc
    return response(await run_in_threadpool(call, lambda: apply(request, value["prepared"])))


@router.get("/original/{identifier}")
def original_endpoint(request: Request, identifier: str):
    authority(request, request.headers.get("X-Lightwork-Step-Context"))
    return response(call(lambda: original(request, identifier)))
