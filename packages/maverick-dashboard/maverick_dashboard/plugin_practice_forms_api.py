"""Authorized ordinary practice questions from exact restricted plugin contracts."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import plugin_practice_forms as forms
from maverick import plugin_workbench as workbench
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import plugin_workbench_api as native
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/plugins/practice", tags=["plugin-practice"])


class InspectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    operation_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    confirm: Literal[True]


class PracticeIn(InspectIn):
    contract: str = Field(pattern=r"^[a-f0-9]{32}$")
    contract_revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool: str = Field(min_length=1, max_length=200)
    sample: dict
    expected: Any = None
    mode: Literal["sample", "timeout", "cancellation"]


def _call(function):
    try:
        return function()
    except (ValueError, LookupError, PermissionError) as exc:
        raise HTTPException(409, str(exc)) from exc


def _label(value):
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value).replace("_", " ").replace("-", " ").capitalize()


def project(row):
    if row is None:
        return {"state": "not_read", "notice": "Read this version's practice questions before completing a check."}
    result = {key: row[key] for key in ("state", "notice", "plugin", "version")}
    result["receipt"] = row["id"]
    if row["state"] == "ready":
        result["revision"] = row["revision"]
        result["contracts"] = [{"name": item["name"], "label": _label(item["name"]), "schema": item["input_schema"]} for item in row["contracts"]]
    return result


def current(request, fingerprint):
    native._authority(request)
    context = context_for(request)
    return _call(lambda: project(forms.current_contract(context, fingerprint, authorize=lambda: native._authority(request, context))))


def inspect_current(request, body: InspectIn):
    native._authority(request, body.context)
    return _call(lambda: project(forms.inspect_contract(body.context, body.operation_id, body.fingerprint,
        authorize=lambda: native._authority(request, body.context))))


def inspected(request, context, fingerprint, contract, revision, tool, sample):
    native._authority(request, context)
    return _call(lambda: forms.practice_input(context, contract, fingerprint, revision, tool, sample,
                                              authorize=lambda: native._authority(request, context)))


def check_current(request, body: PracticeIn):
    sample = inspected(request, body.context, body.fingerprint, body.contract, body.contract_revision, body.tool, body.sample)
    reviewed = forms.read_contract(body.context, body.contract, fingerprint=body.fingerprint,
                                   authorize=lambda: native._authority(request, body.context))
    schema_digest = workbench._digest(next(item["input_schema"] for item in reviewed["contracts"] if item["name"] == body.tool))
    try:
        encoded = json.dumps(body.expected, sort_keys=True, allow_nan=False).encode()
        if len(encoded) > 16384:
            raise ValueError
    except (ValueError, TypeError, RecursionError) as exc:
        raise HTTPException(422, "Use a finite expected answer with fewer details. No check has started.") from exc
    expected_digest = hashlib.sha256(encoded).hexdigest()
    existing = next((row for row in workbench.history(body.context)["checks"] if row["id"] == body.operation_id), None)
    if existing:
        if (existing["fingerprint"] != body.fingerprint or existing["mode"] != body.mode
                or existing["sample_sha256"] != workbench._digest(sample) or existing["expected_result_sha256"] != expected_digest
                or existing.get("input_schema_sha256") != schema_digest):
            raise HTTPException(409, "This saved request belongs to another practice check. Read its original result.")
        return existing

    def authority():
        inspected(request, body.context, body.fingerprint, body.contract, body.contract_revision, body.tool, body.sample)
    return _call(lambda: workbench.run_check(body.context, body.operation_id, body.fingerprint, sample, body.mode,
                                             expected=body.expected, input_schema_sha256=schema_digest, authorize=authority))


@router.get("/version/{fingerprint}")
async def questions(request: Request, fingerprint: str):
    return JSONResponse(await run_in_threadpool(current, request, fingerprint), headers={"Cache-Control": "private, no-store"})


@router.post("/inspect")
async def inspect_questions(request: Request, body: InspectIn):
    return JSONResponse(await run_in_threadpool(inspect_current, request, body), headers={"Cache-Control": "private, no-store"})


@router.get("/inspection/{operation}")
async def inspection_result(request: Request, operation: str):
    native._authority(request)
    context = context_for(request)
    return JSONResponse(await run_in_threadpool(_call, lambda: project(forms.read_contract(context, operation,
        authorize=lambda: native._authority(request, context)))), headers={"Cache-Control": "private, no-store"})


@router.post("/check")
async def check_practice(request: Request, body: PracticeIn):
    return JSONResponse(await run_in_threadpool(check_current, request, body), headers={"Cache-Control": "private, no-store"})
