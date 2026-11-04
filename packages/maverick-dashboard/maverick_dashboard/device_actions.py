"""Two explicit companion controls, backed by the native reviewed services."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import auth, device_pairing
from .draft_api import context_for

router = APIRouter()
TTL = 180
PURPOSE = "lightwork.device-action.v1"


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Prepare(Input):
    goal_id: int = Field(gt=0)
    action: Literal["answer", "stop"]
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")
    arguments: dict[str, Any] = Field(default_factory=dict, max_length=2)


class Execute(Input):
    token: str = Field(min_length=1, max_length=64000)
    confirmed: bool


def _require_device(request):
    ident = getattr(request.state, "paired_device_id", None)
    if not ident:
        raise HTTPException(403, "Pair and explicitly approve this device for reviewed task actions first.")
    principal = device_pairing.authenticate(auth._bearer_token(request), request.method, request.url.path)
    if principal.principal != auth.caller_principal(request) or principal.claims["device_id"] != ident:
        raise HTTPException(401, "Your paired connection changed. Reconnect before reviewing an action.")
    auth.require_permission(request, "operate")
    return digest([context_for(request), ident, auth.caller_role(request), device_pairing._policy()])


def _adapter(action):
    from .product_operations_stop import entries as stop_entries
    from .product_operations_tasks import entries as task_entries
    if action == "stop":
        return stop_entries()[0]
    if action == "answer":
        return next(entry for entry in task_entries() if entry.id == "clarifications.answer")
    raise HTTPException(404, "That action is unavailable on a companion.")


def _response(value, background=None):
    return JSONResponse(value, background=background, headers={"Cache-Control": "private, no-store"})


def _arguments(adapter, value):
    try:
        return adapter.input_model.model_validate(value).model_dump(mode="json")
    except ValidationError as exc:
        raise HTTPException(422, "Review the selected question and answer. Nothing was changed.") from exc


@router.get("/api/v1/devices/actions/context")
def context(request: Request, goal_id: int):
    with authority_effect_fence():
        binding = _require_device(request)
        selection = {"kind": "goal", "id": goal_id}
        answer = _adapter("answer").snapshot(request, selection)
        stop = _adapter("stop").snapshot(request, selection)
        if _require_device(request) != binding:
            raise HTTPException(409, "Access changed. Refresh the task before reviewing an action.")
        return _response({"context": binding, "checked_at": time.time(),
            "answer": {"revision": answer.revision, "blocked": answer.blocked,
                       "questions": answer.details["questions"][:20], "partial": len(answer.details["questions"]) > 20},
            "stop": {"revision": stop.revision, "blocked": stop.blocked, "summary": stop.summary},
            "title": stop.details["title"], "status": stop.details["status"]})


@router.post("/api/v1/devices/actions/prepare")
def prepare(request: Request, body: Prepare):
    from .app import _require_same_origin
    _require_same_origin(request)
    with authority_effect_fence():
        binding = _require_device(request)
        adapter, selection = _adapter(body.action), {"kind": "goal", "id": body.goal_id}
        state = adapter.snapshot(request, selection)
        if state.blocked or body.context != binding or body.revision != state.revision:
            raise HTTPException(409, state.blocked or "The task or access changed. Refresh and review again.")
        arguments = _arguments(adapter, body.arguments)
        preview = adapter.prepare(request, selection, arguments)
        if adapter.snapshot(request, selection).revision != state.revision or _require_device(request) != binding:
            raise HTTPException(409, "The task changed while preparing this review. Refresh and review again.")
        material = {"purpose": PURPOSE, "goal_id": body.goal_id, "action": body.action,
                    "context": binding, "revision": state.revision, "arguments": arguments,
                    "native": preview.native, "operation_id": secrets.token_hex(16), "expires_at": time.time() + TTL}
        encoded = json.dumps(material, sort_keys=True, allow_nan=False)
        if len(encoded.encode()) > 45000:
            raise HTTPException(422, "This answer is too large for mobile review. Use the full dashboard composer.")
        token = crypto_at_rest.seal_to_str(encoded)
        if not crypto_at_rest.is_sealed_str(token):
            raise HTTPException(503, "The review could not be protected. Nothing was changed.")
        return _response({"token": token, "expires_at": material["expires_at"], "summary": preview.summary,
                          "changes": preview.changes, "action": body.action, "operation_id": material["operation_id"]})


def _open(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError("sealed review required")
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        expected = {"purpose", "goal_id", "action", "context", "revision", "arguments", "native", "operation_id", "expires_at"}
        if (not isinstance(value, dict) or set(value) != expected or value["purpose"] != PURPOSE
                or type(value["expires_at"]) not in {int, float}
                or not time.time() < value["expires_at"] <= time.time() + TTL):
            raise ValueError("invalid review")
        return value
    except Exception as exc:
        raise HTTPException(409, "This review expired or changed. Refresh the current task and review again.") from exc


@router.post("/api/v1/devices/actions/execute")
def execute(request: Request, body: Execute):
    from .app import _require_same_origin
    _require_same_origin(request)
    if body.confirmed is not True:
        raise HTTPException(400, "Confirm the exact review before applying it.")
    value = _open(body.token)
    with authority_effect_fence():
        if _require_device(request) != value["context"]:
            raise HTTPException(409, "The paired device or access changed. Prepare a new review.")
        selection, adapter = {"kind": "goal", "id": value["goal_id"]}, _adapter(value["action"])
        arguments = _arguments(adapter, value["arguments"])
        # Exact native receipts are checked before source freshness so a lost
        # reply never repeats an accepted answer/restart or a Stop request.
        outcome = adapter.recover(request, selection, arguments, value["native"], value["operation_id"])
        if outcome is None:
            state = adapter.snapshot(request, selection)
            if state.blocked or state.revision != value["revision"]:
                raise HTTPException(409, "The task changed after review. Your draft is kept; refresh before deciding again.")
            outcome = adapter.execute(request, selection, arguments, value["native"], value["operation_id"])
        if _require_device(request) != value["context"]:
            raise HTTPException(409, "Access changed. Reopen the task to check its result.")
        return _response({"status": outcome.status, "message": outcome.message,
                          "details": outcome.details, "operation_id": value["operation_id"]}, outcome.background)
