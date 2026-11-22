"""Legal workspace routes and shared request-bound operation handlers."""
from __future__ import annotations

import json
import logging
import secrets
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from maverick import crypto_at_rest
from maverick.budget import BudgetExceeded
from maverick.governed_operations import digest
from maverick.governed_records import RecordConflict
from maverick.legal_workforce_catalog import BOUNDARY, ROLE_MAP
from maverick.legal_workspace import LegalService, enabled
from maverick.legal_workspace_models import OPERATIONS, Input
from maverick.paths import current_tenant_id_strict
from pydantic import Field, ValidationError

from . import auth, rbac, workspace_tenants
from .draft_api import context_for
from .store_failures import log_store_failure, remember_route

router = APIRouter(prefix="/api/v1/legal", tags=["legal-workspace"], dependencies=[Depends(remember_route)])
log = logging.getLogger(__name__)
PURPOSE = "lightwork.legal-workspace.review.v1"
TTL = 600


class ReviewInput(Input):
    action: str = Field(min_length=1, max_length=80)
    arguments: dict = Field(max_length=20)
    matter_id: str = Field(default="", max_length=80)
    expected_revision: int = Field(default=0, ge=0)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class TokenInput(Input):
    token: str = Field(min_length=1, max_length=2000000)
    confirmed: bool = False


def context(request):
    from maverick.tenant.registry import assert_tenant_active

    from .vendor_onboarding_composition import (
        _budget_authority,
        _role_authority,
        _workspace_authority,
    )

    auth.require_permission(request, "operate")
    auth.require_suite(request, "legal")
    if not enabled():
        raise HTTPException(409, "Turn on Legal workspace in Settings to continue.")
    tenant, actor = current_tenant_id_strict(), auth.caller_principal(request)
    if not tenant or not actor:
        raise HTTPException(403, "Sign in and choose a workspace before opening legal matters.")
    assert_tenant_active(tenant)
    if (getattr(request.state, "workspace_tenant_source", "") == "principal_selection"
            and not workspace_tenants.principal_can_select(actor, tenant)):
        raise HTTPException(403, "Your workspace membership changed. Choose an available workspace.")
    key = getattr(request.state, "api_key_id", None)
    scopes = auth.api_key_scopes(request)
    role = auth.caller_role(request)
    return {"actor": actor, "tenant": tenant, "human": not (key or scopes is not None),
            "account": context_for(request), "role": _role_authority(role),
            "key": key, "scopes": sorted(scopes or ()),
            "workspace": _workspace_authority(request, actor, tenant), "budget": _budget_authority(tenant)}


def service(request):
    bound = context(request)
    return LegalService(bound["tenant"], bound["actor"], human=bound["human"],
                        authorize=lambda: context(request) == bound)


def member_choices(request):
    bound = context(request)
    users = rbac.list_tenant_roles(bound["tenant"])
    users[bound["actor"]] = auth.caller_role(request)
    return [{"value": principal, "label": principal.removeprefix("user:")}
            for principal, role in sorted(users.items()) if "operate" in rbac.permissions_for(role)]


def prepare_operation(request, action, arguments, matter_id=""):
    if action == "access" and arguments.get("grant", True):
        if arguments.get("principal") not in {entry["value"] for entry in member_choices(request)}:
            raise HTTPException(422, "Choose a current workspace member with permission to operate legal work.")
    material = service(request).prepare(action, arguments, matter_id)
    material["authority"] = context(request)
    if matter_id:
        row = service(request).get(matter_id)
        material["labels"] = {entry["id"]: entry.get("title", entry.get("firm", entry.get("reference", "Record")))
                              for key in ("sources", "contracts", "engagements", "assignments", "invoices", "obligations", "decisions")
                              for entry in row[key]}
    return material


def execute_operation(request, material, operation_id):
    if material["authority"] != context(request):
        raise HTTPException(409, "Your account, workspace or permissions changed. Review the operation again.")
    if material["action"] == "access" and material["arguments"]["grant"]:
        if material["arguments"]["principal"] not in {entry["value"] for entry in member_choices(request)}:
            raise HTTPException(409, "The selected member no longer has workspace access.")
    return service(request).execute(material, operation_id)


def recover_operation(request, material, operation_id):
    if material["authority"] != context(request):
        raise HTTPException(409, "Return to the original account and workspace to check this result.")
    return service(request).recover(material, operation_id)


def call(operation):
    try:
        return operation()
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(409, "The matter changed. Refresh it and review the operation again.") from exc
    except BudgetExceeded as exc:
        raise HTTPException(409, "This assignment exceeds the current spending or time limits. Review its budget in Settings.") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(422, "Check the required fields, allowed choices and input limits.") from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        log_store_failure(log, exc)
        raise HTTPException(503, "Legal storage is unavailable. Check the original result before retrying.") from exc


def response(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


def public_preview(material):
    args = material["arguments"]
    if material["action"] == "run":
        return {"Worker": args["role"]["title"], "Model": args["model"],
                "Maximum cost (USD)": args["max_dollars"], "Maximum seconds": args["max_seconds"],
                "Evidence sent to the configured AI provider": args["packet"], "Authority": BOUNDARY}
    labels = OPERATIONS[material["action"]][1].model_json_schema()["properties"]
    references = material.get("labels", {})
    public = {}
    for key, value in args.items():
        if key in {"budget", "amount", "max_hourly_rate", "hourly_rate"}:
            value /= 100
        elif key == "role_id":
            value = ROLE_MAP[value]["title"]
        elif isinstance(value, list):
            value = [references.get(entry, entry) for entry in value]
        elif isinstance(value, str):
            value = references.get(value, value)
        public[labels[key].get("title", key)] = value
    return public


@router.get("")
def overview(request: Request):
    return response(call(lambda: {**service(request).overview(), "context": digest(context(request)),
        "actor": context(request)["actor"], "notice": BOUNDARY,
        "operations": {key: {"label": label, "schema": model.model_json_schema()} for key, (label, model) in OPERATIONS.items()},
        "members": member_choices(request)}))


@router.get("/matters/{matter_id}")
def read_matter(request: Request, matter_id: str):
    return response(call(lambda: {"matter": service(request).get(matter_id), "context": digest(context(request))}))


@router.get("/matters/{matter_id}/export")
def export_matter(request: Request, matter_id: str, packet_id: str = ""):
    value = call(lambda: service(request).export(matter_id, packet_id))
    if packet_id:
        lines = [value["title"], "", "For: " + value["recipient"] + " at " + value["firm"],
                 "", "Instructions", value["instructions"], "", value["notice"]]
        for source in value["sources"]:
            lines.extend(["", "=" * 60, source["title"], "Source: " + source["reference"],
                          "Status: " + source["status"], "", source["text"]])
        return Response("\n".join(lines), media_type="text/plain",
                        headers={"Cache-Control": "private, no-store", "Content-Disposition": 'attachment; filename="counsel-packet.txt"',
                                 "X-Content-Type-Options": "nosniff"})
    return Response(json.dumps(value, ensure_ascii=False, indent=2), media_type="application/json",
                    headers={"Cache-Control": "private, no-store", "Content-Disposition": 'attachment; filename="legal-record.json"',
                             "X-Content-Type-Options": "nosniff"})


@router.post("/review")
def review(request: Request, body: ReviewInput):
    from .app import _require_same_origin
    _require_same_origin(request)
    if digest(context(request)) != body.context:
        raise HTTPException(409, "Your account or workspace changed. Reload before reviewing.")
    material = call(lambda: prepare_operation(request, body.action, body.arguments, body.matter_id))
    if material["revision"] != body.expected_revision:
        raise HTTPException(409, "The matter changed. Refresh before reviewing.")
    envelope = {"purpose": PURPOSE, "expires_at": time.time() + TTL, "operation_id": secrets.token_hex(16), "material": material}
    token = crypto_at_rest.seal_to_str(json.dumps(envelope, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "The review could not be secured. Nothing changed.")
    return response({"token": token, "preview": public_preview(material)})


def open_token(token, *, recovery=False):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        envelope = json.loads(crypto_at_rest.unseal_from_str(token))
        if envelope["purpose"] != PURPOSE or envelope["material"]["action"] not in OPERATIONS:
            raise ValueError
        if not recovery and not time.time() < envelope["expires_at"] <= time.time() + TTL:
            raise ValueError
        return envelope
    except Exception as exc:
        raise HTTPException(409, "The review expired or is unavailable. Prepare a fresh review.") from exc


@router.post("/confirm")
def confirm(request: Request, body: TokenInput):
    from .app import _require_same_origin
    _require_same_origin(request)
    if not body.confirmed or not context(request)["human"]:
        raise HTTPException(403, "A person must confirm the reviewed operation.")
    envelope = open_token(body.token)
    return response(call(lambda: {"matter": execute_operation(request, envelope["material"], envelope["operation_id"])}))


@router.post("/original")
def original(request: Request, body: TokenInput):
    from .app import _require_same_origin
    _require_same_origin(request)
    envelope = open_token(body.token, recovery=True)
    return response(call(lambda: {"matter": recover_operation(request, envelope["material"], envelope["operation_id"])}))


def create_page_router(templates):
    pages = APIRouter()

    @pages.get("/legal", include_in_schema=False)
    def legal_page(request: Request):
        auth.require_permission(request, "operate")
        auth.require_suite(request, "legal")
        return templates.TemplateResponse(request, "legal_workspace.html", {"legal_enabled": enabled(), "notice": BOUNDARY})

    @pages.get("/static/lightwork-legal.js", include_in_schema=False)
    def legal_client():
        return FileResponse(Path(__file__).parent / "static" / "lightwork-legal.js",
                            media_type="application/javascript", headers={"Cache-Control": "no-cache"})

    return pages
