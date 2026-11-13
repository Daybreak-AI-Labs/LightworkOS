"""Webhook subscriptions, the delivery log and deadline alerts over the dashboard.

* ``GET/POST /api/v1/webhooks/subscriptions`` and
  ``GET/PATCH /api/v1/webhooks/subscriptions/{id}`` -- saved subscriptions
  (address, event filter, signing secret, on/off, description). Global
  ``admin``, like the signing-secret panel. The secret is never returned.
* ``POST /api/v1/webhooks/subscriptions/{id}/test`` -- send a ``webhook.test``
  event now and return the delivery row.
* ``GET /api/v1/webhooks/deliveries`` and
  ``POST /api/v1/webhooks/deliveries/{id}/retry`` -- the delivery log
  (attempts, status, latency, response snippet, next retry) and "Retry now".
* ``GET /api/v1/webhooks/events`` -- the event catalogue for the page.
* ``GET /api/v1/deadline-alerts`` (``operate``) -- alerts sent about one
  record (``record_type`` + ``record_id``) or the latest across the
  workspace; ``POST /api/v1/deadline-alerts/run`` (global ``admin``) runs
  one evaluation cycle now.
* ``GET /settings/webhooks/manage`` -- the Settings > Webhooks page.

Every change is written to the activity log by the kernel store before it
happens; a refused audit write changes nothing.
"""
from __future__ import annotations

import json
import math
import re
import secrets
import time
from decimal import Decimal
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from ._shared import _world
from .auth import (
    caller_principal,
    has_global_permission,
    require_global_permission,
    require_permission,
)
from .draft_api import context_for

router = APIRouter(tags=["webhooks"])
PAGE_PATH = "/settings/webhooks/manage"
RECOVERY_PURPOSE = "lightwork.webhook-new-attempt.v1"
RECOVERY_TTL = 600


def _actor(request: Request) -> str:
    return caller_principal(request) or "local administrator"


def _refused(exc: Exception) -> HTTPException:
    from maverick.audit import AuditRefused
    from maverick.webhook_subscriptions import (
        DeliveryConflict,
        DeliveryUnconfirmed,
        SubscriptionError,
    )

    if isinstance(exc, DeliveryConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, DeliveryUnconfirmed):
        return HTTPException(status_code=503, detail=str(exc))
    if isinstance(exc, SubscriptionError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, AuditRefused):
        return HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was changed."))
    return HTTPException(status_code=500, detail="The webhook store is unavailable.")


class SubscriptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2048)
    events: list[str] | str = "*"
    secret: str = Field(default="", max_length=4096)
    description: str = Field(default="", max_length=500)
    enabled: bool = True


class SubscriptionPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    events: list[str] | str | None = None
    secret: str | None = Field(default=None, max_length=4096)
    description: str | None = Field(default=None, max_length=500)
    enabled: bool | None = None


class DeliveryRecoveryIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    token: str = Field(default="", max_length=8192)
    confirmed: bool = False


def _recovery_authority(request: Request, expected: str | None = None) -> tuple[str, str, str]:
    from maverick.governed_operations import digest
    from maverick.paths import current_tenant_id_strict

    from .api_flow_operator_review import _workspace_authority

    with auth.fresh_configuration():
        require_global_permission(request, "admin")
        principal = getattr(request.state, "principal", None)
        if principal is not None:
            claims = principal.claims or {}
            via = claims.get("via")
            # An API key is re-verified too: a key revoked during the review
            # must not carry it through, as in the other governed flows.
            fresh = (auth._session_principal(request) if via == "session" else
                     auth._invite_session_principal(request) if via == "invite" else
                     auth._proxy_principal(request) if via == "proxy" else
                     auth._authenticate_api_key(request, auth._api_key_bearer(request)) if via == "api_key"
                     else principal)
            expiry = claims.get("exp")
            if (fresh is None or fresh.principal != principal.principal or
                    (expiry is not None and (type(expiry) not in (int, float) or
                                            not time.time() < expiry < math.inf))):
                raise HTTPException(401, "Sign in again before reviewing this delivery.")
            auth._enforce_scim_active(fresh)
            auth._enforce_workspace_policies(request, fresh)
        current = context_for(request)
        if expected is not None and current != expected:
            raise HTTPException(409, "Your account or workspace changed. Reload Webhooks before continuing.")
        actor, tenant = _actor(request), current_tenant_id_strict() or ""
        scopes = auth.api_key_scopes(request)
        suites = auth.caller_suites(request)
        access = digest([_workspace_authority(request, actor, tenant), auth.caller_role(request),
                         sorted(scopes) if scopes is not None else None,
                         sorted(suites) if suites is not None else None])
        return current, actor, access


def _recovery_token(value: dict) -> str:
    from maverick.crypto_at_rest import deployment_key_scope, seal_to_str

    with deployment_key_scope():
        return seal_to_str(json.dumps(value, separators=(",", ":"), allow_nan=False))


def _recovery_open(token: str) -> dict:
    from maverick.crypto_at_rest import deployment_key_scope, is_sealed_str, unseal_from_str

    try:
        if not is_sealed_str(token):
            raise ValueError("invalid protected review")
        with deployment_key_scope():
            value = json.loads(unseal_from_str(token))
        if (set(value) != {"purpose", "operation", "actor", "workspace", "context", "access", "expires",
                          "original", "before", "source", "review"} or value["purpose"] != RECOVERY_PURPOSE
                or not re.fullmatch(r"[a-f0-9]{32}", value["operation"])
                or any(not re.fullmatch(r"[a-f0-9]{64}", value[key]) for key in ("context", "access", "before", "source", "review"))
                or not isinstance(value["actor"], str) or not 0 < len(value["actor"]) <= 512
                or not isinstance(value["workspace"], str) or len(value["workspace"]) > 128
                or not isinstance(value["original"], str) or not 0 < len(value["original"]) <= 64
                or type(value["expires"]) not in (int, float) or not math.isfinite(value["expires"])):
            raise ValueError("invalid protected review")
        return value
    except Exception as exc:
        raise HTTPException(409, "This protected review could not be verified. Nothing was repeated.") from exc


def _body_review(text: str) -> list[dict]:
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate name")
            value[key] = item
        return value

    if len(text.encode("utf-8")) > 262144:
        raise HTTPException(422, "This complete message is too large to review here. Nothing was sent. Check the receiving system and keep the original record.")
    try:
        body = json.loads(text, object_pairs_hook=pairs, parse_int=Decimal, parse_float=Decimal,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid number")))
    except (ValueError, RecursionError) as exc:
        raise HTTPException(422, "This message cannot be completely shown as named values. Nothing was sent; check the receiving system and keep the original record.") from exc
    rows, pending = [], [(["Message"], body)]
    while pending:
        path, value = pending.pop()
        if len(rows) >= 2048 or len(path) > 16:
            raise HTTPException(422, "This complete message has too many nested values to review here. Nothing was sent; check the receiving system and keep the original record.")
        if isinstance(value, (dict, list)):
            label = f"{len(value)} named values" if isinstance(value, dict) else f"{len(value)} items"
            children = list(value.items()) if isinstance(value, dict) else [(f"Item {index + 1}", item) for index, item in enumerate(value)]
            pending.extend(([*path, key], item) for key, item in reversed(children))
        else:
            label = "No value" if value is None else "Yes" if value is True else "No" if value is False else str(value)
        rows.append({"name": path, "value": label})
    if len(json.dumps(rows).encode("utf-8")) > 524288:
        raise HTTPException(422, "This complete message review is too large. Nothing was sent; check the receiving system and keep the original record.")
    return rows


def _recovery_owned(request: Request, body: DeliveryRecoveryIn, delivery_id: str) -> dict:
    from maverick.paths import current_tenant_id_strict

    context, actor, _access = _recovery_authority(request, body.context)
    value = _recovery_open(body.token)
    if (value["context"] != context or value["actor"] != actor or value["original"] != delivery_id
            or value["workspace"] != (current_tenant_id_strict() or "")):
        raise HTTPException(404, "This original request belongs to another account or workspace.")
    return value


def _recovery_result(request: Request, value: dict, expected: str) -> dict:
    from maverick import webhook_subscriptions as subs

    _recovery_authority(request, expected)
    row = subs.recovery_original(value, world=_world())
    if row is not None:
        row.pop("body", None)
    _recovery_authority(request, expected)
    return {"context": expected, "operation": value["operation"], "admitted": row is not None, "delivery": row,
            "message": ("Your separately reviewed new attempt is retained. Nothing was repeated by reading it. "
                        "Destination acceptance and later actions are separate outcomes." if row is not None else
                        "This original new attempt is unconfirmed. Nothing was repeated. Check the receiving system before a separately reviewed decision.")}


@router.get("/api/v1/webhooks/events")
async def webhook_events(request: Request) -> dict[str, Any]:
    require_permission(request, "view")
    from maverick.webhook_events import catalog

    return {"events": catalog()}


@router.get("/api/v1/webhooks/subscriptions")
async def list_subscriptions(request: Request) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    try:
        rows = await run_in_threadpool(lambda: subs.list_subscriptions(world=_world()))
    except Exception as exc:
        raise _refused(exc) from exc
    from maverick.webhooks import _load_config_outbound

    urls, secret = _load_config_outbound()
    return {"subscriptions": rows,
            "legacy": {"urls": urls, "signed": bool(secret),
                       "subscription_id": subs.LEGACY_SUBSCRIPTION_ID},
            "retry_schedule_seconds": list(subs.RETRY_DELAYS),
            "max_attempts": subs.MAX_ATTEMPTS}


@router.post("/api/v1/webhooks/subscriptions", status_code=201)
async def create_subscription(request: Request, body: SubscriptionIn) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    try:
        return await run_in_threadpool(lambda: subs.create_subscription(
            body.url, events=body.events, secret=body.secret, description=body.description,
            enabled=body.enabled, actor=_actor(request), world=_world()))
    except Exception as exc:
        raise _refused(exc) from exc


@router.get("/api/v1/webhooks/subscriptions/{sub_id}")
async def get_subscription(request: Request, sub_id: str) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    row = await run_in_threadpool(lambda: subs.get_subscription(sub_id, world=_world()))
    if row is None:
        raise HTTPException(status_code=404, detail="That subscription could not be found.")
    return row


@router.patch("/api/v1/webhooks/subscriptions/{sub_id}")
async def update_subscription(request: Request, sub_id: str, body: SubscriptionPatch) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    try:
        row = await run_in_threadpool(lambda: subs.update_subscription(
            sub_id, url=body.url, events=body.events, secret=body.secret,
            description=body.description, enabled=body.enabled,
            actor=_actor(request), world=_world()))
    except Exception as exc:
        raise _refused(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="That subscription could not be found.")
    return row


@router.post("/api/v1/webhooks/subscriptions/{sub_id}/test")
async def test_subscription(request: Request, sub_id: str) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    try:
        row = await run_in_threadpool(lambda: subs.send_test_event(
            sub_id, actor=_actor(request), world=_world()))
    except Exception as exc:
        raise _refused(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="That subscription could not be found.")
    return {"delivery": row}


@router.get("/api/v1/webhooks/deliveries")
async def list_deliveries(
    request: Request,
    subscription_id: str | None = Query(default=None, max_length=64),
    status: str | None = Query(default=None, max_length=16),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    if status is not None and status not in subs.STATUSES:
        raise HTTPException(status_code=400, detail="Choose a current delivery status.")
    rows = await run_in_threadpool(lambda: subs.list_deliveries(
        world=_world(), subscription_id=subscription_id, status=status, limit=limit))
    for row in rows:
        row.pop("body", None)  # the page shows the event, not the whole payload
    return {"deliveries": rows}


@router.get("/api/v1/webhooks/deliveries/{delivery_id}")
async def get_delivery(request: Request, delivery_id: str) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    row = await run_in_threadpool(lambda: subs.get_delivery(delivery_id, world=_world()))
    if row is None:
        raise HTTPException(status_code=404, detail="That delivery could not be found.")
    return row


@router.post("/api/v1/webhooks/deliveries/{delivery_id}/retry")
async def retry_delivery(request: Request, delivery_id: str) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick import webhook_subscriptions as subs

    try:
        row = await run_in_threadpool(lambda: subs.retry_now(
            delivery_id, actor=_actor(request), world=_world()))
    except Exception as exc:
        raise _refused(exc) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="That delivery could not be found.")
    return {"delivery": row}


@router.post("/api/v1/webhooks/deliveries/{delivery_id}/recovery-review")
async def recovery_review(request: Request, response: Response, delivery_id: str, body: DeliveryRecoveryIn) -> dict:
    response.headers["Cache-Control"] = "no-store"
    from maverick import webhook_subscriptions as subs
    from maverick.governed_operations import digest
    from maverick.webhook_events import catalog

    def review():
        context, actor, access = _recovery_authority(request, body.context)
        row, source, signed = subs.recovery_material(delivery_id, world=_world())
        fields = _body_review(row["body"])
        names = {item["type"]: item["description"] for item in catalog()}
        details = {"Destination": row["url"], "Update": names.get(row["event_type"], "Previously recorded update"),
                   "Original attempt": "May still be running" if row["status"] == "sending" else "Acceptance unconfirmed",
                   "Original attempted at": row["updated_at"], "Attempts already recorded": row["attempts"],
                   "Signing key": "Current saved key will be used" if signed else "No signing key; the message will be unsigned",
                   "Message contents": fields}
        value = {"purpose": RECOVERY_PURPOSE, "operation": secrets.token_hex(16), "actor": actor,
                 "workspace": subs.workspace_id(), "context": context, "access": access,
                 "expires": time.time() + RECOVERY_TTL, "original": delivery_id,
                 "before": digest(row), "source": source, "review": digest(details)}
        _recovery_authority(request, context)
        return {"context": context, "token": _recovery_token(value), "operation": value["operation"],
                "expires": value["expires"], "review": details,
                "warning": "The earlier attempt may still be running or may already have been accepted. "
                           "Check the receiving system first. This is a separate new send and may repeat outside actions. "
                           "Known unsuccessful replies follow the normal retry schedule; an unconfirmed send is not repeated automatically."}

    try:
        return await run_in_threadpool(review)
    except HTTPException:
        raise
    except Exception as exc:
        raise _refused(exc) from exc


@router.post("/api/v1/webhooks/deliveries/{delivery_id}/recovery-apply")
async def recovery_apply(request: Request, response: Response, delivery_id: str, body: DeliveryRecoveryIn) -> dict:
    response.headers["Cache-Control"] = "no-store"
    from maverick import webhook_subscriptions as subs
    from maverick.authority_effects import authority_effect_fence

    value = _recovery_owned(request, body, delivery_id)
    if body.confirmed is not True:
        raise HTTPException(422, "Review the complete message and separately confirm the new attempt. Nothing was sent.")

    def guard():
        context, actor, access = _recovery_authority(request, body.context)
        if (context != value["context"] or actor != value["actor"] or access != value["access"]):
            raise HTTPException(409, "Current access changed. Review this delivery again before a new attempt.")
        if time.time() >= value["expires"]:
            raise HTTPException(409, "This review expired. Nothing was sent by this decision; review the current original again.")

    def apply():
        with authority_effect_fence():
            subs.recover_delivery(value, guard=guard, world=_world())
            return _recovery_result(request, value, body.context)

    try:
        return await run_in_threadpool(apply)
    except HTTPException:
        raise
    except Exception as exc:
        raise _refused(exc) from exc


@router.post("/api/v1/webhooks/deliveries/{delivery_id}/recovery-original")
async def recovery_original(request: Request, response: Response, delivery_id: str, body: DeliveryRecoveryIn) -> dict:
    response.headers["Cache-Control"] = "no-store"
    from maverick import webhook_subscriptions as subs

    def read():
        if body.token:
            value = _recovery_owned(request, body, delivery_id)
        else:
            context, actor, _access = _recovery_authority(request, body.context)
            row = subs.get_delivery(delivery_id, world=_world())
            decision = subs._recovery_decision(row) if row is not None else None
            if (decision is None or decision["actor"] != actor or decision["context"] != context
                    or decision["workspace"] != subs.workspace_id()):
                raise HTTPException(404, "This original new attempt is unavailable to your current account.")
            value = {key: item for key, item in decision.items() if key != "state"}
        return _recovery_result(request, value, body.context)

    try:
        return await run_in_threadpool(read)
    except HTTPException:
        raise
    except Exception as exc:
        raise _refused(exc) from exc


# ---- deadline alerts -------------------------------------------------------

@router.get("/api/v1/deadline-alerts")
async def deadline_alerts(
    request: Request,
    record_type: str | None = Query(default=None, max_length=64),
    record_id: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    require_permission(request, "operate")
    from maverick import deadline_alerts as alerts

    if bool(record_type) != bool(record_id):
        raise HTTPException(status_code=400, detail="record_type and record_id go together")
    if record_type:
        rows = await run_in_threadpool(lambda: alerts.alerts_for(
            record_type, record_id, world=_world(), limit=limit))
    else:
        rows = await run_in_threadpool(lambda: alerts.recent_alerts(world=_world(), limit=limit))
    from .deadline_alerts_scheduler import last_cycle

    return {"alerts": rows, "settings": alerts.settings(), "last_cycle": last_cycle()}


@router.post("/api/v1/deadline-alerts/run")
async def run_deadline_alerts(request: Request) -> dict[str, Any]:
    require_global_permission(request, "admin")
    from maverick.audit import AuditRefused, audit_event

    from .deadline_alerts_scheduler import run_once

    try:
        audit_event("control_plane_action", agent="dashboard", action="deadline_alerts_run_now",
                    actor=_actor(request))
    except AuditRefused as exc:
        raise HTTPException(status_code=503, detail=(
            "This could not be added to the activity log, so nothing was run.")) from exc
    summary = await run_in_threadpool(run_once)
    return summary


def record_alerts(record_type: str, record_id: str) -> list[dict]:
    """The "Alerts" section of a record page; empty (never an error) when the
    ledger is unavailable."""
    from maverick import deadline_alerts as alerts

    try:
        return alerts.alerts_for(record_type, record_id, world=_world())
    except Exception:
        return []


def create_webhooks_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("webhooks page requires a Jinja template authority")
    page = APIRouter(tags=["webhooks"])

    @page.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def webhooks_page(request: Request) -> HTMLResponse:
        require_global_permission(request, "admin")
        from maverick.webhook_events import catalog

        return templates.TemplateResponse(request, "settings_webhooks.html", {
            "events": catalog(),
            "can_admin": has_global_permission(request, "admin"),
            "webhook_recovery_context": _recovery_authority(request)[0],
        })

    return page


__all__ = ["PAGE_PATH", "create_webhooks_page_router", "record_alerts", "router"]
