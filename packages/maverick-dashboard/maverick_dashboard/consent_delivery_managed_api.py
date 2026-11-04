"""Protected signing keys and one explicit future-only delivery subscription."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import consent_delivery_api as existing
from .api_flow_operator_review import _workspace_authority
from .draft_api import context_for

router = APIRouter(prefix="/consent/delivery/managed", tags=["consent-delivery"])
REFERENCE = "future-delivery"
PURPOSE = "lightwork.consent-delivery-setup.v1"


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: Literal["key", "subscription"]
    label: str = Field(min_length=1, max_length=100)
    secret: str = Field(default="", max_length=200)
    destination_ids: list[str] = Field(default_factory=list, max_length=64)
    active: bool = True


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=262144)


def authority(request, *, admin=False, historical=False):
    with auth.fresh_configuration():
        principal = getattr(request.state, "principal", None)
        refresh = {"session": auth._session_principal, "invite": auth._invite_session_principal,
                   "proxy": auth._proxy_principal}.get((getattr(principal, "claims", None) or {}).get("via"))
        if refresh is not None:
            fresh = refresh(request)
            if fresh is None or fresh.principal != principal.principal:
                raise HTTPException(401, "Sign in again before continuing delivery setup.")
            request.state.principal = principal = fresh
        if principal is not None:
            auth._enforce_scim_active(principal)
            auth._enforce_workspace_policies(request, principal)
        permission = "admin" if admin else "audit"
        auth.require_global_permission(request, permission)
        auth.require_permission(request, permission)
        auth.require_page_permission(request, "/consent/delivery")
        if not historical:
            existing._ops()
        tenant = existing._tenant_id()
        actor = auth.caller_principal(request) or "local:dashboard"
        _workspace_authority(request, actor, tenant)
        return tenant, actor, context_for(request)


def _store(tenant, *, historical=False):
    if historical:
        from maverick.consent_delivery import ConsentDeliveryStore
        from maverick.paths import data_dir
        return ConsentDeliveryStore(data_dir("consent_preferences", "consent-delivery.sqlite3", tenant=tenant), config_gate=lambda: True)
    return existing._delivery_store(existing._ops(), tenant)


def worker_enabled():
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current delivery settings could not be read.")
    worker = config.load_config().get("consent_preferences", {}).get("delivery", {}).get("worker", {})
    if not isinstance(worker, dict) or set(worker)-{"enable"} or not isinstance(worker.get("enable", False), bool):
        raise HTTPException(503, "Automatic delivery settings could not be verified.")
    return worker.get("enable", False)


def _pins(store, tenant, identifiers):
    if not identifiers or len(set(identifiers)) != len(identifiers):
        raise HTTPException(422, "Choose one to 64 different destinations.")
    pins = []
    for identifier in sorted(identifiers):
        row = store.destination(tenant, identifier)
        if row["status"] != "active" or not row["active_key_id"]:
            raise HTTPException(409, "A selected destination is stopped or has no active signing key.")
        key = store.managed_record(tenant, "key", row["active_key_id"])
        if key is None:
            raise HTTPException(409, "Save this destination’s shared signing secret in Lightwork before enabling automatic delivery.")
        pins.append({"destination_id": identifier, "revision": row["revision"],
                     "key_id": row["active_key_id"], "key_revision": key["revision"], "origin": row["origin"]})
    return pins


def state(request):
    tenant, actor, context = authority(request)
    store = _store(tenant)
    subscription = store.managed_record(tenant, "subscription", REFERENCE)
    keys = store.managed_keys(tenant)
    from . import consent_delivery_scheduler as scheduler
    holding = ""
    if subscription is not None and subscription["material"]["active"]:
        try:
            scheduler.subscription_authority(store, tenant, subscription)
        except Exception:
            holding = "Automatic delivery is held. Review the current destination editions and the owner’s access before starting again."
    enabled = worker_enabled()
    if authority(request) != (tenant, actor, context):
        raise HTTPException(409, "Your workspace or access changed. Refresh delivery setup.")
    material = None if subscription is None else subscription["material"]
    return {"context": context, "keys": keys,
            "subscription": None if material is None else {"label": material["label"], "active": material["active"],
                "revision": subscription["revision"], "destinations": material["destinations"], "starts_after": material["started_at"]},
            "holding": holding, "worker": {**scheduler.status(tenant), "enabled": enabled},
            "setup_requires_sign_in": actor == "local:dashboard"}


def _private(value):
    return JSONResponse(value, headers={"Cache-Control": "private, no-store"})


@router.get("")
def read_setup(request: Request):
    return _private(state(request))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    from .app import _require_same_origin
    _require_same_origin(request)
    tenant, actor, context = authority(request, admin=True)
    label = body.label.strip()
    if not label or re.search(r"[\x00-\x1f\x7f]", label):
        raise HTTPException(422, "Give this setup an ordinary name.")
    store = _store(tenant)
    if body.kind == "key":
        if body.destination_ids or not body.active or not 32 <= len(body.secret.encode("utf-8")) <=64 or re.search(r"[\x00-\x1f\x7f]",body.secret):
            raise HTTPException(422, "Enter the exact shared secret: 32 to 64 bytes, with no line breaks.")
        reference, previous = "managed-key-"+secrets.token_hex(12), 0
        material = {"label": label, "secret": body.secret}
        summary = "Save shared signing secret: "+label+". It is encrypted, never returned, and must match the receiving system. This does not send an update."
    else:
        if actor == "local:dashboard" or body.secret:
            raise HTTPException(409, "Sign in with an administrator account before authorizing ongoing delivery.")
        reference = REFERENCE
        old = store.managed_record(tenant, "subscription", reference)
        previous = 0 if old is None else old["revision"]
        if not body.active and old is None:
            raise HTTPException(409, "There is no automatic subscription to pause.")
        pins = _pins(store, tenant, body.destination_ids) if body.active else old["material"]["destinations"]
        preferences = existing._preference_store(tenant)
        material = {"label": label, "owner": actor, "active": body.active, "destinations": pins,
                    "workspace_authority": getattr(request.state, "workspace_tenant_source", "") or "operator_floor",
                    "watermark": preferences.outbox_watermark(tenant) if body.active else old["material"]["watermark"],
                    "started_at": time.time() if body.active else old["material"]["started_at"]}
        summary = ("Start automatic future delivery: " if body.active else "Pause automatic delivery: ")+label+"\n\n"+"\n".join(
            item["destination_id"]+": "+item["origin"]+"\nSigning key: "+store.managed_record(tenant,"key",item["key_id"])["material"]["label"]+
            " (destination edition "+str(item["revision"])+")" for item in pins)
        if old is not None:
            summary += "\n\nThis replaces the previous automatic subscription; it does not add a second one."
        summary += "\n\nOnly consent choices recorded after this review are included. Earlier queued updates for these destinations may still finish. Changed destinations or keys are held for a new review. Unconfirmed sends are held without automatic replay."
        if not worker_enabled():
            summary += "\n\nThe automatic worker is turned off in Settings. Saving this subscription does not turn it on."
    value = {"purpose": PURPOSE, "tenant": tenant, "actor": actor, "context": context,
             "expires_at": time.time()+900, "operation": secrets.token_hex(16),
             "request": {"kind": body.kind, "reference": reference, "material": material, "expected_revision": previous}}
    token = crypto_at_rest.seal_to_str(json.dumps(value, sort_keys=True, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "The review could not be protected. Nothing was saved.")
    if authority(request, admin=True) != (tenant, actor, context):
        raise HTTPException(409, "Your workspace or access changed during review.")
    return _private({"token": token, "context": context, "summary": summary, "expires_at": value["expires_at"]})


def _open(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if set(value) != {"purpose","tenant","actor","context","expires_at","operation","request"} or value["purpose"] != PURPOSE:
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, crypto_at_rest.EncryptionUnavailable) as exc:
        raise HTTPException(422, "This original setup review could not be read.") from exc


def _current(request, value, *, historical=False, store=None):
    if authority(request, admin=True, historical=historical) != (value["tenant"], value["actor"], value["context"]):
        raise HTTPException(409, "Your account or workspace changed. Read setup again.")
    if historical:
        return
    if time.time() >= value["expires_at"]:
        raise HTTPException(409, "The review expired. Read its original before preparing another review.")
    source = value["request"]
    material = source["material"]
    if store is not None and source["kind"] == "subscription" and material["active"]:
        if _pins(store, value["tenant"], [item["destination_id"] for item in material["destinations"]]) != material["destinations"]:
            raise HTTPException(409, "A destination or key changed after review. Nothing new was authorized.")


@router.post("/save")
def save(request: Request, body: TokenIn):
    from .app import _require_same_origin
    _require_same_origin(request)
    value = _open(body.token)
    with authority_effect_fence():
        _current(request, value)
        store = _store(value["tenant"])
        source = value["request"]
        try:
            result = store.managed_save(value["tenant"], source["kind"], source["reference"], source["material"],
                expected_revision=source["expected_revision"], idempotency_key=value["operation"],
                before_effect=lambda: _current(request, value, store=store))
        except existing._ops().ConsentDeliveryConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        return _private(result)


@router.post("/original")
def original(request: Request, body: TokenIn):
    from .app import _require_same_origin
    _require_same_origin(request)
    value = _open(body.token)
    _current(request, value, historical=True)
    result = _store(value["tenant"], historical=True).managed_original(value["tenant"], value["request"], value["operation"])
    _current(request, value, historical=True)
    return _private({"confirmed": result is not None, "result": result,
                     "new_review_available": result is None and time.time() >= value["expires_at"],
                     "message": "This exact setup was saved. Read current status before relying on it." if result else "No original confirms this save. Do not send Save again blindly."})
