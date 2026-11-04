"""Billing page: plan contents and Stripe billing for a workspace.

* ``maverick billing entitlements``: what a workspace's plan includes
  (``maverick.billing.entitlements_for``).
* ``maverick billing stripe-status``: whether Stripe billing is ready and, if
  not, the first thing in the way (``maverick.billing_stripe.status``).
* ``maverick billing stripe-preview``: what a sync would charge, with no call
  to Stripe (``preview_charges``).
* ``maverick billing stripe-sync``: make sure the workspace has its Stripe
  customer and subscription, and send metered usage only when that is turned
  on (``sync_tenant_for_period``). It uses the Stripe credentials the
  installation already has; this page never asks for or shows a key.

Global administrators only (like the invoice maker on the same page). The sync
contacts Stripe, so it needs an explicit confirmation and is recorded in the
activity record before it runs.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(prefix="/api/v1/admin/billing-ops")
asset_router = APIRouter()
_STATIC = Path(__file__).parent / "static"
_FEATURES = {"core": "Everyday tasks", "grpc": "Connections from other systems", "channels": "Chat apps",
             "sso": "Single sign-on", "audit_export": "Activity record export", "self_host": "Run on your own servers"}


@asset_router.get("/static/lightwork-billing-ops.js", include_in_schema=False)
async def billing_ops_script() -> FileResponse:
    return FileResponse(_STATIC / "lightwork-billing-ops.js", media_type="application/javascript; charset=utf-8",
                        headers={"Cache-Control": "public, max-age=300"})


def _admin(request: Request) -> None:
    require_global_permission(request, "admin")


def _words(value: Any) -> str:
    text = " ".join(str(value or "").replace("_", " ").split())
    return text[:1].upper() + text[1:120]


def _workspace(workspace: str) -> Any:
    from maverick.tenant.registry import get_tenant
    record = get_tenant(workspace.strip())
    if record is None:
        raise HTTPException(404, "Choose a workspace from the list.")
    return record


# ---- plan contents (maverick billing entitlements) -----------------------------

def _entitlements(workspace: str) -> dict[str, Any]:
    from maverick.billing import BillingPolicyError, entitlements_for
    record = _workspace(workspace)
    try:
        ent = entitlements_for(record.plan)
    except BillingPolicyError as exc:
        raise HTTPException(409, "The plan settings could not be read, so what the plan includes is unknown. "
                                 "Whoever installed Lightwork needs to repair them.") from exc
    return {
        "workspace": record.display_name or record.id,
        "plan": _words(ent.plan),
        "features": sorted(_FEATURES.get(f, _words(f)) for f in ent.features),
        "daily_limit": f"${ent.max_daily_dollars:g} a day" if ent.max_daily_dollars else "No limit",
        "tasks_at_once": str(ent.max_concurrent_goals) if ent.max_concurrent_goals else "No limit",
    }


@router.get("/plan")
async def plan_contents(request: Request, workspace: str = Query(..., min_length=1, max_length=128)) -> dict:
    _admin(request)
    return await run_in_threadpool(_entitlements, workspace)


# ---- Stripe billing (maverick billing stripe-status / preview / sync) -----------

def _notice_address(request: Request) -> str:
    """Where Stripe sends payment notices: this server's address for others
    (``MAVERICK_PUBLIC_URL`` / ``[dashboard] public_url``), else the address
    this page was opened at."""
    from .automation_queue import _public_base_url

    base = _public_base_url() or str(request.base_url)
    return base.rstrip("/") + "/webhook/stripe"


def _stripe_status(address: str) -> dict[str, Any]:
    from maverick.billing_stripe import status
    st = status()
    if st.enabled and st.sdk_available:
        summary = "Stripe billing is ready."
    elif not st.enable_flag:
        summary = "Stripe billing is turned off. Charges are only worked out here, never sent."
    elif not st.has_secret_key:
        summary = "Stripe billing is turned on, but no Stripe key has been saved for this installation yet."
    else:
        summary = "Stripe billing is turned on, but the Stripe connector isn't installed with this copy of Lightwork."
    return {
        "ready": bool(st.enabled and st.sdk_available), "summary": summary,
        "facts": [
            {"label": "Turned on", "value": "Yes" if st.enable_flag else "No"},
            {"label": "Stripe key saved", "value": "Yes" if st.has_secret_key else "No"},
            {"label": "Payment notices from Stripe accepted", "value": "Yes" if st.has_webhook_secret else "No"},
            {"label": "Address for Stripe payment notices", "value": address},
            {"label": "Stripe connector installed", "value": "Yes" if st.sdk_available else "No"},
            {"label": "AI usage billed", "value": "Yes" if st.bill_metered_usage else "No, plan fee only"},
            {"label": "Plans with a Stripe price", "value": ", ".join(_words(p) for p in st.plans_priced) or "None"},
            {"label": "Currency", "value": str(st.currency).upper()},
        ],
    }


@router.get("/stripe")
async def stripe_status(request: Request) -> dict:
    _admin(request)
    return await run_in_threadpool(_stripe_status, _notice_address(request))


def _card(markup: float, minimum: float):
    from maverick.billing import RateCard
    return RateCard(markup_pct=markup, minimum_charge=minimum)


def _period(since: date | None, until: date | None) -> tuple[str | None, str | None]:
    if since and until and since > until:
        raise HTTPException(422, "The start date must be on or before the end date.")
    return (since.isoformat() if since else None, until.isoformat() if until else None)


def _preview(context: dict, workspace: str, since: date | None, until: date | None, markup: float, minimum: float) -> dict:
    from . import billing_sync_reviews
    record = _workspace(workspace)
    start, end = _period(since, until)
    review = billing_sync_reviews.prepare(context, {"workspace": record.id, "since": start, "until": end,
                                                   "markup": float(markup), "minimum": float(minimum)})
    prev = review["snapshot"]
    currency = str(prev["currency"]).upper()
    lines = [("The plan fee is set up in Stripe." if prev["platform_fee_configured"] else
              f"No Stripe price is set for the {_words(prev['plan'])} plan, so no plan fee would be charged.")]
    if prev["metered_billing_enabled"]:
        lines.append(f"AI usage would be billed: {len(prev['usage_items_that_would_bill'])} item(s), "
                     f"{prev['metered_total']:.2f} {currency}.")
    else:
        lines.append(f"AI usage adds up to {prev['metered_total']:.2f} {currency}, but only the plan fee is billed.")
    if not prev["billing_enabled"]:
        lines.append("Stripe billing is off, so this is only a preview.")
    return {"workspace": record.display_name or record.id, "plan": _words(prev["plan"]),
            "summary": " ".join(lines), "usage_total": round(float(prev["metered_total"]), 2),
            "currency": currency, "can_sync": bool(prev["billing_enabled"]), **review}


@router.get("/stripe/preview")
async def stripe_preview(request: Request, workspace: str = Query(..., min_length=1, max_length=128),
                         since: date | None = Query(None), until: date | None = Query(None),
                         markup: float = Query(0.0, ge=0.0, le=1000.0),
                         minimum: float = Query(0.0, ge=0.0, le=1_000_000.0)) -> dict:
    _admin(request)
    from . import app as app_module
    from . import billing_sync_reviews
    app_module._require_same_origin(request)
    result = await run_in_threadpool(_preview, billing_sync_reviews.scope(request), workspace, since, until, markup, minimum)
    _admin(request)
    return result


class SyncIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workspace: str = Field(min_length=1, max_length=128)
    since: date | None = None
    until: date | None = None
    markup: float = Field(0.0, ge=0.0, le=1000.0)
    minimum: float = Field(0.0, ge=0.0, le=1_000_000.0)
    confirm: bool = Field(default=False, strict=True)
    review_id: str = Field(min_length=48, max_length=48, pattern=r"^[a-f0-9]+$")
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-f0-9]+$")


def _sync(body: SyncIn, request: Request) -> dict[str, Any]:
    from . import billing_sync_reviews
    record = _workspace(body.workspace)
    start, end = _period(body.since, body.until)
    fields = {"workspace": record.id, "since": start, "until": end,
              "markup": float(body.markup), "minimum": float(body.minimum)}
    return billing_sync_reviews.execute(billing_sync_reviews.scope(request), fields, body.review_id, body.sha256,
                                        lambda: _admin(request))


@router.get("/stripe/receipt")
async def stripe_receipt(request: Request, workspace: str = Query(..., min_length=1, max_length=128),
                         offset: int = Query(0, ge=0)) -> dict:
    _admin(request)
    from . import billing_sync_reviews
    await run_in_threadpool(_workspace, workspace)
    result = await run_in_threadpool(billing_sync_reviews.receipt, billing_sync_reviews.scope(request), workspace, offset)
    _admin(request)
    return result


@router.post("/stripe/sync")
async def stripe_sync(body: SyncIn, request: Request) -> dict:
    from . import app as app_module
    app_module._require_same_origin(request)
    _admin(request)
    if body.confirm is not True:
        raise HTTPException(409, "Confirm to send this workspace to Stripe. Nothing was sent.")
    await run_in_threadpool(_workspace, body.workspace)
    from maverick.billing_stripe import StripeError
    from maverick.tenant.registry import UnknownTenant
    try:
        result = await run_in_threadpool(_sync, body, request)
        _admin(request)
        return result
    except UnknownTenant as exc:
        raise HTTPException(404, "Choose a workspace from the list.") from exc
    except StripeError as exc:
        raise HTTPException(409, "Stripe billing could not finish. Read the retained stage receipt before retrying; earlier stages may have changed Stripe.") from exc
