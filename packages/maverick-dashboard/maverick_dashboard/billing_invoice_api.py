"""Make a workspace invoice from the Billing page (``maverick billing invoice``).

An administrator picks a workspace and a date range, optionally a markup and a
minimum charge; the kernel's ``billing.generate_invoice`` rates that
workspace's recorded usage. The result comes back as a readable summary, or as
a spreadsheet file. Read-only: nothing is charged or stored. Global admin only.
"""
from __future__ import annotations

import csv
import io
from datetime import date

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from maverick import practice_costs
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission

router = APIRouter(prefix="/api/v1/admin/billing")


def _invoice(tenant: str, since: date | None, until: date | None, markup: float, minimum: float):
    from maverick.billing import RateCard, generate_invoice
    from maverick.tenant.registry import get_tenant, list_tenants
    tenant = tenant.strip()
    if list_tenants() and get_tenant(tenant) is None:
        raise HTTPException(404, "Choose a workspace from the list.")
    if since and until and since > until:
        raise HTTPException(422, "The start date must be on or before the end date.")
    return generate_invoice(
        tenant or None, RateCard(markup_pct=markup, minimum_charge=minimum),
        since=since.isoformat() if since else None, until=until.isoformat() if until else None)


def _who(principal: str) -> str:
    from .identity_format import humanize_principal
    ident = humanize_principal(principal)
    return ident.name + (f" ({ident.detail})" if ident.detail and ident.detail != "Email" else "")


def _display_amounts(inv):
    """Use the same deterministic currency allocation as actual collection."""
    from decimal import Decimal

    from maverick.billing_stripe import _ZERO_DECIMAL, _rated_usage_items
    currency = inv.currency.lower()
    factor = 1 if currency in _ZERO_DECIMAL and currency != "ugx" else 100
    places = 0 if currency in _ZERO_DECIMAL or currency == "isk" else 2
    rows = _rated_usage_items(inv, currency)
    amounts = [Decimal(row["amount_minor"]) / factor for row in rows]
    return rows, amounts, sum(amounts, Decimal(0)), places


@router.get("/invoice")
async def invoice_summary(request: Request, tenant: str = Query(..., min_length=1, max_length=128),
                          since: date | None = Query(None), until: date | None = Query(None),
                          markup: float = Query(0.0, ge=0.0, le=1000.0),
                          minimum: float = Query(0.0, ge=0.0, le=1_000_000.0)) -> JSONResponse:
    require_global_permission(request, "admin")
    inv = await run_in_threadpool(_invoice, tenant, since, until, markup, minimum)
    rows, amounts, total, places = _display_amounts(inv)
    return JSONResponse({
        "period_start": inv.period_start or "", "period_end": inv.period_end or "",
        "total": float(total), "subtotal": inv.subtotal, "currency": inv.currency,
        "total_display": f"{total:.{places}f}",
        "rounding": "Line amounts use the same largest-remainder currency allocation as collection; underlying rated contents are unchanged.",
        "lines": [{"day": row["day"], "person": _who(row["principal"]), "charge": float(amount),
                   "charge_display": f"{amount:.{places}f}", "kind": row["kind"],
                   "usage": row["in_tokens"] + row["out_tokens"]} for row, amount in zip(rows, amounts, strict=True)],
        "closed_period": bool(inv.invoice_id),
        "practice": await run_in_threadpool(_practice_line, tenant, since, until),
    }, headers={"Cache-Control": "private, no-store"})


def _practice_line(tenant: str, since: date | None, until: date | None) -> dict | None:
    """Practice runs in this workspace and period (only for the active workspace,
    whose practice record this server can read)."""
    from datetime import datetime, timedelta, timezone

    from maverick.paths import current_tenant

    if tenant.strip() != (current_tenant() or "default"):
        return None
    start = datetime.combine(since, datetime.min.time(), timezone.utc).timestamp() if since else None
    end = (datetime.combine(until, datetime.min.time(), timezone.utc) + timedelta(days=1)).timestamp() if until else None
    return practice_costs.summary(None, since=start, until=end)


@router.get("/invoice.csv")
async def invoice_csv(request: Request, tenant: str = Query(..., min_length=1, max_length=128),
                      since: date | None = Query(None), until: date | None = Query(None),
                      markup: float = Query(0.0, ge=0.0, le=1000.0),
                      minimum: float = Query(0.0, ge=0.0, le=1_000_000.0)) -> Response:
    require_global_permission(request, "admin")
    inv = await run_in_threadpool(_invoice, tenant, since, until, markup, minimum)
    rows, amounts, total, places = _display_amounts(inv)
    from .audit_actions_api import csv_safe

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Day", "Person", "Charge (" + inv.currency + ")", "AI usage (tokens)"])
    for row, amount in zip(rows, amounts, strict=True):
        writer.writerow([row["day"], csv_safe(_who(row["principal"])), f"{amount:.{places}f}", row["in_tokens"] + row["out_tokens"]])
    writer.writerow([])
    writer.writerow(["Total", "", f"{total:.{places}f}", ""])
    writer.writerow(["Rounding", "Currency-aware allocation reconciles the visible lines to this total; original rated contents are unchanged.", "", ""])
    practice = await run_in_threadpool(_practice_line, tenant, since, until)
    if practice:  # real provider cost of practice runs: shown, never charged on this invoice
        writer.writerow(["Practice", f"Practice runs ({practice_costs.NOT_COUNTED}; not charged on this invoice)",
                         f"{practice['dollars']:.2f}", practice["input_tokens"] + practice["output_tokens"]])
    if inv.invoice_id:
        writer.writerow(["Invoice number", inv.invoice_id, "", ""])
    safe = "".join(ch for ch in tenant if ch.isalnum() or ch in "-_")[:64] or "workspace"
    span = "-".join(p for p in (since.isoformat() if since else "", until.isoformat() if until else "") if p)
    return Response(out.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="Lightwork-invoice-{safe}{("-" + span) if span else ""}.csv"',
                             "Cache-Control": "private, no-store"})
