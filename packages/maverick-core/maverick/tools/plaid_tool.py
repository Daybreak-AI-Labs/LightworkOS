"""Plaid tool — banking accounts + transactions (read-only).

Plaid auth is unusual: a server-side ``CLIENT_ID`` + ``SECRET`` plus a
per-user ``access_token`` (obtained by the user's bank-link flow,
not by this tool). All read ops require the user to pass
``access_token``.

Auth:
  - ``PLAID_CLIENT_ID``
  - ``PLAID_SECRET``
  - ``PLAID_ENV`` = sandbox | development | production (default sandbox)

ops:
  - accounts(access_token)
  - balance(access_token)
  - transactions(access_token, start_date, end_date, count)
  - identity(access_token)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool

log = logging.getLogger(__name__)


_PL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["accounts", "balance", "transactions", "identity"]},
        "access_token": {"type": "string"},
        "start_date": {"type": "string"},
        "end_date": {"type": "string"},
        "count": {"type": "integer"},
    },
    "required": ["op", "access_token"],
}


def _base() -> str:
    env = (os.environ.get("PLAID_ENV") or "sandbox").strip()
    return {
        "sandbox":     "https://sandbox.plaid.com",
        "development": "https://development.plaid.com",
        "production":  "https://production.plaid.com",
    }.get(env, "https://sandbox.plaid.com")


def _config() -> tuple[str, str]:
    cid = os.environ.get("PLAID_CLIENT_ID", "").strip()
    sec = os.environ.get("PLAID_SECRET", "").strip()
    if not cid or not sec:
        raise RuntimeError("Plaid requires PLAID_CLIENT_ID + PLAID_SECRET.")
    return cid, sec


def _post(path: str, body: dict) -> tuple[int, Any]:
    import httpx
    cid, sec = _config()
    body = {"client_id": cid, "secret": sec, **body}
    r = _governed_sender(httpx.post)(f"{_base()}{path}", json=body, timeout=30.0)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _money(v, ccy) -> str:
    try:
        return f"{float(v):,.2f} {ccy or ''}"
    except (TypeError, ValueError):
        return "?"


def _op_accounts(args: dict) -> str:
    code, data = _post("/accounts/get", {"access_token": args["access_token"]})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: accounts ({code}): {data}"
    rows = data.get("accounts") or []
    if not rows:
        return "no accounts"
    return "\n".join(
        f"  {a.get('account_id', '?')[:10]}  {(a.get('name') or '?')[:30]:<30}  "
        f"{a.get('type', '?')}/{a.get('subtype', '?')}  "
        f"{_money((a.get('balances') or {}).get('current'), (a.get('balances') or {}).get('iso_currency_code'))}"
        for a in rows
    )


def _op_balance(args: dict) -> str:
    code, data = _post("/accounts/balance/get", {"access_token": args["access_token"]})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: balance ({code}): {data}"
    rows = data.get("accounts") or []
    if not rows:
        return "no accounts"
    out = []
    for a in rows:
        b = a.get("balances") or {}
        out.append(
            f"  {(a.get('name') or '?')[:30]:<30}  "
            f"current={_money(b.get('current'), b.get('iso_currency_code'))}  "
            f"available={_money(b.get('available'), b.get('iso_currency_code'))}"
        )
    return "\n".join(out)


def _op_transactions(args: dict) -> str:
    body = {
        "access_token": args["access_token"],
        "start_date": (args.get("start_date") or "").strip() or "2025-01-01",
        "end_date":   (args.get("end_date") or "").strip() or "2030-12-31",
        "options": {"count": max(1, min(int(args.get("count") or 25), 500))},
    }
    code, data = _post("/transactions/get", body)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: transactions ({code}): {data}"
    rows = data.get("transactions") or []
    if not rows:
        return "no transactions"
    return "\n".join(
        f"  {t.get('date', '?')}  {_money(t.get('amount'), t.get('iso_currency_code'))}  "
        f"{(t.get('name') or '')[:60]}"
        for t in rows
    )


def _op_identity(args: dict) -> str:
    code, data = _post("/identity/get", {"access_token": args["access_token"]})
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: identity ({code}): {data}"
    accounts = data.get("accounts") or []
    out = []
    for a in accounts:
        for o in (a.get("owners") or []):
            names = ", ".join(o.get("names") or [])
            emails = ", ".join(
                e.get("data", "?") for e in (o.get("emails") or [])
            )
            phones = ", ".join(
                p.get("data", "?") for p in (o.get("phone_numbers") or [])
            )
            out.append(f"  {names}\n      emails: {emails}\n      phones: {phones}")
    return "\n".join(out) or "(no identity info)"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    if not (args.get("access_token") or "").strip():
        return "ERROR: access_token is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed."
    try:
        return {
            "accounts":     _op_accounts,
            "balance":      _op_balance,
            "transactions": _op_transactions,
            "identity":     _op_identity,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Plaid request failed: {type(e).__name__}: {e}"


def plaid_tool() -> Tool:
    return Tool(
        name="plaid",
        description=(
            "Plaid banking (read-only). ops: accounts, balance, "
            "transactions (date range + count), identity. Every op "
            "takes access_token (obtained externally via Plaid Link). "
            "Auth: PLAID_CLIENT_ID + PLAID_SECRET + PLAID_ENV."
        ),
        input_schema=_PL_SCHEMA,
        fn=_run,
    )
