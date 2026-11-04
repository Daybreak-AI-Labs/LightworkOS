"""TrueLayer tool — open-banking accounts + transactions (read-only).

The European open-banking counterpart to ``plaid`` (US/Canada). Like Plaid,
auth is a per-user OAuth2 ``access_token`` obtained out-of-band by the user's
bank-link flow (not by this tool); every read op takes it. The Data API reads
are Bearer-authenticated with that token — no server client_id/secret needed
for the reads themselves.

Auth:
  - ``access_token`` (per call; from the user's TrueLayer auth flow)
  - ``TRUELAYER_ENV`` = sandbox | production (default sandbox)

ops:
  - accounts(access_token)
  - balance(access_token, account_id)
  - transactions(access_token, account_id, from_date, to_date)
  - info(access_token)                       — account-holder identity
"""
from __future__ import annotations

import logging
import os
from typing import Any

from ..governed_http import guarded_sender as _governed_sender
from . import Tool, safe_path_segment

log = logging.getLogger(__name__)


_TL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string",
               "enum": ["accounts", "balance", "transactions", "info"]},
        "access_token": {"type": "string"},
        "account_id": {"type": "string"},
        "from_date": {"type": "string", "description": "ISO date (transactions)"},
        "to_date": {"type": "string", "description": "ISO date (transactions)"},
    },
    "required": ["op", "access_token"],
}


def _base() -> str:
    env = (os.environ.get("TRUELAYER_ENV") or "sandbox").strip().lower()
    return ("https://api.truelayer.com" if env == "production"
            else "https://api.truelayer-sandbox.com")


def _get(path: str, access_token: str, params: dict | None = None) -> tuple[int, Any]:
    import httpx
    r = _governed_sender(httpx.get)(
        f"{_base()}{path}",
        headers={"Authorization": f"Bearer {access_token}"},
        params=params or {},
        timeout=30.0,
    )
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text[:300]


def _money(v, ccy) -> str:
    try:
        return f"{float(v):,.2f} {ccy or ''}".strip()
    except (TypeError, ValueError):
        return "?"


def _op_accounts(args: dict) -> str:
    code, data = _get("/data/v1/accounts", args["access_token"])
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: accounts ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no accounts"
    return "\n".join(
        f"  {(a.get('account_id') or '?')[:12]}  "
        f"{(a.get('display_name') or '?')[:30]:<30}  "
        f"{a.get('account_type', '?')}  {a.get('currency', '')}"
        for a in rows
    )


def _op_balance(args: dict) -> str:
    acct = (args.get("account_id") or "").strip()
    if not acct:
        return "ERROR: balance requires account_id"
    seg = safe_path_segment(acct)
    if seg is None:
        return "ERROR: balance requires a valid account_id"
    code, data = _get(f"/data/v1/accounts/{seg}/balance", args["access_token"])
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: balance ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no balance"
    out = []
    for b in rows:
        ccy = b.get("currency")
        out.append(
            f"  current={_money(b.get('current'), ccy)}  "
            f"available={_money(b.get('available'), ccy)}  "
            f"overdraft={_money(b.get('overdraft'), ccy)}"
        )
    return "\n".join(out)


def _op_transactions(args: dict) -> str:
    acct = (args.get("account_id") or "").strip()
    if not acct:
        return "ERROR: transactions requires account_id"
    seg = safe_path_segment(acct)
    if seg is None:
        return "ERROR: transactions requires a valid account_id"
    params = {}
    if (args.get("from_date") or "").strip():
        params["from"] = args["from_date"].strip()
    if (args.get("to_date") or "").strip():
        params["to"] = args["to_date"].strip()
    code, data = _get(f"/data/v1/accounts/{seg}/transactions",
                      args["access_token"], params)
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: transactions ({code}): {data}"
    rows = data.get("results") or []
    if not rows:
        return "no transactions"
    return "\n".join(
        f"  {(t.get('timestamp') or '?')[:10]}  "
        f"{_money(t.get('amount'), t.get('currency'))}  "
        f"{(t.get('description') or '')[:60]}"
        for t in rows
    )


def _op_info(args: dict) -> str:
    code, data = _get("/data/v1/info", args["access_token"])
    if code >= 400 or not isinstance(data, dict):
        return f"ERROR: info ({code}): {data}"
    rows = data.get("results") or []
    out = []
    for o in rows:
        names = o.get("full_name") or ", ".join(o.get("full_names") or []) or "?"
        emails = ", ".join(o.get("emails") or [])
        phones = ", ".join(o.get("phones") or [])
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
            "info":         _op_info,
        }.get(op, lambda a: f"ERROR: unknown op {op!r}")(args)
    except Exception as e:
        return f"ERROR: TrueLayer request failed: {type(e).__name__}: {e}"


def truelayer_tool() -> Tool:
    return Tool(
        name="truelayer",
        description=(
            "TrueLayer open banking (read-only, EU/UK). ops: accounts, "
            "balance (account_id), transactions (account_id + optional "
            "from_date/to_date), info (identity). Every op takes "
            "access_token (obtained externally via TrueLayer auth). "
            "Env: TRUELAYER_ENV = sandbox | production."
        ),
        input_schema=_TL_SCHEMA,
        fn=_run,
    )
