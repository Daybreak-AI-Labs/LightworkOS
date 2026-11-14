"""Shopify tool — orders, products, customers (read-mostly).

Wraps the Shopify Admin REST API (2024-04+). Read operations are
freely callable; writes (refund, fulfillment_create) are gated by
``confirm=true`` so the agent can't accidentally mutate a live
store.

Auth: ``SHOPIFY_STORE`` (subdomain like ``my-store`` — we expand to
``my-store.myshopify.com``) + ``SHOPIFY_ACCESS_TOKEN`` (custom-app
admin token; legacy private-app passwords also accepted).

ops:
  - orders(limit, status)             — list recent orders
  - order_get(order_id)
  - products(limit, vendor)
  - product_get(product_id)
  - customer_get(customer_id)
  - inventory(limit)                  — inventory_levels
  - refund_create(order_id, amount_cents, currency, confirm)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from . import Tool, as_bool

log = logging.getLogger(__name__)


_SHOPIFY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {
            "type": "string",
            "enum": ["orders", "order_get", "products", "product_get",
                     "customer_get", "inventory", "refund_create"],
        },
        "order_id": {"type": "integer"},
        "product_id": {"type": "integer"},
        "customer_id": {"type": "integer"},
        "vendor": {"type": "string"},
        "status": {"type": "string", "enum": ["open", "closed", "cancelled", "any"]},
        "limit": {"type": "integer"},
        "amount_cents": {"type": "integer"},
        "currency": {"type": "string"},
        "confirm": {"type": "boolean"},
    },
    "required": ["op"],
}


_API_VERSION = "2024-04"


def _config() -> tuple[str, str]:
    store = os.environ.get("SHOPIFY_STORE", "").strip()
    tok = os.environ.get("SHOPIFY_ACCESS_TOKEN", "").strip()
    if not store or not tok:
        raise RuntimeError(
            "Shopify requires SHOPIFY_STORE (subdomain) + SHOPIFY_ACCESS_TOKEN."
        )
    # Reject URL-special chars so SHOPIFY_STORE can't escape the
    # .myshopify.com host (e.g. "evil.com#", "evil.com/", "user@host").
    if any(c in store for c in "/@#?:\\ "):
        raise RuntimeError(f"invalid SHOPIFY_STORE: {store!r}")
    if "." not in store:
        store = f"{store}.myshopify.com"
    return store, tok


def _client():
    import httpx

    from ..governed_http import GuardedClient
    store, tok = _config()
    return store, GuardedClient(httpx.Client(
        headers={
            "X-Shopify-Access-Token": tok,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        # follow_redirects=False: the X-Shopify-Access-Token is a client default
        # header httpx replays across a cross-origin 30x, so an open-redirect off
        # the store host would leak the token to another host.
        timeout=30.0, follow_redirects=False,
    ))


def _money(amount: str | float | None, currency: str | None) -> str:
    try:
        v = float(amount or 0)
    except (TypeError, ValueError):
        return "?"
    return f"{v:,.2f} {(currency or '').upper()}"


def _next_page_url(link_header: str | None) -> str | None:
    """Extract the ``rel="next"`` URL from a Shopify RFC-5988 Link header.

    Shopify paginates list endpoints with a cursor carried in the ``Link``
    response header: ``<https://...?page_info=XYZ>; rel="next"``. Returns the
    next-page URL, or None when there are no more pages.
    """
    if not link_header or not isinstance(link_header, str):
        return None
    for part in link_header.split(","):
        seg = part.strip()
        if 'rel="next"' in seg and seg.startswith("<"):
            end = seg.find(">")
            if end > 1:
                return seg[1:end]
    return None


def _paginated_list(c, url: str, params: dict, key: str, limit: int) -> tuple[int, str, list[dict]]:
    """GET ``url`` following the Link-header ``rel="next"`` cursor until
    ``limit`` rows under ``key`` are collected. Returns (code, error, rows).

    On follow-up requests Shopify only accepts ``limit`` + ``page_info`` (the
    next-page URL already encodes the other filters), so we follow the full
    URL it hands back. Bounded by a hard page cap.
    """
    rows: list[dict] = []
    next_url: str | None = url
    use_params: dict | None = dict(params)
    max_pages = max(1, (limit // 250) + 2)
    for _ in range(max_pages):
        if use_params is not None:
            use_params["limit"] = min(250, max(1, limit - len(rows)))
        r = c.get(next_url, params=use_params)
        if r.status_code >= 400:
            return r.status_code, r.text[:300], rows
        rows.extend(r.json().get(key) or [])
        if len(rows) >= limit:
            break
        next_url = _next_page_url(r.headers.get("Link") or r.headers.get("link"))
        if not next_url:
            break
        use_params = None  # the next-page URL already carries limit + page_info
    return 200, "", rows[:limit]


def _op_orders(limit: int, status: str) -> str:
    store, c = _client()
    with c:
        code, err, rows = _paginated_list(
            c, f"https://{store}/admin/api/{_API_VERSION}/orders.json",
            {"status": status or "open"}, "orders", limit,
        )
    if code >= 400:
        return f"ERROR: orders ({code}): {err}"
    if not rows:
        return "no orders"
    out = []
    for o in rows:
        out.append(
            f"  #{o.get('name', '?')}  {o.get('financial_status', '?')}  "
            f"{_money(o.get('total_price'), o.get('currency'))}  "
            f"customer={(o.get('customer') or {}).get('email', '?')}"
        )
    return "\n".join(out)


def _op_order_get(order_id: int) -> str:
    store, c = _client()
    with c:
        r = c.get(f"https://{store}/admin/api/{_API_VERSION}/orders/{order_id}.json")
        if r.status_code == 404:
            return f"order {order_id} not found"
        if r.status_code >= 400:
            return f"ERROR: order_get ({r.status_code}): {r.text[:300]}"
        o = r.json().get("order") or {}
    line_items = o.get("line_items") or []
    items_txt = "\n".join(
        f"    {li.get('quantity', '?')}× {li.get('title', '?')}  "
        f"{_money(li.get('price'), o.get('currency'))}"
        for li in line_items
    )
    return (
        f"#{o.get('name')}  {o.get('financial_status', '?')}  "
        f"{_money(o.get('total_price'), o.get('currency'))}\n"
        f"  email:    {o.get('email', '?')}\n"
        f"  created:  {o.get('created_at', '?')}\n"
        f"  line items:\n{items_txt}"
    )


def _op_products(limit: int, vendor: str) -> str:
    store, c = _client()
    params: dict = {}
    if vendor:
        params["vendor"] = vendor
    with c:
        code, err, rows = _paginated_list(
            c, f"https://{store}/admin/api/{_API_VERSION}/products.json",
            params, "products", limit,
        )
    if code >= 400:
        return f"ERROR: products ({code}): {err}"
    if not rows:
        return "no products"
    return "\n".join(
        f"  {p.get('id'):>10}  {(p.get('title') or '')[:60]:<60}  "
        f"variants={len(p.get('variants') or [])}"
        for p in rows
    )


def _op_product_get(product_id: int) -> str:
    store, c = _client()
    with c:
        r = c.get(f"https://{store}/admin/api/{_API_VERSION}/products/{product_id}.json")
        if r.status_code == 404:
            return f"product {product_id} not found"
        if r.status_code >= 400:
            return f"ERROR: product_get ({r.status_code}): {r.text[:300]}"
        p = r.json().get("product") or {}
    variants = p.get("variants") or []
    v_lines = "\n".join(
        f"    {v.get('sku', '?')}  {v.get('title', '?')}  "
        f"price={v.get('price')}  inventory={v.get('inventory_quantity', '?')}"
        for v in variants
    )
    return (
        f"#{p.get('id')}  {p.get('title', '')}\n"
        f"  vendor: {p.get('vendor', '?')}\n"
        f"  variants:\n{v_lines or '    (none)'}"
    )


def _op_customer_get(customer_id: int) -> str:
    store, c = _client()
    with c:
        r = c.get(f"https://{store}/admin/api/{_API_VERSION}/customers/{customer_id}.json")
        if r.status_code == 404:
            return f"customer {customer_id} not found"
        if r.status_code >= 400:
            return f"ERROR: customer_get ({r.status_code}): {r.text[:300]}"
        cu = r.json().get("customer") or {}
    return (
        f"{cu.get('id')}  {cu.get('email', '?')}  "
        f"{cu.get('first_name', '')} {cu.get('last_name', '')}\n"
        f"  orders:        {cu.get('orders_count', '?')}\n"
        f"  total spent:   {cu.get('total_spent')} {cu.get('currency', '?')}\n"
        f"  state:         {cu.get('state', '?')}"
    )


def _op_inventory(limit: int) -> str:
    store, c = _client()
    with c:
        # Inventory_levels requires location_ids; pick first location.
        loc = c.get(f"https://{store}/admin/api/{_API_VERSION}/locations.json")
        if loc.status_code >= 400:
            return f"ERROR: locations ({loc.status_code}): {loc.text[:300]}"
        locs = (loc.json().get("locations") or [])
        if not locs:
            return "no locations"
        loc_id = locs[0].get("id")
        r = c.get(
            f"https://{store}/admin/api/{_API_VERSION}/inventory_levels.json",
            params={"location_ids": loc_id, "limit": limit},
        )
        if r.status_code >= 400:
            return f"ERROR: inventory ({r.status_code}): {r.text[:300]}"
        rows = (r.json().get("inventory_levels") or [])
    if not rows:
        return f"no inventory at location {loc_id}"
    return "\n".join(
        f"  item={lvl.get('inventory_item_id')}  available={lvl.get('available')}"
        for lvl in rows
    )


def _op_refund_create(order_id: int, amount_cents: int, currency: str,
                      confirm: bool) -> str:
    if not order_id:
        return "ERROR: refund_create requires order_id"
    if amount_cents <= 0:
        # A refund with no transactions moves no money, so a "full" refund
        # without an amount would notify the customer and refund nothing.
        return ("ERROR: refund_create requires a positive amount_cents; "
                "no refund was created")
    amount = f"{amount_cents/100:.2f}"
    if not confirm:
        return (
            f"DRY RUN: would refund {amount} {currency or '?'} on order {order_id}. "
            "Re-run with confirm=true."
        )
    store, c = _client()
    body: dict = {"refund": {"notify": True, "transactions": [{
        "amount": amount, "kind": "refund",
        "currency": (currency or "USD").upper(),
    }]}}
    with c:
        r = c.post(
            f"https://{store}/admin/api/{_API_VERSION}/orders/{order_id}/refunds.json",
            json=body,
        )
        if r.status_code >= 400:
            return f"ERROR: refund_create ({r.status_code}): {r.text[:300]}"
        data = r.json()
    ref = data.get("refund") or {}
    return f"refunded {ref.get('id')} on order {order_id}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "orders":
            return _op_orders(
                max(1, min(int(args.get("limit") or 25), 250)),
                (args.get("status") or "open"),
            )
        if op == "order_get":
            oid = int(args.get("order_id") or 0)
            if not oid:
                return "ERROR: order_get requires order_id"
            return _op_order_get(oid)
        if op == "products":
            return _op_products(
                max(1, min(int(args.get("limit") or 25), 250)),
                (args.get("vendor") or "").strip(),
            )
        if op == "product_get":
            pid = int(args.get("product_id") or 0)
            if not pid:
                return "ERROR: product_get requires product_id"
            return _op_product_get(pid)
        if op == "customer_get":
            cid = int(args.get("customer_id") or 0)
            if not cid:
                return "ERROR: customer_get requires customer_id"
            return _op_customer_get(cid)
        if op == "inventory":
            return _op_inventory(max(1, min(int(args.get("limit") or 25), 250)))
        if op == "refund_create":
            return _op_refund_create(
                int(args.get("order_id") or 0),
                int(args.get("amount_cents") or 0),
                (args.get("currency") or "").strip(),
                as_bool(args.get("confirm")),
            )
    except RuntimeError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: Shopify request failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def shopify_tool() -> Tool:
    return Tool(
        name="shopify",
        description=(
            "Shopify Admin API (read-mostly). ops: orders, "
            "order_get, products, product_get, customer_get, "
            "inventory, refund_create (DRY RUN unless "
            "confirm=true). Auth: SHOPIFY_STORE + "
            "SHOPIFY_ACCESS_TOKEN."
        ),
        input_schema=_SHOPIFY_SCHEMA,
        fn=_run,
    )
