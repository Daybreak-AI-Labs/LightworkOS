"""Commerce tools -- the shopper and merchant packs' hands.

A thin layer over :mod:`maverick.commerce`: every tool delegates to a
:class:`~maverick.commerce.ShopperSession` or
:class:`~maverick.commerce.MerchantSession`, which is where the safety rules
live (per-session spend / quantity / cart caps, the provenance gate, staged
writes that only a human approval token can apply, and the checkout handoff
that returns an opaque cart reference). The tools render results and refusals
as text; they never carry a rule of their own, so a prompt cannot argue one
away.

Registered into the base registry only when ``[commerce] enable`` is on
(``maverick.commerce.enabled``), so the default tool catalog is unchanged.
"""
from __future__ import annotations

from typing import Any

from ..commerce import (
    CommerceError,
    MerchantSession,
    ShopperSession,
    StagedChange,
)
from ..fastjson import dumps_compact
from . import Tool

_REFUSABLE = (CommerceError, ValueError)


def _dump(value: Any) -> str:
    return dumps_compact(value, sort_keys=True)


def _arg(args: dict, key: str) -> str:
    return str(args.get(key) or "").strip()


def _int(args: dict, key: str, default: int) -> int:
    # Only a missing value takes the default: quantity=0 must reach the
    # session (which refuses it), not silently become 1.
    value = args.get(key)
    return default if value is None or value == "" else int(value)


def _refused(exc: Exception) -> str:
    return f"REFUSED ({type(exc).__name__}): {exc}"


def _staged(change: StagedChange) -> str:
    return (
        "STAGED (awaiting a human decision -- nothing has been applied):\n"
        + _dump(change.to_public_dict())
    )


def _shopper_read_tools(session: ShopperSession) -> list[Tool]:
    async def _search(args: dict) -> str:
        query = _arg(args, "query")
        if not query:
            return "ERROR: 'query' is required."
        try:
            products = session.search(query, limit=_int(args, "limit", 10))
        except _REFUSABLE as exc:
            return _refused(exc)
        if not products:
            return f"No catalog products match {query!r}."
        return _dump([p.to_dict() for p in products])

    async def _product(args: dict) -> str:
        product_id = _arg(args, "product_id")
        if not product_id:
            return "ERROR: 'product_id' is required."
        try:
            return _dump(session.product(product_id).to_dict())
        except _REFUSABLE as exc:
            return _refused(exc)

    async def _cart_view(args: dict) -> str:
        try:
            return _dump(session.cart_view().to_dict())
        except _REFUSABLE as exc:
            return _refused(exc)

    async def _orders(args: dict) -> str:
        order_id = _arg(args, "order_id")
        try:
            if order_id:
                return _dump(session.order(order_id).to_dict())
            orders = session.orders()
        except _REFUSABLE as exc:
            return _refused(exc)
        if not orders:
            return "No orders on file for this shopper."
        return _dump([o.to_dict() for o in orders])

    return [
        Tool(
            name="storefront_search",
            description="Search the storefront catalog. Every result carries "
                        "provenance (source + fetched_at); quote nothing else.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
            fn=_search,
            parallel_safe=True,
        ),
        Tool(
            name="storefront_product",
            description="Read one catalog product's full record (price, "
                        "availability, attributes) with its provenance.",
            input_schema={
                "type": "object",
                "properties": {"product_id": {"type": "string"}},
                "required": ["product_id"],
            },
            fn=_product,
            parallel_safe=True,
        ),
        Tool(
            name="cart_view",
            description="Show the session cart: lines, quantities, unit prices, "
                        "subtotal.",
            input_schema={"type": "object", "properties": {}},
            fn=_cart_view,
        ),
        Tool(
            name="shopper_orders_read",
            description="Read the shopper's OWN orders (status, items, total, "
                        "tracking) with provenance; one order when order_id "
                        "is given.",
            input_schema={
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
            },
            fn=_orders,
            parallel_safe=True,
        ),
    ]


def _shopper_action_tools(session: ShopperSession) -> list[Tool]:
    async def _cart_add(args: dict) -> str:
        product_id = _arg(args, "product_id")
        if not product_id:
            return "ERROR: 'product_id' is required."
        try:
            cart = session.cart_add(product_id, _int(args, "quantity", 1))
        except _REFUSABLE as exc:
            return _refused(exc)
        return _dump(cart.to_dict())

    async def _cart_remove(args: dict) -> str:
        product_id = _arg(args, "product_id")
        if not product_id:
            return "ERROR: 'product_id' is required."
        try:
            return _dump(session.cart_remove(product_id).to_dict())
        except _REFUSABLE as exc:
            return _refused(exc)

    async def _handoff(args: dict) -> str:
        try:
            handoff = session.checkout_handoff()
        except _REFUSABLE as exc:
            return _refused(exc)
        return (
            "CHECKOUT HANDOFF -- give the shopper this cart link; they complete "
            "the purchase themselves. You never see or ask for payment details.\n"
            + _dump(handoff.to_dict())
        )

    async def _stage_return(args: dict) -> str:
        order_id, reason = _arg(args, "order_id"), _arg(args, "reason")
        if not (order_id and reason):
            return "ERROR: 'order_id' and 'reason' are required."
        try:
            return _staged(session.stage_return(order_id, reason))
        except _REFUSABLE as exc:
            return _refused(exc)

    async def _preferences(args: dict) -> str:
        op = _arg(args, "op").lower() or "get"
        try:
            if op == "set":
                session.set_preference(_arg(args, "key"), _arg(args, "value"))
            elif op == "delete":
                session.delete_preference(_arg(args, "key"))
            elif op != "get":
                return "ERROR: 'op' must be one of get, set, delete."
        except _REFUSABLE as exc:
            return _refused(exc)
        return _dump(session.preferences())

    return [
        Tool(
            name="cart_add",
            description="Add a catalog product to the session cart. The per-line "
                        "quantity, cart-size, and per-session spend caps are "
                        "enforced by the platform; a refused add is final -- "
                        "report it, do not retry or split it.",
            input_schema={
                "type": "object",
                "properties": {
                    "product_id": {"type": "string"},
                    "quantity": {"type": "integer"},
                },
                "required": ["product_id"],
            },
            fn=_cart_add,
        ),
        Tool(
            name="cart_remove",
            description="Remove a product line from the session cart.",
            input_schema={
                "type": "object",
                "properties": {"product_id": {"type": "string"}},
                "required": ["product_id"],
            },
            fn=_cart_remove,
        ),
        Tool(
            name="checkout_handoff",
            description="Hand the cart to the shopper to check out: returns an "
                        "opaque cart reference and cart link ONLY. It never "
                        "places an order and never exposes payment, address, "
                        "or checkout-page details.",
            input_schema={"type": "object", "properties": {}},
            fn=_handoff,
        ),
        Tool(
            name="shopper_stage_return",
            description="Stage a return/exchange request for one of the "
                        "shopper's orders as a proposal for the merchant's "
                        "human to approve. Never cancels, refunds, or re-ships.",
            input_schema={
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["order_id", "reason"],
            },
            fn=_stage_return,
        ),
        Tool(
            name="shopper_preferences",
            description="Read (op=get), record (op=set key value), or delete "
                        "(op=delete key) a preference the shopper STATED. "
                        "Payment, credential, and address data are refused.",
            input_schema={
                "type": "object",
                "properties": {
                    "op": {"type": "string", "enum": ["get", "set", "delete"]},
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
            },
            fn=_preferences,
        ),
    ]


def shopper_tools(session: ShopperSession) -> list[Tool]:
    """The shopper-side tool surface over one governed session."""
    return _shopper_read_tools(session) + _shopper_action_tools(session)


def merchant_tools(session: MerchantSession) -> list[Tool]:
    """The merchant-side tool surface over one governed session."""

    async def _catalog(args: dict) -> str:
        try:
            rows = session.catalog(_arg(args, "query"), limit=_int(args, "limit", 50))
        except _REFUSABLE as exc:
            return _refused(exc)
        return _dump([p.to_dict() for p in rows]) if rows else "No catalog products match."

    def _rows(fn):
        async def _run(args: dict) -> str:
            try:
                rows = fn(args)
            except _REFUSABLE as exc:
                return _refused(exc)
            return _dump(rows) if rows else "No rows."
        return _run

    _inventory = _rows(lambda args: session.inventory(_arg(args, "sku") or None))
    _pricing = _rows(lambda args: session.pricing(_arg(args, "sku") or None))
    _orders = _rows(lambda args: [
        o.to_dict() for o in session.orders(_arg(args, "status") or None,
                                            limit=_int(args, "limit", 50))
    ])
    _analytics = _rows(lambda args: session.analytics(_arg(args, "metric"),
                                                      _arg(args, "window") or "7d"))
    _campaigns = _rows(lambda args: session.campaigns())

    async def _stage(args: dict) -> str:
        changes = args.get("changes")
        if not isinstance(changes, dict):
            return "ERROR: 'changes' must be an object of field -> proposed value."
        try:
            change = session.stage_change(
                _arg(args, "kind"), _arg(args, "target"), changes, _arg(args, "rationale"),
            )
        except _REFUSABLE as exc:
            return _refused(exc)
        return _staged(change)

    return [
        Tool(
            name="catalog_read",
            description="Read the merchant catalog (optionally filtered by "
                        "query) with provenance on every product.",
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}},
            },
            fn=_catalog,
            parallel_safe=True,
        ),
        Tool(
            name="inventory_read",
            description="Read stock-on-hand / inbound per SKU (one SKU when "
                        "given) with provenance.",
            input_schema={"type": "object", "properties": {"sku": {"type": "string"}}},
            fn=_inventory,
            parallel_safe=True,
        ),
        Tool(
            name="pricing_read",
            description="Read current price, unit cost, and margin floor per "
                        "SKU with provenance.",
            input_schema={"type": "object", "properties": {"sku": {"type": "string"}}},
            fn=_pricing,
            parallel_safe=True,
        ),
        Tool(
            name="orders_read",
            description="Read store orders (optionally by status) with "
                        "fulfillment/shipping state and provenance.",
            input_schema={
                "type": "object",
                "properties": {"status": {"type": "string"}, "limit": {"type": "integer"}},
            },
            fn=_orders,
            parallel_safe=True,
        ),
        Tool(
            name="analytics_read",
            description="Read one store metric (revenue, orders, sessions, "
                        "conversion, aov) over a window such as 7d or 30d, "
                        "with its baseline and provenance.",
            input_schema={
                "type": "object",
                "properties": {"metric": {"type": "string"}, "window": {"type": "string"}},
                "required": ["metric"],
            },
            fn=_analytics,
            parallel_safe=True,
        ),
        Tool(
            name="promotions_read",
            description="Read current and past campaigns/promotions with "
                        "provenance.",
            input_schema={"type": "object", "properties": {}},
            fn=_campaigns,
            parallel_safe=True,
        ),
        Tool(
            name="merchant_stage_change",
            description="Stage a store change as a PROPOSAL for a human to "
                        "approve: kind is one of price, inventory, listing, "
                        "campaign, order_resolution; target is the SKU / "
                        "product / campaign / order id; changes maps field -> "
                        "proposed value. Nothing is applied by this tool.",
            input_schema={
                "type": "object",
                "properties": {
                    "kind": {"type": "string"},
                    "target": {"type": "string"},
                    "changes": {"type": "object"},
                    "rationale": {"type": "string"},
                },
                "required": ["kind", "target", "changes", "rationale"],
            },
            fn=_stage,
        ),
    ]


def commerce_tools(*, principal: str | None = None) -> list[Tool]:
    """Shopper + merchant tools over the configured backend, one fresh
    governed session each (so the caps are per run)."""
    from ..commerce import merchant_session, shopper_session

    who = principal or "agent:commerce"
    return shopper_tools(shopper_session(principal=who)) + merchant_tools(
        merchant_session(principal=who)
    )
