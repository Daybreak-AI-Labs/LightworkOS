"""Platform billing collection via Stripe — turn metered invoices into charges.

:mod:`maverick.billing` *rates* a tenant's metered usage into an
:class:`~maverick.billing.Invoice`, and gates features by plan. This module is
the missing last mile: it turns that arithmetic into money by driving a Stripe
account the operator owns.

Three moving parts, all per-tenant:

  - **Customer** — :func:`ensure_customer` create-or-looks-up one Stripe customer
    per tenant (idempotent; the ``cus_...`` id is stored on the tenant record so
    it is never re-created).
  - **Subscription** — :func:`ensure_subscription` keeps a recurring subscription
    matching the tenant's current *plan* (the platform fee), creating it or
    switching its price when the plan changes.
  - **Metered usage** — :func:`push_usage_items` pushes the invoice's line items
    as Stripe invoice items so model-usage is billed *on top of* the
    subscription. This is behind the :func:`bill_metered_usage` flag
    (**default off**): until the operator turns it on, only the platform fee
    is billed. No markup is hardcoded anywhere — the amounts come
    straight from whatever :class:`~maverick.billing.RateCard` produced the
    invoice.

  - **Webhook** — :func:`handle_event` maps a *verified* Stripe event to an
    entitlement change: a failed payment / past-due subscription downgrades the
    tenant to the base tier (via ``billing_status`` on the tenant record, which
    :func:`maverick.billing.tenant_entitled` honors), a recovered payment
    restores it. :func:`verify_webhook` checks the signature with stdlib HMAC —
    no SDK, no network — so the whole webhook path unit-tests offline.

Design (kernel rule 5):

  - **Default off + optional dependency.** The ``stripe`` SDK is an optional
    extra (``maverick-core[stripe]``), imported lazily inside the functions that
    talk to Stripe. The module imports and :func:`status` reports *disabled*
    cleanly when the extra or the key is absent — nothing here is a hard import.
  - **Secrets never touch logs.** The API key
    (``MAVERICK_STRIPE_SECRET_KEY``) and webhook signing secret
    (``MAVERICK_STRIPE_WEBHOOK_SECRET``) are resolved through the secret provider
    first; when it holds none, the value a global administrator saved on the
    All settings page is used (``[billing.stripe] secret_key`` /
    ``webhook_secret``, stored sealed in the dashboard overlay).
  - **Injectable client.** Every Stripe-touching function takes an optional
    ``client`` implementing the small :class:`StripeClient` protocol, so tests
    pass a fake and never hit the network.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import ROUND_FLOOR, ROUND_HALF_UP, Decimal, InvalidOperation

from .config import env_flag, get_billing_stripe

log = logging.getLogger(__name__)

# ---- errors ----------------------------------------------------------------


class StripeError(RuntimeError):
    """Base class for every refusal this module issues."""


class StripeDisabled(StripeError):
    """A Stripe operation was attempted while platform billing is turned off."""


class StripeNotConfigured(StripeError):
    """Stripe billing is enabled but the secret key / SDK is missing."""


class StripeWebhookError(StripeError):
    """A webhook payload failed signature verification."""


# ---- config / gate ---------------------------------------------------------

_SECRET_KEY_ENV = "MAVERICK_STRIPE_SECRET_KEY"  # pragma: allowlist secret
_WEBHOOK_SECRET_ENV = "MAVERICK_STRIPE_WEBHOOK_SECRET"  # pragma: allowlist secret
_DEFAULT_WEBHOOK_TOLERANCE = 300  # seconds; Stripe's own default replay window


def available() -> bool:
    """Whether the optional ``stripe`` SDK is importable. Never raises."""
    import importlib.util
    try:
        return importlib.util.find_spec("stripe") is not None
    except Exception:  # pragma: no cover -- a broken importer must not crash the gate
        return False


def _saved_secret(key: str) -> str:
    """``[billing.stripe] <key>`` as saved on the All settings page.

    The page stores it sealed with the deployment key in the dashboard
    overlay (like every other secret setting there) and ``load_config``
    opens it; the value is never logged or returned to the page."""
    try:
        from .config import load_config
        billing = (load_config() or {}).get("billing") or {}
        stripe = billing.get("stripe") if isinstance(billing, dict) else None
        value = stripe.get(key) if isinstance(stripe, dict) else None
    except Exception:  # pragma: no cover -- config never blocks a billing read
        return ""
    return value.strip() if isinstance(value, str) else ""


def _secret_key() -> str:
    """The platform Stripe secret key: the secret provider (environment or a
    mounted secret file) wins; otherwise the sealed ``[billing.stripe]
    secret_key`` saved on the All settings page. Never logged."""
    from .secret_provider import get_secret
    return (get_secret(_SECRET_KEY_ENV) or "").strip() or _saved_secret("secret_key")


def _webhook_secret() -> str:
    """The webhook signing secret: the secret provider wins; otherwise the
    sealed ``[billing.stripe] webhook_secret`` saved on the All settings page."""
    from .secret_provider import get_secret
    return (get_secret(_WEBHOOK_SECRET_ENV) or "").strip() or _saved_secret("webhook_secret")


def _enable_flag() -> bool:
    """The ``[billing.stripe] enable`` toggle (``MAVERICK_STRIPE_ENABLE`` wins).
    This is intent only -- :func:`enabled` also requires a key. Never raises."""
    flag = env_flag("MAVERICK_STRIPE_ENABLE")
    if flag is not None:
        return flag
    try:
        return bool(get_billing_stripe().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def enabled() -> bool:
    """Whether platform billing is BOTH turned on AND has a usable secret key.
    The operative gate; **default off**. Never raises."""
    return _enable_flag() and bool(_secret_key())


def bill_metered_usage() -> bool:
    """Whether metered model-usage line items are pushed to Stripe on top of
    the platform fee. **Default off** -- until the operator turns it on, only
    the recurring subscription is billed.
    ``MAVERICK_STRIPE_BILL_METERED`` overrides ``[billing.stripe]
    bill_metered_usage``. Never raises."""
    flag = env_flag("MAVERICK_STRIPE_BILL_METERED")
    if flag is not None:
        return flag
    try:
        return bool(get_billing_stripe().get("bill_metered_usage", False))
    except Exception:  # pragma: no cover
        return False


@dataclass(frozen=True)
class StripeStatus:
    """A never-raising snapshot of the integration's readiness, for the gate /
    ``maverick billing stripe-status`` to render."""

    enabled: bool
    enable_flag: bool
    has_secret_key: bool
    has_webhook_secret: bool
    sdk_available: bool
    bill_metered_usage: bool
    currency: str = "usd"
    plans_priced: tuple[str, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "enable_flag": self.enable_flag,
            "has_secret_key": self.has_secret_key,
            "has_webhook_secret": self.has_webhook_secret,
            "sdk_available": self.sdk_available,
            "bill_metered_usage": self.bill_metered_usage,
            "currency": self.currency,
            "plans_priced": list(self.plans_priced),
            "reason": self.reason,
        }


def status() -> StripeStatus:
    """Report readiness without ever raising -- the disabled-clean contract.

    ``reason`` explains the first thing standing between the current config and a
    real charge, so an operator sees *why* it is off (flag, key, or SDK)."""
    enable_flag = _enable_flag()
    has_key = bool(_secret_key())
    sdk = available()
    try:
        cfg = get_billing_stripe()
    except Exception:  # pragma: no cover
        cfg = {"currency": "usd", "prices": {}}
    priced = tuple(sorted(cfg.get("prices", {})))
    if not enable_flag:
        reason = "disabled ([billing.stripe] enable is off / MAVERICK_STRIPE_ENABLE unset)"
    elif not has_key:
        reason = f"enabled but no secret key ({_SECRET_KEY_ENV} is unset)"
    elif not sdk:
        reason = "enabled with a key but the 'stripe' extra is not installed " \
                 "(python -m pip install -e './packages/maverick-core[stripe]')"
    else:
        reason = "ready"
    return StripeStatus(
        enabled=enable_flag and has_key,
        enable_flag=enable_flag,
        has_secret_key=has_key,
        has_webhook_secret=bool(_webhook_secret()),
        sdk_available=sdk,
        bill_metered_usage=bill_metered_usage(),
        currency=str(cfg.get("currency", "usd")),
        plans_priced=priced,
        reason=reason,
    )


def require_enabled() -> None:
    """Guard the Stripe-touching operations: the *policy* gate only.

    Raises :class:`StripeDisabled` when billing is off and
    :class:`StripeNotConfigured` when it is on but the secret key is missing. The
    ``stripe`` SDK requirement is deliberately NOT checked here -- it is enforced
    only when a *real* client is built (:func:`_client`), so a caller that injects
    a client (the tests) never needs the optional extra installed."""
    if not _enable_flag():
        raise StripeDisabled(
            "Stripe platform billing is off. Turn it on with "
            "[billing.stripe] enable = true (or MAVERICK_STRIPE_ENABLE=1)."
        )
    if not _secret_key():
        raise StripeNotConfigured(
            f"Stripe billing is enabled but {_SECRET_KEY_ENV} is not set."
        )


# ---- money -----------------------------------------------------------------

# Currencies whose smallest unit IS the whole unit (¥5000 is charged as 5000,
# not 500000). Multiplying by 100 for these over-charges 100x.
_ZERO_DECIMAL = frozenset({
    "bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf",
    "ugx", "vnd", "vuv", "xaf", "xof", "xpf",
})


def _to_minor_units(amount: float, currency: str) -> int:
    """Convert a dollar (major-unit) amount to Stripe's integer minor units,
    honoring zero-decimal currencies. Rounds half-up on the cent."""
    cur = (currency or "usd").lower()
    value = _money(amount)
    # ISK/UGX charges are whole units represented with two API decimal places.
    if cur in {"isk", "ugx"}:
        return int(value.quantize(Decimal(1), rounding=ROUND_HALF_UP)) * 100
    factor = 1 if cur in _ZERO_DECIMAL else 100
    return int((value * factor).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def _money(amount) -> Decimal:
    try:
        if isinstance(amount, bool):
            raise ValueError
        value = Decimal(str(amount))
        if not value.is_finite() or value < 0:
            raise ValueError
        return value
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise StripeError("Invoice amounts must be finite and non-negative") from exc


def _rated_usage_items(invoice, currency: str) -> list[dict]:
    """Reconcile line rounding to the invoice total using largest remainders."""
    lines = list(invoice.line_items)
    charges = [_money(line.charge) for line in lines]
    total = _money(invoice.total)
    if abs(sum(charges, Decimal(0)) - total) > Decimal("0.000001"):
        raise StripeError("Invoice total does not reconcile to its rated line items")
    factor = 1 if currency in _ZERO_DECIMAL or currency == "isk" else 100
    api_factor = 100 if currency in {"isk", "ugx"} else 1
    raw = [charge * factor for charge in charges]
    rounded = [int(value.to_integral_value(rounding=ROUND_FLOOR)) for value in raw]
    target = _to_minor_units(total, currency) // api_factor
    residual = target - sum(rounded)
    if not 0 <= residual <= len(lines):
        raise StripeError("Invoice rounding does not reconcile")
    order = sorted(range(len(lines)), key=lambda index: (-(raw[index] - rounded[index]), index))
    for index in order[:residual]:
        rounded[index] += 1
    rows, identities = [], set()
    for line, amount in zip(lines, rounded, strict=True):
        kind = getattr(line, "kind", "usage")
        identity = (kind, line.day, line.principal)
        if identity in identities:
            raise StripeError("Invoice contains duplicate line identities")
        identities.add(identity)
        rows.append({"day": line.day, "principal": line.principal, "kind": kind,
                     "in_tokens": line.in_tokens, "out_tokens": line.out_tokens,
                     "charge": str(_money(line.charge)), "amount_minor": amount * api_factor})
    return rows


def _validate_collection_period(tenant_id, invoice) -> None:
    try:
        start = date.fromisoformat(invoice.period_start)
        end = date.fromisoformat(invoice.period_end)
        if (invoice.tenant != tenant_id or not invoice.invoice_id or start > end
                or end >= datetime.now(timezone.utc).date()):
            raise ValueError
    except (AttributeError, TypeError, ValueError) as exc:
        raise StripeError("Metered collection requires an identified, closed past UTC period for this tenant; set --since and --until") from exc


# ---- client protocol + real implementation ---------------------------------
#
# A tiny surface so the fake in the tests is small. Each method returns a
# mapping-like object (the Stripe SDK's StripeObject already behaves as one, and
# the fake returns plain dicts), accessed only via ``[...]`` / ``.get(...)``.


class StripeClient:  # pragma: no cover -- structural/protocol documentation only
    """The Stripe operations this module needs. Implemented by
    :class:`_RealStripeClient` (thin SDK wrapper) and by the test fake."""

    def create_customer(self, *, name: str, metadata: dict,
                        idempotency_key: str) -> dict: ...

    def list_subscriptions(self, customer_id: str) -> list[dict]: ...

    def create_subscription(self, *, customer_id: str, price_id: str,
                           metadata: dict, idempotency_key: str) -> dict: ...

    def update_subscription(self, subscription_id: str, *, item_id: str,
                           price_id: str, metadata: dict) -> dict: ...

    def create_invoice_item(self, *, customer_id: str, amount: int, currency: str,
                           description: str, metadata: dict,
                           idempotency_key: str) -> dict: ...


class _RealStripeClient:
    """Adapts the official ``stripe`` SDK to :class:`StripeClient`. Constructed
    only when billing is enabled and the SDK is present (lazy import)."""

    def __init__(self, api_key: str):
        import stripe  # optional dependency, imported lazily
        self._stripe = stripe
        # Per-call api_key (never a process-global mutation that could leak into
        # another tenant's request in a multi-tenant host).
        self._key = api_key

    def create_customer(self, *, name, metadata, idempotency_key):
        return self._stripe.Customer.create(
            api_key=self._key, name=name, metadata=metadata,
            idempotency_key=idempotency_key,
        )

    def list_subscriptions(self, customer_id):
        res = self._stripe.Subscription.list(
            api_key=self._key, customer=customer_id, status="all", limit=100)
        return list(res.auto_paging_iter())

    def create_subscription(self, *, customer_id, price_id, metadata, idempotency_key):
        return self._stripe.Subscription.create(
            api_key=self._key, customer=customer_id,
            items=[{"price": price_id}], metadata=metadata,
            idempotency_key=idempotency_key,
        )

    def update_subscription(self, subscription_id, *, item_id, price_id, metadata):
        return self._stripe.Subscription.modify(
            subscription_id, api_key=self._key,
            items=[{"id": item_id, "price": price_id}], metadata=metadata,
        )

    def create_invoice_item(self, *, customer_id, amount, currency, description,
                           metadata, idempotency_key):
        return self._stripe.InvoiceItem.create(
            api_key=self._key, customer=customer_id, amount=amount,
            currency=currency, description=description, metadata=metadata,
            idempotency_key=idempotency_key,
        )


def _client(client: StripeClient | None = None) -> StripeClient:
    """Return the caller's injected client, else build the real one (which lazily
    imports the optional ``stripe`` SDK). Assumes :func:`require_enabled` has
    already passed. Translates a missing SDK into :class:`StripeNotConfigured`."""
    if client is not None:
        return client
    try:
        return _RealStripeClient(_secret_key())
    except ImportError as exc:  # optional extra absent
        raise StripeNotConfigured(
            "Stripe billing is enabled but the 'stripe' extra is not installed. "
            "Run: python -m pip install -e './packages/maverick-core[stripe]'."
        ) from exc


# ---- customer / subscription / usage ---------------------------------------

_TENANT_META_KEY = "maverick_tenant"
_PLAN_META_KEY = "maverick_plan"


def _get_tenant(tenant_id: str):
    from .tenant.registry import UnknownTenant, get_tenant
    rec = get_tenant(tenant_id)
    if rec is None:
        raise UnknownTenant(tenant_id)
    return rec


def ensure_customer(tenant_id: str, *, client: StripeClient | None = None) -> str:
    """Return the tenant's Stripe customer id, creating it once if needed.

    Idempotent on both ends: the stored ``stripe_customer_id`` short-circuits any
    repeat, and the create carries a deterministic idempotency key so even a
    racing first call cannot mint two customers. The id is persisted on the
    tenant record before returning."""
    require_enabled()
    rec = _get_tenant(tenant_id)
    if rec.stripe_customer_id:
        return rec.stripe_customer_id
    cli = _client(client)
    cust = cli.create_customer(
        name=rec.display_name or tenant_id,
        metadata={_TENANT_META_KEY: tenant_id},
        idempotency_key=f"maverick-customer-{tenant_id}",
    )
    cid = str(cust["id"])
    from .tenant.registry import set_stripe_customer_id
    set_stripe_customer_id(tenant_id, cid)
    return cid


def _sub_is_ours(sub: dict, tenant_id: str) -> bool:
    return (sub.get("metadata") or {}).get(_TENANT_META_KEY) == tenant_id


def _sub_price_and_item(sub: dict) -> tuple[str, str]:
    """Extract ``(price_id, item_id)`` from a subscription's first item, or
    ``("", "")`` if it has none. Defensive against missing nesting."""
    items = ((sub.get("items") or {}).get("data")) or []
    if not items:
        return "", ""
    first = items[0] or {}
    price = (first.get("price") or {})
    return str(price.get("id") or ""), str(first.get("id") or "")


def ensure_subscription(tenant_id: str, *,
                        client: StripeClient | None = None) -> dict:
    """Create or update the tenant's platform-fee subscription to match its
    current plan.

    The price for a plan comes from ``[billing.stripe] prices`` (plan id ->
    Stripe recurring price id). A plan with no configured price (e.g. ``free``)
    has no platform fee and is a no-op. Returns a small summary dict with a
    ``status`` of ``created`` / ``updated`` / ``unchanged`` / ``no_price``."""
    require_enabled()
    rec = _get_tenant(tenant_id)
    plan = rec.plan
    prices = get_billing_stripe().get("prices", {})
    price_id = prices.get(plan)
    if not price_id:
        return {"status": "no_price", "plan": plan, "tenant": tenant_id}
    cid = ensure_customer(tenant_id, client=client)
    cli = _client(client)
    metadata = {_TENANT_META_KEY: tenant_id, _PLAN_META_KEY: plan}
    owned = [s for s in cli.list_subscriptions(cid) if _sub_is_ours(s, tenant_id)]
    terminal = {"canceled", "incomplete_expired"}
    live = [s for s in owned if s.get("status") not in terminal]
    if len(live) > 1:
        raise StripeError("Multiple current platform subscriptions require reconciliation before sync")
    existing = live[0] if live else None
    if existing is None:
        # A new lifecycle must not reuse a key whose earlier response names a
        # now-canceled subscription. Identical readback still yields one key.
        lifecycle = ("-" + hashlib.sha256(json.dumps(sorted(str(s["id"]) for s in owned)).encode()).hexdigest()[:24]) if owned else ""
        sub = cli.create_subscription(
            customer_id=cid, price_id=price_id, metadata=metadata,
            idempotency_key=f"maverick-sub-{tenant_id}-{plan}{lifecycle}",
        )
        return {"status": "created", "tenant": tenant_id, "plan": plan,
                "price": price_id, "subscription": str(sub["id"]),
                "customer": cid}
    if existing.get("status") not in {"active", "trialing"}:
        raise StripeError(f"Platform subscription {existing['id']} is {existing.get('status', 'unknown')}; resolve its billing state before sync")
    if existing.get("cancel_at_period_end") or existing.get("cancel_at"):
        return {"status": "pending_cancellation", "tenant": tenant_id, "plan": plan,
                "subscription": str(existing["id"]), "customer": cid}
    cur_price, item_id = _sub_price_and_item(existing)
    if not item_id or len((existing.get("items") or {}).get("data") or []) != 1:
        raise StripeError("Platform subscription items require reconciliation before sync")
    if cur_price == price_id:
        return {"status": "unchanged", "tenant": tenant_id, "plan": plan,
                "price": price_id, "subscription": str(existing["id"]),
                "customer": cid}
    sub = cli.update_subscription(
        str(existing["id"]), item_id=item_id, price_id=price_id, metadata=metadata)
    return {"status": "updated", "tenant": tenant_id, "plan": plan,
            "price": price_id, "old_price": cur_price,
            "subscription": str(sub["id"]), "customer": cid}


def push_usage_items(tenant_id: str, invoice, *,
                     client: StripeClient | None = None) -> list[dict]:
    """Push the metered invoice's line items to Stripe as invoice items.

    Behind the :func:`bill_metered_usage` flag: **off by
    default**, in which case this bills nothing (the platform fee is the only
    charge) and returns ``[]``. When on, each :class:`~maverick.billing.LineItem`
    becomes one Stripe invoice item whose amount is the line's ``charge`` in the
    invoice currency's minor units -- so the amount is exactly what the operator's
    RateCard produced, never a markup invented here. Each item carries a
    deterministic idempotency key so re-running a closed period never
    double-bills."""
    require_enabled()
    if not bill_metered_usage():
        log.info("stripe: metered usage billing disabled (bill_metered_usage "
                 "is off); billing platform fee only for tenant %r", tenant_id)
        return []
    currency = (getattr(invoice, "currency", None) or "usd").lower()
    _validate_collection_period(tenant_id, invoice)
    rated = _rated_usage_items(invoice, currency)
    from .stripe_collection import collect_invoice

    return collect_invoice(tenant_id, invoice, currency, rated, client=client)


def _collect_invoice_items(tenant_id, invoice, currency, rated, *, client, state, save):
    cid = ensure_customer(tenant_id, client=client)
    cli = _client(client)
    if state.get("customer") not in {None, cid}:
        raise StripeError("Frozen invoice is bound to a different customer")
    state["customer"] = cid
    save()
    out: list[dict] = []
    period = invoice.invoice_id
    for li in rated:
        amount = li["amount_minor"]
        if amount <= 0:
            continue
        identity = (f"{li['day']}:{li['principal']}" if li["kind"] == "usage"
                    else json.dumps([li["kind"], li["day"], li["principal"]], separators=(",", ":")))
        key = "maverick-usage-" + hashlib.sha256(f"{tenant_id}:{period}:{identity}".encode()).hexdigest()[:32]
        receipt = state["items"].get(key)
        if receipt is not None and (
            not isinstance(receipt, dict) or receipt.get("status") not in {"pending", "complete"}
            or type(receipt.get("attempted_at")) not in (int, float)
            or not _money(receipt["attempted_at"]).is_finite()
            or receipt["attempted_at"] > time.time()
        ):
            raise StripeError("Collection receipt is invalid; reconcile before billing")
        if receipt and receipt.get("status") == "complete":
            result = receipt.get("result")
            if (not isinstance(result, dict) or not result.get("id")
                    or result.get("customer") != cid or result.get("amount") != amount
                    or result.get("currency") != currency or result.get("idempotency_key") != key):
                raise StripeError("Completed collection receipt does not match this invoice item")
            out.append(receipt["result"])
            continue
        if receipt and time.time() - receipt["attempted_at"] >= 23 * 3600:
            raise StripeError("Invoice item outcome is uncertain beyond the safe retry window; reconcile in Stripe before further collection")
        if receipt is None:
            receipt = {"status": "pending", "attempted_at": time.time()}
            state["items"][key] = receipt
            save()  # record intent before the external call; preserve on failure
        item = cli.create_invoice_item(
            customer_id=cid, amount=amount, currency=currency,
            description=("Minimum invoice adjustment" if li["kind"] == "minimum_adjustment" else f"Model usage {li['day']} · {li['principal']}"),
            metadata={
                _TENANT_META_KEY: tenant_id, "day": li["day"],
                "principal": li["principal"], "in_tokens": str(li["in_tokens"]),
                "out_tokens": str(li["out_tokens"]),
            },
            idempotency_key=key,
        )
        if not isinstance(item.get("id"), str) or not item["id"]:
            raise StripeError("Invoice item response lacks its durable identity; reconcile before retry")
        result = {"id": item["id"], "customer": cid, "amount": amount,
                  "currency": currency, "idempotency_key": key}
        receipt.update(status="complete", result=result)
        save()
        out.append(result)
    return out


def sync_tenant(tenant_id: str, *, client: StripeClient | None = None,
                invoice=None) -> dict:
    """One-shot: ensure the tenant's Stripe customer and platform-fee
    subscription, and (only when :func:`bill_metered_usage` is on and an
    ``invoice`` is supplied) push its metered usage. Returns a combined summary.

    The operator surface behind ``maverick billing stripe-sync``."""
    require_enabled()
    if invoice is not None and bill_metered_usage():
        _validate_collection_period(tenant_id, invoice)
        _rated_usage_items(invoice, (invoice.currency or "usd").lower())
    cid = ensure_customer(tenant_id, client=client)
    sub = ensure_subscription(tenant_id, client=client)
    result = {"tenant": tenant_id, "customer": cid, "subscription": sub}
    if invoice is not None:
        result["usage_items"] = push_usage_items(tenant_id, invoice, client=client)
    return result


def sync_tenant_for_period(tenant_id: str, card, *, since: str | None = None,
                           until: str | None = None,
                           client: StripeClient | None = None) -> dict:
    """What ``maverick billing stripe-sync`` does for one tenant and period.

    The period's usage is rated under ``card`` only when metered billing is on
    (otherwise only the platform-fee subscription is ensured), then
    :func:`sync_tenant` runs. Raises what :func:`sync_tenant` raises."""
    invoice = None
    if bill_metered_usage():
        from .billing import generate_invoice
        invoice = generate_invoice(tenant_id, card, since=since, until=until)
    return sync_tenant(tenant_id, client=client, invoice=invoice)


def preview_charges(tenant_id: str, card, *, since: str | None = None,
                    until: str | None = None) -> dict:
    """Dry-run: what a sync WOULD charge -- with no network calls at all.

    Shows the platform-fee price id for the tenant's plan and the metered invoice
    (from :func:`maverick.billing.generate_invoice` under ``card``), plus whether
    the metered line would actually be pushed given the bill_metered_usage flag.
    Works even when billing is disabled, so an operator can inspect before
    turning it on. Behind ``maverick billing stripe-preview``."""
    from .billing import generate_invoice
    from .tenant.registry import get_tenant
    rec = get_tenant(tenant_id)
    plan = rec.plan if rec else "free"
    cfg = get_billing_stripe()
    price_id = cfg.get("prices", {}).get(plan)
    invoice = generate_invoice(tenant_id, card, since=since, until=until)
    currency = (invoice.currency or cfg.get("currency", "usd")).lower()
    metered_on = bill_metered_usage()
    usage_minor = [row for row in _rated_usage_items(invoice, currency) if row["amount_minor"] > 0]
    return {
        "tenant": tenant_id,
        "plan": plan,
        "platform_fee_price": price_id,
        "platform_fee_configured": bool(price_id),
        "currency": currency,
        "metered_billing_enabled": metered_on,
        "metered_subtotal": invoice.subtotal,
        "metered_total": invoice.total,
        "usage_items_that_would_bill": usage_minor if metered_on else [],
        "usage_items_computed_but_not_billed": [] if metered_on else usage_minor,
        "invoice_id": invoice.invoice_id,
        "invoice": invoice.to_dict(),
        "billing_enabled": enabled(),
    }


# ---- webhook ---------------------------------------------------------------
#
# invoice.payment_failed / a past-due subscription -> downgrade to base tier;
# a recovered payment -> restore. The tenant is found from the event's metadata
# (maverick_tenant) or its Stripe customer id.

# invoice.* events that mean "paid"/"unpaid".
_DOWNGRADE_EVENTS = frozenset({"invoice.payment_failed"})
_RESTORE_EVENTS = frozenset({"invoice.payment_succeeded", "invoice.paid"})
# customer.subscription.* events carry a status we interpret.
_SUBSCRIPTION_EVENTS = frozenset({
    "customer.subscription.updated", "customer.subscription.deleted",
    "customer.subscription.created",
})
# Subscription statuses that mean the tenant should be on the base tier.
_PAST_DUE_SUB_STATUSES = frozenset({
    "past_due", "unpaid", "canceled", "incomplete_expired", "paused",
})
# Subscription statuses that mean the tenant is in good standing.
_ACTIVE_SUB_STATUSES = frozenset({"active", "trialing"})


def _parse_sig_header(header: str) -> tuple[int | None, list[str]]:
    """Parse a Stripe-Signature header ``t=...,v1=...,v1=...`` into
    ``(timestamp, [v1 signatures])``."""
    ts: int | None = None
    sigs: list[str] = []
    for part in (header or "").split(","):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k, v = k.strip(), v.strip()
        if k == "t":
            try:
                ts = int(v)
            except ValueError:
                ts = None
        elif k == "v1":
            sigs.append(v)
    return ts, sigs


def verify_webhook(payload: bytes | str, sig_header: str, *,
                   secret: str | None = None,
                   tolerance: int = _DEFAULT_WEBHOOK_TOLERANCE,
                   now: float | None = None) -> dict:
    """Verify a Stripe webhook signature (stdlib HMAC-SHA256) and return the
    parsed event.

    Implements Stripe's documented scheme -- ``HMAC-SHA256(secret,
    f"{t}.{payload}")`` compared constant-time against the header's ``v1``
    signature -- so it needs neither the SDK nor the network and unit-tests
    offline. Raises :class:`StripeWebhookError` on a missing secret, a malformed
    header, a stale timestamp (older than ``tolerance`` seconds; pass
    ``tolerance<=0`` to skip), or a signature mismatch."""
    body = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    key = (secret if secret is not None else _webhook_secret()).strip()
    if not key:
        raise StripeWebhookError(
            f"no webhook signing secret ({_WEBHOOK_SECRET_ENV} is unset)")
    ts, sigs = _parse_sig_header(sig_header)
    if ts is None or not sigs:
        raise StripeWebhookError("malformed Stripe-Signature header")
    if tolerance > 0:
        current = time.time() if now is None else now
        if abs(current - ts) > tolerance:
            raise StripeWebhookError("webhook timestamp outside tolerance window")
    signed = f"{ts}.".encode() + body
    expected = hmac.new(key.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    # Compare as bytes: the header is sender-controlled and compare_digest
    # raises TypeError on a str with any non-ASCII character.
    if not any(hmac.compare_digest(expected.encode("utf-8"), s.encode("utf-8"))
               for s in sigs):
        raise StripeWebhookError("webhook signature mismatch")
    import json
    try:
        event = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise StripeWebhookError(f"webhook body is not valid JSON: {exc}") from exc
    if not isinstance(event, dict):
        raise StripeWebhookError("webhook body is not a JSON object")
    return event


def _event_object(event: dict) -> dict:
    obj = ((event.get("data") or {}).get("object")) or {}
    return obj if isinstance(obj, dict) else {}


def _tenant_for_event(obj: dict) -> str | None:
    """Find the tenant an event's object belongs to: prefer the
    ``maverick_tenant`` metadata we stamp on every object we create, else map the
    Stripe customer id back through the registry."""
    tid = (obj.get("metadata") or {}).get(_TENANT_META_KEY)
    if tid:
        return str(tid)
    customer = obj.get("customer")
    if isinstance(customer, dict):
        customer = customer.get("id")
    if customer:
        from .tenant.registry import get_tenant_by_stripe_customer
        rec = get_tenant_by_stripe_customer(str(customer))
        if rec is not None:
            return rec.id
    return None


def _intended_action(event_type: str, obj: dict) -> str | None:
    """Map a (verified) event to ``"downgrade"`` / ``"restore"`` / ``None``."""
    if event_type in _DOWNGRADE_EVENTS:
        return "downgrade"
    if event_type in _RESTORE_EVENTS:
        return "restore"
    if event_type in _SUBSCRIPTION_EVENTS:
        if event_type == "customer.subscription.deleted":
            return "downgrade"
        sub_status = str(obj.get("status") or "")
        if sub_status in _PAST_DUE_SUB_STATUSES:
            return "downgrade"
        if sub_status in _ACTIVE_SUB_STATUSES:
            return "restore"
    return None


def handle_event(event: dict) -> dict:
    """Apply a **verified** Stripe event's entitlement effect.

    Pass the dict returned by :func:`verify_webhook` (or an equivalent already
    verified upstream -- this function does no signature check itself). A failed
    payment or a past-due/canceled subscription flips the tenant to
    ``billing_status = past_due`` (which downgrades it to the base entitlement
    tier via :func:`maverick.billing.tenant_entitled`); a recovered payment or a
    reactivated subscription flips it back to ``current``. Returns a summary dict
    with ``handled`` and, when acted on, the ``tenant`` and ``action``. Never
    raises for an unrelated/irrelevant event -- it is a no-op."""
    event_type = str(event.get("type") or "")
    obj = _event_object(event)
    action = _intended_action(event_type, obj)
    if action is None:
        return {"handled": False, "reason": "event not billing-relevant",
                "type": event_type}
    tenant_id = _tenant_for_event(obj)
    if tenant_id is None:
        return {"handled": False, "reason": "no tenant for event",
                "type": event_type}
    from .tenant.registry import (
        BILLING_CURRENT,
        BILLING_PAST_DUE,
        UnknownTenant,
        set_billing_status,
    )
    target = BILLING_PAST_DUE if action == "downgrade" else BILLING_CURRENT
    try:
        set_billing_status(tenant_id, target)
    except UnknownTenant:
        return {"handled": False, "reason": "unknown tenant", "tenant": tenant_id,
                "type": event_type}
    log.info("stripe webhook %s -> tenant %r billing_status=%s",
             event_type, tenant_id, target)
    return {"handled": True, "tenant": tenant_id, "action": action,
            "billing_status": target, "type": event_type}


__all__ = [
    "StripeError", "StripeDisabled", "StripeNotConfigured", "StripeWebhookError",
    "StripeStatus", "StripeClient",
    "available", "enabled", "bill_metered_usage", "status", "require_enabled",
    "ensure_customer", "ensure_subscription", "push_usage_items", "sync_tenant",
    "preview_charges", "verify_webhook", "handle_event",
]
