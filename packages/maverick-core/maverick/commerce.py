"""Commerce suite: governed shopper and merchant agents over pluggable backends.

Brings the design of Anthropic's open-source ``commerce-agents`` reference
(Apache-2.0; design only, no code copied) into the kernel as a *governed*
suite: a shopping agent (search / compare / cart / product Q&A / orders /
preference memory) and a merchant agent (analytics / inventory / pricing /
campaigns / listings / order ops), each over an abstract backend --
:class:`StorefrontBackend` and :class:`MerchantBackend` -- with an in-memory
:class:`DemoBackend` for tests and demos. The ``com_shop_*`` / ``com_merch_*``
domain packs are the agents; :mod:`maverick.tools.commerce_tools` is their
tool surface; this module is where the rules live.

The safety rules are encoded HERE, not in the pack prompts, so a prompt cannot
argue them away:

* **Caps** -- a :class:`ShopperSession` refuses a cart add that would exceed
  the per-line quantity cap, the cart-size cap, or the per-session spend cap
  (:class:`CommerceLimits`, from ``[commerce]``). A refused add is final.
* **Provenance gate** -- every product fact and merchant row a session returns
  carries :class:`Provenance` (``source`` + ``fetched_at``); a backend result
  without it is rejected (:class:`ProvenanceError`), never passed through.
* **Staged writes** -- a change to price, inventory, listing, campaign, order
  resolution, or a return request is a :class:`StagedChange` recorded in a
  :class:`ProposalLedger`. The proposing agent gets back only the public
  summary; the approval token is minted for the human approval path and an
  ``agent:`` principal can never apply a proposal.
* **Checkout handoff** -- :meth:`ShopperSession.checkout_handoff` returns an
  opaque cart reference and a scheme-host-path cart link. Query strings and
  fragments (session tokens, coupons) are dropped, a link naming the
  checkout/payment step is refused, and the backend interface has no method
  that could return card, address, or checkout-page data.

Off by default (``[commerce] enable`` / ``MAVERICK_COMMERCE=1``): the tools are
registered into the base registry only when the operator opts in
(:func:`enabled`), so the default tool catalog is unchanged (kernel rule 1).
"""
from __future__ import annotations

import functools
import re
import secrets
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .config import env_flag
from .constant_time import text_equals

#: Staged-write kinds a session may propose. Every one changes the store or an
#: order, so every one waits for a human. A shopper session stages only
#: ``return_request`` (about its own order); the rest are merchant-side.
STAGED_KINDS: tuple[str, ...] = (
    "price", "inventory", "listing", "campaign", "order_resolution", "return_request",
)

_MAX_CHANGE_FIELDS = 32
_MAX_CHANGE_VALUE_CHARS = 500
_MAX_PREFERENCES = 32
_MAX_PREFERENCE_CHARS = 200
_MAX_SEARCH_LIMIT = 50
_PREFERENCE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
#: Preference keys the memory must never hold -- refused, not remembered.
_FORBIDDEN_PREFERENCE_KEYS = frozenset({
    "card", "card_number", "credit_card", "cvv", "cvc", "pan", "expiry",
    "bank", "bank_account", "iban", "routing_number", "password", "passcode",
    "pin", "ssn", "address", "shipping_address", "billing_address", "token",
})
#: Path segments that mark the checkout / payment step of a storefront. A cart
#: link that points there is refused: the agent hands off the cart, never the
#: checkout.
_CHECKOUT_STEP_SEGMENTS = frozenset({
    "checkout", "checkouts", "payment", "payments", "pay", "billing",
})


# --- errors -----------------------------------------------------------------

class CommerceError(RuntimeError):
    """Base class for every refusal this module issues."""


class CapExceeded(CommerceError):
    """A cart add or handoff would exceed a per-session cap."""


class ProvenanceError(CommerceError):
    """A backend returned a product fact without source + fetched_at."""


class ApprovalRequired(CommerceError):
    """A staged change was asked to apply without a valid human approval."""


class UnknownProduct(CommerceError):
    """The product is not in the catalog (or not in the cart)."""


class UnknownOrder(CommerceError):
    """The order does not exist for this customer."""


class UnknownProposal(CommerceError):
    """No staged change with that proposal id."""


def _utcnow() -> str:
    return (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        .replace("+00:00", "Z")
    )


# --- records ----------------------------------------------------------------

@dataclass(frozen=True)
class Provenance:
    """Where a product fact came from and when it was read. Every fact a
    session passes to an agent carries one; the agent cites it."""
    source: str
    fetched_at: str  # ISO-8601 UTC

    @classmethod
    def now(cls, source: str) -> Provenance:
        return cls(source=source, fetched_at=_utcnow())

    def valid(self) -> bool:
        return bool(str(self.source).strip()) and bool(str(self.fetched_at).strip())

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "fetched_at": self.fetched_at}


@dataclass
class Product:
    product_id: str
    title: str
    price: float
    currency: str = "USD"
    in_stock: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)
    provenance: Provenance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "title": self.title,
            "price": self.price,
            "currency": self.currency,
            "in_stock": self.in_stock,
            "attributes": dict(self.attributes),
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }


@dataclass
class CartLine:
    product_id: str
    title: str
    unit_price: float
    quantity: int
    currency: str = "USD"

    @property
    def line_total(self) -> float:
        return round(self.unit_price * self.quantity, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "title": self.title,
            "unit_price": self.unit_price,
            "quantity": self.quantity,
            "line_total": self.line_total,
            "currency": self.currency,
        }


@dataclass
class Cart:
    cart_ref: str
    lines: list[CartLine] = field(default_factory=list)
    currency: str = "USD"

    @property
    def subtotal(self) -> float:
        return round(sum(line.line_total for line in self.lines), 2)

    @property
    def item_count(self) -> int:
        return sum(line.quantity for line in self.lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cart_ref": self.cart_ref,
            "lines": [line.to_dict() for line in self.lines],
            "item_count": self.item_count,
            "subtotal": self.subtotal,
            "currency": self.currency,
        }


@dataclass
class Order:
    order_id: str
    customer_ref: str
    status: str
    placed_at: str
    total: float
    currency: str = "USD"
    items: list[dict[str, Any]] = field(default_factory=list)
    tracking: str = ""
    provenance: Provenance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "order_id": self.order_id,
            "customer_ref": self.customer_ref,
            "status": self.status,
            "placed_at": self.placed_at,
            "total": self.total,
            "currency": self.currency,
            "items": [dict(item) for item in self.items],
            "tracking": self.tracking,
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }


@dataclass(frozen=True)
class CheckoutHandoff:
    """What the agent may render for the shopper: an opaque cart reference and
    a cart link reduced to scheme + host + path. Nothing else crosses."""
    cart_ref: str
    cart_link: str
    item_count: int
    subtotal: float
    currency: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cart_ref": self.cart_ref,
            "cart_link": self.cart_link,
            "item_count": self.item_count,
            "subtotal": self.subtotal,
            "currency": self.currency,
        }


@dataclass
class StagedChange:
    """A proposed store/order change awaiting a human decision.

    There is deliberately no approval token on this record: the token lives
    only in the :class:`ProposalLedger`, so serializing a proposal for the
    proposing agent (or a dashboard) can never hand out the means to apply it.
    """
    proposal_id: str
    kind: str
    target: str
    changes: dict[str, Any]
    rationale: str
    proposed_by: str
    created_at: str
    status: str = "pending"  # pending | applied | rejected
    decided_by: str = ""
    decided_at: str = ""
    result: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "kind": self.kind,
            "target": self.target,
            "changes": dict(self.changes),
            "rationale": self.rationale,
            "proposed_by": self.proposed_by,
            "created_at": self.created_at,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "result": dict(self.result),
        }


@dataclass(frozen=True)
class Approval:
    """A human decision on a staged change: who, and the proposal's approval
    token obtained through the human approval path."""
    approver: str
    token: str


# --- knob + caps ------------------------------------------------------------

@dataclass(frozen=True)
class CommerceLimits:
    """Per-session caps. Defaults are deliberately modest; ``[commerce]``
    raises them explicitly."""
    max_session_spend: float = 500.0
    max_line_quantity: int = 10
    max_cart_lines: int = 25


def enabled() -> bool:
    """Whether the Commerce suite tools are on. ``MAVERICK_COMMERCE`` overrides
    ``[commerce] enable``; OFF by default (an explicit opt-in, like
    ``[fleet_memory]``). Never raises."""
    flag = env_flag("MAVERICK_COMMERCE")
    if flag is not None:
        return flag
    try:
        from .config import get_commerce
        return bool(get_commerce().get("enable", False))
    except Exception:  # pragma: no cover -- config never blocks a run
        return False


def configured_limits() -> CommerceLimits:
    """The caps from ``[commerce]`` (defaults when unset or unreadable --
    a config failure tightens, it never removes a cap)."""
    try:
        from .config import get_commerce
        cfg = get_commerce()
        return CommerceLimits(
            max_session_spend=float(cfg["max_session_spend"]),
            max_line_quantity=int(cfg["max_line_quantity"]),
            max_cart_lines=int(cfg["max_cart_lines"]),
        )
    except Exception:  # pragma: no cover -- config never blocks a run
        return CommerceLimits()


def _configured_backend_name() -> str:
    try:
        from .config import get_commerce
        return str(get_commerce().get("backend") or "demo")
    except Exception:  # pragma: no cover
        return "demo"


# --- backend interfaces -----------------------------------------------------

class StorefrontBackend(ABC):
    """The shopper-side surface a storefront exposes to the agent.

    Deliberately narrow: there is no method that returns payment, address, or
    checkout-page data, so no implementation can hand them to an agent through
    this interface. :meth:`cart_link` is the shareable *cart* URL (the session
    reduces it to scheme + host + path before it reaches the agent); the
    checkout step itself belongs to the shopper, outside the agent entirely.
    """

    @abstractmethod
    def search(self, query: str, *, limit: int = 10) -> list[Product]:
        """Catalog products matching ``query``, each with provenance."""
        raise NotImplementedError

    @abstractmethod
    def product(self, product_id: str) -> Product | None:
        """One product's full record with provenance, or ``None``."""
        raise NotImplementedError

    @abstractmethod
    def cart_view(self, cart_ref: str) -> Cart:
        """The cart for an opaque reference (created empty on first use)."""
        raise NotImplementedError

    @abstractmethod
    def cart_add(self, cart_ref: str, product_id: str, quantity: int) -> Cart:
        """Add ``quantity`` of a product; returns the updated cart."""
        raise NotImplementedError

    @abstractmethod
    def cart_remove(self, cart_ref: str, product_id: str) -> Cart:
        """Drop a product line; returns the updated cart."""
        raise NotImplementedError

    @abstractmethod
    def cart_link(self, cart_ref: str) -> str:
        """The shareable cart URL. NOT the checkout URL."""
        raise NotImplementedError

    @abstractmethod
    def customer_orders(self, customer_ref: str) -> list[Order]:
        """Only this customer's orders, each with provenance."""
        raise NotImplementedError

    @abstractmethod
    def return_policy(self) -> str:
        """The store's return / exchange policy text."""
        raise NotImplementedError


class MerchantBackend(ABC):
    """The merchant-side surface. Reads return rows that each carry
    ``provenance``; the ONLY write is :meth:`apply_change`, which the
    :class:`ProposalLedger` calls after a human approval is verified -- a
    backend is never handed an unapproved change."""

    @abstractmethod
    def catalog(self, query: str = "", *, limit: int = 50) -> list[Product]:
        raise NotImplementedError

    @abstractmethod
    def inventory(self, sku: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def pricing(self, sku: str | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def orders(self, status: str | None = None, *, limit: int = 50) -> list[Order]:
        raise NotImplementedError

    @abstractmethod
    def analytics(self, metric: str, window: str = "7d") -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def campaigns(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def apply_change(self, change: StagedChange) -> dict[str, Any]:
        """Apply an APPROVED staged change and return a result summary."""
        raise NotImplementedError


# --- gates ------------------------------------------------------------------

def _gate_product(product: Any, *, where: str) -> Product:
    """The provenance gate for a product fact."""
    if not isinstance(product, Product):
        raise ProvenanceError(f"{where} returned a non-product result; refusing to pass it on")
    prov = product.provenance
    if not isinstance(prov, Provenance) or not prov.valid():
        raise ProvenanceError(
            f"{where} returned product {product.product_id!r} without provenance "
            "(source + fetched_at); refusing to pass it on"
        )
    return product


def _gate_row(row: Any, *, where: str) -> dict[str, Any]:
    """The provenance gate for a merchant/analytics row."""
    if not isinstance(row, dict):
        raise ProvenanceError(f"{where} returned a non-row result; refusing to pass it on")
    prov = row.get("provenance")
    if isinstance(prov, Provenance):
        prov = prov.to_dict()
    if (
        not isinstance(prov, dict)
        or not str(prov.get("source") or "").strip()
        or not str(prov.get("fetched_at") or "").strip()
    ):
        raise ProvenanceError(
            f"{where} returned a row without provenance (source + fetched_at); "
            "refusing to pass it on"
        )
    return {**row, "provenance": dict(prov)}


def _gate_order(order: Any, *, where: str) -> Order:
    if not isinstance(order, Order):
        raise ProvenanceError(f"{where} returned a non-order result; refusing to pass it on")
    prov = order.provenance
    if not isinstance(prov, Provenance) or not prov.valid():
        raise ProvenanceError(
            f"{where} returned order {order.order_id!r} without provenance; "
            "refusing to pass it on"
        )
    return order


def opaque_cart_link(raw: str) -> str:
    """Reduce a backend cart link to ``scheme://host/path``.

    Query strings and fragments are dropped (session tokens, coupons, tracking
    parameters), embedded credentials are refused, and a path that names the
    checkout / payment step is refused outright: the agent renders the cart,
    never the checkout.
    """
    parts = urlsplit(str(raw or "").strip())
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise CommerceError("the backend returned an unusable cart link")
    if "@" in parts.netloc:
        raise CommerceError("cart link must not embed credentials")
    path = parts.path or "/"
    segments = {seg.lower() for seg in path.split("/") if seg}
    if segments & _CHECKOUT_STEP_SEGMENTS:
        raise CommerceError(
            "cart link points at the checkout/payment step; the agent hands off "
            "the cart only"
        )
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _clean_changes(changes: Any) -> dict[str, Any]:
    if not isinstance(changes, dict) or not changes:
        raise ValueError("changes must be a non-empty mapping of field -> proposed value")
    if len(changes) > _MAX_CHANGE_FIELDS:
        raise ValueError(f"a staged change carries at most {_MAX_CHANGE_FIELDS} fields")
    out: dict[str, Any] = {}
    for raw_key, value in changes.items():
        key = str(raw_key).strip()
        if not key:
            raise ValueError("a change field name is empty")
        if value is None or isinstance(value, (bool, int, float)):
            out[key] = value
            continue
        text = str(value)
        if len(text) > _MAX_CHANGE_VALUE_CHARS:
            raise ValueError(
                f"change field {key!r} exceeds {_MAX_CHANGE_VALUE_CHARS} characters"
            )
        out[key] = text
    return out


def _is_human_principal(approver: str) -> bool:
    who = str(approver or "").strip()
    return bool(who) and not who.startswith("agent:") and who != "system"


def _audit(event_kind: str, **payload: Any) -> None:
    """One signed audit row per staged proposal and per human decision.

    ``audit_event`` applies the refusal contract: an ``AuditRefused`` propagates
    (a decision we cannot record must not proceed), any other write failure is
    logged with a traceback rather than silently dropped.
    """
    from .audit import audit_event
    audit_event(event_kind, agent="commerce", **payload)


# --- staged writes ----------------------------------------------------------

class ProposalLedger:
    """Staged writes awaiting a human decision.

    The proposing agent receives only a proposal's public summary. The
    approval token is minted here and handed only to the human approval path
    (:meth:`approval_token`); :meth:`apply` and :meth:`reject` verify it in
    constant time and refuse any ``agent:`` principal, so an agent can neither
    approve its own proposal nor forge someone else's decision. Tokens are
    single-use.
    """

    def __init__(self) -> None:
        self._items: dict[str, StagedChange] = {}
        self._tokens: dict[str, str] = {}

    def stage(self, *, kind: str, target: str, changes: Any, rationale: str,
              proposed_by: str) -> StagedChange:
        kind = str(kind or "").strip().lower()
        if kind not in STAGED_KINDS:
            raise ValueError(
                f"unknown staged-change kind {kind!r}; expected one of "
                + ", ".join(STAGED_KINDS)
            )
        target = str(target or "").strip()
        if not target:
            raise ValueError("target (the SKU / product / campaign / order id) is required")
        rationale = str(rationale or "").strip()
        if not rationale:
            raise ValueError("rationale is required: say why the change is proposed")
        cleaned = _clean_changes(changes)
        proposal_id = f"prop_{secrets.token_hex(6)}"
        who = str(proposed_by or "").strip() or "agent:commerce"
        # Audit BEFORE recording: a proposal the chain refuses to record does
        # not exist.
        from .audit import EventKind
        _audit(
            EventKind.AUTONOMY_GATED, tool=f"commerce_stage_{kind}",
            proposal_id=proposal_id, target=target, proposed_by=who,
            commerce="staged",
        )
        change = StagedChange(
            proposal_id=proposal_id, kind=kind, target=target, changes=cleaned,
            rationale=rationale, proposed_by=who, created_at=_utcnow(),
        )
        self._items[proposal_id] = change
        self._tokens[proposal_id] = secrets.token_urlsafe(24)
        return change

    def get(self, proposal_id: str) -> StagedChange | None:
        return self._items.get(str(proposal_id))

    def pending(self) -> list[dict[str, Any]]:
        return [c.to_public_dict() for c in self._items.values() if c.status == "pending"]

    def approval_token(self, proposal_id: str) -> str:
        """The token the HUMAN approval path presents to :meth:`apply` or
        :meth:`reject`. Never return it to the proposing agent: it is what
        separates *proposed* from *approved*."""
        token = self._tokens.get(str(proposal_id))
        if token is None:
            raise UnknownProposal(f"no pending proposal {proposal_id!r}")
        return token

    def _authorize(self, proposal_id: str, approval: Any) -> StagedChange:
        change = self._items.get(str(proposal_id))
        if change is None:
            raise UnknownProposal(f"no proposal {proposal_id!r}")
        if change.status != "pending":
            raise ApprovalRequired(f"proposal {proposal_id!r} is already {change.status}")
        if not isinstance(approval, Approval):
            raise ApprovalRequired("a human Approval (approver + token) is required")
        if not _is_human_principal(approval.approver):
            raise ApprovalRequired(
                "a staged change is decided by a person, never by an agent principal"
            )
        expected = self._tokens.get(change.proposal_id, "")
        if not expected or not text_equals(expected, str(approval.token or "")):
            raise ApprovalRequired("approval token does not match this proposal")
        return change

    def _decide(self, change: StagedChange, approval: Approval, decision: str,
                **extra: Any) -> None:
        from .audit import EventKind
        _audit(
            EventKind.APPROVAL_DECISION, approval_event_id=uuid.uuid4().hex,
            decision=decision, proposal_id=change.proposal_id,
            change_kind=change.kind, target=change.target,
            approver=approval.approver.strip(), commerce=decision, **extra,
        )

    def apply(self, proposal_id: str, approval: Any,
              applier: Callable[[StagedChange], dict[str, Any] | None]) -> StagedChange:
        """Verify the human approval, record the decision, then apply through
        ``applier`` (the backend's ``apply_change``). If the applier fails the
        proposal stays pending and the token stays valid for a retry."""
        change = self._authorize(proposal_id, approval)
        self._decide(change, approval, "approved")
        result = applier(change)
        change.status = "applied"
        change.decided_by = approval.approver.strip()
        change.decided_at = _utcnow()
        change.result = dict(result or {})
        self._tokens.pop(change.proposal_id, None)
        return change

    def reject(self, proposal_id: str, approval: Any, reason: str = "") -> StagedChange:
        change = self._authorize(proposal_id, approval)
        self._decide(change, approval, "rejected", reason=str(reason or ""))
        change.status = "rejected"
        change.decided_by = approval.approver.strip()
        change.decided_at = _utcnow()
        change.result = {"reason": str(reason or "")}
        self._tokens.pop(change.proposal_id, None)
        return change


@functools.lru_cache(maxsize=1)
def default_ledger() -> ProposalLedger:
    """The process-wide ledger the tool sessions share (proposals await a
    person, so they outlive one agent turn)."""
    return ProposalLedger()


# --- governed sessions ------------------------------------------------------

class ShopperSession:
    """The shopper-side facade the tools call. Owns one opaque cart, the
    per-session caps, the provenance gate, the customer scope for orders, and
    the shopper's stated preferences."""

    def __init__(self, backend: StorefrontBackend, *, customer_ref: str = "cust_demo",
                 principal: str = "agent:commerce", limits: CommerceLimits | None = None,
                 ledger: ProposalLedger | None = None) -> None:
        self.backend = backend
        self.customer_ref = str(customer_ref or "cust_demo")
        self.principal = str(principal or "agent:commerce")
        self.limits = limits or configured_limits()
        self.ledger = ledger or default_ledger()
        self.cart_ref = f"cart_{secrets.token_hex(8)}"
        self._preferences: dict[str, str] = {}

    # reads ------------------------------------------------------------
    def search(self, query: str, *, limit: int = 10) -> list[Product]:
        query = str(query or "").strip()
        if not query:
            raise ValueError("query is required")
        limit = max(1, min(int(limit), _MAX_SEARCH_LIMIT))
        results = self.backend.search(query, limit=limit)
        return [_gate_product(p, where="storefront search") for p in list(results)[:limit]]

    def product(self, product_id: str) -> Product:
        product_id = str(product_id or "").strip()
        found = self.backend.product(product_id) if product_id else None
        if found is None:
            raise UnknownProduct(f"no catalog product {product_id!r}")
        return _gate_product(found, where="storefront product")

    def cart_view(self) -> Cart:
        return self.backend.cart_view(self.cart_ref)

    def orders(self) -> list[Order]:
        # The session passes ONLY its own customer reference: another
        # customer's orders are unreachable by construction.
        rows = self.backend.customer_orders(self.customer_ref)
        return [_gate_order(o, where="storefront orders") for o in rows]

    def order(self, order_id: str) -> Order:
        order_id = str(order_id or "").strip()
        for order in self.orders():
            if order.order_id == order_id:
                return order
        raise UnknownOrder(f"no order {order_id!r} for this shopper")

    def return_policy(self) -> str:
        return str(self.backend.return_policy() or "")

    # cart (capped) -----------------------------------------------------
    def cart_add(self, product_id: str, quantity: int = 1) -> Cart:
        quantity = int(quantity)
        if quantity < 1:
            raise ValueError("quantity must be at least 1")
        lim = self.limits
        if quantity > lim.max_line_quantity:
            raise CapExceeded(
                f"quantity {quantity} exceeds the per-line cap of {lim.max_line_quantity}"
            )
        product = self.product(product_id)
        if not product.in_stock:
            raise CommerceError(f"{product.title!r} is out of stock")
        cart = self.cart_view()
        existing = next((ln for ln in cart.lines if ln.product_id == product.product_id), None)
        if existing is not None and existing.quantity + quantity > lim.max_line_quantity:
            raise CapExceeded(
                f"{existing.quantity + quantity} of {product.title!r} exceeds the "
                f"per-line cap of {lim.max_line_quantity}"
            )
        if existing is None and len(cart.lines) + 1 > lim.max_cart_lines:
            raise CapExceeded(f"the cart holds at most {lim.max_cart_lines} lines")
        projected = round(cart.subtotal + product.price * quantity, 2)
        if projected > lim.max_session_spend:
            raise CapExceeded(
                f"adding {quantity} x {product.title!r} would bring the cart to "
                f"{projected:.2f} {product.currency}, over the session cap of "
                f"{lim.max_session_spend:.2f}"
            )
        return self.backend.cart_add(self.cart_ref, product.product_id, quantity)

    def cart_remove(self, product_id: str) -> Cart:
        product_id = str(product_id or "").strip()
        cart = self.cart_view()
        if not any(ln.product_id == product_id for ln in cart.lines):
            raise UnknownProduct(f"{product_id!r} is not in the cart")
        return self.backend.cart_remove(self.cart_ref, product_id)

    def checkout_handoff(self) -> CheckoutHandoff:
        """Hand the cart to the shopper. Returns the opaque cart reference and
        the sanitized cart link -- never card, address, or checkout-page data
        (the interface cannot even return them)."""
        cart = self.cart_view()
        if not cart.lines:
            raise CommerceError("the cart is empty; nothing to hand off")
        if cart.subtotal > self.limits.max_session_spend:
            raise CapExceeded(
                f"cart subtotal {cart.subtotal:.2f} exceeds the session cap of "
                f"{self.limits.max_session_spend:.2f}"
            )
        link = opaque_cart_link(self.backend.cart_link(self.cart_ref))
        return CheckoutHandoff(
            cart_ref=self.cart_ref, cart_link=link, item_count=cart.item_count,
            subtotal=cart.subtotal, currency=cart.currency,
        )

    # staged writes -----------------------------------------------------
    def stage_return(self, order_id: str, reason: str) -> StagedChange:
        order = self.order(order_id)  # customer-scoped: not yours -> UnknownOrder
        return self.ledger.stage(
            kind="return_request", target=order.order_id,
            changes={"reason": str(reason or "").strip(), "customer_ref": self.customer_ref},
            rationale=str(reason or ""), proposed_by=self.principal,
        )

    # preference memory ---------------------------------------------------
    def preferences(self) -> dict[str, str]:
        return dict(self._preferences)

    @staticmethod
    def _preference_key(key: str) -> str:
        norm = re.sub(r"[^a-z0-9]+", "_", str(key or "").strip().lower()).strip("_")
        if not _PREFERENCE_KEY_RE.fullmatch(norm):
            raise ValueError("preference key must be a short word like shoe_size or brand")
        if norm in _FORBIDDEN_PREFERENCE_KEYS or any(
            norm.startswith(f"{bad}_") or norm.endswith(f"_{bad}")
            for bad in _FORBIDDEN_PREFERENCE_KEYS
        ):
            raise CommerceError(
                f"refusing to remember {norm!r}: payment, credential, and address "
                "data are never stored as preferences"
            )
        return norm

    def set_preference(self, key: str, value: str) -> None:
        norm = self._preference_key(key)
        text = str(value or "").strip()
        if not text:
            raise ValueError("preference value is required")
        if len(text) > _MAX_PREFERENCE_CHARS:
            raise ValueError(f"preference value exceeds {_MAX_PREFERENCE_CHARS} characters")
        if norm not in self._preferences and len(self._preferences) >= _MAX_PREFERENCES:
            raise CapExceeded(f"at most {_MAX_PREFERENCES} preferences are kept")
        self._preferences[norm] = text

    def delete_preference(self, key: str) -> None:
        self._preferences.pop(self._preference_key(key), None)


class MerchantSession:
    """The merchant-side facade: provenance-gated reads and staged writes.
    Nothing here applies a change; :meth:`apply` is the human path."""

    def __init__(self, backend: MerchantBackend, *, principal: str = "agent:commerce",
                 ledger: ProposalLedger | None = None) -> None:
        self.backend = backend
        self.principal = str(principal or "agent:commerce")
        self.ledger = ledger or default_ledger()

    def catalog(self, query: str = "", *, limit: int = 50) -> list[Product]:
        limit = max(1, min(int(limit), 500))
        rows = self.backend.catalog(str(query or "").strip(), limit=limit)
        return [_gate_product(p, where="merchant catalog") for p in list(rows)[:limit]]

    def inventory(self, sku: str | None = None) -> list[dict[str, Any]]:
        return [_gate_row(r, where="inventory") for r in self.backend.inventory(sku)]

    def pricing(self, sku: str | None = None) -> list[dict[str, Any]]:
        return [_gate_row(r, where="pricing") for r in self.backend.pricing(sku)]

    def orders(self, status: str | None = None, *, limit: int = 50) -> list[Order]:
        limit = max(1, min(int(limit), 500))
        rows = self.backend.orders(status, limit=limit)
        return [_gate_order(o, where="merchant orders") for o in list(rows)[:limit]]

    def analytics(self, metric: str, window: str = "7d") -> dict[str, Any]:
        metric = str(metric or "").strip().lower()
        if not metric:
            raise ValueError("metric is required")
        return _gate_row(self.backend.analytics(metric, str(window or "7d")), where="analytics")

    def campaigns(self) -> list[dict[str, Any]]:
        return [_gate_row(r, where="campaigns") for r in self.backend.campaigns()]

    def stage_change(self, kind: str, target: str, changes: Any, rationale: str) -> StagedChange:
        return self.ledger.stage(
            kind=kind, target=target, changes=changes, rationale=rationale,
            proposed_by=self.principal,
        )

    def pending(self) -> list[dict[str, Any]]:
        return self.ledger.pending()

    def apply(self, proposal_id: str, approval: Approval) -> StagedChange:
        """The HUMAN path: apply one staged change with its approval token."""
        return self.ledger.apply(proposal_id, approval, self.backend.apply_change)

    def reject(self, proposal_id: str, approval: Approval, reason: str = "") -> StagedChange:
        return self.ledger.reject(proposal_id, approval, reason)


# --- demo backend -----------------------------------------------------------

_DEMO_PRODUCTS: tuple[tuple[str, str, float, bool, dict[str, Any]], ...] = (
    ("sku-trail-01", "Trail Runner Shoes", 129.0, True,
     {"category": "footwear", "sizes": "7-13", "weight_g": 280, "waterproof": False,
      "color": "slate"}),
    ("sku-merino-02", "Merino Base Layer", 79.0, True,
     {"category": "apparel", "material": "merino wool", "sizes": "S-XL", "color": "charcoal"}),
    ("sku-hydra-03", "Hydration Pack 2L", 59.0, True,
     {"category": "packs", "capacity_l": 2, "weight_g": 340, "color": "moss"}),
    ("sku-stove-04", "Compact Camp Stove", 45.0, True,
     {"category": "cooking", "fuel": "isobutane", "boil_time_min": 3.5}),
    ("sku-lamp-05", "Headlamp 400lm", 39.0, False,
     {"category": "lighting", "lumens": 400, "battery": "USB-C"}),
)

_DEMO_ANALYTICS: dict[tuple[str, str], tuple[float, float, str]] = {
    ("revenue", "7d"): (12840.0, 11210.0, "USD"),
    ("revenue", "30d"): (51200.0, 48900.0, "USD"),
    ("orders", "7d"): (164.0, 141.0, "count"),
    ("orders", "30d"): (655.0, 630.0, "count"),
    ("sessions", "7d"): (9120.0, 8770.0, "count"),
    ("sessions", "30d"): (36400.0, 35100.0, "count"),
    ("conversion", "7d"): (1.8, 1.6, "percent"),
    ("conversion", "30d"): (1.8, 1.8, "percent"),
    ("aov", "7d"): (78.3, 79.5, "USD"),
    ("aov", "30d"): (78.2, 77.6, "USD"),
}

_DEMO_RETURN_POLICY = (
    "Returns are accepted within 30 days of delivery for unused items in their "
    "original packaging; final-sale items are excluded. Refunds go to the "
    "original payment method within 5 business days of receipt."
)


class DemoBackend(StorefrontBackend, MerchantBackend):
    """In-memory storefront + merchant backend for tests and demos.

    Small fixed catalog, inventory, pricing, orders for two customers,
    analytics, and one campaign. Everything it returns carries provenance
    (``source="demo-store"``). The cart link carries a session parameter on
    purpose, so the handoff sanitizer is exercised; the checkout page
    (:meth:`checkout_url`) exists only so a test can prove it never crosses.
    """

    SOURCE = "demo-store"

    def __init__(self) -> None:
        self._products: dict[str, Product] = {
            pid: Product(pid, title, price, "USD", in_stock, dict(attrs))
            for pid, title, price, in_stock, attrs in _DEMO_PRODUCTS
        }
        self._inventory: dict[str, dict[str, Any]] = {
            "sku-trail-01": {"on_hand": 42, "inbound": 60, "sell_through_7d": 31},
            "sku-merino-02": {"on_hand": 8, "inbound": 0, "sell_through_7d": 19},
            "sku-hydra-03": {"on_hand": 120, "inbound": 0, "sell_through_7d": 6},
            "sku-stove-04": {"on_hand": 15, "inbound": 40, "sell_through_7d": 12},
            "sku-lamp-05": {"on_hand": 0, "inbound": 200, "sell_through_7d": 0},
        }
        self._pricing: dict[str, dict[str, Any]] = {
            "sku-trail-01": {"unit_cost": 61.0, "margin_floor_pct": 35.0, "map_price": 119.0},
            "sku-merino-02": {"unit_cost": 34.0, "margin_floor_pct": 40.0, "map_price": None},
            "sku-hydra-03": {"unit_cost": 22.0, "margin_floor_pct": 40.0, "map_price": None},
            "sku-stove-04": {"unit_cost": 19.5, "margin_floor_pct": 35.0, "map_price": 42.0},
            "sku-lamp-05": {"unit_cost": 14.0, "margin_floor_pct": 40.0, "map_price": None},
        }
        self._orders: list[Order] = [
            Order("ord-1001", "cust_demo", "shipped", "2026-08-28T10:00:00Z", 129.0, "USD",
                  [{"product_id": "sku-trail-01", "quantity": 1, "unit_price": 129.0}],
                  tracking="TRK-1001-DEMO"),
            Order("ord-1002", "cust_demo", "processing", "2026-09-01T16:30:00Z", 138.0, "USD",
                  [{"product_id": "sku-merino-02", "quantity": 1, "unit_price": 79.0},
                   {"product_id": "sku-hydra-03", "quantity": 1, "unit_price": 59.0}]),
            Order("ord-2001", "cust_other", "delivered", "2026-08-20T09:15:00Z", 45.0, "USD",
                  [{"product_id": "sku-stove-04", "quantity": 1, "unit_price": 45.0}],
                  tracking="TRK-2001-DEMO"),
        ]
        self._campaigns: list[dict[str, Any]] = [{
            "campaign_id": "cmp-fall-01", "name": "Fall Trail Sale", "status": "scheduled",
            "discount_pct": 15.0, "skus": ["sku-trail-01", "sku-hydra-03"],
            "starts": "2026-09-15", "ends": "2026-09-22",
        }]
        self._carts: dict[str, Cart] = {}
        self._session_param = secrets.token_hex(8)
        # The shopper's checkout data. It is NOT reachable through either
        # interface; it is here so tests can prove the handoff never carries it.
        self._private_checkout: dict[str, str] = {
            "card_on_file": "visa ending 4242",
            "shipping_address": "1 Demo Way, Springfield",
        }

    # helpers ---------------------------------------------------------------
    def _stamp(self, product: Product) -> Product:
        return Product(
            product.product_id, product.title, product.price, product.currency,
            product.in_stock, dict(product.attributes), Provenance.now(self.SOURCE),
        )

    def _stamp_order(self, order: Order) -> Order:
        return Order(
            order.order_id, order.customer_ref, order.status, order.placed_at,
            order.total, order.currency, [dict(i) for i in order.items], order.tracking,
            Provenance.now(self.SOURCE),
        )

    def _row(self, **fields: Any) -> dict[str, Any]:
        return {**fields, "provenance": Provenance.now(self.SOURCE).to_dict()}

    def _cart(self, cart_ref: str) -> Cart:
        cart = self._carts.get(cart_ref)
        if cart is None:
            cart = self._carts[cart_ref] = Cart(cart_ref=cart_ref)
        return cart

    def _find_order(self, order_id: str) -> Order:
        for order in self._orders:
            if order.order_id == order_id:
                return order
        raise UnknownOrder(f"no order {order_id!r}")

    def checkout_url(self, cart_ref: str) -> str:
        """The shopper's checkout page. Outside both interfaces on purpose."""
        return f"https://demo-store.invalid/checkout/{cart_ref}?session={self._session_param}"

    # StorefrontBackend -----------------------------------------------------
    def search(self, query: str, *, limit: int = 10) -> list[Product]:
        tokens = [t for t in re.split(r"\W+", str(query).lower()) if t]
        out: list[Product] = []
        for product in self._products.values():
            haystack = " ".join(
                [product.product_id, product.title]
                + [str(v) for v in product.attributes.values()]
            ).lower()
            if any(tok in haystack for tok in tokens):
                out.append(self._stamp(product))
        out.sort(key=lambda p: p.title)
        return out[:max(1, int(limit))]

    def product(self, product_id: str) -> Product | None:
        product = self._products.get(str(product_id))
        return self._stamp(product) if product else None

    def cart_view(self, cart_ref: str) -> Cart:
        return self._cart(cart_ref)

    def cart_add(self, cart_ref: str, product_id: str, quantity: int) -> Cart:
        product = self._products.get(product_id)
        if product is None:
            raise UnknownProduct(f"no catalog product {product_id!r}")
        cart = self._cart(cart_ref)
        for line in cart.lines:
            if line.product_id == product_id:
                line.quantity += int(quantity)
                return cart
        cart.lines.append(CartLine(product_id, product.title, product.price, int(quantity),
                                   product.currency))
        return cart

    def cart_remove(self, cart_ref: str, product_id: str) -> Cart:
        cart = self._cart(cart_ref)
        cart.lines = [ln for ln in cart.lines if ln.product_id != product_id]
        return cart

    def cart_link(self, cart_ref: str) -> str:
        # Deliberately carries a session parameter: the handoff must strip it.
        return f"https://demo-store.invalid/cart/{cart_ref}?session={self._session_param}"

    def customer_orders(self, customer_ref: str) -> list[Order]:
        return [self._stamp_order(o) for o in self._orders if o.customer_ref == customer_ref]

    def return_policy(self) -> str:
        return _DEMO_RETURN_POLICY

    # MerchantBackend -------------------------------------------------------
    def catalog(self, query: str = "", *, limit: int = 50) -> list[Product]:
        if query:
            return self.search(query, limit=limit)
        return [self._stamp(p) for p in list(self._products.values())[:max(1, int(limit))]]

    def orders(self, status: str | None = None, *, limit: int = 50) -> list[Order]:
        rows = [o for o in self._orders if not status or o.status == status]
        return [self._stamp_order(o) for o in rows[:max(1, int(limit))]]

    def inventory(self, sku: str | None = None) -> list[dict[str, Any]]:
        return [self._row(sku=key, **row) for key, row in self._inventory.items()
                if not sku or key == sku]

    def pricing(self, sku: str | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key, row in self._pricing.items():
            if sku and key != sku:
                continue
            price = self._products[key].price
            margin = round((price - row["unit_cost"]) / price * 100.0, 1) if price else 0.0
            out.append(self._row(sku=key, price=price, currency="USD",
                                 margin_pct=margin, **row))
        return out

    def analytics(self, metric: str, window: str = "7d") -> dict[str, Any]:
        key = (str(metric).lower(), str(window).lower())
        if key not in _DEMO_ANALYTICS:
            metrics = sorted({m for m, _ in _DEMO_ANALYTICS})
            windows = sorted({w for _, w in _DEMO_ANALYTICS})
            raise ValueError(
                f"unknown metric/window {key!r}; metrics: {', '.join(metrics)}; "
                f"windows: {', '.join(windows)}"
            )
        value, baseline, unit = _DEMO_ANALYTICS[key]
        return self._row(metric=key[0], window=key[1], value=value,
                         baseline_prior_period=baseline, unit=unit)

    def campaigns(self) -> list[dict[str, Any]]:
        return [self._row(**c) for c in self._campaigns]

    def apply_change(self, change: StagedChange) -> dict[str, Any]:
        kind, target, changes = change.kind, change.target, change.changes
        if kind == "price":
            product = self._products.get(target)
            if product is None:
                raise UnknownProduct(f"no catalog product {target!r}")
            price = float(changes.get("price", product.price))
            if price <= 0:
                raise ValueError("price must be positive")
            product.price = round(price, 2)
            return {"sku": target, "price": product.price}
        if kind == "inventory":
            row = self._inventory.get(target)
            if row is None:
                raise UnknownProduct(f"no inventory record {target!r}")
            for key in ("on_hand", "inbound"):
                if key in changes:
                    value = int(changes[key])
                    if value < 0:
                        raise ValueError(f"{key} must be non-negative")
                    row[key] = value
            return {"sku": target, **{k: row[k] for k in ("on_hand", "inbound")}}
        if kind == "listing":
            product = self._products.get(target)
            if product is None:
                raise UnknownProduct(f"no catalog product {target!r}")
            for key, value in changes.items():
                if key == "title":
                    product.title = str(value)
                else:
                    product.attributes[key] = value
            return {"sku": target, "title": product.title,
                    "attributes": dict(product.attributes)}
        if kind == "campaign":
            for campaign in self._campaigns:
                if campaign["campaign_id"] == target:
                    campaign.update(changes)
                    return dict(campaign)
            created = {"campaign_id": target, "status": "scheduled", **changes}
            self._campaigns.append(created)
            return dict(created)
        if kind == "order_resolution":
            order = self._find_order(target)
            order.status = str(changes.get("status", order.status))
            order.tracking = str(changes.get("tracking", order.tracking))
            return {"order_id": target, "status": order.status, "tracking": order.tracking}
        if kind == "return_request":
            order = self._find_order(target)
            order.status = "return_requested"
            return {"order_id": target, "status": order.status}
        raise ValueError(f"unsupported change kind {kind!r}")  # pragma: no cover


# --- backend registry + session factories -------------------------------------

_BACKENDS: dict[str, Callable[[], Any]] = {}


def register_backend(name: str, factory: Callable[[], Any]) -> None:
    """Register a backend factory under ``name`` for ``[commerce] backend``.

    The factory returns an object implementing :class:`StorefrontBackend`,
    :class:`MerchantBackend`, or both. This is the plug point for a real
    storefront (Shopify, a headless commerce API, an internal OMS): the
    sessions, caps, gates, and staged-write ledger are the same whatever the
    backend."""
    key = str(name or "").strip().lower()
    if not key:
        raise ValueError("backend name is required")
    _BACKENDS[key] = factory


def backend_for(name: str | None = None) -> Any:
    """Instantiate the named (or configured) backend."""
    key = str(name or _configured_backend_name()).strip().lower()
    factory = _BACKENDS.get(key)
    if factory is None:
        raise CommerceError(
            f"unknown commerce backend {key!r}; registered: {', '.join(sorted(_BACKENDS))}"
        )
    return factory()


@functools.lru_cache(maxsize=1)
def _shared_demo_backend() -> DemoBackend:
    # One demo store per process, so the shopper and merchant tools of a run
    # see the same catalog (a staged price change, once approved, shows up in
    # the storefront).
    return DemoBackend()


register_backend("demo", _shared_demo_backend)


def shopper_session(backend: StorefrontBackend | None = None, *,
                    customer_ref: str | None = None,
                    principal: str = "agent:commerce") -> ShopperSession:
    """A governed shopper session over the configured backend. The customer
    scope is the human principal when there is one (``user:alice`` sees only
    her orders); an agent-only principal falls back to the demo customer."""
    who = str(principal or "agent:commerce")
    if customer_ref is None:
        customer_ref = who if _is_human_principal(who) else "cust_demo"
    return ShopperSession(backend or backend_for(), customer_ref=customer_ref, principal=who)


def merchant_session(backend: MerchantBackend | None = None, *,
                     principal: str = "agent:commerce") -> MerchantSession:
    """A governed merchant session over the configured backend."""
    return MerchantSession(backend or backend_for(), principal=str(principal or "agent:commerce"))


__all__ = [
    "STAGED_KINDS",
    "Approval",
    "ApprovalRequired",
    "CapExceeded",
    "Cart",
    "CartLine",
    "CheckoutHandoff",
    "CommerceError",
    "CommerceLimits",
    "DemoBackend",
    "MerchantBackend",
    "MerchantSession",
    "Order",
    "Product",
    "ProposalLedger",
    "Provenance",
    "ProvenanceError",
    "ShopperSession",
    "StagedChange",
    "StorefrontBackend",
    "UnknownOrder",
    "UnknownProduct",
    "UnknownProposal",
    "backend_for",
    "configured_limits",
    "default_ledger",
    "enabled",
    "merchant_session",
    "opaque_cart_link",
    "register_backend",
    "shopper_session",
]
