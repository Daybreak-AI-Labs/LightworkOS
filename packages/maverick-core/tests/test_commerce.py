"""Commerce suite: the safety rules live in ``maverick.commerce``, not in prompts.

Caps (spend / quantity / cart size), the provenance gate, staged writes that
only a human approval token can apply, the opaque checkout handoff, the knob,
the tool surface, and the ``com_`` packs' governance invariants.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from maverick import commerce
from maverick.commerce import (
    Approval,
    ApprovalRequired,
    CapExceeded,
    CommerceError,
    CommerceLimits,
    DemoBackend,
    MerchantSession,
    Product,
    ProposalLedger,
    ProvenanceError,
    ShopperSession,
    UnknownOrder,
    UnknownProduct,
    UnknownProposal,
    opaque_cart_link,
)


@pytest.fixture(autouse=True)
def _isolated_audit(tmp_path, monkeypatch):
    # Staging and decisions write signed audit rows; keep them out of ~/.maverick.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_AUDIT_DIR", str(tmp_path / "audit"))
    monkeypatch.delenv("MAVERICK_COMMERCE", raising=False)


def _shopper(**kw) -> ShopperSession:
    kw.setdefault("limits", CommerceLimits(max_session_spend=300.0, max_line_quantity=3,
                                           max_cart_lines=2))
    kw.setdefault("ledger", ProposalLedger())
    return ShopperSession(kw.pop("backend", DemoBackend()), **kw)


def _merchant(backend=None, **kw) -> MerchantSession:
    kw.setdefault("ledger", ProposalLedger())
    return MerchantSession(backend or DemoBackend(), **kw)


# --- knob ---------------------------------------------------------------

def test_off_by_default(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {})
    assert commerce.enabled() is False


def test_env_overrides_config_both_ways(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"commerce": {"enable": True}})
    assert commerce.enabled() is True
    monkeypatch.setenv("MAVERICK_COMMERCE", "0")
    assert commerce.enabled() is False
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {})
    monkeypatch.setenv("MAVERICK_COMMERCE", "1")
    assert commerce.enabled() is True


def test_get_commerce_caps_fall_back_to_tighter_defaults(monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"commerce": {
        "enable": "yes",              # stringy truthiness is not a real bool
        "max_session_spend": "lots",  # malformed
        "max_line_quantity": -4,      # non-positive
        "max_cart_lines": True,       # bool is not a count
        "backend": "  ",
    }})
    got = config.get_commerce()
    assert got == {"enable": False, "backend": "demo", "max_session_spend": 500.0,
                   "max_line_quantity": 10, "max_cart_lines": 25}
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {"commerce": {
        "enable": True, "max_session_spend": 42, "max_line_quantity": "2",
        "max_cart_lines": 3, "backend": "Demo"}})
    got = config.get_commerce()
    assert got["enable"] is True
    assert got["max_session_spend"] == 42.0 and got["max_line_quantity"] == 2
    assert commerce.configured_limits() == CommerceLimits(42.0, 2, 3)
    assert isinstance(commerce.backend_for(got["backend"]), DemoBackend)


def test_unknown_backend_is_refused():
    with pytest.raises(CommerceError):
        commerce.backend_for("not-registered")


# --- provenance gate ----------------------------------------------------

def test_every_demo_product_fact_carries_provenance():
    s = _shopper()
    results = s.search("trail")
    assert results and all(p.provenance and p.provenance.valid() for p in results)
    p = s.product("sku-trail-01")
    assert p.provenance.source == "demo-store"
    assert p.provenance.fetched_at.endswith("Z")
    assert p.to_dict()["provenance"] == {"source": "demo-store",
                                         "fetched_at": p.provenance.fetched_at}
    m = _merchant()
    for row in m.inventory() + m.pricing() + m.campaigns() + [m.analytics("revenue", "7d")]:
        assert row["provenance"]["source"] == "demo-store"
        assert row["provenance"]["fetched_at"]
    assert all(o.provenance for o in s.orders())


class _UnsourcedBackend(DemoBackend):
    def search(self, query, *, limit=10):
        return [Product("sku-x", "Unsourced", 1.0)]

    def product(self, product_id):
        return Product(product_id, "Unsourced", 1.0)

    def inventory(self, sku=None):
        return [{"sku": "sku-x", "on_hand": 1}]

    def customer_orders(self, customer_ref):
        return [commerce.Order("ord-x", customer_ref, "shipped", "2026-01-01T00:00:00Z", 1.0)]


def test_provenance_gate_rejects_unsourced_backend_results():
    s = _shopper(backend=_UnsourcedBackend())
    with pytest.raises(ProvenanceError):
        s.search("anything")
    with pytest.raises(ProvenanceError):
        s.product("sku-x")
    with pytest.raises(ProvenanceError):
        s.cart_add("sku-x", 1)  # the gate sits in front of the cart, too
    with pytest.raises(ProvenanceError):
        s.orders()
    with pytest.raises(ProvenanceError):
        _merchant(_UnsourcedBackend()).inventory()


# --- caps ---------------------------------------------------------------

def test_quantity_cap_is_enforced_per_line_including_merges():
    s = _shopper()
    with pytest.raises(CapExceeded):
        s.cart_add("sku-stove-04", 4)
    s.cart_add("sku-stove-04", 2)
    with pytest.raises(CapExceeded):
        s.cart_add("sku-stove-04", 2)  # 2 + 2 > 3
    assert s.cart_view().item_count == 2
    with pytest.raises(ValueError):
        s.cart_add("sku-stove-04", 0)


def test_spend_cap_is_enforced_on_projected_subtotal():
    s = _shopper()
    s.cart_add("sku-trail-01", 2)  # 258.00
    with pytest.raises(CapExceeded) as exc:
        s.cart_add("sku-stove-04", 1)  # 303.00 > 300.00
    assert "session cap" in str(exc.value)
    assert s.cart_view().subtotal == 258.0


def test_cart_line_cap_and_out_of_stock_and_unknown_product():
    s = _shopper()
    s.cart_add("sku-stove-04", 1)
    s.cart_add("sku-hydra-03", 1)
    with pytest.raises(CapExceeded):
        s.cart_add("sku-merino-02", 1)  # third distinct line
    with pytest.raises(CommerceError, match="out of stock"):
        s.cart_add("sku-lamp-05", 1)
    with pytest.raises(UnknownProduct):
        s.cart_add("sku-nope", 1)
    with pytest.raises(UnknownProduct):
        s.cart_remove("sku-nope")
    assert [ln.product_id for ln in s.cart_remove("sku-stove-04").lines] == ["sku-hydra-03"]


def test_caps_are_per_session():
    backend = DemoBackend()
    a = _shopper(backend=backend)
    a.cart_add("sku-trail-01", 2)
    b = _shopper(backend=backend)
    assert b.cart_view().lines == []
    b.cart_add("sku-trail-01", 2)  # a fresh session, a fresh cap
    assert a.cart_ref != b.cart_ref


# --- checkout handoff ---------------------------------------------------

def test_checkout_handoff_is_opaque_and_leaks_nothing():
    backend = DemoBackend()
    s = _shopper(backend=backend)
    with pytest.raises(CommerceError, match="empty"):
        s.checkout_handoff()
    s.cart_add("sku-trail-01", 1)
    handoff = s.checkout_handoff()
    body = handoff.to_dict()
    assert set(body) == {"cart_ref", "cart_link", "item_count", "subtotal", "currency"}
    assert body["cart_ref"] == s.cart_ref
    assert body["cart_link"] == f"https://demo-store.invalid/cart/{s.cart_ref}"
    assert body["item_count"] == 1 and body["subtotal"] == 129.0
    rendered = json.dumps(body)
    # The backend's cart link carried a session parameter; it is gone.
    assert "?" not in rendered and "session" not in rendered
    assert backend._session_param not in rendered
    # The checkout page and payment/address data never cross.
    assert backend.checkout_url(s.cart_ref) not in rendered
    assert "checkout" not in rendered.lower()
    for private in backend._private_checkout.values():
        assert private not in rendered


def test_handoff_refuses_over_cap_cart():
    s = _shopper(limits=CommerceLimits(max_session_spend=1000.0, max_line_quantity=5,
                                       max_cart_lines=5))
    s.cart_add("sku-trail-01", 3)  # 387.00
    s.limits = CommerceLimits(max_session_spend=100.0)  # cap tightened mid-session
    with pytest.raises(CapExceeded):
        s.checkout_handoff()


@pytest.mark.parametrize("raw", [
    "https://shop.example/checkout/abc",
    "https://shop.example/cart/abc/payment",
    "https://shop.example/pay",
    "https://user:pw@shop.example/cart/abc",  # pragma: allowlist secret
    "ftp://shop.example/cart/abc",
    "not a url",
    "",
])
def test_opaque_cart_link_refuses_checkout_steps_and_junk(raw):
    with pytest.raises(CommerceError):
        opaque_cart_link(raw)


def test_opaque_cart_link_strips_query_and_fragment():
    assert (opaque_cart_link("https://shop.example/cart/abc?token=SECRET&utm=x#frag")
            == "https://shop.example/cart/abc")
    assert opaque_cart_link("http://shop.example") == "http://shop.example/"


# --- staged writes ------------------------------------------------------

def test_stage_change_is_pending_and_the_agent_never_sees_the_token():
    m = _merchant()
    change = m.stage_change("price", "sku-trail-01", {"price": 119.0}, "match MAP")
    assert change.status == "pending"
    public = change.to_public_dict()
    token = m.ledger.approval_token(change.proposal_id)
    assert token and token not in json.dumps(public)
    assert "token" not in json.dumps(public)
    assert m.pending() == [public]
    # Nothing applied: the catalog still shows the old price.
    assert m.catalog()[0].price == 129.0


def test_apply_requires_a_matching_token_from_a_human():
    backend = DemoBackend()
    m = _merchant(backend)
    change = m.stage_change("price", "sku-trail-01", {"price": 119.0}, "match MAP")
    pid = change.proposal_id
    token = m.ledger.approval_token(pid)
    with pytest.raises(ApprovalRequired):
        m.apply(pid, None)
    with pytest.raises(ApprovalRequired):
        m.apply(pid, Approval(approver="user:alice", token="wrong"))
    with pytest.raises(ApprovalRequired):
        m.apply(pid, Approval(approver="agent:com_merch_pricing", token=token))
    with pytest.raises(ApprovalRequired):
        m.apply(pid, Approval(approver="", token=token))
    with pytest.raises(UnknownProposal):
        m.apply("prop_missing", Approval(approver="user:alice", token=token))
    assert backend.product("sku-trail-01").price == 129.0  # still untouched
    done = m.apply(pid, Approval(approver="user:alice", token=token))
    assert done.status == "applied" and done.decided_by == "user:alice"
    assert done.result == {"sku": "sku-trail-01", "price": 119.0}
    assert backend.product("sku-trail-01").price == 119.0
    # Single-use: the same approval cannot be replayed.
    with pytest.raises(ApprovalRequired):
        m.apply(pid, Approval(approver="user:alice", token=token))
    with pytest.raises(UnknownProposal):
        m.ledger.approval_token(pid)
    assert m.pending() == []


def test_reject_closes_a_proposal():
    m = _merchant()
    change = m.stage_change("inventory", "sku-merino-02", {"on_hand": 40}, "recount")
    token = m.ledger.approval_token(change.proposal_id)
    with pytest.raises(ApprovalRequired):
        m.reject(change.proposal_id, Approval(approver="agent:x", token=token))
    out = m.reject(change.proposal_id, Approval(approver="user:bob", token=token), "wrong SKU")
    assert out.status == "rejected" and out.result == {"reason": "wrong SKU"}
    with pytest.raises(ApprovalRequired):
        m.apply(change.proposal_id, Approval(approver="user:bob", token=token))


def test_non_ascii_approval_token_is_refused_not_a_crash():
    # The token comes from the human approval path; a non-ASCII value used to
    # raise TypeError out of hmac.compare_digest instead of ApprovalRequired.
    m = _merchant()
    change = m.stage_change("price", "sku-trail-01", {"price": 119.0}, "match MAP")
    token = m.ledger.approval_token(change.proposal_id)
    with pytest.raises(ApprovalRequired):
        m.apply(change.proposal_id, Approval(approver="user:alice", token="é" * len(token)))
    with pytest.raises(ApprovalRequired):
        m.reject(change.proposal_id, Approval(approver="user:alice", token=" " + token))
    assert m.pending()


def test_failed_apply_keeps_the_proposal_pending():
    m = _merchant()
    change = m.stage_change("price", "sku-trail-01", {"price": -1}, "bad")
    token = m.ledger.approval_token(change.proposal_id)
    with pytest.raises(ValueError):
        m.apply(change.proposal_id, Approval(approver="user:alice", token=token))
    assert m.ledger.get(change.proposal_id).status == "pending"


@pytest.mark.parametrize("kind,target,changes,rationale", [
    ("delete_store", "sku-trail-01", {"x": 1}, "why"),
    ("price", "", {"price": 1}, "why"),
    ("price", "sku-trail-01", {}, "why"),
    ("price", "sku-trail-01", "not a mapping", "why"),
    ("price", "sku-trail-01", {"price": 1}, ""),
    ("listing", "sku-trail-01", {"title": "x" * 501}, "why"),
    ("listing", "sku-trail-01", {f"f{i}": i for i in range(33)}, "why"),
])
def test_stage_change_validation(kind, target, changes, rationale):
    with pytest.raises(ValueError):
        _merchant().stage_change(kind, target, changes, rationale)


def test_every_staged_kind_applies_through_the_demo_backend():
    backend = DemoBackend()
    m = _merchant(backend)
    cases = {
        "inventory": ("sku-merino-02", {"on_hand": 40, "inbound": 5}),
        "listing": ("sku-hydra-03", {"title": "Hydration Pack 2 L", "color": "moss green"}),
        "campaign": ("cmp-fall-01", {"status": "paused"}),
        "order_resolution": ("ord-1002", {"status": "shipped", "tracking": "TRK-NEW"}),
    }
    for kind, (target, changes) in cases.items():
        change = m.stage_change(kind, target, changes, f"test {kind}")
        m.apply(change.proposal_id,
                Approval(approver="user:ops", token=m.ledger.approval_token(change.proposal_id)))
    assert backend.inventory("sku-merino-02")[0]["on_hand"] == 40
    assert backend.product("sku-hydra-03").title == "Hydration Pack 2 L"
    assert backend.campaigns()[0]["status"] == "paused"
    assert backend.orders("shipped")[0].tracking in {"TRK-1001-DEMO", "TRK-NEW"}


# --- shopper orders + returns ------------------------------------------

def test_shopper_orders_are_scoped_to_the_customer():
    backend = DemoBackend()
    ledger = ProposalLedger()
    s = _shopper(backend=backend, ledger=ledger, customer_ref="cust_demo")
    assert {o.order_id for o in s.orders()} == {"ord-1001", "ord-1002"}
    with pytest.raises(UnknownOrder):
        s.order("ord-2001")  # another customer's order is unreachable
    with pytest.raises(UnknownOrder):
        s.stage_return("ord-2001", "not mine")
    assert "30 days" in s.return_policy()
    change = s.stage_return("ord-1001", "wrong size")
    assert change.kind == "return_request" and change.status == "pending"
    assert backend.customer_orders("cust_demo")[0].status == "shipped"  # nothing applied
    m = MerchantSession(backend, ledger=ledger)
    m.apply(change.proposal_id,
            Approval(approver="user:support", token=ledger.approval_token(change.proposal_id)))
    assert backend.customer_orders("cust_demo")[0].status == "return_requested"


# --- preference memory --------------------------------------------------

def test_preferences_hold_only_what_the_shopper_states():
    s = _shopper()
    s.set_preference("Shoe Size", "10 US")
    s.set_preference("brand", "any but the loud ones")
    assert s.preferences() == {"shoe_size": "10 US", "brand": "any but the loud ones"}
    for bad in ("card_number", "CVV", "shipping address", "password", "bank_iban"):
        with pytest.raises(CommerceError):
            s.set_preference(bad, "x")
    with pytest.raises(ValueError):
        s.set_preference("brand", "")
    with pytest.raises(ValueError):
        s.set_preference("brand", "x" * 201)
    with pytest.raises(ValueError):
        s.set_preference("!!!", "x")
    s.delete_preference("shoe size")
    assert "shoe_size" not in s.preferences()
    for i in range(31):  # brand + 31 = the 32-entry cap
        s.set_preference(f"pref_{i}", "v")
    assert len(s.preferences()) == 32
    with pytest.raises(CapExceeded):
        s.set_preference("one_too_many", "v")
    s.preferences()["brand"] = "mutated copy"  # a copy: the store is untouched
    assert s.preferences()["brand"] == "any but the loud ones"
    s.set_preference("brand", "updating an existing key still works at the cap")
    assert s.preferences()["brand"].startswith("updating") and len(s.preferences()) == 32


# --- tool surface -------------------------------------------------------

def _run(tool, **args):
    return asyncio.run(tool.fn(args))


def test_tools_render_refusals_and_never_the_token():
    from maverick.tools.commerce_tools import merchant_tools, shopper_tools
    backend = DemoBackend()
    ledger = ProposalLedger()
    shop = {t.name: t for t in shopper_tools(_shopper(backend=backend, ledger=ledger))}
    merch = {t.name: t for t in merchant_tools(MerchantSession(backend, ledger=ledger))}
    assert set(shop) == {"storefront_search", "storefront_product", "cart_view", "cart_add",
                         "cart_remove", "checkout_handoff", "shopper_orders_read",
                         "shopper_stage_return", "shopper_preferences"}
    assert set(merch) == {"catalog_read", "inventory_read", "pricing_read", "orders_read",
                          "analytics_read", "promotions_read", "merchant_stage_change"}
    assert _run(shop["cart_add"], product_id="sku-trail-01", quantity=999).startswith("REFUSED")
    # quantity=0 must be refused, not turned into the default of 1.
    assert _run(shop["cart_add"], product_id="sku-trail-01", quantity=0).startswith("REFUSED")
    assert _run(shop["checkout_handoff"]).startswith("REFUSED")
    assert "demo-store" in _run(shop["storefront_search"], query="trail")
    assert "129.0" in _run(shop["cart_add"], product_id="sku-trail-01", quantity=1)
    handoff = _run(shop["checkout_handoff"])
    assert "CHECKOUT HANDOFF" in handoff and "?session" not in handoff
    assert _run(shop["shopper_preferences"], op="set", key="card_number",
                value="4111").startswith("REFUSED")
    out = _run(merch["merchant_stage_change"], kind="price", target="sku-trail-01",
               changes={"price": 119.0}, rationale="MAP")
    assert out.startswith("STAGED")
    (pending,) = ledger.pending()
    assert ledger.approval_token(pending["proposal_id"]) not in out
    assert _run(merch["merchant_stage_change"], kind="nuke", target="x", changes={"a": 1},
                rationale="r").startswith("REFUSED")
    assert "revenue" in _run(merch["analytics_read"], metric="revenue")
    assert _run(merch["analytics_read"], metric="vibes").startswith("REFUSED")


def test_tools_are_registered_only_when_enabled(monkeypatch):
    from maverick import config, tools
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {})
    names = tools.base_tool_names()
    assert names is not None
    assert not ({"cart_add", "merchant_stage_change", "storefront_search"} & names)
    monkeypatch.setenv("MAVERICK_COMMERCE", "1")
    names = tools.base_tool_names()
    assert names is not None
    assert {"cart_add", "checkout_handoff", "merchant_stage_change",
            "storefront_search", "catalog_read"} <= names


# --- the com_ packs -----------------------------------------------------

_SHOPPER_ONLY = {"storefront_search", "storefront_product", "cart_view", "cart_add",
                 "cart_remove", "checkout_handoff", "shopper_orders_read",
                 "shopper_stage_return", "shopper_preferences"}
_MERCHANT_ONLY = {"catalog_read", "inventory_read", "pricing_read", "orders_read",
                  "analytics_read", "promotions_read", "merchant_stage_change"}
_CONSEQUENTIAL = {"cart_add", "checkout_handoff", "shopper_stage_return", "merchant_stage_change"}


def _com_packs() -> dict:
    from maverick.domain import builtin_dir, load_domains
    packs = {n: p for n, p in load_domains(builtin_dir()).items() if n.startswith("com_")}
    assert len(packs) >= 11, sorted(packs)
    return packs


def test_com_packs_are_a_governed_suite():
    from maverick.agent_autonomy import AutonomyLevel, default_profile_for
    from maverick.domain import enforced_gate, lint_profile, suite_for
    from maverick.domain_discipline import discipline_for
    from maverick.domain_refusals import refusals_for
    from maverick.safety.tool_risk import tool_risk
    for name, p in _com_packs().items():
        assert suite_for(name) == "commerce", name
        assert p.compartment.startswith("com_"), (name, p.compartment)
        assert p.max_risk in ("low", "medium"), (name, p.max_risk)
        errors, warnings = lint_profile(p)
        assert errors == [] and warnings == [], (name, errors, warnings)
        cap = p.capability(f"agent:{name}")
        for dangerous in ("shell", "write_file", "code_exec", "computer", "browser"):
            assert cap.permits(dangerous) is False, (name, dangerous)
        assert cap.permits("read_file") is True, name
        # Every tool the pack grants is classified (reads low, staged/handoff medium).
        for tool in set(p.allow_tools) & (_SHOPPER_ONLY | _MERCHANT_ONLY):
            assert tool_risk(tool) == ("medium" if tool in _CONSEQUENTIAL | {
                "cart_remove", "shopper_preferences"} else "low"), (name, tool)
            assert cap.permits(tool) is True, (name, tool)
        # Anything that stages, adds to a cart, or hands off ends behind a
        # persisted human gate; a read-only pack still declares review.
        assert enforced_gate(p) is not None, name
        if set(p.allow_tools) & _CONSEQUENTIAL:
            assert p.output.gate in ("approval", "review"), name
        # Suite-level baseline: strict (every consequential action staged).
        assert default_profile_for(name).default == AutonomyLevel.SUGGEST, name
        assert "Commerce discipline" in discipline_for(name), name
        refusals = " ".join(refusals_for(name))
        assert "payment card" in refusals and "staged proposal" in refusals, name


def test_shopper_packs_are_fenced_to_the_storefront():
    for name, p in _com_packs().items():
        if not name.startswith("com_shop_"):
            continue
        assert p.compartment == "com_shopper", name
        cap = p.capability(f"agent:{name}")
        for egress in ("web_search", "browser"):
            assert egress in p.deny_tools, (name, egress)
            assert cap.permits(egress) is False, (name, egress)
        # A shopper never holds a merchant write, and vice versa.
        assert not (set(p.allow_tools) & _MERCHANT_ONLY), name
    for name, p in _com_packs().items():
        if name.startswith("com_merch_"):
            assert p.compartment == "com_merchant", name
            assert not (set(p.allow_tools) & _SHOPPER_ONLY), name


def test_only_the_cart_builder_can_hand_off_checkout():
    packs = _com_packs()
    holders = sorted(n for n, p in packs.items() if "checkout_handoff" in p.allow_tools)
    assert holders == ["com_shop_cart_builder"]
    assert packs["com_shop_cart_builder"].workflow[-1].gate == "approval"
    assert packs["com_shop_cart_builder"].output.gate == "approval"


def test_commerce_department_is_listed():
    from maverick import departments
    d = departments.get_department("commerce")
    assert d is not None and d.title == "Commerce" and d.headcount >= 11
    assert d.charter
