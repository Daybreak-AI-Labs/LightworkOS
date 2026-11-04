"""Platform billing collection via Stripe (maverick.billing_stripe).

Fully offline: a FAKE Stripe client stands in for the SDK/network, and the
webhook path is verified with stdlib HMAC. Covers customer create-or-lookup
idempotency, subscription reflecting the plan, metered invoice items matching
the rated Invoice, the payment_failed -> downgrade / payment_succeeded ->
restore webhook effect on entitlements, and the disabled-clean gate.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from maverick import billing, billing_stripe
from maverick.billing import Invoice, LineItem
from maverick.tenant import registry as tr


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    # Default: billing off / no keys, so each test opts in explicitly.
    for var in ("MAVERICK_STRIPE_ENABLE", "MAVERICK_STRIPE_SECRET_KEY",
                "MAVERICK_STRIPE_WEBHOOK_SECRET", "MAVERICK_STRIPE_BILL_METERED"):
        monkeypatch.delenv(var, raising=False)


def _enable(monkeypatch, *, metered: bool = False, prices: dict | None = None):
    monkeypatch.setenv("MAVERICK_STRIPE_ENABLE", "1")
    monkeypatch.setenv("MAVERICK_STRIPE_SECRET_KEY", "sk_test_dummy")  # pragma: allowlist secret
    if metered:
        monkeypatch.setenv("MAVERICK_STRIPE_BILL_METERED", "1")
    cfg = {"billing": {"stripe": {"prices": prices or {}}}}
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: cfg)


# --------------------------------------------------------------------------
# A minimal in-memory Stripe stand-in implementing the StripeClient surface.
# --------------------------------------------------------------------------

class FakeStripe:
    def __init__(self):
        self.customers: list[dict] = []
        self.subs: dict[str, list[dict]] = {}
        self.invoice_items: list[dict] = []
        self.customer_idem: dict[str, str] = {}
        self.subscription_keys: list[str] = []
        self._n = 0

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}_{self._n}"

    def create_customer(self, *, name, metadata, idempotency_key):
        # Stripe dedupes on the idempotency key; the fake mirrors that so a race
        # cannot mint two customers even before the registry stores the id.
        if idempotency_key in self.customer_idem:
            cid = self.customer_idem[idempotency_key]
            return next(c for c in self.customers if c["id"] == cid)
        cid = self._id("cus")
        cust = {"id": cid, "name": name, "metadata": dict(metadata)}
        self.customers.append(cust)
        self.customer_idem[idempotency_key] = cid
        return cust

    def list_subscriptions(self, customer_id):
        return list(self.subs.get(customer_id, []))

    def create_subscription(self, *, customer_id, price_id, metadata, idempotency_key):
        self.subscription_keys.append(idempotency_key)
        sub = {
            "id": self._id("sub"), "status": "active", "metadata": dict(metadata),
            "items": {"data": [{"id": self._id("si"), "price": {"id": price_id}}]},
        }
        self.subs.setdefault(customer_id, []).append(sub)
        return sub

    def update_subscription(self, subscription_id, *, item_id, price_id, metadata):
        for subs in self.subs.values():
            for sub in subs:
                if sub["id"] == subscription_id:
                    sub["items"]["data"][0] = {"id": item_id, "price": {"id": price_id}}
                    sub["metadata"] = dict(metadata)
                    return sub
        raise AssertionError(f"no such subscription {subscription_id}")

    def create_invoice_item(self, *, customer_id, amount, currency, description,
                            metadata, idempotency_key):
        item = {
            "id": self._id("ii"), "customer": customer_id, "amount": amount,
            "currency": currency, "description": description,
            "metadata": dict(metadata), "idempotency_key": idempotency_key,
        }
        self.invoice_items.append(item)
        return item


# ---- gate: disabled-clean --------------------------------------------------

def test_status_reports_disabled_with_no_key():
    st = billing_stripe.status()
    assert st.enabled is False
    assert st.has_secret_key is False
    assert "disabled" in st.reason
    # to_dict never raises and carries the flags.
    assert st.to_dict()["enabled"] is False


def test_enabled_requires_flag_and_key(monkeypatch):
    monkeypatch.setenv("MAVERICK_STRIPE_ENABLE", "1")
    # Flag on but no key -> still not enabled, and status says why.
    assert billing_stripe.enabled() is False
    assert "no secret key" in billing_stripe.status().reason
    monkeypatch.setenv("MAVERICK_STRIPE_SECRET_KEY", "sk_test_x")  # pragma: allowlist secret
    assert billing_stripe.enabled() is True


def test_require_enabled_raises_when_off():
    with pytest.raises(billing_stripe.StripeDisabled):
        billing_stripe.require_enabled()


def test_operations_refuse_when_disabled(monkeypatch):
    tr.create_tenant("acme", plan="pro")
    with pytest.raises(billing_stripe.StripeDisabled):
        billing_stripe.ensure_customer("acme", client=FakeStripe())


# ---- customer create-or-lookup idempotency ---------------------------------

def test_ensure_customer_idempotent(monkeypatch):
    _enable(monkeypatch)
    tr.create_tenant("acme", plan="pro", display_name="Acme Inc")
    fake = FakeStripe()
    cid1 = billing_stripe.ensure_customer("acme", client=fake)
    cid2 = billing_stripe.ensure_customer("acme", client=fake)
    assert cid1 == cid2
    # Created exactly once; the second call short-circuits on the stored id.
    assert len(fake.customers) == 1
    # The id is persisted on the tenant record.
    assert tr.get_tenant("acme").stripe_customer_id == cid1
    # ...and the reverse lookup finds it (webhook path).
    assert tr.get_tenant_by_stripe_customer(cid1).id == "acme"


# ---- subscription reflects the plan ----------------------------------------

def test_subscription_created_for_plan_price(monkeypatch):
    _enable(monkeypatch, prices={"pro": "price_pro", "enterprise": "price_ent"})
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    res = billing_stripe.ensure_subscription("acme", client=fake)
    assert res["status"] == "created"
    assert res["price"] == "price_pro"
    cid = res["customer"]
    assert fake.subs[cid][0]["items"]["data"][0]["price"]["id"] == "price_pro"


def test_subscription_unchanged_then_updated_on_plan_change(monkeypatch):
    _enable(monkeypatch, prices={"pro": "price_pro", "enterprise": "price_ent"})
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    billing_stripe.ensure_subscription("acme", client=fake)
    # Second call, same plan -> no new subscription.
    again = billing_stripe.ensure_subscription("acme", client=fake)
    assert again["status"] == "unchanged"
    cid = again["customer"]
    assert len(fake.subs[cid]) == 1
    # Change the plan -> the subscription is updated to the new price.
    tr.set_plan("acme", "enterprise")
    upd = billing_stripe.ensure_subscription("acme", client=fake)
    assert upd["status"] == "updated"
    assert upd["price"] == "price_ent"
    assert upd["old_price"] == "price_pro"
    assert len(fake.subs[cid]) == 1  # updated in place, not duplicated
    assert fake.subs[cid][0]["items"]["data"][0]["price"]["id"] == "price_ent"


def test_subscription_no_price_for_free_plan(monkeypatch):
    _enable(monkeypatch, prices={"pro": "price_pro"})
    tr.create_tenant("acme", plan="free")
    fake = FakeStripe()
    res = billing_stripe.ensure_subscription("acme", client=fake)
    assert res["status"] == "no_price"
    assert fake.subs == {}


# ---- metered usage items match the rated Invoice ---------------------------

def _invoice() -> Invoice:
    items = [
        LineItem("user:alice", "2026-06-01", 1.00, 10_000, 2_000, charge=1.20),
        LineItem("user:bob", "2026-06-02", 2.00, 20_000, 4_000, charge=2.40),
    ]
    return Invoice(
        tenant="acme", period_start="2026-06-01", period_end="2026-06-02",
        line_items=items, subtotal=3.60, total=3.60, currency="USD",
        invoice_id="inv_test",
    )


def test_push_usage_items_disabled_by_default_bills_nothing(monkeypatch):
    _enable(monkeypatch, prices={"pro": "price_pro"})  # metered flag NOT set
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    out = billing_stripe.push_usage_items("acme", _invoice(), client=fake)
    assert out == []
    assert fake.invoice_items == []


def test_push_usage_items_match_invoice_when_metered_on(monkeypatch):
    _enable(monkeypatch, metered=True, prices={"pro": "price_pro"})
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    out = billing_stripe.push_usage_items("acme", _invoice(), client=fake)
    assert len(out) == 2
    # Amounts are the line charge in minor units (USD cents), no markup added.
    amounts = sorted(it["amount"] for it in fake.invoice_items)
    assert amounts == [120, 240]
    # Every item is stamped with the tenant + the source day/principal.
    for it in fake.invoice_items:
        assert it["metadata"]["maverick_tenant"] == "acme"
        assert it["currency"] == "usd"


# ---- webhook: signature verification ---------------------------------------

def test_canceled_subscription_starts_a_distinct_idempotent_lifecycle(monkeypatch):
    _enable(monkeypatch, prices={"pro": "price_pro"})
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    first = billing_stripe.sync_tenant("acme", client=fake)
    old = fake.subs[first["customer"]][0]
    old["status"] = "canceled"
    second = billing_stripe.sync_tenant("acme", client=fake)
    assert second["subscription"]["status"] == "created"
    assert fake.subscription_keys[0] != fake.subscription_keys[1]
    assert billing_stripe.sync_tenant("acme", client=fake)["subscription"]["status"] == "unchanged"
    assert len(fake.subscription_keys) == 2


@pytest.mark.parametrize("status", ["incomplete", "past_due", "unpaid", "paused", "unknown"])
def test_pending_subscription_requires_resolution_without_duplicate_create(monkeypatch, status):
    _enable(monkeypatch, prices={"pro": "price_pro"})
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    first = billing_stripe.sync_tenant("acme", client=fake)
    fake.subs[first["customer"]][0]["status"] = status
    with pytest.raises(billing_stripe.StripeError, match="resolve its billing state"):
        billing_stripe.sync_tenant("acme", client=fake)
    assert len(fake.subscription_keys) == 1


def test_multiple_active_or_pending_cancellation_are_not_silently_modified(monkeypatch):
    import copy

    _enable(monkeypatch, prices={"pro": "price_pro"})
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    first = billing_stripe.sync_tenant("acme", client=fake)
    sub = fake.subs[first["customer"]][0]
    sub["cancel_at_period_end"] = True
    assert billing_stripe.sync_tenant("acme", client=fake)["subscription"]["status"] == "pending_cancellation"
    fake.subs[first["customer"]].append({**copy.deepcopy(sub), "id": "sub_duplicate"})
    with pytest.raises(billing_stripe.StripeError, match="Multiple current"):
        billing_stripe.sync_tenant("acme", client=fake)
    assert len(fake.subscription_keys) == 1


def test_open_or_current_period_refused_before_any_stripe_mutation(monkeypatch):
    from dataclasses import replace
    from datetime import datetime, timezone

    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    for inv in [replace(_invoice(), invoice_id="", period_end=""),
                replace(_invoice(), period_end=datetime.now(timezone.utc).date().isoformat())]:
        with pytest.raises(billing_stripe.StripeError, match="closed past UTC period"):
            billing_stripe.sync_tenant("acme", invoice=inv, client=fake)
    assert not fake.customers and not fake.invoice_items


def test_frozen_invoice_replays_after_restart_but_rejects_rerating(monkeypatch):
    import importlib
    from dataclasses import replace

    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    first = billing_stripe.push_usage_items("acme", _invoice(), client=fake)
    from maverick import stripe_collection
    importlib.reload(stripe_collection)
    assert billing_stripe.push_usage_items("acme", _invoice(), client=fake) == first
    changed = replace(_invoice(), line_items=[replace(_invoice().line_items[0], charge=2.20), _invoice().line_items[1]], total=4.60, subtotal=4.60)
    with pytest.raises(billing_stripe.StripeError, match="Closed invoice changed"):
        billing_stripe.push_usage_items("acme", changed, client=fake)
    assert len(fake.invoice_items) == 2


@pytest.mark.parametrize("since,until,currency", [
    ("2026-06-01", "2026-06-15", "USD"),
    ("2026-06-15", "2026-07-15", "USD"),
    ("2026-06-01", "2026-06-30", "EUR"),
])
def test_closed_usage_cannot_be_collected_again_through_overlapping_period(monkeypatch, since, until, currency):
    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    ledger = billing.ledger_for_tenant("acme")
    for day in ("2026-06-01", "2026-06-15", "2026-06-30", "2026-07-01"):
        ledger.record("user:alice", 1.0, 10, 1, day=day)
    original = billing.generate_invoice("acme", billing.RateCard(), since="2026-06-01", until="2026-06-30")
    alternate = billing.generate_invoice("acme", billing.RateCard(currency=currency), since=since, until=until)
    fake = FakeStripe()
    billing_stripe.push_usage_items("acme", original, client=fake)
    assert len(fake.invoice_items) == 3
    with pytest.raises(billing_stripe.StripeError, match="overlap"):
        billing_stripe.push_usage_items("acme", alternate, client=fake)
    assert len(fake.invoice_items) == 3
    following = billing.generate_invoice("acme", billing.RateCard(), since="2026-07-01", until="2026-07-31")
    assert len(billing_stripe.push_usage_items("acme", following, client=fake)) == 1


def test_concurrent_processes_cannot_collect_overlapping_usage(monkeypatch, tmp_path):
    import subprocess
    import sys

    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    billing_stripe.ensure_customer("acme", client=FakeStripe())
    attempts = tmp_path / "provider-attempts.txt"
    script = """
import json, sys
from pathlib import Path
from maverick.billing import Invoice, LineItem
from maverick.billing_stripe import push_usage_items, StripeError
class Client:
    def create_invoice_item(self, **kwargs):
        with Path(sys.argv[1]).open('a') as output:
            output.write('attempt\\n')
        return {'id': 'ii_fixture'}
invoice = Invoice('acme', '2026-06-01', sys.argv[2],
                  [LineItem('user:alice', '2026-06-15', 1., 1, 0, 1.)],
                  subtotal=1., total=1., invoice_id=sys.argv[2])
sys.stdin.readline()
try:
    push_usage_items('acme', invoice, client=Client())
    print(json.dumps({'status': 'collected'}), flush=True)
except StripeError as exc:
    print(json.dumps({'status': 'blocked', 'error': str(exc)}), flush=True)
"""
    workers = [subprocess.Popen([sys.executable, "-u", "-c", script, str(attempts), end],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
               for end in ("2026-06-20", "2026-06-30")]
    try:
        for worker in workers:
            worker.stdin.write("go\n")
            worker.stdin.flush()
        results = []
        for worker in workers:
            output, errors = worker.communicate(timeout=30)
            assert worker.returncode == 0, errors
            results.append(json.loads(output))
        assert sorted(result["status"] for result in results) == ["blocked", "collected"]
        assert "overlap" in next(result["error"] for result in results if result["status"] == "blocked")
        assert attempts.read_text().splitlines() == ["attempt"]
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
                worker.wait(timeout=10)


def test_prior_receipt_with_unknown_period_requires_reconciliation(monkeypatch):
    from dataclasses import replace

    from maverick.file_lock import atomic_read_text, atomic_write_text
    from maverick.paths import data_dir

    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    fake = FakeStripe()
    first = billing_stripe.push_usage_items("acme", _invoice(), client=fake)
    receipt_path = next(data_dir("billing", "stripe-collections", tenant="acme").glob("*.json"))
    state = json.loads(atomic_read_text(receipt_path))
    state.pop("binding")
    atomic_write_text(receipt_path, json.dumps(state))
    following = replace(_invoice(), period_start="2026-07-01", period_end="2026-07-31", invoice_id="july")
    with pytest.raises(billing_stripe.StripeError, match="period is unknown"):
        billing_stripe.push_usage_items("acme", following, client=fake)
    assert len(fake.invoice_items) == 2
    # Exact original replay can retain the same completed receipts and recover
    # the explicit binding authenticated by their existing frozen digest.
    assert billing_stripe.push_usage_items("acme", _invoice(), client=fake) == first
    assert len(fake.invoice_items) == 2


@pytest.mark.parametrize("usage,minimum", [(1.0, 10.0), (10.0, 10.0), (20.0, 10.0), (0.0, 10.0), (0.0, 0.0)])
def test_minimum_adjustment_matches_preview_and_collection(monkeypatch, usage, minimum):
    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    ledger = billing.ledger_for_tenant("acme")
    if usage:
        ledger.record("user:alice", usage, 0, 0, day="2026-06-01")
    card = billing.RateCard(minimum_charge=minimum)
    invoice = billing.generate_invoice("acme", card, since="2026-06-01", until="2026-06-01")
    assert sum(li.charge for li in invoice.line_items) == invoice.total
    preview = billing_stripe.preview_charges("acme", card, since="2026-06-01", until="2026-06-01")
    fake = FakeStripe()
    result = billing_stripe.push_usage_items("acme", invoice, client=fake)
    expected = int(max(usage, minimum) * 100)
    assert sum(row["amount"] for row in result) == expected
    assert sum(row["amount_minor"] for row in preview["usage_items_that_would_bill"]) == expected
    assert billing_stripe.push_usage_items("acme", invoice, client=fake) == result
    assert len(fake.invoice_items) == len(result)


@pytest.mark.parametrize("value,currency,expected", [("0.005", "usd", 1), ("1.005", "usd", 101), ("2.675", "usd", 268), ("2.5", "jpy", 3), ("2.5", "isk", 300), ("2.5", "ugx", 300)])
def test_minor_units_follow_explicit_decimal_half_up(value, currency, expected):
    assert billing_stripe._to_minor_units(value, currency) == expected


def test_line_rounding_preserves_rounded_invoice_total(monkeypatch):
    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    invoice = Invoice(tenant="acme", period_start="2026-06-01", period_end="2026-06-01",
                      line_items=[LineItem(name, "2026-06-01", 0.005, 0, 0, 0.005) for name in ("a", "b")],
                      total=0.01, subtotal=0.01, invoice_id="rounding")
    fake = FakeStripe()
    assert sum(row["amount"] for row in billing_stripe.push_usage_items("acme", invoice, client=fake)) == 1


def test_ambiguous_item_does_not_replay_after_idempotency_window(monkeypatch):
    _enable(monkeypatch, metered=True)
    tr.create_tenant("acme", plan="pro")
    class TimeoutStripe(FakeStripe):
        def create_invoice_item(self, **kwargs):
            super().create_invoice_item(**kwargs)
            raise TimeoutError("response lost")
    fake = TimeoutStripe()
    with pytest.raises(TimeoutError):
        billing_stripe.push_usage_items("acme", _invoice(), client=fake)
    future = time.time() + 24 * 3600
    monkeypatch.setattr(billing_stripe.time, "time", lambda: future)
    with pytest.raises(billing_stripe.StripeError, match="uncertain beyond"):
        billing_stripe.push_usage_items("acme", _invoice(), client=fake)
    assert len(fake.invoice_items) == 1

def _sign(payload: str, secret: str, ts: int) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.{payload}".encode(), hashlib.sha256)
    return f"t={ts},v1={mac.hexdigest()}"


def test_verify_webhook_accepts_good_signature(monkeypatch):
    secret = "whsec_test"  # pragma: allowlist secret
    payload = json.dumps({"type": "invoice.payment_succeeded", "data": {"object": {}}})
    ts = int(time.time())
    event = billing_stripe.verify_webhook(payload, _sign(payload, secret, ts), secret=secret)
    assert event["type"] == "invoice.payment_succeeded"


def test_verify_webhook_rejects_tampered_payload(monkeypatch):
    secret = "whsec_test"  # pragma: allowlist secret
    payload = json.dumps({"type": "invoice.payment_failed", "data": {"object": {}}})
    ts = int(time.time())
    header = _sign(payload, secret, ts)
    with pytest.raises(billing_stripe.StripeWebhookError):
        billing_stripe.verify_webhook(payload + " ", header, secret=secret)


def test_verify_webhook_rejects_stale_timestamp():
    secret = "whsec_test"  # pragma: allowlist secret
    payload = "{}"
    old = int(time.time()) - 10_000
    with pytest.raises(billing_stripe.StripeWebhookError):
        billing_stripe.verify_webhook(payload, _sign(payload, secret, old), secret=secret)


def test_verify_webhook_requires_secret(monkeypatch):
    with pytest.raises(billing_stripe.StripeWebhookError):
        billing_stripe.verify_webhook("{}", "t=1,v1=abc", secret="")


# ---- webhook: payment_failed downgrades, payment_succeeded restores --------

def _event(etype: str, obj: dict) -> dict:
    return {"type": etype, "data": {"object": obj}}


def test_payment_failed_downgrades_then_succeeded_restores(monkeypatch):
    tr.create_tenant("acme", plan="pro")
    tr.set_stripe_customer_id("acme", "cus_acme")
    # pro includes grpc; free (base) does not.
    assert billing.tenant_entitled("acme", "grpc") is True

    # A failed payment (found by the stored customer id) downgrades to base.
    res = billing_stripe.handle_event(
        _event("invoice.payment_failed", {"customer": "cus_acme"}))
    assert res["handled"] is True and res["action"] == "downgrade"
    assert tr.get_tenant("acme").billing_status == tr.BILLING_PAST_DUE
    assert billing.tenant_entitled("acme", "grpc") is False   # downgraded
    assert billing.tenant_entitled("acme", "core") is True    # base still on
    assert billing.feature_allowed("grpc", tenant="acme") is False

    # A recovered payment restores the subscribed plan exactly.
    res2 = billing_stripe.handle_event(
        _event("invoice.payment_succeeded", {"customer": "cus_acme"}))
    assert res2["handled"] is True and res2["action"] == "restore"
    assert tr.get_tenant("acme").billing_status == tr.BILLING_CURRENT
    assert billing.tenant_entitled("acme", "grpc") is True     # restored


def test_subscription_past_due_status_downgrades_via_metadata(monkeypatch):
    tr.create_tenant("acme", plan="pro")
    # No stored customer id: resolve the tenant from the metadata we stamp.
    obj = {"status": "past_due", "metadata": {"maverick_tenant": "acme"}}
    res = billing_stripe.handle_event(_event("customer.subscription.updated", obj))
    assert res["action"] == "downgrade"
    assert tr.get_tenant("acme").billing_status == tr.BILLING_PAST_DUE


def test_irrelevant_event_is_noop():
    res = billing_stripe.handle_event(_event("customer.created", {"id": "cus_x"}))
    assert res["handled"] is False


def test_event_for_unknown_tenant_is_noop():
    res = billing_stripe.handle_event(
        _event("invoice.payment_failed", {"customer": "cus_ghost"}))
    assert res["handled"] is False


def test_webhook_end_to_end_verify_then_handle(monkeypatch):
    secret = "whsec_e2e"  # pragma: allowlist secret
    monkeypatch.setenv("MAVERICK_STRIPE_WEBHOOK_SECRET", secret)
    tr.create_tenant("acme", plan="pro")
    tr.set_stripe_customer_id("acme", "cus_acme")
    payload = json.dumps(_event("invoice.payment_failed", {"customer": "cus_acme"}))
    ts = int(time.time())
    event = billing_stripe.verify_webhook(payload, _sign(payload, secret, ts))
    out = billing_stripe.handle_event(event)
    assert out["action"] == "downgrade"
    assert billing.tenant_entitled("acme", "grpc") is False


# ---- registry record round-trips the new fields ----------------------------

def test_tenant_record_roundtrips_stripe_fields():
    rec = tr.TenantRecord(id="acme", plan="pro",
                          stripe_customer_id="cus_1", billing_status=tr.BILLING_PAST_DUE)
    assert tr.TenantRecord.from_dict(rec.to_dict()) == rec
    # An old-style record (no stripe fields) loads with defaults.
    legacy = tr.TenantRecord.from_dict({"id": "beta", "plan": "free"})
    assert legacy.stripe_customer_id == ""
    assert legacy.billing_status == tr.BILLING_CURRENT


def test_set_billing_status_rejects_garbage():
    tr.create_tenant("acme", plan="pro")
    with pytest.raises(ValueError):
        tr.set_billing_status("acme", "nonsense")


# ---- preview is offline and honors the pricing flag ------------------------

def test_preview_offline_shows_computed_but_unbilled_usage(monkeypatch):
    _enable(monkeypatch, prices={"pro": "price_pro"})  # metered off
    tr.create_tenant("acme", plan="pro")
    from maverick.billing import ledger_for_tenant
    ledger_for_tenant("acme").record("user:alice", 1.00, 10_000, 2_000, day="2026-06-01")
    from maverick.billing import RateCard
    prev = billing_stripe.preview_charges(
        "acme", RateCard(markup_pct=20.0), since="2026-06-01", until="2026-06-01")
    assert prev["plan"] == "pro"
    assert prev["platform_fee_price"] == "price_pro"
    assert prev["metered_billing_enabled"] is False
    assert prev["usage_items_that_would_bill"] == []
    assert prev["usage_items_computed_but_not_billed"]  # computed, not billed
