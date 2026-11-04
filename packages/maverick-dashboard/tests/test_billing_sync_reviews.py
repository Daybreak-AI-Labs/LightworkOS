"""Provider-free fault cases for reviewed billing and retained stage recovery."""
import copy
import json

import pytest
from fastapi import HTTPException
from maverick import billing_stripe
from maverick_dashboard import billing_sync_reviews as reviews


class Store:
    def __init__(self):
        self.rows = {}

    def get(self, key):
        return copy.deepcopy(self.rows.get(key))

    def create(self, record, **kwargs):
        record = copy.deepcopy(record)
        record.update(revision=1, updated_at=1000)
        self.rows[record["id"]] = record
        return self.get(record["id"])

    def update(self, key, mutate, *, expected_revision, **kwargs):
        value = self.get(key)
        assert expected_revision == value["revision"]
        mutate(value)
        value["revision"] += 1
        self.rows[key] = value
        return self.get(key)


@pytest.fixture
def service(monkeypatch):
    store = Store()
    clock = [1000.0]
    state = {"customer": "", "price": "price_1", "customer_calls": 0, "subscription_calls": 0,
             "fail_subscription": False, "customer_name": "Workspace"}
    monkeypatch.setattr(reviews, "STORE", store)
    monkeypatch.setattr(reviews.time, "time", lambda: clock[0])
    monkeypatch.setattr(reviews, "_pack", lambda value: json.dumps(value))
    monkeypatch.setattr(reviews, "_unpack", lambda row: json.loads(row["snapshot_sealed"]))

    def fresh(fields):
        return {"tenant": "a", "plan": "team", "platform_fee_price": state["price"], "currency": "usd",
                "metered_billing_enabled": False, "billing_enabled": True, "connection_fingerprint": "connection-a",
                "initial_customer": state["customer"], "invoice": {"invoice_id": "fixed-original"}}
    monkeypatch.setattr(reviews, "_fresh", fresh)
    monkeypatch.setattr(billing_stripe, "require_enabled", lambda: None)
    monkeypatch.setattr(billing_stripe, "_client", lambda client: client)

    class Provider:
        def create_customer(self, **kwargs):
            record = store.get(reviews._key("a"))
            assert record["stages"]["customer"]["state"] == "pending"
            assert record["dispatches"][-1]["state"] == "pending"
            state["customer_calls"] += 1
            return {"id": "cus_1"}

        def create_subscription(self, **kwargs):
            state["subscription_calls"] += 1
            if state["fail_subscription"]:
                raise TimeoutError("provider may have accepted the request")
            return {"id": "sub_1"}

    def customer(tenant, *, client):
        if not state["customer"]:
            result = client.create_customer(name=state["customer_name"], metadata={"maverick_tenant": tenant}, idempotency_key="fixed-customer-key")
            state["customer"] = result["id"]
        return state["customer"]
    def subscription(tenant, *, client):
        result = client.create_subscription(customer_id=state["customer"], price_id=state["price"],
                                            metadata={"maverick_tenant": tenant}, idempotency_key="fixed-subscription-key")
        return {"subscription": result["id"], "status": "created"}
    monkeypatch.setattr(billing_stripe, "ensure_customer", customer)
    monkeypatch.setattr(billing_stripe, "ensure_subscription", subscription)
    return store, state, clock, Provider()


CONTEXT = {"actor": "admin@example.com", "workspace_context": "a"}
FIELDS = {"workspace": "a", "since": "2026-09-01", "until": "2026-09-29", "markup": 0.0, "minimum": 0.0}


def execute(preview, provider, fields=FIELDS):
    return reviews.execute(CONTEXT, fields, preview["review_id"], preview["sha256"], lambda: None, client=provider)


def test_changed_fields_and_settings_refuse_before_dispatch(service):
    _, state, _, provider = service
    preview = reviews.prepare(CONTEXT, FIELDS)
    with pytest.raises(HTTPException):
        execute(preview, provider, {**FIELDS, "markup": 2.0})
    state["price"] = "price_changed"
    with pytest.raises(HTTPException):
        execute(preview, provider)
    assert state["customer_calls"] == state["subscription_calls"] == 0


def test_completed_receipt_deduplicates_repeated_submission(service):
    _, state, _, provider = service
    preview = reviews.prepare(CONTEXT, FIELDS)
    assert execute(preview, provider)["state"] == "complete"
    assert execute(preview, provider)["state"] == "complete"
    assert state["customer_calls"] == state["subscription_calls"] == 1


def test_unknown_subscription_retains_confirmed_customer_and_exact_resume(service):
    _, state, _, provider = service
    preview = reviews.prepare(CONTEXT, FIELDS)
    state["fail_subscription"] = True
    failed = execute(preview, provider)
    assert failed["state"] == "unknown"
    assert failed["stages"]["customer"]["state"] == "confirmed"
    assert failed["stages"]["subscription"]["state"] == "unknown"
    assert failed["stages"]["usage"]["state"] == "not_started"
    with pytest.raises(HTTPException):
        reviews.prepare(CONTEXT, {**FIELDS, "until": "2026-09-28"})
    renewed = reviews.prepare(CONTEXT, FIELDS)
    assert renewed["resume"] and renewed["receipt"]["attempt"] == failed["attempt"]
    state["fail_subscription"] = False
    assert execute(renewed, provider)["state"] == "complete"
    assert state["customer_calls"] == 1


def test_unknown_expired_provider_key_is_not_replayed(service):
    _, state, clock, provider = service
    preview = reviews.prepare(CONTEXT, FIELDS)
    state["fail_subscription"] = True
    execute(preview, provider)
    clock[0] += reviews.SAFE_RETRY_SECONDS + 1
    renewed = reviews.prepare(CONTEXT, FIELDS)
    state["fail_subscription"] = False
    assert execute(renewed, provider)["state"] == "unknown"
    assert state["subscription_calls"] == 1


def test_expired_review_and_other_account_cannot_send(service):
    _, state, clock, provider = service
    preview = reviews.prepare(CONTEXT, FIELDS)
    with pytest.raises(HTTPException):
        reviews.execute({**CONTEXT, "actor": "different"}, FIELDS, preview["review_id"], preview["sha256"], lambda: None, client=provider)
    clock[0] += reviews.REVIEW_SECONDS + 1
    with pytest.raises(HTTPException):
        execute(preview, provider)
    assert state["customer_calls"] == 0
