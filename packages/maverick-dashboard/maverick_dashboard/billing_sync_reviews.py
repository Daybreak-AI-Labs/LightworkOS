"""Reviewed Stripe dispatch with retained stage receipts and conservative recovery.

The workspace record is the admission fence. A different preview cannot bypass
an unresolved dispatch. Native customer/subscription keys and frozen invoice
collection receipts remain authoritative; this surface never invents a new
invoice identity to escape an uncertain result.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import time

from fastapi import HTTPException
from maverick.crypto_at_rest import seal, unseal
from maverick.governed_records import GovernedRecordStore

STORE = GovernedRecordStore("billing_sync_reviews", "BSR", "billing_sync_review",
                            authority_scope="deployment_global")
REVIEW_SECONDS = 600
CLAIM_SECONDS = 120
SAFE_RETRY_SECONDS = 23 * 3600
SETTINGS_FIELDS = ("tenant", "plan", "platform_fee_price", "currency", "metered_billing_enabled", "billing_enabled", "connection_fingerprint")


def _key(workspace):
    return "BSR-" + hashlib.sha256(workspace.encode()).hexdigest()[:40]


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _pack(value):
    return base64.b64encode(seal(json.dumps(value, sort_keys=True, allow_nan=False).encode())).decode()


def _unpack(record):
    value = json.loads(unseal(base64.b64decode(record["snapshot_sealed"])))
    if not hmac.compare_digest(_digest(value), record["snapshot_sha256"]):
        raise HTTPException(409, "The saved billing review failed its integrity check. No new dispatch is allowed.")
    return value


def scope(request):
    from maverick.paths import current_tenant_id_strict

    from .auth import caller_principal
    return {"actor": caller_principal(request) or "local administrator",
            "workspace_context": current_tenant_id_strict() or ""}


def _saved(record, actor, action, change):
    value = STORE.update(record["id"], change, expected_revision=record["revision"], action=action, actor=actor)
    if value is None:
        raise HTTPException(409, "The billing receipt is no longer available.")
    return value


def _audited(record):
    if record.get("_audit_pending"):
        raise HTTPException(503, "Billing review is retained, but its audit receipt is pending. Retry the review before dispatching.")
    return record


def _same_scope(record, context):
    if record["scope"] != context:
        raise HTTPException(409, "This billing review belongs to a different account or workspace context. Return to that context to inspect its receipt.")


def _fresh(fields):
    from maverick.billing import RateCard
    from maverick.billing_stripe import _secret_key, preview_charges
    from maverick.tenant.registry import get_tenant
    result = preview_charges(fields["workspace"], RateCard(markup_pct=fields["markup"], minimum_charge=fields["minimum"]),
                             since=fields["since"], until=fields["until"])
    result["connection_fingerprint"] = hashlib.sha256(_secret_key().encode()).hexdigest()
    tenant = get_tenant(fields["workspace"])
    result["initial_customer"] = tenant.stripe_customer_id if tenant else ""
    return result


def prepare(context, fields):
    now = time.time()
    current = STORE.get(_key(fields["workspace"]))
    fresh = _fresh(fields)
    resume = bool(current and current["state"] in {"running", "unknown"})
    if resume:
        _same_scope(current, context)
        if current.get("claim_until", 0) > now:
            raise HTTPException(409, "This workspace has a sync in progress. Read its retained receipt before retrying.")
        if current["fields"] != fields:
            raise HTTPException(409, "Resolve the retained sync before changing its workspace, period or rates. A new invoice identity cannot bypass uncertainty.")
        snapshot = _unpack(current)
        if any(snapshot.get(key) != fresh.get(key) for key in SETTINGS_FIELDS):
            raise HTTPException(409, "Billing settings changed after dispatch. Reconcile the retained receipt before any further sync.")
    else:
        snapshot = fresh
    review = secrets.token_hex(24)
    if current:
        def change(value):
            if not resume:
                history = list(value.get("history", []))
                if value["state"] == "complete":
                    history.append(public_receipt(value))
                if len(history) > 500:
                    raise HTTPException(409, "This workspace has reached the retained receipt limit. Export and arrange governed archival before starting another sync.")
                value.update(_new(context, fields, snapshot, now))
                value["history"] = history
            value.update(review=review, review_expires=now + REVIEW_SECONDS, claim_until=0)
        current = _saved(current, context["actor"], "review", change)
    else:
        current = _new(context, fields, snapshot, now)
        current.update(id=_key(fields["workspace"]), review=review, review_expires=now + REVIEW_SECONDS, history=[])
        current = STORE.create(current, action="review", actor=context["actor"])
    _audited(current)
    return {"review_id": review, "review_expires": current["review_expires"],
            "sha256": current["snapshot_sha256"], "snapshot": {k: v for k, v in snapshot.items() if k != "connection_fingerprint"},
            "resume": resume, "receipt": public_receipt(current),
            "ledger_changed_since_dispatch": resume and _digest(fresh["invoice"]) != _digest(snapshot["invoice"])}


def _new(context, fields, snapshot, now):
    return {"scope": context, "fields": fields, "state": "prepared", "attempt": secrets.token_hex(16),
            "prepared_at": now, "snapshot_sealed": _pack(snapshot), "snapshot_sha256": _digest(snapshot),
            "stages": {name: {"state": "not_started"} for name in ("customer", "subscription", "usage")},
            "claim_until": 0, "dispatches": []}


def public_receipt(record):
    from urllib.parse import urlencode
    return {"attempt": record["attempt"], "workspace": record["fields"]["workspace"],
            "state": record["state"], "prepared_at": record["prepared_at"],
            "updated_at": record.get("updated_at", record["prepared_at"]),
            "sha256": record["snapshot_sha256"], "stages": copy.deepcopy(record["stages"]),
            "dispatches": copy.deepcopy(record.get("dispatches", [])),
            "audit_pending": bool(record.get("_audit_pending")),
            "receipt_href": "/api/v1/admin/billing-ops/stripe/receipt?" + urlencode({"workspace": record["fields"]["workspace"]}),
            "reconciliation_href": "https://dashboard.stripe.com/",
            "message": ("All requested stages are confirmed in this receipt; this does not mean an invoice was paid."
                        if record["state"] == "complete" else
                        "Pending or unknown stages may have changed Stripe. Inspect this receipt before retrying; no automatic paid retry occurs.")}


def receipt(context, workspace, offset=0):
    record = STORE.get(_key(workspace))
    if not record:
        return {"current": None, "history": [], "next_offset": None}
    _same_scope(record, context)
    history = list(reversed(record.get("history", [])))
    return {"current": public_receipt(record), "history": history[offset:offset + 25],
            "next_offset": offset + 25 if offset + 25 < len(history) else None}


class _DispatchSession:
    def __init__(self, record, context, fields, snapshot, token, authorize):
        self.record, self.context, self.fields = record, context, fields
        self.snapshot, self.token, self.authorize = snapshot, token, authorize

    def save(self, action, change):
        current = STORE.get(self.record["id"])
        if not current or current.get("claim") != self.token:
            raise HTTPException(409, "Another recovery owns this receipt. Read its current state.")
        self.record = _saved(current, self.context["actor"], action, change)
        return self.record

    def check(self):
        self.authorize()
        current = _fresh(self.fields)
        if any(self.snapshot.get(key) != current.get(key) for key in SETTINGS_FIELDS):
            raise HTTPException(409, "Billing settings changed during sync. Remaining stages were held; inspect the retained receipt.")
        customer = self.record["stages"]["customer"]
        if customer["state"] == "confirmed" and current.get("initial_customer") != customer.get("result", {}).get("customer"):
            raise HTTPException(409, "The workspace's billing customer changed. Reconcile the retained receipt before further dispatch.")


class _GuardedClient:
    def __init__(self, delegate, session):
        self.delegate = delegate
        self.session = session

    def list_subscriptions(self, customer_id):
        self.session.check()
        return self.delegate.list_subscriptions(customer_id)

    def dispatch(self, method, stage, args):
        self.session.check()
        identity = _digest({"method": method, "idempotency_key": args.get("idempotency_key"),
                            "subscription_id": args.get("subscription_id")})
        arguments_digest = _digest(args)
        existing = next((d for d in self.session.record["dispatches"] if d["identity"] == identity), None)
        if existing and existing.get("arguments_sha256") != arguments_digest:
            raise HTTPException(409, "The provider request parameters changed after dispatch. Reconcile the original request before retrying.")
        if existing and method in {"create_customer", "create_subscription"} and time.time() - existing["started_at"] > SAFE_RETRY_SECONDS:
            raise HTTPException(409, "A prior provider dispatch is outside the safe idempotency retry window. Reconcile it in Stripe; a fresh preview cannot bypass it.")
        if len(self.session.record["dispatches"]) >= 5000 and not existing:
            raise HTTPException(409, "Dispatch receipt capacity reached. Remaining effects were held.")
        def pending(value):
            value["claim_until"] = time.time() + CLAIM_SECONDS
            if not existing:
                value["dispatches"].append({"identity": identity, "arguments_sha256": arguments_digest, "method": method, "stage": stage,
                                            "started_at": time.time(), "state": "pending"})
        _audited(self.session.save("provider_dispatch", pending))
        result = getattr(self.delegate, method)(**args)
        def confirmed(value):
            dispatch = next(d for d in value["dispatches"] if d["identity"] == identity)
            dispatch.update(state="confirmed", provider_id=str(result.get("id", ""))[:128], confirmed_at=time.time())
        self.session.save("provider_result", confirmed)
        return result

    def create_customer(self, **kwargs):
        return self.dispatch("create_customer", "customer", kwargs)

    def create_subscription(self, **kwargs):
        if kwargs.get("price_id") != self.session.snapshot["platform_fee_price"]:
            raise HTTPException(409, "The subscription price differs from the review.")
        return self.dispatch("create_subscription", "subscription", kwargs)

    def update_subscription(self, subscription_id, **kwargs):
        if kwargs.get("price_id") != self.session.snapshot["platform_fee_price"]:
            raise HTTPException(409, "The subscription price differs from the review.")
        return self.dispatch("update_subscription", "subscription", {"subscription_id": subscription_id, **kwargs})

    def create_invoice_item(self, **kwargs):
        return self.dispatch("create_invoice_item", "usage", kwargs)


def execute(context, fields, review, digest, authorize, *, client=None):
    """Explicit invocation only. CAS prevents concurrent ownership of a dispatch."""
    from maverick import billing_stripe as stripe
    from maverick.billing import Invoice, LineItem

    record = STORE.get(_key(fields["workspace"]))
    if not record:
        raise HTTPException(409, "Prepare and review this billing change first.")
    _same_scope(record, context)
    if record["fields"] != fields or not hmac.compare_digest(record.get("review", ""), review):
        raise HTTPException(409, "The fields or review changed. Review the exact change again before sending.")
    if not hmac.compare_digest(record["snapshot_sha256"], digest):
        raise HTTPException(409, "The reviewed billing contents do not match.")
    if record["state"] == "complete":
        return public_receipt(record)
    if time.time() > record["review_expires"]:
        raise HTTPException(409, "The billing review expired. Prepare it again; no new dispatch occurred.")
    if record.get("claim_until", 0) > time.time():
        return public_receipt(record)
    snapshot = _unpack(record)
    fresh = _fresh(fields)
    if record["state"] == "prepared":
        stale = _digest(fresh) != record["snapshot_sha256"]
    else:
        stale = any(snapshot.get(key) != fresh.get(key) for key in SETTINGS_FIELDS)
    if stale:
        raise HTTPException(409, "The plan, settings or rated contents changed. Inspect the existing receipt and review again.")
    authorize()
    stripe.require_enabled()
    invoice = None
    if snapshot["metered_billing_enabled"]:
        frozen = dict(snapshot["invoice"])
        frozen["line_items"] = [LineItem(**line) for line in frozen["line_items"]]
        invoice = Invoice(**frozen)
        stripe._validate_collection_period(fields["workspace"], invoice)
        stripe._rated_usage_items(invoice, snapshot["currency"])
    token = secrets.token_hex(16)
    record = _audited(_saved(record, context["actor"], "claim_dispatch",
        lambda value: value.update(state="running", claim=token, claim_until=time.time() + CLAIM_SECONDS)))

    session = _DispatchSession(record, context, fields, snapshot, token, authorize)
    save, check = session.save, session.check

    current_stage = None
    try:
        guarded = _GuardedClient(stripe._client(client), session)
        steps = (
            ("customer", lambda: {"customer": stripe.ensure_customer(fields["workspace"], client=guarded)}),
            ("subscription", lambda: stripe.ensure_subscription(fields["workspace"], client=guarded)),
            ("usage", lambda: {"items": stripe.push_usage_items(fields["workspace"], invoice, client=guarded)} if invoice else {"not_requested": True}),
        )
        for name, operation in steps:
            current_stage = name
            if session.record["stages"][name]["state"] == "confirmed":
                continue
            check()
            _audited(save("stage_started", lambda value, name=name: value["stages"][name].update(state="pending", started_at=time.time())))
            result = operation()
            save("stage_confirmed", lambda value, name=name, result=result: value["stages"][name].update(state="confirmed", result=result, confirmed_at=time.time()))
        save("sync_complete", lambda value: value.update(state="complete", claim_until=0))
    except Exception:
        def uncertain(value):
            value.update(state="unknown", claim_until=0)
            if current_stage and value["stages"][current_stage]["state"] != "confirmed":
                value["stages"][current_stage]["state"] = "unknown"
        try:
            save("sync_uncertain", uncertain)
        except Exception:
            # The durable pre-dispatch receipt remains pending when a result
            # cannot be persisted. Never replace it with a success claim.
            latest = STORE.get(session.record["id"])
            if latest:
                session.record = latest
        return public_receipt(session.record)
    return public_receipt(session.record)
