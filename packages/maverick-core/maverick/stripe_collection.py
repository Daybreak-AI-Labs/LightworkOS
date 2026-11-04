"""Frozen per-period Stripe collection receipts, independent of API key retention."""
from __future__ import annotations

import hashlib
import json
from datetime import date

from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .paths import data_dir


def _exclude_overlapping_periods(path, binding) -> None:
    """A daily ledger row can belong to only one frozen collection period.

    The tenant fence covers this read and publication of the new receipt. A
    changed currency or changed date range cannot create a second lifecycle
    for usage already claimed by an earlier or ambiguous collection.
    """
    from .billing_stripe import StripeError

    for existing in path.parent.glob("*.json"):
        if existing == path:
            continue
        try:
            receipt = json.loads(atomic_read_text(existing))
            prior = receipt["binding"]
            if (receipt.get("schema") != 1
                    or not isinstance(prior, dict) or prior.get("tenant") != binding["tenant"]
                    or not isinstance(prior.get("start"), str)
                    or not isinstance(prior.get("end"), str)
                    or prior["start"] != date.fromisoformat(prior["start"]).isoformat()
                    or prior["end"] != date.fromisoformat(prior["end"]).isoformat()
                    or prior["start"] > prior["end"]
                    or receipt.get("digest") != _binding_digest(prior)):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise StripeError("Prior collection period is unknown; reconcile before billing") from exc
        if prior["start"] <= binding["end"] and binding["start"] <= prior["end"]:
            raise StripeError("Invoice period overlaps a frozen collection; reconcile before billing")


def _binding_digest(binding):
    return hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def collect_invoice(tenant_id, invoice, currency, rated, *, client):
    from .billing_stripe import StripeError, _collect_invoice_items

    binding = {"tenant": tenant_id, "invoice_id": invoice.invoice_id,
               "start": invoice.period_start, "end": invoice.period_end,
               "currency": currency, "lines": rated, "total": str(invoice.total)}
    digest = _binding_digest(binding)
    # The period, not a caller-chosen invoice id, defines the charge lifecycle.
    identity = json.dumps([tenant_id, invoice.period_start, invoice.period_end, currency])
    path = data_dir("billing", "stripe-collections", hashlib.sha256(identity.encode()).hexdigest() + ".json", tenant=tenant_id)
    ensure_private_directory(path.parent)
    with cross_process_lock(path.parent / ".collection-fence", strict=True), cross_process_lock(path, strict=True):
        _exclude_overlapping_periods(path, binding)
        try:
            state = json.loads(atomic_read_text(path))
        except FileNotFoundError:
            state = {"schema": 1, "digest": digest, "items": {}, "binding": binding}
        except (OSError, ValueError) as exc:
            raise StripeError("Collection receipt is unreadable; reconcile before billing") from exc
        if (not isinstance(state, dict) or state.get("schema") != 1
                or state.get("digest") != digest or not isinstance(state.get("items"), dict)):
            raise StripeError("Closed invoice changed or receipt is invalid; reconcile before billing")
        # Existing same-period receipts have already authenticated this binding
        # through their digest; retain its explicit dates for future overlap checks.
        if state.get("binding", binding) != binding:
            raise StripeError("Collection period binding is invalid; reconcile before billing")
        state["binding"] = binding

        def save():
            atomic_write_text(path, json.dumps(state, sort_keys=True, allow_nan=False))

        save()  # Freeze the rated invoice before creating any external item.
        return _collect_invoice_items(tenant_id, invoice, currency, rated,
                                      client=client, state=state, save=save)
