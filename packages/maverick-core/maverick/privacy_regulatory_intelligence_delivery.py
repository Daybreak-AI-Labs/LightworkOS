"""Explicit worker boundary for privacy-intelligence alert delivery.

The regulatory-intelligence store persists an at-least-once delivery outbox but
does not turn an opaque ``destination_ref`` into an email address or perform
network I/O.  This module owns that final boundary: a deployment injects a
tenant-aware destination resolver and a transport, then explicitly runs a
bounded batch.  Raw credentials and destination addresses never enter the
regulatory-intelligence database or batch result.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Protocol

from .privacy_regulatory_intelligence import (
    DeliveryItem,
    PrivacyRegulatoryIntelligenceStore,
)


class PrivacyAlertDeliveryError(RuntimeError):
    """Base error for the external notification boundary."""


class DestinationResolutionError(PrivacyAlertDeliveryError):
    """An opaque destination reference could not be safely resolved."""


class PrivacyAlertTransport(Protocol):
    """External side-effect boundary used by :func:`deliver_alert_batch`."""

    def send(
        self,
        *,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> None: ...


DestinationResolver = Callable[[str, str], str]


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    delivery_id: str
    state: str
    error_code: str | None = None


@dataclass(frozen=True, slots=True)
class DeliveryBatchResult:
    tenant_id: str
    claimed: int
    acknowledged: int
    retry_pending: int
    dead_lettered: int
    acknowledgement_ambiguous: int
    outcomes: tuple[DeliveryOutcome, ...]
    semantics: str = "at_least_once"


class SmtpPrivacyAlertTransport:
    """Use Lightwork's existing credential-safe platform SMTP sender."""

    def send(
        self,
        *,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> None:
        from . import mailer

        # SMTP has no portable idempotency primitive.  Include the immutable
        # delivery ID in the body so a recipient/operator can identify retries.
        mailer.send(
            recipient,
            subject,
            f"{body}\n\nLightwork delivery reference: {idempotency_key}\n",
        )


def _recipient(value: str) -> str:
    if not isinstance(value, str):
        raise DestinationResolutionError("destination resolver returned non-text")
    candidate = value.strip()
    if not candidate or "\r" in candidate or "\n" in candidate:
        raise DestinationResolutionError("destination resolver returned unsafe value")
    display, address = parseaddr(candidate)
    if display or address != candidate or len(address) > 320:
        raise DestinationResolutionError("destination must be one plain email address")
    local, separator, domain = address.rpartition("@")
    if not separator or not local or not domain or "." not in domain:
        raise DestinationResolutionError("destination is not a valid email address")
    return address


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, DestinationResolutionError):
        return "destination_unavailable"
    name = type(error).__name__.lower()
    if "reject" in name or "refus" in name:
        return "provider_rejected"
    if "timeout" in name or "connection" in name or "transport" in name:
        return "transport_unavailable"
    return "delivery_error"


def _message(store: PrivacyRegulatoryIntelligenceStore, item: DeliveryItem) -> str:
    tracker = store.get_saved_query(item.tenant_id, item.subscription_id)
    jurisdictions = ", ".join(tracker.jurisdictions)
    query = tracker.query[:2_048]
    return (
        "A newly retained, licensed regulatory document matched your Lightwork "
        "privacy tracker.\n\n"
        f"Tracker: {tracker.subscription_id}\n"
        f"Query: {query}\n"
        f"Jurisdictions: {jurisdictions}\n"
        f"Alert reference: {item.alert_id}\n\n"
        "Open the authenticated Privacy Regulatory Intelligence workspace to "
        "review the cited evidence. This notification is not legal advice."
    )


def deliver_alert_batch(
    store: PrivacyRegulatoryIntelligenceStore,
    *,
    tenant_id: str,
    worker_id: str,
    resolve_destination: DestinationResolver,
    transport: PrivacyAlertTransport,
    limit: int = 10,
    lease_seconds: float = 60.0,
    base_backoff_seconds: float = 30.0,
    maximum_backoff_seconds: float = 86_400.0,
) -> DeliveryBatchResult:
    """Claim and deliver one bounded outbox batch.

    Sending is at-least-once.  If the transport succeeds but durable
    acknowledgement fails, the outcome is reported as ``ack_ambiguous`` and the
    lease is left intact; callers must reconcile before retrying because SMTP
    and many notification providers cannot prove exactly-once delivery.
    """

    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer from 1 to 100")
    if not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool):
        raise ValueError("lease_seconds must be numeric")
    if not 1.0 <= float(lease_seconds) <= 3_600.0:
        raise ValueError("lease_seconds must be from 1 through 3600")
    if not callable(resolve_destination):
        raise TypeError("resolve_destination must be callable")

    items = store.claim_deliveries(
        tenant_id,
        worker_id=worker_id,
        limit=limit,
        lease_seconds=float(lease_seconds),
    )
    outcomes: list[DeliveryOutcome] = []
    acknowledged = retry_pending = dead_lettered = ambiguous = 0

    for item in items:
        assert item.lease_token is not None
        try:
            recipient = _recipient(
                resolve_destination(item.tenant_id, item.destination_ref)
            )
            transport.send(
                recipient=recipient,
                subject="Lightwork privacy regulatory update",
                body=_message(store, item),
                idempotency_key=item.delivery_id,
            )
        except Exception as error:  # noqa: BLE001 - sanitize at transport boundary
            code = _safe_error_code(error)
            # ``item.attempt`` counts the failures before this one, so the
            # first failure waits the base interval and each later one doubles.
            exponent = max(0, item.attempt)
            backoff = min(
                float(maximum_backoff_seconds),
                float(base_backoff_seconds) * (2**exponent),
            )
            failed = store.fail_delivery(
                item.tenant_id,
                item.delivery_id,
                lease_token=item.lease_token,
                error_code=code,
                backoff_seconds=backoff,
            )
            if failed.state == "dead_letter":
                dead_lettered += 1
            else:
                retry_pending += 1
            outcomes.append(DeliveryOutcome(item.delivery_id, failed.state, code))
            continue

        try:
            stored = store.acknowledge_delivery(
                item.tenant_id,
                item.delivery_id,
                lease_token=item.lease_token,
            )
        except Exception:  # noqa: BLE001 - post-send outcome is intentionally ambiguous
            ambiguous += 1
            outcomes.append(
                DeliveryOutcome(item.delivery_id, "ack_ambiguous", "acknowledgement_error")
            )
        else:
            acknowledged += 1
            outcomes.append(DeliveryOutcome(item.delivery_id, stored.state))

    return DeliveryBatchResult(
        tenant_id=tenant_id,
        claimed=len(items),
        acknowledged=acknowledged,
        retry_pending=retry_pending,
        dead_lettered=dead_lettered,
        acknowledgement_ambiguous=ambiguous,
        outcomes=tuple(outcomes),
    )


__all__ = [
    "DeliveryBatchResult",
    "DeliveryOutcome",
    "DestinationResolutionError",
    "PrivacyAlertDeliveryError",
    "PrivacyAlertTransport",
    "SmtpPrivacyAlertTransport",
    "deliver_alert_batch",
]
