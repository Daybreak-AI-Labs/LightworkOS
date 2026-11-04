"""Explicit notification worker for third-party monitoring alerts.

The intelligence authority owns a durable at-least-once outbox while this
module owns the external side effect. Saved addresses use the tenant vault;
batch evidence contains delivery references and outcomes only. An admitted but
uncertain send is retained for review and is never automatically replayed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Protocol

from .third_party_intelligence import OutboxItem, ThirdPartyIntelligenceStore


class ThirdPartyAlertDeliveryError(RuntimeError):
    """Base error for the external notification boundary."""


class DestinationResolutionError(ThirdPartyAlertDeliveryError):
    """An opaque destination reference could not be safely resolved."""


class ThirdPartyAlertTransport(Protocol):
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
    cancelled: int = 0
    semantics: str = "at_least_once"


class SmtpThirdPartyAlertTransport:
    """Use Lightwork's credential-safe platform mail sender."""

    def send(
        self,
        *,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
        before_effect: Callable[[], None] | None = None,
    ) -> None:
        from . import mailer

        mailer.send(
            recipient,
            subject,
            f"{body}\n\nLightwork delivery reference: {idempotency_key}\n",
            before_effect=before_effect,
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


def _message(store: ThirdPartyIntelligenceStore, item: OutboxItem) -> str:
    alert = store.get_monitoring_alert(item.tenant_id, item.alert_id)
    monitor = store.get_monitor(item.tenant_id, alert.monitor_id)
    vendor = store.get_vendor(item.tenant_id, alert.vendor_id)
    return (
        f"An approved risk-data source reported a change for {vendor.display_label}.\n\n"
        "Open Lightwork → Third-party intelligence → Watching for changes to "
        "review the source evidence and decide what to do. Sign in to your own workspace.\n\n"
        "This change needs review. It does not approve the vendor or make a legal "
        "or compliance decision.\n\n"
        f"Review reference: {alert.alert_id}\nWatch reference: {monitor.monitor_id}"
    )


def deliver_alert_batch(
    store: ThirdPartyIntelligenceStore,
    *,
    tenant_id: str,
    worker_id: str,
    resolve_destination: DestinationResolver,
    transport: ThirdPartyAlertTransport,
    limit: int = 10,
    lease_seconds: float = 60.0,
    base_backoff_seconds: float = 30.0,
    maximum_backoff_seconds: float = 86_400.0,
    delivery_ids: tuple[str, ...] | None = None,
    claim_guard: Callable[[], None] | None = None,
    effect_guard: Callable[[OutboxItem], None] | None = None,
) -> DeliveryBatchResult:
    """Claim and deliver one bounded batch with explicit at-least-once limits."""

    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
        raise ValueError("limit must be an integer from 1 to 100")
    if not isinstance(lease_seconds, (int, float)) or isinstance(lease_seconds, bool):
        raise ValueError("lease_seconds must be numeric")
    if not 1.0 <= float(lease_seconds) <= 3_600.0:
        raise ValueError("lease_seconds must be from 1 through 3600")
    if not callable(resolve_destination):
        raise TypeError("resolve_destination must be callable")

    items = store.claim_outbox(
        tenant_id,
        worker_id=worker_id,
        limit=limit,
        lease_seconds=float(lease_seconds),
        delivery_ids=delivery_ids,
        effect_guard=claim_guard,
    )
    outcomes: list[DeliveryOutcome] = []
    acknowledged = retry_pending = dead_lettered = ambiguous = cancelled = 0
    for item in items:
        assert item.lease_token is not None
        dispatched = False
        try:
            recipient = _recipient(
                resolve_destination(item.tenant_id, item.destination_ref)
            )
            body = _message(store, item)

            def current_effect(item=item, recipient=recipient):
                store.assert_delivery_authority(item)
                if effect_guard:
                    effect_guard(item)
                if _recipient(resolve_destination(item.tenant_id, item.destination_ref)) != recipient:
                    raise DestinationResolutionError("The selected recipient changed before sending.")

            store.mark_outbox_dispatch(item)
            dispatched = True
            kwargs = dict(recipient=recipient, subject="Lightwork third-party risk change",
                          body=body, idempotency_key=item.delivery_id)
            if isinstance(transport, SmtpThirdPartyAlertTransport):
                transport.send(**kwargs, before_effect=current_effect)
            else:
                from .authority_effects import authority_effect_fence

                with authority_effect_fence():
                    current_effect()
                    transport.send(**kwargs)
        except Exception as error:  # noqa: BLE001 - sanitized at transport boundary
            from .mailer import MailerNotSent

            if dispatched and not isinstance(error, MailerNotSent):
                # A physical write may have happened. Durable dispatching already
                # prevents expiry/restart from reclaiming this admitted effect.
                try:
                    store.mark_outbox_dispatch(item, ambiguous=True)
                except Exception:
                    pass  # The original dispatch receipt must remain retained.
                ambiguous += 1
                outcomes.append(DeliveryOutcome(item.delivery_id, "ambiguous", "send_unconfirmed"))
                continue
            error_code = _safe_error_code(error)
            backoff = min(
                float(maximum_backoff_seconds),
                float(base_backoff_seconds) * (2 ** max(0, item.attempt - 1)),
            )
            failed = store.fail_outbox(
                item.tenant_id,
                item.delivery_id,
                lease_token=item.lease_token,
                error_code=error_code,
                backoff_seconds=backoff,
            )
            if failed.state == "dead_letter":
                dead_lettered += 1
            elif failed.state == "cancelled":
                cancelled += 1
            else:
                retry_pending += 1
            outcomes.append(DeliveryOutcome(item.delivery_id, failed.state, error_code))
            continue

        try:
            stored = store.acknowledge_outbox(
                item.tenant_id,
                item.delivery_id,
                lease_token=item.lease_token,
            )
        except Exception:  # noqa: BLE001 - send succeeded; outcome is ambiguous
            try:
                store.mark_outbox_dispatch(item, ambiguous=True)
            except Exception:
                pass  # Never revert the existing dispatch admission to retryable.
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
        cancelled=cancelled,
    )


__all__ = [
    "DeliveryBatchResult",
    "DeliveryOutcome",
    "DestinationResolutionError",
    "SmtpThirdPartyAlertTransport",
    "ThirdPartyAlertDeliveryError",
    "ThirdPartyAlertTransport",
    "deliver_alert_batch",
]
