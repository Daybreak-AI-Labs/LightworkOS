"""Authoritative bridge from consent receipts to durable outbound delivery.

The bridge accepts no caller-created change body.  It reads the immutable
consent outbox, resolves the exact receipt, verifies every duplicated binding,
and only then constructs :class:`ConsentChange`.  A destination-set digest is
the subscription cursor: retries of the same set are exact, while adding a new
destination is an explicit new subscription/replay decision.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Sequence
from typing import Any

from .consent_delivery import (
    ConsentChange,
    ConsentDeliveryStore,
    ConsentDeliveryValidationError,
    DeliveryPreferenceChoice,
)
from .consent_preferences import ConsentPreferenceStore
from .paths import canonical_tenant_id

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_DESTINATIONS = 64
_MAX_EVENTS = 500


class ConsentDeliveryBridgeError(RuntimeError):
    """Base error for the authority-to-delivery bridge."""


class ConsentDeliveryBridgeValidationError(ConsentDeliveryBridgeError, ValueError):
    """A bridge request is outside the closed subscription contract."""


class ConsentDeliveryBridgeIntegrityError(ConsentDeliveryBridgeError):
    """An outbox event and its immutable receipt do not agree exactly."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ConsentDeliveryBridgeIntegrityError(
            "consent delivery bridge data is not finite JSON"
        ) from exc


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise ConsentDeliveryBridgeValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise ConsentDeliveryBridgeValidationError("tenant_id is invalid") from exc


def _destinations(values: object) -> tuple[str, ...]:
    if (
        isinstance(values, (str, bytes))
        or not isinstance(values, Sequence)
        or not 1 <= len(values) <= _MAX_DESTINATIONS
    ):
        raise ConsentDeliveryBridgeValidationError(
            f"destination_ids must contain 1 to {_MAX_DESTINATIONS} entries"
        )
    normalized = tuple(sorted(_ref(value, "destination_id") for value in values))
    if len(set(normalized)) != len(normalized):
        raise ConsentDeliveryBridgeValidationError(
            "destination_ids cannot contain duplicates"
        )
    return normalized


def _limit(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_EVENTS:
        raise ConsentDeliveryBridgeValidationError(
            f"limit must be between 1 and {_MAX_EVENTS}"
        )
    return value


def _same(left: object, right: object) -> bool:
    return hmac.compare_digest(_canonical(left), _canonical(right))


class ConsentDeliveryBridge:
    """Synchronize one explicit destination set from the receipt authority."""

    def __init__(
        self,
        preference_store: ConsentPreferenceStore,
        delivery_store: ConsentDeliveryStore,
    ) -> None:
        if not isinstance(preference_store, ConsentPreferenceStore):
            raise TypeError("preference_store must be a ConsentPreferenceStore")
        if not isinstance(delivery_store, ConsentDeliveryStore):
            raise TypeError("delivery_store must be a ConsentDeliveryStore")
        self._preferences = preference_store
        self._delivery = delivery_store

    @staticmethod
    def _subscription(destinations: tuple[str, ...]) -> tuple[str, str]:
        digest = hashlib.sha256(_canonical(list(destinations))).hexdigest()
        return f"delivery.{digest[:32]}", digest

    def _change(self, tenant_id: str, event: dict[str, Any]) -> ConsentChange:
        if event.get("event_type") != "preferences.changed":
            raise ConsentDeliveryBridgeValidationError(
                "only preferences.changed events can become delivery changes"
            )
        payload = event.get("payload")
        if not isinstance(payload, dict):
            raise ConsentDeliveryBridgeIntegrityError("outbox payload shape is invalid")
        receipt_id = payload.get("receipt_id")
        if not isinstance(receipt_id, str):
            raise ConsentDeliveryBridgeIntegrityError("outbox receipt binding is invalid")
        receipt = self._preferences.get_receipt(tenant_id, receipt_id)
        duplicated = {
            "profile_id": payload.get("profile_id"),
            "profile_revision": payload.get("profile_revision"),
            "receipt_id": receipt_id,
            "receipt_sha256": payload.get("receipt_sha256"),
            "policy_id": payload.get("policy_id"),
            "policy_version": payload.get("policy_version"),
            "choices": payload.get("choices"),
        }
        authoritative = {
            "profile_id": receipt.get("profile_id"),
            "profile_revision": receipt.get("profile_revision"),
            "receipt_id": receipt.get("receipt_id"),
            "receipt_sha256": receipt.get("receipt_sha256"),
            "policy_id": receipt.get("policy_id"),
            "policy_version": receipt.get("policy_version"),
            "choices": receipt.get("choices"),
        }
        if not _same(duplicated, authoritative):
            raise ConsentDeliveryBridgeIntegrityError(
                "outbox event does not match its immutable receipt"
            )
        raw_choices = receipt.get("choices")
        if not isinstance(raw_choices, list) or not raw_choices:
            raise ConsentDeliveryBridgeIntegrityError("receipt choices are invalid")
        try:
            choices = tuple(
                DeliveryPreferenceChoice(
                    purpose_id=str(item["purpose_id"]),
                    action=str(item["action"]),
                    channel=str(item["channel"]),
                    vendor_id=str(item["vendor_id"]),
                )
                for item in raw_choices
                if isinstance(item, dict)
            )
            if len(choices) != len(raw_choices):
                raise KeyError("choice shape")
            change = ConsentChange(
                event_id=str(event["event_id"]),
                event_kind="preferences_changed",
                profile_id=str(receipt["profile_id"]),
                profile_revision=int(receipt["profile_revision"]),
                receipt_id=str(receipt["receipt_id"]),
                receipt_sha256=str(receipt["receipt_sha256"]),
                policy_id=str(receipt["policy_id"]),
                policy_version=int(receipt["policy_version"]),
                policy_sha256=str(receipt["policy_sha256"]),
                choices=choices,
                occurred_at=float(receipt["created_at"]),
            )
            change.normalized()
            return change
        except (KeyError, TypeError, ValueError, ConsentDeliveryValidationError) as exc:
            raise ConsentDeliveryBridgeIntegrityError(
                "receipt cannot be represented by the delivery contract"
            ) from exc

    def sync_once(
        self,
        tenant_id: str,
        destination_ids: Sequence[str],
        *,
        limit: int = 100,
        after_sequence: int = 0,
    ) -> dict[str, Any]:
        """Queue and acknowledge one bounded page in source sequence order.

        Source acknowledgment happens only after an atomic delivery enqueue.
        Non-preference authority events are acknowledged as explicitly skipped;
        they are never coerced into a preference-change envelope.
        """

        tenant = _tenant_id(tenant_id)
        destinations = _destinations(destination_ids)
        page_size = _limit(limit)
        subscription_id, destination_set_sha256 = self._subscription(destinations)
        page = self._preferences.read_outbox(
            tenant,
            subscription_id,
            limit=page_size,
            after_sequence=after_sequence,
        )
        queued = 0
        skipped = 0
        messages = 0
        last_sequence = 0
        for event in page["events"]:
            event_id = _ref(event.get("event_id"), "event_id")
            last_sequence = int(event["sequence"])
            if event.get("event_type") == "preferences.changed":
                change = self._change(tenant, event)
                result = self._delivery.enqueue_change(
                    tenant,
                    change,
                    destination_ids=destinations,
                    idempotency_key=f"bridge.enqueue.{event_id}.{destination_set_sha256[:32]}",
                )
                queued += 1
                messages += len(result["messages"])
            else:
                skipped += 1
            self._preferences.ack_outbox(
                tenant,
                subscription_id,
                event_id,
                f"bridge.ack.{event_id}",
            )
        return {
            "subscription_id": subscription_id,
            "destination_ids": list(destinations),
            "destination_set_sha256": destination_set_sha256,
            "events_read": len(page["events"]),
            "changes_queued": queued,
            "messages_queued": messages,
            "events_skipped": skipped,
            "last_sequence": last_sequence,
            "truncated": bool(page["truncated"]),
            "complete": not bool(page["truncated"]),
        }


__all__ = [
    "ConsentDeliveryBridge",
    "ConsentDeliveryBridgeError",
    "ConsentDeliveryBridgeIntegrityError",
    "ConsentDeliveryBridgeValidationError",
]
