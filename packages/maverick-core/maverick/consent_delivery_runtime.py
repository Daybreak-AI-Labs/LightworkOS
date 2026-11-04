"""Deployable consent delivery worker with external signing custody.

Signing secrets are resolved at send time from environment variables whose
names are derived from key IDs.  SQLite stores only key IDs and digests.  The
runtime first bridges immutable consent receipts into the delivery queue, then
claims and sends a bounded batch through the hardened HTTPS transport.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from collections.abc import Sequence
from typing import Any

from .consent_delivery import (
    ConsentDeliveryConfigError,
    ConsentDeliveryDispatcher,
    ConsentDeliveryStore,
    DeliverySigner,
    DeliveryTransport,
)
from .consent_delivery_bridge import ConsentDeliveryBridge
from .consent_preferences import ConsentPreferenceStore

_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_WORKER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def signing_secret_environment_name(key_id: str) -> str:
    """Return a stable non-revealing environment name for one signing key ID."""

    if not isinstance(key_id, str) or not _KEY_RE.fullmatch(key_id):
        raise ConsentDeliveryConfigError("signing key id is invalid")
    digest = hashlib.sha256(key_id.encode("utf-8")).hexdigest().upper()
    return f"MAVERICK_CONSENT_DELIVERY_KEY_{digest[:32]}"


class EnvironmentHMACDeliverySigner:
    """HMAC-SHA256 signer whose raw keys remain in deployment custody."""

    def __init__(self, *, environ: dict[str, str] | None = None) -> None:
        self._environ = os.environ if environ is None else environ

    def sign(self, key_id: str, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or not payload:
            raise ConsentDeliveryConfigError("signing payload is invalid")
        name = signing_secret_environment_name(key_id)
        encoded = self._environ.get(name, "")
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except (ValueError, TypeError) as exc:
            raise ConsentDeliveryConfigError("delivery signing key is unavailable") from exc
        if not 32 <= len(raw) <= 64:
            raise ConsentDeliveryConfigError("delivery signing key is unavailable")
        return hmac.new(raw, payload, hashlib.sha256).digest()


class SavedHMACDeliverySigner(EnvironmentHMACDeliverySigner):
    """Exact tenant-scoped saved key; existing deployment keys remain supported."""

    def __init__(self, store, tenant_id):
        super().__init__()
        self._store, self._tenant = store, tenant_id

    def sign(self, key_id, payload):
        record = self._store.managed_record(self._tenant, "key", key_id)
        if record is None:
            return super().sign(key_id, payload)
        raw = record["material"]["secret"].encode("utf-8")
        if not 32 <= len(raw) <= 64:
            raise ConsentDeliveryConfigError("Saved delivery signing key is unavailable.")
        return hmac.new(raw, payload, hashlib.sha256).digest()


def run_delivery_once(
    tenant_id: str,
    destination_ids: Sequence[str],
    *,
    worker_id: str,
    sync_limit: int = 100,
    delivery_limit: int = 10,
    lease_seconds: float = 60.0,
    preference_store: ConsentPreferenceStore | None = None,
    delivery_store: ConsentDeliveryStore | None = None,
    signer: DeliverySigner | None = None,
    transport: DeliveryTransport | None = None,
    after_sequence: int = 0,
    before_effect=None,
    hold_unknown: bool = False,
) -> dict[str, Any]:
    """Bridge and dispatch one bounded batch for an explicitly selected tenant."""

    if not isinstance(worker_id, str) or not _WORKER_RE.fullmatch(worker_id):
        raise ConsentDeliveryConfigError("worker_id is invalid")
    if preference_store is None or delivery_store is None:
        from .paths import data_dir

        preference_store = preference_store or ConsentPreferenceStore(
            data_dir(
                "consent_preferences",
                "consent-preferences.sqlite3",
                tenant=tenant_id,
            )
        )
        delivery_store = delivery_store or ConsentDeliveryStore(
            data_dir(
                "consent_preferences",
                "consent-delivery.sqlite3",
                tenant=tenant_id,
            )
        )
    bridge = ConsentDeliveryBridge(preference_store, delivery_store)
    if before_effect is not None:
        before_effect(None)
    synchronized = bridge.sync_once(
        tenant_id,
        destination_ids,
        limit=sync_limit,
        after_sequence=after_sequence,
    )
    if before_effect is not None:
        before_effect(None)
    dispatcher = ConsentDeliveryDispatcher(
        delivery_store,
        signer=signer or SavedHMACDeliverySigner(delivery_store, tenant_id),
        transport=transport,
        before_effect=before_effect,
        hold_unknown=hold_unknown,
    )
    dispatched = dispatcher.deliver_once(
        tenant_id,
        worker_id=worker_id,
        limit=delivery_limit,
        lease_seconds=lease_seconds,
        destination_ids=tuple(destination_ids),
    )
    return {
        "synchronized": synchronized,
        "dispatched": dispatched,
        "source_complete": synchronized["complete"],
        "live_external_acceptance": False,
    }


__all__ = [
    "EnvironmentHMACDeliverySigner",
    "SavedHMACDeliverySigner",
    "run_delivery_once",
    "signing_secret_environment_name",
]
