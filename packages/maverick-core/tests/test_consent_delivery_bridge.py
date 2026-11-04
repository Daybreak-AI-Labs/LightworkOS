from __future__ import annotations

import hashlib
import itertools
import sqlite3

import pytest
from maverick import config
from maverick.consent_delivery import ConsentDeliveryStore
from maverick.consent_delivery_bridge import (
    ConsentDeliveryBridge,
    ConsentDeliveryBridgeIntegrityError,
    ConsentDeliveryBridgeValidationError,
)
from maverick.consent_preferences import (
    ConsentContext,
    ConsentPreferenceStore,
    PreferenceChoice,
)

NOW = 1_800_000_000.0
DIGEST_A = hashlib.sha256(b"notice").hexdigest()
DIGEST_B = hashlib.sha256(b"actor").hexdigest()


@pytest.fixture(autouse=True)
def _enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: ())
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "delivery": {"enable": True},
            }
        },
    )


def _stores(tmp_path):
    ids = itertools.count(1)
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
    )
    delivery = ConsentDeliveryStore(
        tmp_path / "delivery.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
        config_gate=lambda: True,
        origin_validator=lambda _origin: None,
    )
    return preferences, delivery


def _seed(
    preferences: ConsentPreferenceStore,
    delivery: ConsentDeliveryStore,
    *,
    tenant: str = "tenant-a",
):
    preferences.publish_policy(
        tenant, "notice", 1, {"analytics": "consent"}, DIGEST_A, NOW - 1
    )
    preferences.create_profile(
        tenant, "profile-a", "anonymous", DIGEST_B, "profile-create"
    )
    receipt = preferences.record_preferences(
        tenant,
        "profile-a",
        "notice",
        1,
        ConsentContext(
            jurisdiction="global",
            country_code="US",
            region_code="",
            collection_point="web",
            asserted_source="edge",
        ),
        [PreferenceChoice("analytics", "grant")],
        expected_revision=0,
        idempotency_key="receipt-create",
        actor_sha256=DIGEST_B,
    )
    for destination in ("crm", "warehouse"):
        delivery.enroll_destination(
            tenant,
            destination_id=destination,
            origin=f"https://{destination}.example.com",
            signing_key_id=f"key-{destination}",
            idempotency_key=f"enroll-{destination}",
        )
    return receipt


def test_bridge_uses_one_canonical_tenant_across_consent_authorities(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    decomposed = "Acme Cafe\u0301 Corp"
    canonical = "Acme Caf\u00e9 Corp"
    _seed(preferences, delivery, tenant=decomposed)
    bridge = ConsentDeliveryBridge(preferences, delivery)

    result = bridge.sync_once(canonical, ["crm"])

    assert result["changes_queued"] == 1
    assert delivery.counts(decomposed)["queued"] == 1
    assert preferences.summary(canonical)["profiles"] == 1
    assert delivery.counts("Other Corp")["queued"] == 0


def test_bridge_queues_only_authoritative_receipts_and_replays_exactly(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    receipt = _seed(preferences, delivery)
    bridge = ConsentDeliveryBridge(preferences, delivery)

    first = bridge.sync_once("tenant-a", ["warehouse", "crm"])
    assert first["events_read"] == 2
    assert first["events_skipped"] == 1
    assert first["changes_queued"] == 1
    assert first["messages_queued"] == 2
    assert first["complete"] is True
    assert delivery.counts("tenant-a")["queued"] == 2
    dead = bridge.sync_once("tenant-a", ["crm", "warehouse"])
    assert dead["events_read"] == 0
    assert dead["messages_queued"] == 0

    messages = []
    with sqlite3.connect(delivery.path) as connection:
        rows = connection.execute(
            "SELECT payload_json FROM delivery_messages ORDER BY destination_id"
        ).fetchall()
        messages = [row[0] for row in rows]
    assert all(receipt["receipt_sha256"] in payload for payload in messages)
    assert DIGEST_B not in delivery.path.read_text("latin1")


def test_bridge_fails_closed_on_outbox_receipt_mismatch_without_ack(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    _seed(preferences, delivery)
    bridge = ConsentDeliveryBridge(preferences, delivery)
    with sqlite3.connect(preferences.path) as connection:
        row = connection.execute(
            "SELECT sequence,payload_json FROM consent_outbox "
            "WHERE event_type='preferences.changed'"
        ).fetchone()
        payload = row[1].replace('"profile_revision":1', '"profile_revision":2')
        digest = hashlib.sha256(payload.encode("ascii")).hexdigest()
        # The outbox now carries DB-level immutability triggers, so a plain
        # UPDATE can no longer stand in for corruption. Drop the trigger for
        # the tamper -- exactly what out-of-band corruption or an attacker
        # with raw file access can do, and precisely why the BRIDGE must
        # verify receipts itself instead of trusting the store's triggers.
        connection.execute("DROP TRIGGER consent_outbox_no_update")
        connection.execute(
            "UPDATE consent_outbox SET payload_json=?,payload_sha256=? WHERE sequence=?",
            (payload, digest, row[0]),
        )

    with pytest.raises(ConsentDeliveryBridgeIntegrityError):
        bridge.sync_once("tenant-a", ["crm"])
    assert delivery.counts("tenant-a")["queued"] == 0


def test_bridge_destination_set_is_explicit_bounded_and_tenant_scoped(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    _seed(preferences, delivery)
    bridge = ConsentDeliveryBridge(preferences, delivery)
    with pytest.raises(ConsentDeliveryBridgeValidationError):
        bridge.sync_once("tenant-a", [])
    with pytest.raises(ConsentDeliveryBridgeValidationError):
        bridge.sync_once("tenant-a", ["crm", "crm"])
    isolated = bridge.sync_once("tenant-b", ["crm"])
    assert isolated["events_read"] == 0
    assert delivery.counts("tenant-b")["queued"] == 0


def test_bridge_reports_bounded_pagination_without_claiming_completeness(tmp_path) -> None:
    preferences, delivery = _stores(tmp_path)
    _seed(preferences, delivery)
    bridge = ConsentDeliveryBridge(preferences, delivery)
    first = bridge.sync_once("tenant-a", ["crm"], limit=1)
    assert first["events_read"] == 1
    assert first["truncated"] is True
    assert first["complete"] is False
    second = bridge.sync_once("tenant-a", ["crm"], limit=1)
    assert second["changes_queued"] == 1
