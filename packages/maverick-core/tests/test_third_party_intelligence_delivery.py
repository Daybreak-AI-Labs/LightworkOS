from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick import third_party_intelligence as intelligence
from maverick import third_party_intelligence_delivery as delivery


def _item(*, attempt: int = 1, maximum_attempts: int = 5) -> intelligence.OutboxItem:
    return intelligence.OutboxItem(
        tenant_id="tenant-a",
        delivery_id="delivery-1",
        alert_id="alert-1",
        destination_ref="risk-operations",
        state="leased",
        attempt=attempt,
        maximum_attempts=maximum_attempts,
        next_attempt_at=1_800_000_000.0,
        lease_token="lease-token-1234567890",
        lease_until=1_800_000_060.0,
        revision=2,
        last_error_code=None,
        integrity_sha256="a" * 64,
    )


def _alert() -> intelligence.MonitoringAlert:
    return intelligence.MonitoringAlert(
        tenant_id="tenant-a",
        alert_id="alert-1",
        monitor_id="monitor-1",
        vendor_id="vendor-1",
        previous_observation_sha256="b" * 64,
        observation_sha256="c" * 64,
        evidence_sha256="d" * 64,
        snapshot_bindings={"cyber_posture": "snapshot-cyber-v2"},
        citations=(),
        created_at=1_800_000_000.0,
        integrity_sha256="e" * 64,
    )


def _monitor() -> intelligence.Monitor:
    return intelligence.Monitor(
        tenant_id="tenant-a",
        monitor_id="monitor-1",
        vendor_id="vendor-1",
        source_bindings={"cyber_posture": "source-cyber"},
        destination_ref="risk-operations",
        cadence_seconds=3_600,
        next_run_at=1_800_003_600.0,
        state="active",
        last_observation_sha256="c" * 64,
        revision=2,
        created_by="risk-owner",
        created_at=1_800_000_000.0,
        updated_at=1_800_000_000.0,
        integrity_sha256="f" * 64,
    )


class Store:
    def __init__(self, *, item=None, acknowledgement_error: Exception | None = None):
        self.item = item or _item()
        self.acknowledgement_error = acknowledgement_error
        self.failures: list[dict[str, object]] = []
        self.acknowledged: list[str] = []
        self.events: list[str] = []

    def claim_outbox(self, tenant_id, *, worker_id, limit, lease_seconds,
                     delivery_ids=None, effect_guard=None):
        assert (tenant_id, worker_id, limit, lease_seconds) == (
            "tenant-a",
            "worker-1",
            10,
            60.0,
        )
        assert delivery_ids is None and effect_guard is None
        return (self.item,)

    def get_vendor(self, tenant_id, vendor_id):
        assert (tenant_id, vendor_id) == ("tenant-a", "vendor-1")
        return SimpleNamespace(vendor_id=vendor_id, display_label="Example Vendor")

    def assert_delivery_authority(self, item):
        assert item.delivery_id == "delivery-1"
        self.events.append("authority")

    def mark_outbox_dispatch(self, item, *, ambiguous=False):
        assert item.lease_token == "lease-token-1234567890"
        self.events.append("ambiguous" if ambiguous else "dispatching")
        return replace(item, state="dispatching")

    def get_monitoring_alert(self, tenant_id, alert_id):
        assert (tenant_id, alert_id) == ("tenant-a", "alert-1")
        return _alert()

    def get_monitor(self, tenant_id, monitor_id):
        assert (tenant_id, monitor_id) == ("tenant-a", "monitor-1")
        return _monitor()

    def fail_outbox(
        self,
        tenant_id,
        delivery_id,
        *,
        lease_token,
        error_code,
        backoff_seconds,
    ):
        self.failures.append(
            {
                "tenant_id": tenant_id,
                "delivery_id": delivery_id,
                "lease_token": lease_token,
                "error_code": error_code,
                "backoff_seconds": backoff_seconds,
            }
        )
        state = (
            "dead_letter"
            if self.item.attempt >= self.item.maximum_attempts
            else "pending"
        )
        return replace(
            self.item,
            state=state,
            lease_token=None,
            lease_until=None,
            last_error_code=error_code,
        )

    def acknowledge_outbox(self, tenant_id, delivery_id, *, lease_token):
        assert tenant_id == "tenant-a"
        assert lease_token == "lease-token-1234567890"
        if self.acknowledgement_error is not None:
            raise self.acknowledgement_error
        self.acknowledged.append(delivery_id)
        return replace(self.item, state="delivered", lease_token=None, lease_until=None)


class Transport:
    def __init__(self, error: Exception | None = None, store: Store | None = None):
        self.error = error
        self.store = store
        self.calls: list[dict[str, str]] = []

    def send(self, **kwargs):
        if self.store is not None:
            self.store.events.append("send")
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error


def test_delivers_digest_bounded_alert_and_acknowledges() -> None:
    store = Store()
    transport = Transport(store=store)
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda tenant, ref: (
            "risk@example.com"
            if (tenant, ref) == ("tenant-a", "risk-operations")
            else ""
        ),
        transport=transport,
    )
    assert result.claimed == result.acknowledged == 1
    assert result.semantics == "at_least_once"
    assert transport.calls[0]["recipient"] == "risk@example.com"
    assert transport.calls[0]["idempotency_key"] == "delivery-1"
    assert "Example Vendor" in transport.calls[0]["body"]
    assert "does not approve the vendor or make a legal or compliance decision" in transport.calls[0]["body"]
    # The send is durably admitted and its authority re-checked before the effect.
    assert store.events == ["dispatching", "authority", "send"]
    assert "risk@example.com" not in repr(result)
    assert store.acknowledged == ["delivery-1"]


@pytest.mark.parametrize(
    "resolved",
    [
        "Risk Team <risk@example.com>",
        "risk@example.com\nBcc: attacker@example.com",
        "not-an-email",
    ],
)
def test_destination_failure_is_sanitized_and_retried(resolved: str) -> None:
    store = Store(item=_item(attempt=2))
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda _tenant, _ref: resolved,
        transport=Transport(),
        base_backoff_seconds=30.0,
    )
    assert result.retry_pending == 1
    assert result.outcomes[0].error_code == "destination_unavailable"
    assert store.failures[0]["backoff_seconds"] == 60.0
    assert resolved not in repr(result)


def test_transport_failure_dead_letters_at_attempt_limit() -> None:
    from maverick.mailer import MailerNotSent

    # A send refused before any effect started is retryable up to the limit.
    store = Store(item=_item(attempt=5, maximum_attempts=5))
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda _tenant, _ref: "risk@example.com",
        transport=Transport(MailerNotSent("secret provider detail")),
    )
    assert result.dead_lettered == 1
    assert result.outcomes[0].error_code == "delivery_error"
    assert "secret provider detail" not in repr(result)


def test_interrupted_send_after_admission_is_ambiguous_and_never_retried() -> None:
    store = Store(item=_item(attempt=1, maximum_attempts=5))
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda _tenant, _ref: "risk@example.com",
        transport=Transport(ConnectionError("secret provider detail")),
    )
    assert result.acknowledgement_ambiguous == 1 and result.retry_pending == 0
    assert result.outcomes[0].state == "ambiguous"
    assert result.outcomes[0].error_code == "send_unconfirmed"
    assert store.failures == [] and store.acknowledged == []
    assert store.events[-1] == "ambiguous"
    assert "secret provider detail" not in repr(result)


def test_post_send_acknowledgement_failure_is_explicitly_ambiguous() -> None:
    store = Store(acknowledgement_error=RuntimeError("database unavailable"))
    transport = Transport()
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda _tenant, _ref: "risk@example.com",
        transport=transport,
    )
    assert len(transport.calls) == 1
    assert result.acknowledgement_ambiguous == 1
    assert result.outcomes[0].state == "ack_ambiguous"
    assert store.failures == []
    assert store.events[-1] == "ambiguous"  # retained, never made retryable


def test_smtp_transport_reuses_platform_mailer(monkeypatch: pytest.MonkeyPatch) -> None:
    from maverick import mailer

    calls: list[tuple[str, str, str, object]] = []
    monkeypatch.setattr(
        mailer,
        "send",
        lambda recipient, subject, body, *, before_effect=None: calls.append(
            (recipient, subject, body, before_effect)),
    )

    def guard():
        return None

    delivery.SmtpThirdPartyAlertTransport().send(
        recipient="risk@example.com",
        subject="Third-party change",
        body="Review evidence.",
        idempotency_key="delivery-1",
        before_effect=guard,
    )
    assert calls[0][0] == "risk@example.com"
    assert "delivery-1" in calls[0][2]
    assert calls[0][3] is guard  # the mailer re-checks authority at the effect


@pytest.mark.parametrize(
    ("keyword", "value"),
    [("limit", 0), ("limit", True), ("lease_seconds", 0.5), ("lease_seconds", True)],
)
def test_batch_bounds_fail_before_claim(keyword: str, value: object) -> None:
    arguments = {
        "tenant_id": "tenant-a",
        "worker_id": "worker-1",
        "resolve_destination": lambda _tenant, _ref: "risk@example.com",
        "transport": Transport(),
        keyword: value,
    }
    with pytest.raises(ValueError):
        delivery.deliver_alert_batch(Store(), **arguments)
