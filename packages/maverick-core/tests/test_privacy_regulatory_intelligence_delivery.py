from __future__ import annotations

from dataclasses import replace

import pytest
from maverick import privacy_regulatory_intelligence as intelligence
from maverick import privacy_regulatory_intelligence_delivery as delivery


def _item(*, attempt: int = 1, max_attempts: int = 3) -> intelligence.DeliveryItem:
    return intelligence.DeliveryItem(
        tenant_id="tenant-a",
        delivery_id="delivery-1",
        alert_id="alert-1",
        subscription_id="tracker-1",
        destination_ref="privacy-counsel",
        state="leased",
        attempt=attempt,
        max_attempts=max_attempts,
        next_attempt_at=1_800_000_000.0,
        lease_token="lease-token-1234567890",
        lease_until=1_800_000_060.0,
        revision=2,
        last_error_code=None,
        integrity_sha256="a" * 64,
    )


def _tracker() -> intelligence.SavedQuery:
    return intelligence.SavedQuery(
        tenant_id="tenant-a",
        subscription_id="tracker-1",
        query="access request response timing",
        jurisdictions=("US-CA",),
        principal_ref="privacy-owner",
        destination_ref="privacy-counsel",
        cadence_seconds=86_400,
        next_run_at=1_800_086_400.0,
        state="active",
        revision=1,
        created_at=1_800_000_000.0,
        updated_at=1_800_000_000.0,
        integrity_sha256="b" * 64,
    )


class Store:
    def __init__(self, *, item=None, acknowledgement_error: Exception | None = None):
        self.item = item or _item()
        self.acknowledgement_error = acknowledgement_error
        self.failures: list[dict[str, object]] = []
        self.acknowledged: list[str] = []

    def claim_deliveries(self, tenant_id, *, worker_id, limit, lease_seconds):
        assert tenant_id == "tenant-a"
        assert worker_id == "worker-1"
        assert limit == 10
        assert lease_seconds == 60.0
        return (self.item,)

    def get_saved_query(self, tenant_id, subscription_id):
        assert tenant_id == "tenant-a"
        assert subscription_id == "tracker-1"
        return _tracker()

    def fail_delivery(
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
        state = "dead_letter" if self.item.attempt >= self.item.max_attempts else "pending"
        return replace(
            self.item,
            state=state,
            lease_token=None,
            lease_until=None,
            last_error_code=error_code,
        )

    def acknowledge_delivery(self, tenant_id, delivery_id, *, lease_token):
        assert tenant_id == "tenant-a"
        assert lease_token == "lease-token-1234567890"
        if self.acknowledgement_error is not None:
            raise self.acknowledgement_error
        self.acknowledged.append(delivery_id)
        return replace(self.item, state="delivered", lease_token=None, lease_until=None)


class Transport:
    def __init__(self, error: Exception | None = None):
        self.error = error
        self.calls: list[dict[str, str]] = []

    def send(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error


def test_delivers_bounded_notification_and_acknowledges() -> None:
    store = Store()
    transport = Transport()
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda tenant, ref: (
            "counsel@example.com" if (tenant, ref) == ("tenant-a", "privacy-counsel") else ""
        ),
        transport=transport,
    )
    assert result.claimed == result.acknowledged == 1
    assert result.retry_pending == result.dead_lettered == 0
    assert result.semantics == "at_least_once"
    assert transport.calls[0]["recipient"] == "counsel@example.com"
    assert transport.calls[0]["idempotency_key"] == "delivery-1"
    assert "access request response timing" in transport.calls[0]["body"]
    assert "not legal advice" in transport.calls[0]["body"]
    assert "counsel@example.com" not in repr(result)
    assert store.acknowledged == ["delivery-1"]


@pytest.mark.parametrize(
    ("resolved", "error_code"),
    [
        ("Display Name <counsel@example.com>", "destination_unavailable"),
        ("counsel@example.com\nBcc: attacker@example.com", "destination_unavailable"),
        ("not-an-email", "destination_unavailable"),
    ],
)
def test_destination_failures_are_sanitized_and_retried(
    resolved: str,
    error_code: str,
) -> None:
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
    assert result.outcomes[0].error_code == error_code
    assert store.failures[0]["error_code"] == error_code
    assert store.failures[0]["backoff_seconds"] == 60.0
    assert resolved not in repr(result)


def test_transport_failure_dead_letters_at_attempt_limit() -> None:
    store = Store(item=_item(attempt=3, max_attempts=3))
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda _tenant, _ref: "counsel@example.com",
        transport=Transport(TimeoutError("secret provider detail")),
    )
    assert result.dead_lettered == 1
    assert result.outcomes[0].error_code == "transport_unavailable"
    assert "secret provider detail" not in repr(result)


def test_post_send_acknowledgement_failure_is_explicitly_ambiguous() -> None:
    store = Store(acknowledgement_error=RuntimeError("database unavailable"))
    transport = Transport()
    result = delivery.deliver_alert_batch(
        store,
        tenant_id="tenant-a",
        worker_id="worker-1",
        resolve_destination=lambda _tenant, _ref: "counsel@example.com",
        transport=transport,
    )
    assert len(transport.calls) == 1
    assert result.acknowledgement_ambiguous == 1
    assert result.outcomes[0].state == "ack_ambiguous"
    assert store.failures == []


def test_smtp_transport_reuses_platform_mailer_without_leaking_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick import mailer

    calls: list[tuple[str, str, str]] = []
    monkeypatch.setattr(
        mailer,
        "send",
        lambda recipient, subject, body: calls.append((recipient, subject, body)),
    )
    delivery.SmtpPrivacyAlertTransport().send(
        recipient="counsel@example.com",
        subject="Privacy update",
        body="Review the cited evidence.",
        idempotency_key="delivery-1",
    )
    assert calls[0][0] == "counsel@example.com"
    assert "delivery-1" in calls[0][2]


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("limit", 0),
        ("limit", True),
        ("lease_seconds", 0.5),
        ("lease_seconds", True),
    ],
)
def test_batch_bounds_fail_before_claim(keyword: str, value: object) -> None:
    arguments = {
        "tenant_id": "tenant-a",
        "worker_id": "worker-1",
        "resolve_destination": lambda _tenant, _ref: "counsel@example.com",
        "transport": Transport(),
        keyword: value,
    }
    with pytest.raises(ValueError):
        delivery.deliver_alert_batch(Store(), **arguments)
