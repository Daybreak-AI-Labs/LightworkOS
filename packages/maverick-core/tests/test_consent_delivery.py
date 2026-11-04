from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from maverick import config
from maverick.consent_delivery import (
    DELIVERY_PATH,
    ConsentChange,
    ConsentDeliveryConfigError,
    ConsentDeliveryConflict,
    ConsentDeliveryDispatcher,
    ConsentDeliveryError,
    ConsentDeliveryIdempotencyConflict,
    ConsentDeliveryLeaseLost,
    ConsentDeliveryNotFound,
    ConsentDeliveryRevoked,
    ConsentDeliveryStore,
    ConsentDeliveryTransportError,
    ConsentDeliveryValidationError,
    DeliveryPreferenceChoice,
    DeliveryResponse,
    HTTPSConsentDeliveryTransport,
    SignedDeliveryRequest,
    enabled,
)

NOW = 1_800_000_000.0


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class MutableClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.value += seconds


class IdFactory:
    def __init__(self) -> None:
        self.value = 0
        self._lock = threading.Lock()

    def __call__(self, prefix: str) -> str:
        with self._lock:
            self.value += 1
            return f"{prefix}-{self.value}"


class HMACSigner:
    def __init__(
        self,
        keys: dict[str, bytes] | None = None,
        callback: Callable[[str], None] | None = None,
    ) -> None:
        self.keys = keys or {"key-1": b"external-key-one", "key-2": b"external-key-two"}
        self.callback = callback
        self.calls: list[tuple[str, bytes]] = []

    def sign(self, key_id: str, payload: bytes) -> bytes:
        self.calls.append((key_id, payload))
        if self.callback is not None:
            self.callback(key_id)
        return hmac.new(self.keys[key_id], payload, hashlib.sha256).digest()


class FakeTransport:
    def __init__(
        self,
        responses: list[DeliveryResponse] | None = None,
        *,
        error: bool = False,
        callback: Callable[[SignedDeliveryRequest], None] | None = None,
    ) -> None:
        self.responses = responses or [
            DeliveryResponse(204, response_sha256=_digest("empty-response"))
        ]
        self.error = error
        self.callback = callback
        self.requests: list[SignedDeliveryRequest] = []

    def post(
        self,
        request: SignedDeliveryRequest,
        *,
        timeout_seconds: float,
        max_response_bytes: int,
    ) -> DeliveryResponse:
        assert timeout_seconds > 0
        assert max_response_bytes > 0
        self.requests.append(request)
        if self.callback is not None:
            self.callback(request)
        if self.error:
            raise ConsentDeliveryTransportError("synthetic transport failure")
        if len(self.requests) > len(self.responses):
            return self.responses[-1]
        return self.responses[len(self.requests) - 1]


def _change(
    event: str = "event-1",
    profile: str = "profile-1",
    *,
    action: str = "grant",
    occurred_at: float = NOW - 10,
) -> ConsentChange:
    return ConsentChange(
        event_id=event,
        event_kind="preferences_changed",
        profile_id=profile,
        profile_revision=1,
        receipt_id=f"receipt-{event}",
        receipt_sha256=_digest(f"receipt-{event}"),
        policy_id="policy-1",
        policy_version=3,
        policy_sha256=_digest("policy-1-v3"),
        choices=(
            DeliveryPreferenceChoice(
                purpose_id="analytics",
                action=action,
                channel="web",
                vendor_id="vendor-755",
            ),
        ),
        occurred_at=occurred_at,
    )


def _store(
    path: Path,
    clock: MutableClock | None = None,
    *,
    id_factory: IdFactory | None = None,
    gate: Callable[[], bool] | None = None,
    validated: list[str] | None = None,
) -> ConsentDeliveryStore:
    return ConsentDeliveryStore(
        path,
        clock=clock or MutableClock(),
        id_factory=id_factory or IdFactory(),
        config_gate=gate or (lambda: True),
        origin_validator=(
            (lambda origin: validated.append(origin))
            if validated is not None
            else (lambda _origin: None)
        ),
    )


def _enroll(
    store: ConsentDeliveryStore,
    tenant: str = "tenant-a",
    destination: str = "destination-a",
    *,
    key_id: str = "key-1",
    max_attempts: int = 3,
    retention: int = 3600,
) -> dict[str, object]:
    return store.enroll_destination(
        tenant,
        destination_id=destination,
        origin="https://consent.example.test",
        signing_key_id=key_id,
        idempotency_key=f"enroll-{tenant}-{destination}",
        max_attempts=max_attempts,
        base_backoff_seconds=5,
        max_backoff_seconds=60,
        default_retention_seconds=retention,
    )


def _enqueue(
    store: ConsentDeliveryStore,
    change: ConsentChange | None = None,
    *,
    tenant: str = "tenant-a",
    destinations: tuple[str, ...] = ("destination-a",),
    key: str = "enqueue-1",
    retention_until: float | None = None,
) -> dict[str, object]:
    return store.enqueue_change(
        tenant,
        change or _change(),
        destination_ids=destinations,
        idempotency_key=key,
        retention_until=retention_until,
    )


def test_config_gate_is_explicit_and_fails_before_creating_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "delivery": {"enable": True},
            },
        },
    )
    assert enabled() is True
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": True,
                "delivery": {"enable": False},
            },
        },
    )
    assert enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "consent_preferences": {
                "enable": False,
                "delivery": {"enable": True},
            },
        },
    )
    assert enabled() is False

    path = tmp_path / "disabled.db"
    with pytest.raises(ConsentDeliveryConfigError, match="disabled"):
        ConsentDeliveryStore(path, config_gate=lambda: False)
    assert not path.exists()


def test_config_source_errors_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "config_source_errors", lambda: ["bad config"])
    monkeypatch.setattr(config, "load_config", lambda: pytest.fail("must not load"))
    assert enabled() is False


@pytest.mark.parametrize(
    "origin",
    [
        "http://consent.example.test",
        "https://user:password@consent.example.test",
        "https://consent.example.test/hook",
        "https://consent.example.test?token=secret",
        "https://consent.example.test/#fragment",
        "https://localhost",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://169.254.169.254",
        "https://[::1]",
    ],
)
def test_enrollment_requires_exact_public_https_origin(
    tmp_path: Path,
    origin: str,
) -> None:
    store = _store(tmp_path / "delivery.db")
    with pytest.raises(ConsentDeliveryValidationError):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin=origin,
            signing_key_id="key-1",
            idempotency_key="enroll-1",
        )


def test_enrollment_uses_ssrf_validator_and_canonical_origin(tmp_path: Path) -> None:
    validated: list[str] = []
    store = _store(tmp_path / "delivery.db", validated=validated)
    result = store.enroll_destination(
        "tenant-a",
        destination_id="destination-a",
        origin="https://CONSENT.Example.Test:443/",
        signing_key_id="key-1",
        idempotency_key="enroll-1",
    )
    assert validated == ["https://consent.example.test"]
    assert result["origin"] == "https://consent.example.test"


def test_ssrf_validator_failure_does_not_persist_destination(tmp_path: Path) -> None:
    def blocked(_origin: str) -> None:
        raise RuntimeError("private resolution")

    store = ConsentDeliveryStore(
        tmp_path / "delivery.db",
        config_gate=lambda: True,
        origin_validator=blocked,
    )
    with pytest.raises(ConsentDeliveryConfigError, match="SSRF"):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin="https://blocked.example.test",
            signing_key_id="key-1",
            idempotency_key="enroll-1",
        )
    with pytest.raises(ConsentDeliveryNotFound):
        store.destination("tenant-a", "destination-a")


def test_delivery_refuses_process_wide_private_fetch_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    store = ConsentDeliveryStore(
        tmp_path / "delivery.db",
        config_gate=lambda: True,
    )
    with pytest.raises(ConsentDeliveryConfigError, match="private-network browsing"):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin="https://8.8.8.8",
            signing_key_id="key-1",
            idempotency_key="enroll-1",
        )
    with pytest.raises(ConsentDeliveryNotFound):
        store.destination("tenant-a", "destination-a")


def test_delivery_refuses_private_network_browsing_from_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text("[tools]\nfetch_allow_private = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_file))
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    config.reset_config_cache()

    store = ConsentDeliveryStore(tmp_path / "delivery.db", config_gate=lambda: True)
    with pytest.raises(ConsentDeliveryConfigError, match="private-network browsing"):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin="https://8.8.8.8",
            signing_key_id="key-1",
            idempotency_key="enroll-1",
        )
    with pytest.raises(ConsentDeliveryNotFound):
        store.destination("tenant-a", "destination-a")


def test_delivery_enrollment_obeys_enterprise_outbound_hosts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import maverick.enterprise as enterprise
    import maverick.tools._ssrf as ssrf

    observed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        enterprise, "enterprise_egress_denial",
        lambda url, *, tool: observed.append((url, tool)) or "blocked",
    )
    monkeypatch.setattr(
        ssrf, "resolve_pinned_ip", lambda _host, **_kwargs: "8.8.8.8"
    )
    store = ConsentDeliveryStore(tmp_path / "delivery.db", config_gate=lambda: True)
    with pytest.raises(ConsentDeliveryConfigError, match="approved outbound hosts"):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin="https://8.8.8.8",
            signing_key_id="key-1",
            idempotency_key="enroll-1",
        )
    assert observed == [("https://8.8.8.8", "consent_delivery")]
    with pytest.raises(ConsentDeliveryNotFound):
        store.destination("tenant-a", "destination-a")


def test_enrollment_is_idempotent_but_key_cannot_be_rebound(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    first = _enroll(store)
    second = _enroll(store)
    assert first == second
    with pytest.raises(ConsentDeliveryIdempotencyConflict):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-b",
            origin="https://consent.example.test",
            signing_key_id="key-1",
            idempotency_key="enroll-tenant-a-destination-a",
        )
    with pytest.raises(ConsentDeliveryConflict):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin="https://consent.example.test",
            signing_key_id="key-2",
            idempotency_key="different-key",
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_attempts": 0},
        {"max_attempts": 21},
        {"base_backoff_seconds": 0},
        {"base_backoff_seconds": 30, "max_backoff_seconds": 29},
        {"max_backoff_seconds": 86_401},
        {"default_retention_seconds": 0},
        {"default_retention_seconds": 157_680_001},
    ],
)
def test_enrollment_configuration_is_bounded(
    tmp_path: Path,
    overrides: dict[str, int],
) -> None:
    store = _store(tmp_path / "delivery.db")
    values = {
        "max_attempts": 3,
        "base_backoff_seconds": 5,
        "max_backoff_seconds": 60,
        "default_retention_seconds": 3600,
        **overrides,
    }
    with pytest.raises(ConsentDeliveryValidationError):
        store.enroll_destination(
            "tenant-a",
            destination_id="destination-a",
            origin="https://consent.example.test",
            signing_key_id="key-1",
            idempotency_key="enroll-bounds",
            **values,
        )


def test_invalid_clock_fails_closed_without_persisting_enrollment(tmp_path: Path) -> None:
    path = tmp_path / "delivery.db"
    store = ConsentDeliveryStore(
        path,
        clock=lambda: float("nan"),
        config_gate=lambda: True,
        origin_validator=lambda _origin: None,
    )
    with pytest.raises(ConsentDeliveryValidationError, match="current time"):
        _enroll(store)
    with pytest.raises(ConsentDeliveryNotFound):
        store.destination("tenant-a", "destination-a")


def test_cross_tenant_destinations_are_isolated(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store, "tenant-a", "shared")
    _enroll(store, "tenant-b", "shared")
    assert store.destination("tenant-a", "shared")["revision"] == 1
    assert store.destination("tenant-b", "shared")["revision"] == 1
    with pytest.raises(ConsentDeliveryNotFound):
        store.destination("tenant-c", "shared")


def test_change_payload_is_closed_bounded_and_deterministic() -> None:
    change = _change()
    normalized = change.normalized()
    assert normalized["schema"] == "lightwork.consent-delivery-change.v1"
    assert "email" not in json.dumps(normalized)
    reordered = ConsentChange(
        **{
            **change.__dict__,
            "choices": (
                DeliveryPreferenceChoice("marketing", "deny", "email", "vendor-1"),
                change.choices[0],
            ),
        }
    )
    reverse = ConsentChange(
        **{**reordered.__dict__, "choices": tuple(reversed(reordered.choices))}
    )
    assert reordered.normalized() == reverse.normalized()


@pytest.mark.parametrize(
    "change",
    [
        ConsentChange(**{**_change().__dict__, "event_id": "raw event words"}),
        ConsentChange(**{**_change().__dict__, "receipt_sha256": "bad"}),
        ConsentChange(**{**_change().__dict__, "event_kind": "unknown"}),
        ConsentChange(
            **{
                **_change().__dict__,
                "choices": (
                    DeliveryPreferenceChoice("analytics", "grant", "web", "all"),
                    DeliveryPreferenceChoice("analytics", "deny", "web", "all"),
                ),
            }
        ),
        ConsentChange(
            **{
                **_change().__dict__,
                "choices": tuple(
                    DeliveryPreferenceChoice(f"purpose-{index}", "deny")
                    for index in range(129)
                ),
            }
        ),
    ],
)
def test_change_rejects_free_text_unknowns_duplicates_and_overflow(
    change: ConsentChange,
) -> None:
    with pytest.raises(ConsentDeliveryValidationError):
        change.normalized()


def test_enqueue_is_idempotent_and_sequences_once_across_destinations(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store, destination="destination-a")
    _enroll(store, destination="destination-b")
    first = _enqueue(
        store,
        destinations=("destination-b", "destination-a"),
        retention_until=NOW + 600,
    )
    replay = _enqueue(
        store,
        destinations=("destination-a", "destination-b"),
        retention_until=NOW + 600,
    )
    assert first == replay
    assert first["profile_sequence"] == 1
    assert len(first["messages"]) == 2
    assert {item["destination_id"] for item in first["messages"]} == {
        "destination-a",
        "destination-b",
    }
    second = _enqueue(store, _change("event-2"), key="enqueue-2")
    assert second["profile_sequence"] == 2


def test_enqueue_idempotency_conflict_rolls_back_sequence(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store, key="stable-key")
    with pytest.raises(ConsentDeliveryIdempotencyConflict):
        _enqueue(store, _change("event-2"), key="stable-key")
    result = _enqueue(store, _change("event-3"), key="new-key")
    assert result["profile_sequence"] == 2


def test_per_profile_ordering_blocks_later_message_until_ack(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store)
    first = _enqueue(store, _change("event-1"), key="enqueue-1")
    _enqueue(store, _change("event-2"), key="enqueue-2")

    claims = store.claim("tenant-a", worker_id="worker-1", limit=10)
    assert [claim.event_id for claim in claims] == ["event-1"]
    assert store.claim("tenant-a", worker_id="worker-2", limit=10) == ()
    acknowledgement = store.acknowledge(
        claims[0],
        response_sha256=_digest("response-1"),
    )
    assert acknowledgement["state"] == "delivered"
    assert store.acknowledge(
        claims[0],
        response_sha256=_digest("response-1"),
    ) == acknowledgement
    next_claim = store.claim("tenant-a", worker_id="worker-2", limit=10)
    assert [claim.event_id for claim in next_claim] == ["event-2"]
    assert first["profile_sequence"] == 1


def test_ack_rejects_different_response_and_stale_lease(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1", lease_seconds=10)[0]
    store.acknowledge(claim, response_sha256=_digest("response-1"))
    with pytest.raises(ConsentDeliveryConflict):
        store.acknowledge(claim, response_sha256=_digest("response-2"))

    _enqueue(store, _change("event-2", "profile-2"), key="enqueue-2")
    expired = store.claim("tenant-a", worker_id="worker-1", lease_seconds=10)[0]
    clock.advance(11)
    with pytest.raises(ConsentDeliveryLeaseLost):
        store.acknowledge(expired, response_sha256=_digest("late"))


def test_concurrent_claimers_never_receive_same_message(tmp_path: Path) -> None:
    clock = MutableClock()
    factory = IdFactory()
    path = tmp_path / "delivery.db"
    first_store = _store(path, clock, id_factory=factory)
    second_store = _store(path, clock, id_factory=factory)
    _enroll(first_store)
    for index in range(20):
        _enqueue(
            first_store,
            _change(f"event-{index}", f"profile-{index}"),
            key=f"enqueue-{index}",
        )
    barrier = threading.Barrier(3)
    claimed: list[str] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker(store: ConsentDeliveryStore, worker_id: str) -> None:
        try:
            barrier.wait()
            rows = store.claim("tenant-a", worker_id=worker_id, limit=20)
            with lock:
                claimed.extend(row.message_id for row in rows)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(first_store, "worker-1")),
        threading.Thread(target=worker, args=(second_store, "worker-2")),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=10)

    assert errors == []
    assert len(claimed) == 20
    assert len(set(claimed)) == 20


def test_expired_lease_is_recovered_after_crash(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store, max_attempts=3)
    _enqueue(store)
    first = store.claim("tenant-a", worker_id="crashed", lease_seconds=10)[0]
    clock.advance(11)
    recovered = store.claim("tenant-a", worker_id="recovery", lease_seconds=10)[0]
    assert recovered.message_id == first.message_id
    assert recovered.lease_token != first.lease_token
    assert recovered.attempt == 2
    with pytest.raises(ConsentDeliveryLeaseLost):
        store.fail_claim(first, error_code="timeout")
    assert "lease_recovered" in {
        event["event_type"] for event in store.list_audit("tenant-a")
    }


def test_retry_backoff_dead_letter_ordering_and_replay(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store, max_attempts=2)
    first = _enqueue(store, _change("event-1"), key="enqueue-1")
    _enqueue(store, _change("event-2"), key="enqueue-2")
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    retry = store.fail_claim(claim, error_code="remote_unavailable")
    assert retry["state"] == "queued"
    assert retry["next_attempt_at"] == NOW + 5
    assert store.claim("tenant-a", worker_id="worker-2") == ()
    clock.advance(5)
    second_attempt = store.claim("tenant-a", worker_id="worker-2")[0]
    dead = store.fail_claim(second_attempt, error_code="remote_unavailable")
    assert dead["state"] == "dead_letter"
    assert store.claim("tenant-a", worker_id="worker-3") == ()
    letter = store.list_dead_letters("tenant-a")[0]
    assert letter["message_id"] == first["messages"][0]["message_id"]
    replay = store.replay_dead_letter(
        "tenant-a",
        letter["message_id"],
        expected_revision=letter["revision"],
        idempotency_key="replay-1",
    )
    assert replay["state"] == "queued"
    assert store.replay_dead_letter(
        "tenant-a",
        letter["message_id"],
        expected_revision=letter["revision"],
        idempotency_key="replay-1",
    ) == replay
    replay_claim = store.claim("tenant-a", worker_id="worker-4")[0]
    assert replay_claim.event_id == "event-1"


def test_retry_after_is_bounded_by_destination_maximum(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    retry = store.fail_claim(
        claim,
        error_code="rate_limited",
        retry_after_seconds=1000,
    )
    assert retry["next_attempt_at"] == NOW + 60


def test_key_rotation_invalidates_claim_and_new_claim_uses_new_key(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    old_claim = store.claim("tenant-a", worker_id="worker-1")[0]
    rotation = store.rotate_signing_key(
        "tenant-a",
        "destination-a",
        new_key_id="key-2",
        expected_revision=1,
        idempotency_key="rotate-1",
    )
    assert rotation["revision"] == 2
    with pytest.raises(ConsentDeliveryLeaseLost):
        store.authorize_claim(old_claim)
    new_claim = store.claim("tenant-a", worker_id="worker-2")[0]
    assert new_claim.signing_key_id == "key-2"
    assert new_claim.destination_revision == 2
    keys = store.destination("tenant-a", "destination-a")["keys"]
    assert {item["key_id"]: item["status"] for item in keys} == {
        "key-1": "retired",
        "key-2": "active",
    }


def test_retired_key_revocation_releases_old_revision_lease(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    store.rotate_signing_key(
        "tenant-a",
        "destination-a",
        new_key_id="key-2",
        expected_revision=1,
        idempotency_key="rotate-1",
    )
    _enqueue(store)
    stale = store.claim("tenant-a", worker_id="worker-1")[0]
    result = store.revoke_signing_key(
        "tenant-a",
        "destination-a",
        key_id="key-1",
        expected_revision=2,
        idempotency_key="revoke-retired-key",
    )
    assert result["destination_status"] == "active"
    assert result["active_key_id"] == "key-2"
    with pytest.raises(ConsentDeliveryLeaseLost):
        store.authorize_claim(stale)
    replacement = store.claim("tenant-a", worker_id="worker-2")[0]
    assert replacement.signing_key_id == "key-2"
    assert replacement.destination_revision == 3


def test_active_key_revocation_suspends_then_new_rotation_resumes(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    revoked = store.revoke_signing_key(
        "tenant-a",
        "destination-a",
        key_id="key-1",
        expected_revision=1,
        idempotency_key="revoke-key-1",
    )
    assert revoked["destination_status"] == "suspended"
    assert store.claim("tenant-a", worker_id="worker-2") == ()
    with pytest.raises(ConsentDeliveryLeaseLost):
        store.authorize_claim(claim)
    resumed = store.rotate_signing_key(
        "tenant-a",
        "destination-a",
        new_key_id="key-2",
        expected_revision=2,
        idempotency_key="rotate-key-2",
    )
    assert resumed["status"] == "active"
    assert store.claim("tenant-a", worker_id="worker-3")[0].signing_key_id == "key-2"
    with pytest.raises(ConsentDeliveryConflict, match="cannot be reused"):
        store.rotate_signing_key(
            "tenant-a",
            "destination-a",
            new_key_id="key-1",
            expected_revision=3,
            idempotency_key="reuse-key-1",
        )


def test_destination_revocation_cancels_unsent_and_prevents_enqueue(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    result = store.revoke_destination(
        "tenant-a",
        "destination-a",
        expected_revision=1,
        idempotency_key="revoke-destination",
    )
    assert result["cancelled_messages"] == 1
    assert store.counts("tenant-a")["cancelled"] == 1
    assert store.claim("tenant-a", worker_id="worker-1") == ()
    with pytest.raises(ConsentDeliveryRevoked):
        _enqueue(store, _change("event-2"), key="enqueue-2")


def test_signed_envelope_is_canonical_bound_and_contains_no_key_material(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    signer = HMACSigner()
    first = store.build_signed_request(claim, signer)
    second = store.build_signed_request(claim, signer)
    assert first.body == second.body
    assert first.headers == second.headers
    assert first.url == "https://consent.example.test" + DELIVERY_PATH
    assert first.body_sha256 == hashlib.sha256(first.body).hexdigest()
    envelope = json.loads(first.body)
    assert envelope["message_id"] == claim.message_id
    assert envelope["event_sha256"] == claim.payload_sha256
    assert envelope["signing_key_id"] == "key-1"
    assert b"external-key-one" not in first.body
    assert first.header_map()["X-Lightwork-Signature"].startswith("v1=")
    assert signer.calls[0][0] == "key-1"


def test_dispatcher_rechecks_authorization_after_signing(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    transport = FakeTransport()

    def revoke(_key_id: str) -> None:
        store.revoke_signing_key(
            "tenant-a",
            "destination-a",
            key_id="key-1",
            expected_revision=1,
            idempotency_key="revoke-during-sign",
        )

    dispatcher = ConsentDeliveryDispatcher(
        store,
        signer=HMACSigner(callback=revoke),
        transport=transport,
    )
    result = dispatcher.deliver_once("tenant-a", worker_id="worker-1")
    assert result["authorization_invalidated"] == 1
    assert transport.requests == []
    assert store.destination("tenant-a", "destination-a")["status"] == "suspended"


def test_dispatcher_handles_rotation_while_response_is_in_flight(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)

    def rotate(_request: SignedDeliveryRequest) -> None:
        store.rotate_signing_key(
            "tenant-a",
            "destination-a",
            new_key_id="key-2",
            expected_revision=1,
            idempotency_key="rotate-in-flight",
        )

    dispatcher = ConsentDeliveryDispatcher(
        store,
        signer=HMACSigner(),
        transport=FakeTransport(callback=rotate),
    )
    result = dispatcher.deliver_once("tenant-a", worker_id="worker-1")
    assert result["delivered"] == 0
    assert result["authorization_invalidated"] == 1
    replacement = store.claim("tenant-a", worker_id="worker-2")[0]
    assert replacement.signing_key_id == "key-2"


def test_dispatcher_success_retry_and_permanent_failure(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store)
    for index in range(3):
        _enqueue(
            store,
            _change(f"event-{index}", f"profile-{index}"),
            key=f"enqueue-{index}",
        )
    transport = FakeTransport(
        [
            DeliveryResponse(204, response_sha256=_digest("ok")),
            DeliveryResponse(503, retry_after_seconds=7),
            DeliveryResponse(400, response_sha256=_digest("bad-request")),
        ]
    )
    dispatcher = ConsentDeliveryDispatcher(
        store,
        signer=HMACSigner(),
        transport=transport,
    )
    result = dispatcher.deliver_once("tenant-a", worker_id="worker-1", limit=3)
    assert result == {
        "claimed": 3,
        "delivered": 1,
        "retry_scheduled": 1,
        "dead_lettered": 1,
        "authorization_invalidated": 0,
    }
    counts = store.counts("tenant-a")
    assert counts["delivered"] == 1
    assert counts["queued"] == 1
    assert counts["dead_letter"] == 1
    queued = [
        store.message("tenant-a", request.message_id)
        for request in transport.requests
        if store.message("tenant-a", request.message_id)["state"] == "queued"
    ][0]
    assert queued["next_attempt_at"] == NOW + 7


def test_dispatcher_transport_error_retries_without_response_content(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    dispatcher = ConsentDeliveryDispatcher(
        store,
        signer=HMACSigner(),
        transport=FakeTransport(error=True),
    )
    result = dispatcher.deliver_once("tenant-a", worker_id="worker-1")
    assert result["retry_scheduled"] == 1
    assert store.counts("tenant-a")["queued"] == 1


def test_dispatcher_contains_untyped_transport_failure(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)

    def crash(_request: SignedDeliveryRequest) -> None:
        raise RuntimeError("synthetic client implementation leaked an exception")

    dispatcher = ConsentDeliveryDispatcher(
        store,
        signer=HMACSigner(),
        transport=FakeTransport(callback=crash),
    )
    result = dispatcher.deliver_once("tenant-a", worker_id="worker-1")
    assert result["retry_scheduled"] == 1
    message = store.list_audit("tenant-a")[-1]
    assert message["details"]["error_code"] == "transport_error"
    assert "synthetic" not in json.dumps(message)


def test_cross_tenant_claim_ack_and_audit_isolation(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store, "tenant-a", "destination-a")
    _enroll(store, "tenant-b", "destination-a")
    first = _enqueue(store, tenant="tenant-a", key="enqueue-a")
    second = _enqueue(store, tenant="tenant-b", key="enqueue-b")
    claim_a = store.claim("tenant-a", worker_id="worker-a")[0]
    assert claim_a.message_id == first["messages"][0]["message_id"]
    assert store.message("tenant-b", second["messages"][0]["message_id"])["state"] == "queued"
    with pytest.raises(ConsentDeliveryNotFound):
        store.message("tenant-b", claim_a.message_id)
    assert all(
        event["details"].get("destination_id") != "tenant-b"
        for event in store.list_audit("tenant-a")
    )


def test_retention_metadata_purges_only_terminal_messages(tmp_path: Path) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store, retention=10)
    delivered = _enqueue(store, _change("delivered", "profile-1"), key="delivered")
    dead = _enqueue(store, _change("dead", "profile-2"), key="dead")
    delivered_claim = store.claim("tenant-a", worker_id="worker-1", limit=2)
    delivered_by_event = {claim.event_id: claim for claim in delivered_claim}
    store.acknowledge(
        delivered_by_event["delivered"],
        response_sha256=_digest("ok"),
    )
    store.fail_claim(
        delivered_by_event["dead"],
        error_code="contract_rejected",
        permanent=True,
    )
    clock.advance(11)
    due = store.retention_due("tenant-a")
    assert due["delivered"] == 1
    assert due["dead_letter"] == 1
    purged = store.purge_terminal("tenant-a")
    assert purged["purged"] == 1
    with pytest.raises(ConsentDeliveryNotFound):
        store.message("tenant-a", delivered["messages"][0]["message_id"])
    assert store.message("tenant-a", dead["messages"][0]["message_id"])["state"] == "dead_letter"


def test_audit_chain_is_tenant_scoped_and_valid(tmp_path: Path) -> None:
    path = tmp_path / "delivery.db"
    store = _store(path)
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    store.fail_claim(claim, error_code="timeout")
    report = store.verify_audit_chain("tenant-a")
    assert report["valid"] is True
    assert report["events"] >= 4
    events = store.list_audit("tenant-a")
    assert events[0]["previous_event_sha256"] is None
    assert events[-1]["event_sha256"] == report["head_sha256"]
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE delivery_audit SET details_json='{}' WHERE sequence=1"
            )
        connection.execute("DROP TRIGGER delivery_audit_no_update")
        connection.execute(
            "UPDATE delivery_audit SET details_json='{}' WHERE sequence=1"
        )
        connection.commit()
    with pytest.raises(ConsentDeliveryError, match="details changed"):
        store.verify_audit_chain("tenant-a")


def test_non_ascii_stored_digests_are_refused_not_type_errors(tmp_path: Path) -> None:
    # Edited digests must not raise TypeError from hmac.compare_digest instead
    # of the idempotency conflict and audit-integrity refusals.
    path = tmp_path / "delivery.db"
    store = _store(path)
    _enroll(store)
    _enqueue(store, key="stable-key")
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER delivery_idempotency_no_update")
        connection.execute("DROP TRIGGER delivery_audit_no_update")
        connection.execute("UPDATE delivery_idempotency SET request_sha256=?", ("é" * 64,))
        connection.execute("UPDATE delivery_audit SET details_sha256=?", ("é" * 64,))
        connection.commit()
    with pytest.raises(ConsentDeliveryIdempotencyConflict):
        _enqueue(store, key="stable-key")
    with pytest.raises(ConsentDeliveryError, match="details changed"):
        store.verify_audit_chain("tenant-a")
    with pytest.raises(ConsentDeliveryError, match="details changed"):
        store.list_audit("tenant-a")


def test_privacy_posture_and_database_contain_no_key_material(tmp_path: Path) -> None:
    path = tmp_path / "delivery.db"
    store = _store(path)
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    signer = HMACSigner()
    request = store.build_signed_request(claim, signer)

    posture = store.privacy_posture("tenant-a")
    assert posture["privacy_check_passed"] is True
    assert posture["key_material_persisted"] is False
    database_bytes = path.read_bytes()
    assert b"external-key-one" not in database_bytes
    assert request.header_map()["X-Lightwork-Signature"].encode("ascii") not in database_bytes
    with sqlite3.connect(path) as connection:
        columns = {
            row[1]
            for table in (
                "delivery_destinations",
                "delivery_destination_keys",
                "delivery_messages",
            )
            for row in connection.execute(f"PRAGMA table_info({table})")
        }
    assert not {"secret", "private_key", "key_material", "token"} & columns


def test_runtime_gate_revocation_stops_claim_and_dispatch(tmp_path: Path) -> None:
    gate = {"enabled": True}
    store = _store(
        tmp_path / "delivery.db",
        gate=lambda: gate["enabled"],
    )
    _enroll(store)
    _enqueue(store)
    gate["enabled"] = False
    with pytest.raises(ConsentDeliveryConfigError, match="disabled"):
        store.claim("tenant-a", worker_id="worker-1")


@pytest.mark.parametrize(
    "response",
    [
        lambda: DeliveryResponse(99),
        lambda: DeliveryResponse(600),
        lambda: DeliveryResponse(429, retry_after_seconds=-1),
        lambda: DeliveryResponse(200, response_sha256="bad"),
    ],
)
def test_response_contract_rejects_invalid_metadata(
    response: Callable[[], DeliveryResponse],
) -> None:
    with pytest.raises((ConsentDeliveryTransportError, ConsentDeliveryValidationError)):
        response()


def test_default_transport_uses_safe_client_without_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    request = store.build_signed_request(claim, HMACSigner())
    observed: dict[str, object] = {}

    class Response:
        status_code = 204
        headers = {"content-length": "0", "retry-after": "3"}

        def __enter__(self) -> Response:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def iter_bytes(self):
            return iter(())

    class Client:
        def __enter__(self) -> Client:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def stream(self, method: str, url: str, **kwargs: object) -> Response:
            observed.update(method=method, url=url, **kwargs)
            return Response()

    def safe_client(url: str, **kwargs: object) -> Client:
        observed["safe_client_url"] = url
        observed["safe_client_kwargs"] = kwargs
        return Client()

    import maverick.tools._ssrf as ssrf

    monkeypatch.setattr(ssrf, "safe_client", safe_client)
    response = HTTPSConsentDeliveryTransport().post(
        request,
        timeout_seconds=5,
        max_response_bytes=128,
    )
    assert response.status_code == 204
    assert response.retry_after_seconds == 3
    assert observed["safe_client_url"] == request.url
    assert observed["safe_client_kwargs"]["require_public"] is True
    assert observed["method"] == "POST"
    assert "follow_redirects" not in observed


def test_default_transport_rejects_mutated_request_before_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    request = store.build_signed_request(claim, HMACSigner())
    mutated = SignedDeliveryRequest(
        **{
            **request.__dict__,
            "body": request.body + b" ",
        }
    )

    import maverick.tools._ssrf as ssrf

    monkeypatch.setattr(
        ssrf,
        "safe_client",
        lambda *_args, **_kwargs: pytest.fail("network boundary must not open"),
    )
    with pytest.raises(ConsentDeliveryTransportError, match="canonical JSON"):
        HTTPSConsentDeliveryTransport().post(
            mutated,
            timeout_seconds=5,
            max_response_bytes=128,
        )


def test_default_transport_rechecks_private_fetch_override_before_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    request = store.build_signed_request(claim, HMACSigner())

    import maverick.tools._ssrf as ssrf

    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")
    monkeypatch.setattr(
        ssrf,
        "safe_client",
        lambda *_args, **_kwargs: pytest.fail("network boundary must not open"),
    )
    with pytest.raises(ConsentDeliveryTransportError, match="private-network browsing"):
        HTTPSConsentDeliveryTransport().post(
            request,
            timeout_seconds=5,
            max_response_bytes=128,
        )


def test_default_transport_rechecks_private_network_browsing_from_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    request = store.build_signed_request(
        store.claim("tenant-a", worker_id="worker-1")[0], HMACSigner()
    )
    config_file = tmp_path / "config.toml"
    config_file.write_text("[tools]\nfetch_allow_private = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_file))
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    config.reset_config_cache()

    import maverick.tools._ssrf as ssrf

    monkeypatch.setattr(
        ssrf,
        "safe_client",
        lambda *_args, **_kwargs: pytest.fail("network boundary must not open"),
    )
    with pytest.raises(ConsentDeliveryTransportError, match="private-network browsing"):
        HTTPSConsentDeliveryTransport().post(
            request, timeout_seconds=5, max_response_bytes=128
        )


def test_default_transport_rechecks_enterprise_outbound_hosts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "delivery.db")
    _enroll(store)
    _enqueue(store)
    request = store.build_signed_request(
        store.claim("tenant-a", worker_id="worker-1")[0], HMACSigner()
    )
    import maverick.enterprise as enterprise
    import maverick.tools._ssrf as ssrf

    observed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        enterprise, "enterprise_egress_denial",
        lambda url, *, tool: observed.append((url, tool)) or "blocked",
    )
    monkeypatch.setattr(
        ssrf,
        "safe_client",
        lambda *_args, **_kwargs: pytest.fail("network boundary must not open"),
    )
    with pytest.raises(ConsentDeliveryTransportError, match="approved outbound hosts"):
        HTTPSConsentDeliveryTransport().post(
            request, timeout_seconds=5, max_response_bytes=128
        )
    assert observed == [(request.url, "consent_delivery")]


def test_list_destinations_is_tenant_scoped_and_bounded(tmp_path: Path) -> None:
    store = _store(tmp_path / "delivery.sqlite3")
    _enroll(store, destination="destination-a")
    _enroll(store, destination="destination-b")
    _enroll(store, tenant="tenant-b", destination="other")

    listed = store.list_destinations("tenant-a")
    assert {item["destination_id"] for item in listed["items"]} == {
        "destination-a",
        "destination-b",
    }
    assert listed["truncated"] is False
    assert listed["items"][0]["keys"][0]["key_id"] == "key-1"
    assert store.list_destinations("tenant-a", limit=1)["truncated"] is True
    assert [
        item["destination_id"] for item in store.list_destinations("tenant-b")["items"]
    ] == ["other"]


def _delivery_settings(monkeypatch: pytest.MonkeyPatch, **values: object) -> None:
    monkeypatch.setattr(
        config, "load_config", lambda *a, **k: {"consent_preferences": {"delivery": values}}
    )


def test_installation_retry_defaults_apply_to_destinations_that_choose_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "delivery.db")
    store.enroll_destination(
        "tenant-a", destination_id="before", origin="https://consent.example.test",
        signing_key_id="key-1", idempotency_key="enroll-before",
    )
    unset = store.destination("tenant-a", "before")
    assert (unset["max_attempts"], unset["base_backoff_seconds"],
            unset["max_backoff_seconds"]) == (6, 5.0, 3600.0)
    _delivery_settings(monkeypatch, max_attempts=4, retry_base_seconds=9,
                       retry_max_seconds=90)
    store.enroll_destination(
        "tenant-a", destination_id="after", origin="https://consent.example.test",
        signing_key_id="key-1", idempotency_key="enroll-after",
    )
    chosen = store.destination("tenant-a", "after")
    assert (chosen["max_attempts"], chosen["base_backoff_seconds"],
            chosen["max_backoff_seconds"]) == (4, 9.0, 90.0)
    # A destination may ask for fewer tries, never more than the installation's.
    store.enroll_destination(
        "tenant-a", destination_id="asks-more", origin="https://consent.example.test",
        signing_key_id="key-1", idempotency_key="enroll-more", max_attempts=20,
    )
    assert store.destination("tenant-a", "asks-more")["max_attempts"] == 4


def test_installation_try_limit_also_holds_existing_destinations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = MutableClock()
    store = _store(tmp_path / "delivery.db", clock)
    _enroll(store, max_attempts=5)
    _enqueue(store, _change("event-1"), key="enqueue-1")
    _delivery_settings(monkeypatch, max_attempts=1)
    claim = store.claim("tenant-a", worker_id="worker-1")[0]
    assert store.fail_claim(claim, error_code="remote_unavailable")["state"] == "dead_letter"
