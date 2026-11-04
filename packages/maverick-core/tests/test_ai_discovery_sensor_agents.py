from __future__ import annotations

import gc
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from maverick import ai_discovery_sensor_agents as sensor_agents
from maverick.ai_discovery_sensor_agents import (
    AGENT_CONFIG_SCHEMA,
    DiscoverySensorAgent,
    DiscoverySensorSpool,
    HTTPSObservationTransport,
    SensorAgentConfig,
    SensorAgentConfigError,
    SensorAgentStateError,
    SensorAgentTransportError,
    TransportResponse,
    main,
)
from maverick.ai_discovery_sensor_clients import (
    NormalizedSensorEvent,
    SensorBinding,
    SignedDiscoverySensorClient,
    normalize_identity_audit,
)
from maverick.ai_discovery_sensor_test_estate import (
    ConsentingDiscoveryTestEstate,
    ConsentingTestEstateError,
)

_SENSOR_ID = "DSN-" + "a" * 32
_CONFIG_SHA = "b" * 64
_TENANT = "test-tenant"
_NOW = 1_700_000_000.0


class _Clock:
    def __init__(self, value: float = _NOW) -> None:
        self.value = value
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.value += seconds


def _config(tmp_path: Path, **changes) -> SensorAgentConfig:
    source_kind = changes.get("source_kind", "network_egress")
    values = {
        "schema": AGENT_CONFIG_SCHEMA,
        "enable": True,
        "consent_acknowledged": True,
        "consent_reference": "approved-test-estate-change-42",
        "source_kind": source_kind,
        "source_scope_code": "test_firewall_export",
        "coverage_limitations": [
            "allowlist_only",
            "supplied_events_only",
            "no_enterprise_completeness_claim",
        ],
        "endpoint_url": "http://127.0.0.1:8899",
        "allow_loopback_http": True,
        "key_file": str(tmp_path / f"{source_kind}.pem"),
        "spool_file": str(tmp_path / f"{source_kind}.sqlite"),
        "binding": {
            "tenant_ref": _TENANT,
            "agent_id": f"{source_kind}-sensor",
            "sensor_id": _SENSOR_ID,
            "sensor_revision": 1,
            "config_sha256": _CONFIG_SHA,
        },
        "environment_code": "consenting_test",
        "deployment_type": "hosted_api" if source_kind == "network_egress" else "saas",
        "context_codes": ["managed_device"],
        "batch_size": 500,
        "max_pending": 10_000,
        "request_timeout_seconds": 5.0,
        "lease_seconds": 30.0,
        "base_backoff_seconds": 1.0,
    }
    values.update(changes)
    return SensorAgentConfig.from_mapping(values)


def _network_event(index: int, *, hostname: str = "api.openai.com") -> dict:
    return {
        "hostname": hostname,
        "source_event_sha256": f"{index:064x}",
        "observed_at": _NOW + index / 1000,
        "context_codes": ["approved_source"],
    }


def _browser_event(index: int) -> dict:
    return {
        "source_event_sha256": f"{index:064x}",
        "observed_at": _NOW + index / 1000,
        "provider_code": "microsoft",
        "ai_product_code": "copilot",
        "context_codes": ["approved_source"],
    }


def _estate(
    config: SensorAgentConfig,
    private_key: Ed25519PrivateKey,
    clock: _Clock,
) -> ConsentingDiscoveryTestEstate:
    estate = ConsentingDiscoveryTestEstate(
        consent_acknowledged=True,
        consent_reference=config.consent_reference,
        coverage_limitations=config.coverage_limitations,
        clock=clock,
    )
    estate.register_sensor(
        agent_id=config.binding.agent_id,
        sensor_id=config.binding.sensor_id,
        tenant_ref=config.binding.tenant_ref,
        sensor_revision=config.binding.sensor_revision,
        config_sha256=config.binding.config_sha256,
        domain_category=config.source_kind,
        public_key=private_key.public_key(),
    )
    return estate


def _write_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _signed_transport_request():
    return SignedDiscoverySensorClient(
        SensorBinding(_TENANT, "network_egress-sensor", _SENSOR_ID, 1, _CONFIG_SHA),
        signer=lambda _: b"s" * 64,
        clock=lambda: _NOW,
        nonce_factory=lambda: "nonce-1",
    ).build(
        NormalizedSensorEvent(
            "1" * 64,
            _NOW,
            "openai",
            "openai_api",
            "openai",
            "network_egress",
            "hosted_api",
            "test",
        )
    )


class _StreamingResponse:
    def __init__(self, status_code, headers, chunks):
        self.status_code = status_code
        self.headers = headers
        self._chunks = chunks
        self.iterated_chunks = 0
        self.closed = False

    def iter_bytes(self):
        for chunk in self._chunks:
            self.iterated_chunks += 1
            yield chunk

    def close(self):
        self.closed = True


def test_config_is_closed_consent_gated_and_transport_is_fixed_origin(tmp_path: Path) -> None:
    disabled = _config(tmp_path, enable=False)
    with pytest.raises(SensorAgentConfigError, match="disabled"):
        DiscoverySensorAgent(disabled, signer=lambda _: b"s" * 64)

    no_consent = _config(tmp_path, consent_acknowledged=False)
    with pytest.raises(SensorAgentConfigError, match="consenting-estate"):
        DiscoverySensorAgent(no_consent, signer=lambda _: b"s" * 64)

    values = as_config_dict(_config(tmp_path))
    values["unexpected"] = True
    with pytest.raises(SensorAgentConfigError, match="closed schema"):
        SensorAgentConfig.from_mapping(values)

    for unsafe in (
        "http://example.com",
        "https://user:secret@example.com",
        "https://example.com/base",
        "https://example.com?tenant=x",
    ):
        with pytest.raises(SensorAgentConfigError):
            HTTPSObservationTransport(unsafe)

    calls: list[tuple] = []

    class Response:
        status_code = 201
        headers = {"Retry-After": "2"}

    def sender(*args, **kwargs):
        calls.append((args, kwargs))
        return Response()

    transport = HTTPSObservationTransport("https://gateway.example", sender=sender)
    request = _signed_transport_request()
    assert transport.send(request) == TransportResponse(201, 2.0)
    assert calls[0][0][0].startswith("https://gateway.example/api/v1/external/")
    assert calls[0][1]["follow_redirects"] is False


def test_https_transport_closes_a_bodyless_streaming_response() -> None:
    response = _StreamingResponse(204, {}, [])
    transport = HTTPSObservationTransport(
        "https://gateway.example", sender=lambda *_args, **_kwargs: response
    )

    assert transport.send(_signed_transport_request()) == TransportResponse(204)
    assert response.iterated_chunks == 0
    assert response.closed is True


def test_https_transport_discards_a_bounded_streaming_response() -> None:
    response = _StreamingResponse(
        429,
        {"Content-Length": "3", "Retry-After": "2.5"},
        [b"ok", b"!"],
    )
    transport = HTTPSObservationTransport(
        "https://gateway.example", sender=lambda *_args, **_kwargs: response
    )

    assert transport.send(_signed_transport_request()) == TransportResponse(429, 2.5)
    assert response.iterated_chunks == 2
    assert response.closed is True


def test_https_transport_rejects_oversized_declared_body_before_reading() -> None:
    response = _StreamingResponse(
        503,
        {
            "Content-Length": str(
                sensor_agents._MAX_GATEWAY_RESPONSE_BYTES + 1
            )
        },
        [b"not-read"],
    )
    transport = HTTPSObservationTransport(
        "https://gateway.example", sender=lambda *_args, **_kwargs: response
    )

    with pytest.raises(SensorAgentTransportError, match="byte bound"):
        transport.send(_signed_transport_request())
    assert response.iterated_chunks == 0
    assert response.closed is True


def test_https_transport_stops_oversized_chunked_body_and_closes() -> None:
    response = _StreamingResponse(
        503,
        {},
        [
            b"x" * sensor_agents._MAX_GATEWAY_RESPONSE_BYTES,
            b"x",
            b"must-not-be-read",
        ],
    )
    transport = HTTPSObservationTransport(
        "https://gateway.example", sender=lambda *_args, **_kwargs: response
    )

    with pytest.raises(SensorAgentTransportError, match="byte bound"):
        transport.send(_signed_transport_request())
    assert response.iterated_chunks == 2
    assert response.closed is True


def as_config_dict(config: SensorAgentConfig) -> dict:
    return {
        "schema": config.schema,
        "enable": config.enable,
        "consent_acknowledged": config.consent_acknowledged,
        "consent_reference": config.consent_reference,
        "source_kind": config.source_kind,
        "source_scope_code": config.source_scope_code,
        "coverage_limitations": list(config.coverage_limitations),
        "endpoint_url": config.endpoint_url,
        "allow_loopback_http": config.allow_loopback_http,
        "key_file": str(config.key_file),
        "spool_file": str(config.spool_file),
        "binding": {
            "tenant_ref": config.binding.tenant_ref,
            "agent_id": config.binding.agent_id,
            "sensor_id": config.binding.sensor_id,
            "sensor_revision": config.binding.sensor_revision,
            "config_sha256": config.binding.config_sha256,
        },
        "environment_code": config.environment_code,
        "deployment_type": config.deployment_type,
        "context_codes": list(config.context_codes),
        "batch_size": config.batch_size,
        "max_pending": config.max_pending,
        "request_timeout_seconds": config.request_timeout_seconds,
        "lease_seconds": config.lease_seconds,
        "base_backoff_seconds": config.base_backoff_seconds,
    }


def test_network_agent_runs_against_consenting_estate_and_reports_limits(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path)
    key = Ed25519PrivateKey.generate()
    estate = _estate(config, key, clock)
    agent = DiscoverySensorAgent(
        config, signer=key.sign, transport=estate, clock=clock
    )
    raw_with_forbidden_extra = {**_network_event(4), "raw_url": "https://secret"}
    report = agent.run_once(
        [
            _network_event(1),
            _network_event(2, hostname="unknown.example"),
            raw_with_forbidden_extra,
            _network_event(1),
        ]
    )

    assert report.input_events == 4
    assert report.normalized_events == 1
    assert report.unmatched_events == 1
    assert report.invalid_events == 1
    assert report.duplicate_events == 1
    assert report.delivered_events == 1
    assert report.coverage_complete is False
    assert report.source_scope_code == "test_firewall_export"
    assert report.raw_source_persisted is False
    assert "no_enterprise_completeness_claim" in report.coverage_limitations
    assert agent.spool.privacy_posture()["privacy_check_passed"] is True
    assert b"api.openai.com" not in config.spool_file.read_bytes()
    acceptance = estate.acceptance_report()
    assert acceptance["unique_observations"] == 1
    assert acceptance["raw_source_persisted"] is False
    assert acceptance["coverage_complete"] is False


@pytest.mark.parametrize(
    ("source_kind", "expected_category"),
    [("browser_extension", "browser_extension"), ("oauth_grant", "oauth_grant")],
)
def test_browser_and_oauth_agents_have_fixed_sensor_category(
    tmp_path: Path, source_kind: str, expected_category: str
) -> None:
    clock = _Clock()
    config = _config(tmp_path, source_kind=source_kind)
    key = Ed25519PrivateKey.generate()
    estate = _estate(config, key, clock)
    agent = DiscoverySensorAgent(config, signer=key.sign, transport=estate, clock=clock)

    assert agent.run_once([_browser_event(10)]).delivered_events == 1
    assert estate.acceptance_report()["unique_observations"] == 1
    assert config.source_kind == expected_category
    with pytest.raises(SensorAgentConfigError, match="closed schema"):
        agent.normalize({**_browser_event(11), "oauth_grant": source_kind == "oauth_grant"})
    with pytest.raises(SensorAgentConfigError, match="safe taxonomy"):
        agent.normalize({**_browser_event(12), "provider_code": "employee_42"})
    with pytest.raises(SensorAgentConfigError, match="safe taxonomy"):
        agent.normalize({**_browser_event(13), "context_codes": ["alice"]})


class _RecordingTransport:
    def __init__(self) -> None:
        self.requests = []

    def send(self, request):
        self.requests.append(request)
        return TransportResponse(201)


def _identity_event(index: int, **changes) -> NormalizedSensorEvent:
    values = {
        "source_event_sha256": f"{index:064x}",
        "observed_at": _NOW + index / 1000,
        "ai_service_code": "openai",
        "ai_product_code": "chatgpt",
        "provider_code": "openai",
        "environment_code": "consenting_test",
        "context_codes": ("managed_device",),
    }
    values.update(changes)
    return normalize_identity_audit(**values)


def test_identity_agent_queues_only_closed_reviewed_identity_events(tmp_path: Path) -> None:
    transport = _RecordingTransport()
    agent = DiscoverySensorAgent(
        _config(tmp_path, source_kind="identity_directory"),
        signer=lambda _message: b"s" * 64, transport=transport, clock=_Clock(),
    )

    report = agent.ingest_normalized([
        _identity_event(1),
        _identity_event(1),
        None,
        _identity_event(2, environment_code="other_estate"),
        _identity_event(3, ai_product_code="employee_42"),
        _identity_event(4, context_codes=()),
        {"provider_code": "openai", "user": "private.person@example.test"},
    ])

    assert report == {"input": 7, "normalized": 1, "unmatched": 1, "invalid": 4, "duplicate": 1}
    assert agent.deliver_once()["delivered"] == 1
    assert len(transport.requests) == 1
    assert b"private.person@example.test" not in agent.config.spool_file.read_bytes()
    # Raw identity-provider records never take the generic intake path.
    with pytest.raises(SensorAgentConfigError, match="reviewed identity audit adapter"):
        agent.normalize({"userPrincipalName": "private.person@example.test"})


def test_only_identity_agents_accept_normalized_identity_events(tmp_path: Path) -> None:
    agent = DiscoverySensorAgent(
        _config(tmp_path), signer=lambda _message: b"s" * 64, clock=_Clock(),
    )
    with pytest.raises(SensorAgentConfigError, match="source_kind identity_directory"):
        agent.ingest_normalized([_identity_event(1)])
    assert agent.spool.counts()["pending"] == 0


def test_outage_retry_and_expired_lease_recover_without_raw_event(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path, batch_size=1)
    key = Ed25519PrivateKey.generate()
    estate = _estate(config, key, clock)
    estate.simulate_outage(1)
    first = DiscoverySensorAgent(
        config, signer=key.sign, transport=estate, clock=clock, worker_id="worker-one"
    )
    first_report = first.run_once([_network_event(20), _network_event(21)])
    assert first_report.retry_scheduled_events == 1
    assert first_report.pending_events == 2

    # Simulate a crash after leasing the second event: a different worker may
    # not steal it until the bounded lease expires.
    leased = first.spool.lease("crashed-worker", limit=1, lease_seconds=30, now=clock())
    assert len(leased) == 1
    second = DiscoverySensorAgent(
        config, signer=key.sign, transport=estate, clock=clock, worker_id="worker-two"
    )
    assert second.deliver_once()["delivered"] == 1  # due outage-retry item
    assert second.spool.counts()["leased"] == 1
    clock.advance(31)
    assert second.deliver_once()["delivered"] == 1
    assert second.spool.counts()["pending"] == 0
    assert estate.acceptance_report()["unique_observations"] == 2


def test_ambiguous_success_retries_idempotently_after_response_loss(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path)
    key = Ed25519PrivateKey.generate()
    estate = _estate(config, key, clock)

    class AmbiguousOnce:
        def __init__(self) -> None:
            self.first = True

        def send(self, request):
            response = estate.send(request)
            if self.first:
                self.first = False
                raise SensorAgentTransportError("response was lost after acceptance")
            return response

    agent = DiscoverySensorAgent(
        config,
        signer=key.sign,
        transport=AmbiguousOnce(),
        clock=clock,
    )
    first = agent.run_once([_network_event(25)])
    assert first.retry_scheduled_events == 1
    assert estate.acceptance_report()["unique_observations"] == 1
    clock.advance(1)
    assert agent.deliver_once()["delivered"] == 1
    acceptance = estate.acceptance_report()
    assert acceptance["requests_received"] == 2
    assert acceptance["unique_observations"] == 1


def test_same_event_digest_is_idempotent_per_tenant_and_sensor_not_globally(
    tmp_path: Path,
) -> None:
    clock = _Clock()
    first_config = _config(tmp_path)
    first_key = Ed25519PrivateKey.generate()
    estate = _estate(first_config, first_key, clock)
    second_config = _config(
        tmp_path,
        key_file=str(tmp_path / "second-tenant.pem"),
        spool_file=str(tmp_path / "second-tenant.sqlite"),
        binding={
            "tenant_ref": "second-test-tenant",
            "agent_id": "network-egress-sensor-second-tenant",
            # Use the same sensor id deliberately: the tenant boundary alone
            # must keep this observation distinct from the first tenant.
            "sensor_id": _SENSOR_ID,
            "sensor_revision": 1,
            "config_sha256": _CONFIG_SHA,
        },
    )
    second_key = Ed25519PrivateKey.generate()
    estate.register_sensor(
        agent_id=second_config.binding.agent_id,
        sensor_id=second_config.binding.sensor_id,
        tenant_ref=second_config.binding.tenant_ref,
        sensor_revision=second_config.binding.sensor_revision,
        config_sha256=second_config.binding.config_sha256,
        domain_category=second_config.source_kind,
        public_key=second_key.public_key(),
    )
    raw_event = _network_event(26)
    first_agent = DiscoverySensorAgent(
        first_config,
        signer=first_key.sign,
        transport=estate,
        clock=clock,
    )
    second_agent = DiscoverySensorAgent(
        second_config,
        signer=second_key.sign,
        transport=estate,
        clock=clock,
    )

    assert first_agent.run_once([raw_event]).delivered_events == 1
    assert second_agent.run_once([raw_event]).delivered_events == 1
    assert estate.acceptance_report()["unique_observations"] == 2

    duplicate = SignedDiscoverySensorClient(
        second_config.binding,
        signer=second_key.sign,
        clock=clock,
        nonce_factory=lambda: "same-tenant-sensor-fresh-nonce",
    ).build(second_agent.normalize(raw_event))
    assert estate.send(duplicate).status_code == 201
    assert estate.acceptance_report()["unique_observations"] == 2


def test_key_file_hot_rotation_revocation_and_operator_unblock(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path)
    key_one = Ed25519PrivateKey.generate()
    key_two = Ed25519PrivateKey.generate()
    _write_key(config.key_file, key_one)
    estate = _estate(config, key_one, clock)
    agent = DiscoverySensorAgent(config, transport=estate, clock=clock)
    assert agent.run_once([_network_event(30)]).delivered_events == 1

    estate.rotate_key(config.binding.agent_id, key_two.public_key())
    # Atomic replacement is the production rotation primitive.  The signer
    # reloads each call, so the running process immediately uses the new key.
    replacement = config.key_file.with_suffix(".next")
    _write_key(replacement, key_two)
    replacement.replace(config.key_file)
    assert agent.run_once([_network_event(31)]).delivered_events == 1

    old_request = SignedDiscoverySensorClient(
        config.binding,
        signer=key_one.sign,
        clock=clock,
        nonce_factory=lambda: "old-key-after-rotation",
    ).build(agent.normalize(_network_event(32)))
    assert estate.send(old_request).status_code == 401

    estate.revoke_sensor(config.binding.agent_id)
    blocked = agent.run_once([_network_event(33)])
    assert blocked.auth_blocked_events == 1
    assert blocked.blocked_events == 1
    estate.restore_sensor(config.binding.agent_id)
    assert agent.spool.unblock_auth() == 1
    assert agent.deliver_once()["delivered"] == 1
    actions = [item["action"] for item in estate.ceremony_records()]
    assert actions == ["register", "rotate", "revoke", "restore"]
    ceremony_text = json.dumps(estate.ceremony_records())
    assert key_one.private_bytes_raw().hex() not in ceremony_text
    assert key_two.private_bytes_raw().hex() not in ceremony_text


def test_overlap_rotation_can_be_closed_and_replay_is_denied(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path)
    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()
    estate = _estate(config, old_key, clock)
    estate.rotate_key(
        config.binding.agent_id, new_key.public_key(), overlap_previous=True
    )
    old_client = SignedDiscoverySensorClient(
        config.binding,
        signer=old_key.sign,
        clock=clock,
        nonce_factory=lambda: "overlap-nonce",
    )
    event = NormalizedSensorEvent(
        "9" * 64,
        _NOW,
        "openai",
        "openai_api",
        "openai",
        "network_egress",
        "hosted_api",
        "test",
    )
    request = old_client.build(event)
    assert estate.send(request).status_code == 201
    assert estate.send(request).status_code == 401
    estate.retire_previous_keys(config.binding.agent_id)
    retired_request = SignedDiscoverySensorClient(
        config.binding,
        signer=old_key.sign,
        clock=clock,
        nonce_factory=lambda: "retired-nonce",
    ).build(event)
    assert estate.send(retired_request).status_code == 401


def test_spool_refuses_digest_conflict_and_is_bounded(tmp_path: Path) -> None:
    spool = DiscoverySensorSpool(tmp_path / "spool.sqlite", max_pending=1)
    first = NormalizedSensorEvent(
        "f" * 64,
        _NOW,
        "openai",
        "openai_api",
        "openai",
        "network_egress",
        "hosted_api",
        "test",
    )
    conflicting = NormalizedSensorEvent(
        "f" * 64,
        _NOW,
        "anthropic",
        "claude",
        "anthropic",
        "network_egress",
        "hosted_api",
        "test",
    )
    assert spool.enqueue(first, now=_NOW) is True
    with pytest.raises(SensorAgentStateError, match="conflicts"):
        spool.enqueue(conflicting, now=_NOW)
    second = NormalizedSensorEvent(
        "e" * 64,
        _NOW,
        "openai",
        "chatgpt",
        "openai",
        "network_egress",
        "saas",
        "test",
    )
    with pytest.raises(SensorAgentStateError, match="full"):
        spool.enqueue(second, now=_NOW)


def test_binding_conflict_is_retained_for_operator_reapproval(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path)
    key = Ed25519PrivateKey.generate()

    class BindingConflict:
        def send(self, _request):
            return TransportResponse(409)

    agent = DiscoverySensorAgent(
        config, signer=key.sign, transport=BindingConflict(), clock=clock
    )
    report = agent.run_once([_network_event(80)])
    assert report.auth_blocked_events == 1
    assert report.blocked_events == 1
    assert agent.spool.unblock_auth() == 1
    assert agent.spool.counts()["queued"] == 1


def test_spool_handles_for_one_path_serialize_connection_setup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two in-process handles must not race database-wide SQLite pragmas."""

    path = tmp_path / "shared-spool.sqlite"
    spools = [DiscoverySensorSpool(path), DiscoverySensorSpool(path)]
    real_connect = DiscoverySensorSpool._connect
    state_lock = threading.Lock()
    both_inside = threading.Event()
    active = 0
    maximum_active = 0

    def observed_connect(spool: DiscoverySensorSpool):
        nonlocal active, maximum_active
        with state_lock:
            active += 1
            maximum_active = max(maximum_active, active)
            if active == 2:
                both_inside.set()
        try:
            # If setup is not serialized, both callers reach this wait and make
            # the race deterministic. With the shared lock, each caller simply
            # times out before the next handle enters.
            both_inside.wait(timeout=0.1)
            return real_connect(spool)
        finally:
            with state_lock:
                active -= 1

    monkeypatch.setattr(DiscoverySensorSpool, "_connect", observed_connect)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda spool: spool.counts(), spools))

    assert maximum_active == 1
    assert all(result["pending"] == 0 for result in results)


def test_relative_spool_path_is_bound_before_working_directory_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    startup = tmp_path / "startup"
    later = tmp_path / "later"
    startup.mkdir()
    later.mkdir()
    monkeypatch.chdir(startup)
    spool = DiscoverySensorSpool("spool.sqlite")

    monkeypatch.chdir(later)

    assert spool.counts()["pending"] == 0
    assert spool.path == (startup / "spool.sqlite").resolve()
    assert not (later / "spool.sqlite").exists()


def test_spool_parent_alias_is_not_resolved_before_private_path_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alias = tmp_path / "configured-alias"
    configured = alias / "spool.sqlite"
    inspected: list[Path] = []

    def refuse_alias(path: str | Path) -> Path:
        inspected.append(Path(path))
        raise PermissionError("private directory path is an alias")

    monkeypatch.setattr(sensor_agents, "ensure_private_directory", refuse_alias)

    with pytest.raises(PermissionError, match="alias"):
        DiscoverySensorSpool(configured)

    assert inspected == [Path(os.path.abspath(configured.parent))]


def test_corrupt_selected_payload_does_not_publish_a_poison_lease(tmp_path: Path) -> None:
    spool = DiscoverySensorSpool(tmp_path / "spool.sqlite")
    digest = "f" * 64
    with spool._serialized_connection() as connection:
        connection.execute(
            """INSERT INTO pending_events(
                   event_sha256,payload_json,state,attempts,next_attempt_at,created_at
               ) VALUES(?,?,'queued',0,0,?)""",
            (digest, "not-json", _NOW),
        )

    with pytest.raises(SensorAgentStateError, match="corrupt"):
        spool.lease("worker", limit=1, lease_seconds=60, now=_NOW + 1)

    with spool._serialized_connection() as connection:
        row = connection.execute(
            """SELECT state,lease_owner,lease_until
               FROM pending_events WHERE event_sha256=?""",
            (digest,),
        ).fetchone()
    assert row is not None
    assert tuple(row) == ("queued", None, None)


def test_payload_digest_mismatch_does_not_publish_a_poison_lease(tmp_path: Path) -> None:
    spool = DiscoverySensorSpool(tmp_path / "spool.sqlite")
    event = NormalizedSensorEvent(
        "e" * 64,
        _NOW,
        "openai",
        "openai_api",
        "openai",
        "network_egress",
        "hosted_api",
        "test",
    )
    with spool._serialized_connection() as connection:
        connection.execute(
            """INSERT INTO pending_events(
                   event_sha256,payload_json,state,attempts,next_attempt_at,created_at
               ) VALUES(?,?,'queued',0,0,?)""",
            ("f" * 64, sensor_agents._canonical_event(event), _NOW),
        )

    with pytest.raises(SensorAgentStateError, match="digest mismatch"):
        spool.lease("worker", limit=1, lease_seconds=60, now=_NOW + 1)

    with spool._serialized_connection() as connection:
        row = connection.execute(
            """SELECT state,lease_owner,lease_until
               FROM pending_events WHERE event_sha256=?""",
            ("f" * 64,),
        ).fetchone()
    assert row is not None
    assert tuple(row) == ("queued", None, None)


def test_cross_connection_contention_is_normalized_as_spool_state_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A competing SQLite writer must not leak a raw driver traceback."""

    spool = DiscoverySensorSpool(tmp_path / "spool.sqlite")
    contender = sqlite3.connect(str(spool.path), timeout=0.025, isolation_level=None)
    contender.row_factory = sqlite3.Row
    contender.execute("PRAGMA busy_timeout=25")
    blocker = sqlite3.connect(str(spool.path), isolation_level=None)
    blocker.execute("BEGIN EXCLUSIVE")
    monkeypatch.setattr(spool, "_connect", lambda: contender)
    try:
        with pytest.raises(SensorAgentStateError, match="spool operation failed"):
            spool.counts()
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()


def test_bounded_scale_and_concurrent_workers_deliver_each_digest_once(tmp_path: Path) -> None:
    clock = _Clock()
    config = _config(tmp_path, batch_size=100, max_pending=2_000)
    key = Ed25519PrivateKey.generate()
    estate = _estate(config, key, clock)
    agents = [
        DiscoverySensorAgent(
            config,
            signer=key.sign,
            transport=estate,
            clock=clock,
            worker_id=f"worker-{index}",
        )
        for index in range(8)
    ]
    events = [_network_event(index + 100) for index in range(1_000)]
    chunks = [events[index::8] for index in range(8)]
    with ThreadPoolExecutor(max_workers=8) as executor:
        ingest_counts = list(
            executor.map(
                lambda pair: pair[0].ingest(pair[1]),
                zip(agents, chunks, strict=True),
            )
        )
    assert sum(item["normalized"] for item in ingest_counts) == 1_000

    def drain(agent: DiscoverySensorAgent) -> int:
        delivered = 0
        while True:
            count = agent.deliver_once()["delivered"]
            delivered += count
            if count == 0:
                return delivered

    with ThreadPoolExecutor(max_workers=8) as executor:
        delivered = sum(executor.map(drain, agents))
    assert delivered == 1_000
    assert agents[0].spool.counts()["pending"] == 0
    acceptance = estate.acceptance_report()
    assert acceptance["unique_observations"] == 1_000
    assert acceptance["coverage_complete"] is False


def test_harness_refuses_missing_consent_and_cli_reports_privacy(tmp_path: Path, capsys) -> None:
    with pytest.raises(ConsentingTestEstateError, match="consent"):
        ConsentingDiscoveryTestEstate(
            consent_acknowledged=False,
            consent_reference="change-1",
            coverage_limitations=("test_only",),
        )
    config = _config(tmp_path)
    config_path = tmp_path / "agent.json"
    config_path.write_text(json.dumps(as_config_dict(config)), encoding="utf-8")
    assert main(["--config", str(config_path), "privacy-report"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True
    assert output["result"]["raw_source_persisted"] is False


def test_spool_connection_closes_when_row_setup_fails(tmp_path: Path, monkeypatch) -> None:
    # Same GC-disabled rule as above: an unclosed connection stays open until a GC pass.
    spool = DiscoverySensorSpool(tmp_path / "spool.sqlite")
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    class _RowSetupFails(sqlite3.Connection):
        def __setattr__(self, name, value):
            if name == "row_factory":
                raise sqlite3.OperationalError("row setup failed")
            super().__setattr__(name, value)

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, factory=_RowSetupFails, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sensor_agents.sqlite3, "connect", recording_connect)
    gc.disable()
    try:
        with pytest.raises(sqlite3.OperationalError):
            spool._connect()
    finally:
        gc.enable()
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError):
        opened[0].execute("SELECT 1")
