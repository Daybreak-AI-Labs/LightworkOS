"""Real local sealed-store tests; no provider network or live acceptance."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest
from maverick import config, connections
from maverick import privacy_discovery_credentials as keys
from maverick.paths import tenant_scope
from maverick.privacy_data_discovery_adapters import (
    DiscoveryHTTPRequest,
    DiscoveryTransportError,
    PinnedDiscoveryHTTPTransport,
    credential_reference_present,
)
from maverick.tenant import kms


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("[connections]\nenable=true\n", encoding="utf-8")
    config.reset_config_cache()
    kms._clear_cache()
    with tenant_scope(tenant="tenant-a"), connections.bind_principal("user:owner"):
        yield
    kms._clear_cache()
    config.reset_config_cache()


def saved_connection():
    record = connections.set_connection(
        "cmdb",
        connector="servicenow_cmdb",
        base_url="https://tenant.service-now.com",
        token="synthetic-test-token",
        owner="user:owner",
    )
    return record, "connection:cmdb:" + record["revision"]


def test_keys_are_random_sealed_owner_private_and_never_in_metadata():
    created = keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="create")
    material = keys.resolve_key(created["reference"])
    assert len(material) == 32
    assert created["revision"] == 1
    assert "key_hex" not in json.dumps(created)
    assert material.hex() not in keys._path().read_bytes().decode("latin1")
    assert keys.list_keys() == [created]
    with connections.bind_principal("user:other"):
        assert keys.list_keys() == []
        with pytest.raises(PermissionError):
            keys.resolve_key(created["reference"])
        with pytest.raises(PermissionError):
            keys.create_or_rotate("inventory", expected_revision=1, idempotency_key="steal")
    with tenant_scope(tenant="tenant-b"):
        assert keys.list_keys() == []
        with pytest.raises(PermissionError):
            keys.resolve_key(created["reference"])


def test_rotation_is_exact_idempotent_and_old_references_stop_resolving():
    created = keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="create")
    old = keys.resolve_key(created["reference"])
    rotated = keys.create_or_rotate("inventory", expected_revision=1, idempotency_key="rotate")
    assert keys.resolve_key(rotated["reference"]) != old
    assert (
        keys.create_or_rotate("inventory", expected_revision=1, idempotency_key="rotate") == rotated
    )
    assert (
        keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="create") == created
    )
    assert keys.list_keys()[0]["revision"] == 2
    with pytest.raises(connections.ConnectionVersionConflict):
        keys.resolve_key(created["reference"])
    with pytest.raises(connections.ConnectionVersionConflict):
        keys.create_or_rotate("inventory", expected_revision=1, idempotency_key="another")
    with pytest.raises(connections.ConnectionVersionConflict):
        keys.create_or_rotate("another", expected_revision=0, idempotency_key="rotate")


def test_corrupted_or_cross_tenant_key_store_cannot_be_replaced():
    keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="create")
    blob = keys._path().read_bytes()
    with tenant_scope(tenant="tenant-b"):
        path = keys._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        with pytest.raises(RuntimeError, match="authenticated"):
            keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="replace")
        assert path.read_bytes() == blob


@pytest.mark.parametrize(
    "change",
    ["origin", "provider", "revision", "tenant", "principal", "revoked", "missing-principal"],
)
def test_saved_connection_pins_exact_authority_without_environment_fallback(change, monkeypatch):
    record, reference = saved_connection()
    assert credential_reference_present(reference)
    assert (
        keys.resolve_connection(reference, provider="servicenow_cmdb", origin=record["base_url"])[
            "token"
        ]
        == "synthetic-test-token"
    )
    monkeypatch.setenv(reference, "must-never-be-used")
    origin, provider = record["base_url"], "servicenow_cmdb"
    if change == "origin":
        origin = "https://attacker.example"
    if change == "provider":
        provider = "entra_assets"
    if change == "revision":
        connections.set_connection("cmdb", token="rotated", expected_revision=record["revision"])
    if change == "revoked":
        connections.delete_connection("cmdb")
    tenant = "tenant-b" if change == "tenant" else "tenant-a"
    principal = (
        None
        if change == "missing-principal"
        else "user:other"
        if change == "principal"
        else "user:owner"
    )
    with tenant_scope(tenant=tenant), connections.bind_principal(principal):
        with pytest.raises((PermissionError, connections.ConnectionVersionConflict)):
            keys.resolve_connection(reference, provider=provider, origin=origin)


def test_transport_rechecks_saved_credential_for_each_request_and_rejects_forged_origin():
    record, reference = saved_connection()
    request = DiscoveryHTTPRequest(
        provider="servicenow_cmdb",
        origin=record["base_url"],
        path="/api/now/table/cmdb_ci",
        query=(),
        credential_env=reference,
        method="GET",
        deadline=2_000_000_000,
        timeout_seconds=10,
        max_response_bytes=1024,
    )
    transport = PinnedDiscoveryHTTPTransport(
        credential_resolver=lambda name: "forbidden-env-fallback"
    )
    assert transport._headers(request)["Authorization"] == "Bearer synthetic-test-token"
    with pytest.raises(DiscoveryTransportError):
        transport._headers(replace(request, origin="https://attacker.example"))
    connections.set_connection(
        "cmdb", allowed_principals=[], owner="user:different", expected_revision=record["revision"]
    )
    with pytest.raises(DiscoveryTransportError):
        transport._headers(request)


def test_concurrent_key_rotations_have_one_cas_winner():
    keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="create")
    ready = Barrier(2)

    def rotate(operation):
        with tenant_scope(tenant="tenant-a"), connections.bind_principal("user:owner"):
            ready.wait(timeout=5)
            try:
                return keys.create_or_rotate(
                    "inventory", expected_revision=1, idempotency_key=operation
                )
            except connections.ConnectionVersionConflict:
                return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(rotate, ["rotation-one", "rotation-two"]))
    assert sum(result is not None for result in results) == 1
    assert keys.list_keys()[0]["revision"] == 2


@pytest.mark.parametrize("change", ["rotate-during-read", "wrong-ambient-tenant"])
def test_scan_cannot_publish_retired_key_evidence_or_borrow_another_tenant_context(
    tmp_path, change
):
    from maverick import privacy_data_discovery as discovery

    _, connection = saved_connection()
    key = keys.create_or_rotate("inventory", expected_revision=0, idempotency_key="create")
    store = discovery.PrivacyDataDiscoveryStore(
        tmp_path / "discovery.sqlite3", config_gate=lambda: None
    )
    store.enroll_source(
        "tenant-a",
        source_id="assets",
        provider="servicenow_cmdb",
        kind="structured",
        origin="https://tenant.service-now.com",
        resource_ref="cmdb_ci",
        credential_env=connection,
        evidence_key_env=key["reference"],
        actor_ref="owner",
        idempotency_key="source",
    )
    store.enqueue_scan(
        "tenant-a",
        "assets",
        limits=discovery.ScanLimits(),
        max_attempts=3,
        retention_seconds=3600,
        actor_ref="owner",
        idempotency_key="scan",
    )
    reads = []

    class RotatingRows:
        def iter_rows(self, **_kwargs):
            reads.append(True)
            yield discovery.StructuredRecord("row", {"email": "synthetic@example.com"})
            keys.create_or_rotate("inventory", expected_revision=1, idempotency_key="rotate")

    coordinator = discovery.PrivacyDataDiscoveryCoordinator(
        store, structured_sources={"servicenow_cmdb": RotatingRows()}
    )
    with tenant_scope(tenant="tenant-b" if change == "wrong-ambient-tenant" else "tenant-a"):
        result = coordinator.run_once("tenant-a", worker_id="worker")
    assert not result.completed_reports
    assert len(result.failed_jobs) == 1
    assert result.failed_jobs[0].last_error_code == "credential_unavailable"
    assert not store.list_reports("tenant-a")
    assert len(reads) == (0 if change == "wrong-ambient-tenant" else 1)
