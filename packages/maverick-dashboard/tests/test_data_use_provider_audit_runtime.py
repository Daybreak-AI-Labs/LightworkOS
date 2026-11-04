"""No-network tests for the dashboard provider-audit runtime bridge."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from maverick.data_use_provider_adapters import CredentialLease, ProviderBindingStore
from maverick.data_use_provider_audit import DataUseProviderAuditConfigError
from maverick_dashboard.data_use_provider_audit_runtime import (
    ProviderAuditCredentialOwnerBridge,
    build_provider_audit_runtime,
    provider_audit_config_enabled,
)
from maverick_dashboard.data_use_provider_audit_transport import (
    NativeProviderAuditTransport,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config() -> dict:
    return {
        "data_use_governance": {
            "enable": True,
            "provider_audit": {"enable": True},
        }
    }


class _Authority:
    def __init__(self) -> None:
        self.control_calls = 0
        self.read_calls = 0

    def resolve_control_authority(self, *_args, **_kwargs):
        self.control_calls += 1
        raise AssertionError("status construction must not resolve authority")

    def resolve_read_authority(self, *_args, **_kwargs):
        self.read_calls += 1
        raise AssertionError("status construction must not resolve authority")


class _ReadTransport:
    def __init__(self) -> None:
        self.calls = 0

    def read(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError("an empty worker run must not read from a provider")


class _CredentialOwner:
    def __init__(self, *, revoked: bool = False) -> None:
        self.calls: list[dict[str, str]] = []
        self.revoked = revoked

    def lease(self, *, provider_id: str, tenant_id: str, binding_id: str):
        self.calls.append(
            {
                "provider_id": provider_id,
                "tenant_id": tenant_id,
                "binding_id": binding_id,
            }
        )
        return CredentialLease(
            authorization="Bearer raw-provider-token",
            key_id="snowflake:SNOWFLAKE_CONTROL_TOKEN",
            key_revision=9,
            authority_sha256=_digest("credential-authority"),
            expires_at=160.0,
            revoked=self.revoked,
        )


def _binding_store(tmp_path: Path, name: str = "bindings.sqlite3") -> ProviderBindingStore:
    return ProviderBindingStore(tmp_path / name, clock=lambda: 100.0)


def test_credential_bridge_hashes_key_id_and_preserves_authority_pins() -> None:
    owner = _CredentialOwner(revoked=True)
    bridge = ProviderAuditCredentialOwnerBridge(owner)

    lease = bridge.lease(
        provider_id="snowflake",
        tenant_id="tenant-a",
        binding_id="native-customers",
    )

    assert owner.calls == [
        {
            "provider_id": "snowflake",
            "tenant_id": "tenant-a",
            "binding_id": "native-customers",
        }
    ]
    assert lease.authorization == "Bearer raw-provider-token"
    assert lease.credential_key_id_sha256 == _digest("snowflake:SNOWFLAKE_CONTROL_TOKEN")
    assert lease.credential_revision == 9
    assert lease.credential_authority_sha256 == _digest("credential-authority")
    assert lease.expires_at == 160.0
    assert lease.revoked is True
    assert "raw-provider-token" not in repr(bridge)
    assert "SNOWFLAKE_CONTROL_TOKEN" not in repr(bridge)


def test_credential_bridge_rejects_missing_or_wrong_adapter_owner() -> None:
    with pytest.raises(DataUseProviderAuditConfigError, match="owner is unavailable"):
        ProviderAuditCredentialOwnerBridge(object())

    class WrongOwner:
        def lease(self, **_kwargs):
            return object()

    bridge = ProviderAuditCredentialOwnerBridge(WrongOwner())
    with pytest.raises(DataUseProviderAuditConfigError, match="invalid lease"):
        bridge.lease(
            provider_id="snowflake",
            tenant_id="tenant-a",
            binding_id="native-customers",
        )


def test_builder_fails_closed_before_creating_audit_database(tmp_path: Path) -> None:
    binding_store = _binding_store(tmp_path)
    audit_path = tmp_path / "provider-audit.sqlite3"
    authority = _Authority()
    transport = _ReadTransport()

    disabled = _config()
    disabled["data_use_governance"]["provider_audit"]["enable"] = False
    with pytest.raises(DataUseProviderAuditConfigError, match="disabled"):
        build_provider_audit_runtime(
            tenant_id="tenant-a",
            binding_store=binding_store,
            config=disabled,
            store_path=audit_path,
            authority=authority,
            transport=transport,
        )
    assert not audit_path.exists()

    with pytest.raises(DataUseProviderAuditConfigError, match="authorities"):
        build_provider_audit_runtime(
            tenant_id="tenant-a",
            binding_store=binding_store,
            config=_config(),
            store_path=audit_path,
            transport=transport,
        )
    assert not audit_path.exists()

    native = build_provider_audit_runtime(
        tenant_id="tenant-a",
        binding_store=binding_store,
        config=_config(),
        store_path=audit_path,
        authority=authority,
    )
    assert isinstance(native.transport, NativeProviderAuditTransport)
    assert native.bundled_native_transport is True

    invalid_path = tmp_path / "invalid-transport.sqlite3"
    with pytest.raises(DataUseProviderAuditConfigError, match="transport"):
        build_provider_audit_runtime(
            tenant_id="tenant-a",
            binding_store=binding_store,
            config=_config(),
            store_path=invalid_path,
            authority=authority,
            transport=object(),
        )
    assert not invalid_path.exists()

    class IncompleteAuthority:
        resolve_control_authority = authority.resolve_control_authority

    incomplete_path = tmp_path / "incomplete-authority.sqlite3"
    with pytest.raises(DataUseProviderAuditConfigError, match="complete resolver pair"):
        build_provider_audit_runtime(
            tenant_id="tenant-a",
            binding_store=binding_store,
            config=_config(),
            store_path=incomplete_path,
            authority=IncompleteAuthority(),
            transport=transport,
        )
    assert not incomplete_path.exists()


def test_runtime_is_composable_and_status_is_digest_only(tmp_path: Path) -> None:
    config = _config()
    authority = _Authority()
    transport = _ReadTransport()
    owner = _CredentialOwner()
    audit_path = tmp_path / "private" / "provider-audit.sqlite3"
    runtime = build_provider_audit_runtime(
        tenant_id="tenant-sensitive-name",
        binding_store=_binding_store(tmp_path),
        config=config,
        store_path=audit_path,
        authority=authority,
        credential_owner=owner,
        transport=transport,
        clock=lambda: 100.0,
    )

    assert runtime.worker.store is runtime.store
    assert runtime.transport is transport
    assert runtime.store.path == audit_path
    result = runtime.run_once(worker_id="audit-worker-1")
    assert result.claimed == 0
    assert owner.calls == []
    assert transport.calls == 0
    assert authority.control_calls == 0
    assert authority.read_calls == 0

    status = dict(runtime.status())
    status_digest = status.pop("status_sha256")
    assert (
        status_digest
        == hashlib.sha256(
            json.dumps(
                status,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        ).hexdigest()
    )
    assert status["tenant_sha256"] == _digest("tenant-sensitive-name")
    assert status["store_path_sha256"] == _digest(str(audit_path.resolve()))
    assert status["typed_read_transport_injected"] is True
    assert status["raw_provider_events_persisted"] is False
    assert status["credential_material_persisted"] is False
    assert status["provider_writes"] is False
    assert status["built_in_network_transport"] is False
    assert status["audit_log_completeness_claim"] is False
    assert status["live_provider_acceptance"] is False
    assert status["state_counts"]["total"] == 0

    serialized = json.dumps(status, sort_keys=True)
    for raw_value in (
        "tenant-sensitive-name",
        str(audit_path),
        "raw-provider-token",
        "SNOWFLAKE_CONTROL_TOKEN",
        "snowflake:SNOWFLAKE_CONTROL_TOKEN",
    ):
        assert raw_value not in serialized
        assert raw_value not in repr(runtime)


def test_runtime_gate_rechecks_mutable_captured_config(tmp_path: Path) -> None:
    config = _config()
    runtime = build_provider_audit_runtime(
        tenant_id="tenant-a",
        binding_store=_binding_store(tmp_path),
        config=config,
        store_path=tmp_path / "provider-audit.sqlite3",
        authority=_Authority(),
        transport=_ReadTransport(),
        clock=lambda: 100.0,
    )
    assert runtime.state_counts()["total"] == 0

    config["data_use_governance"]["provider_audit"]["enable"] = False
    with pytest.raises(DataUseProviderAuditConfigError, match="disabled"):
        runtime.state_counts()


def test_default_store_path_is_tenant_namespaced_and_resolves_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "maverick-home"))
    config = _config()
    authority = _Authority()
    transport = _ReadTransport()

    first = build_provider_audit_runtime(
        tenant_id="tenant-a",
        binding_store=_binding_store(tmp_path, "bindings-a.sqlite3"),
        config=config,
        authority=authority,
        transport=transport,
        clock=lambda: 100.0,
    )
    second = build_provider_audit_runtime(
        tenant_id="tenant-b",
        binding_store=_binding_store(tmp_path, "bindings-b.sqlite3"),
        config=config,
        authority=authority,
        transport=transport,
        clock=lambda: 100.0,
    )

    assert first.store.path != second.store.path
    assert first.tenant_sha256 == _digest("tenant-a")
    assert second.tenant_sha256 == _digest("tenant-b")
    assert first.tenant_sha256 != second.tenant_sha256
    assert first.run_once(worker_id="worker-a").claimed == 0
    assert second.run_once(worker_id="worker-b").claimed == 0
    assert transport.calls == 0


def test_explicit_resolvers_are_supported_and_mixed_injection_is_rejected(
    tmp_path: Path,
) -> None:
    authority = _Authority()
    binding_store = _binding_store(tmp_path)
    transport = _ReadTransport()
    explicit_path = tmp_path / "explicit.sqlite3"
    runtime = build_provider_audit_runtime(
        tenant_id="tenant-a",
        binding_store=binding_store,
        config=_config(),
        store_path=explicit_path,
        control_authority_resolver=authority.resolve_control_authority,
        read_authority_resolver=authority.resolve_read_authority,
        transport=transport,
        clock=lambda: 100.0,
    )
    assert runtime.store.path == explicit_path

    ambiguous_path = tmp_path / "ambiguous.sqlite3"
    with pytest.raises(DataUseProviderAuditConfigError, match="ambiguous"):
        build_provider_audit_runtime(
            tenant_id="tenant-a",
            binding_store=binding_store,
            config=_config(),
            store_path=ambiguous_path,
            authority=authority,
            control_authority_resolver=authority.resolve_control_authority,
            read_authority_resolver=authority.resolve_read_authority,
            transport=transport,
        )
    assert not ambiguous_path.exists()


@pytest.mark.parametrize("value", [True, 1, "true"])
def test_provider_audit_gate_requires_exact_booleans(value: object) -> None:
    config = _config()
    config["data_use_governance"]["provider_audit"]["enable"] = value
    assert provider_audit_config_enabled(config) is (value is True)
