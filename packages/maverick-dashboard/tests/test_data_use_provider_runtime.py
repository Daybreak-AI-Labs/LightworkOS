"""No-network tests for the deployable native-provider runtime seams."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from maverick.config_lint import lint_config
from maverick.data_use_provider_adapters import (
    DataUseProviderConfigError,
    DataUseProviderCredentialError,
    ProviderBindingStore,
)
from maverick_dashboard.data_use_provider_runtime import (
    SecretProviderCredentialOwner,
    build_adapter,
    credential_metadata,
    provider_limits,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(*, revision: int = 7) -> dict:
    return {
        "data_use_governance": {
            "enable": True,
            "compiler": {"enable": True},
            "enforcement": {"enable": True, "max_attempts": 2},
            "snowflake": {
                "enable": True,
                "origin": "https://acct1.snowflakecomputing.com",
                "credential_secret_ref": "$SNOWFLAKE_CONTROL_TOKEN",
                "credential_revision": revision,
                "timeout_seconds": 5,
                "max_response_bytes": 65536,
            },
        }
    }


def _enroll(store: ProviderBindingStore, config: dict) -> None:
    metadata = credential_metadata(config, "snowflake")
    store.enroll_snowflake(
        "tenant-a",
        "native-customers",
        origin="https://acct1.snowflakecomputing.com",
        account_or_workspace_id="acct1",
        asset_id="customers",
        catalog="APP_DB",
        schema="PUBLIC",
        table="CUSTOMERS",
        principal="ANALYST_ROLE",
        compute_id="GOVERNANCE_WH",
        field_map={"email": "EMAIL"},
        mask_bindings={"hash_sha256": "GOV.POLICY.MASK_SHA256"},
        row_filter_bindings={},
        state_anchor="GOV.TAGS.DATA_USE_STATE",
        catalog_snapshot_sha256=_digest("catalog"),
        field_inventory_complete=True,
        credential_key_id=metadata.key_id,
        credential_revision=metadata.key_revision,
        credential_authority_sha256=metadata.authority_sha256,
        expected_revision=0,
        idempotency_key="enroll-1",
    )


class _NoNetworkTransport:
    def __init__(self) -> None:
        self.calls = 0

    def request(self, *_args, **_kwargs):
        self.calls += 1
        raise AssertionError("status construction must not open a socket")


def test_metadata_rotation_is_non_secret_and_revision_bound() -> None:
    first = credential_metadata(_config(revision=7), "snowflake")
    rotated = credential_metadata(_config(revision=8), "snowflake")
    assert first.secret_name == "SNOWFLAKE_CONTROL_TOKEN"
    assert first.key_id == "snowflake:SNOWFLAKE_CONTROL_TOKEN"
    assert first.key_revision == 7
    assert first.authority_sha256 != rotated.authority_sha256
    assert "TOKEN" not in first.authority_sha256
    with pytest.raises(DataUseProviderConfigError):
        credential_metadata(
            {
                **_config(),
                "data_use_governance": {
                    **_config()["data_use_governance"],
                    "snowflake": {
                        **_config()["data_use_governance"]["snowflake"],
                        "credential_secret_ref": "literal-secret",
                    },
                },
            },
            "snowflake",
        )


def test_credential_owner_resolves_ephemeral_bearer_and_never_persists_it(
    tmp_path: Path,
) -> None:
    resolved: list[str] = []

    def secret(name: str) -> str:
        resolved.append(name)
        return "raw-secret-token"

    owner = SecretProviderCredentialOwner(_config(), clock=lambda: 100.0, secret_resolver=secret)
    lease = owner.lease(
        provider_id="snowflake",
        tenant_id="tenant-a",
        binding_id="native-customers",
    )
    assert resolved == ["SNOWFLAKE_CONTROL_TOKEN"]
    assert lease.authorization == "Bearer raw-secret-token"
    assert lease.expires_at == 165.0

    store = ProviderBindingStore(tmp_path / "bindings.sqlite")
    _enroll(store, _config())
    assert b"raw-secret-token" not in (tmp_path / "bindings.sqlite").read_bytes()


def test_runtime_status_requires_matching_secret_authority_without_network(
    tmp_path: Path,
) -> None:
    config = _config()
    store = ProviderBindingStore(tmp_path / "bindings.sqlite")
    _enroll(store, config)
    transport = _NoNetworkTransport()
    adapter = build_adapter(
        tenant_id="tenant-a",
        provider_id="snowflake",
        binding_id="native-customers",
        config=config,
        store=store,
        credential_owner=SecretProviderCredentialOwner(
            config,
            secret_resolver=lambda _name: "secret",
        ),
        transport=transport,
    )
    status = adapter.status()
    assert status["provider_writes_possible"] is True
    assert status["live_provider_acceptance_verified"] is False
    assert transport.calls == 0

    rotated_config = _config(revision=8)
    stale = build_adapter(
        tenant_id="tenant-a",
        provider_id="snowflake",
        binding_id="native-customers",
        config=rotated_config,
        store=store,
        credential_owner=SecretProviderCredentialOwner(
            rotated_config,
            secret_resolver=lambda _name: "rotated-secret",
        ),
        transport=transport,
    )
    assert stale.status()["provider_writes_possible"] is False
    assert transport.calls == 0


def test_missing_secret_fails_closed() -> None:
    owner = SecretProviderCredentialOwner(
        _config(), clock=lambda: 100.0, secret_resolver=lambda _name: None
    )
    with pytest.raises(DataUseProviderCredentialError, match="unavailable"):
        owner.lease(
            provider_id="snowflake",
            tenant_id="tenant-a",
            binding_id="native-customers",
        )


def test_every_lint_clean_provider_limit_constructs_at_runtime() -> None:
    config = _config()
    section = config["data_use_governance"]
    section["enforcement"]["max_attempts"] = 5
    section["snowflake"]["timeout_seconds"] = 60
    section["snowflake"]["max_response_bytes"] = 131_072

    assert lint_config(config) == []
    limits = provider_limits(config, "snowflake")
    assert limits.timeout_seconds == 60.0
    assert limits.max_response_bytes == 131_072
    assert limits.max_attempts == 5
    assert limits.max_polls == 5
