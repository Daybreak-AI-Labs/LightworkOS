"""No-network tests for provider-write/audit outbox composition."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from maverick.data_use_provider_adapters import ProviderBindingStore
from maverick.data_use_provider_audit import (
    DataUseProviderAuditConfigError,
    DataUseProviderAuditNotFound,
    DataUseProviderAuditStore,
    ProviderAuditWorkerResult,
)
from maverick.data_use_provider_audit_authority import (
    DataUseProviderAuditAuthorityNotFound,
    DataUseProviderAuditAuthorityStore,
)
from maverick_dashboard.data_use_provider_audit_composition import (
    DataUseProviderAuditComposition,
    ProviderAuditOperationSettings,
    build_provider_audit_composition,
    operation_settings,
)

_DIGEST = "a" * 64


def _config(**audit_overrides) -> dict:
    audit = {
        "enable": True,
        "audit_window_seconds": 300,
        "retention_seconds": 3_600,
        "max_attempts": 4,
        **audit_overrides,
    }
    return {
        "data_use_governance": {
            "enable": True,
            "provider_audit": audit,
        }
    }


@dataclass(frozen=True)
class _Record:
    authority_id: str = "DUAO-authority"
    provider_id: str = "snowflake"
    binding_id: str = "native-customers"
    operation_idempotency_sha256: str = _DIGEST
    authority_revision: int = 1
    state: str = "staged"
    valid_until: float = 4_900.0
    retained_until: float = 8_000.0
    revision: int = 1


@dataclass(frozen=True)
class _Expectation:
    expectation_id: str = "DUA-expectation"
    provider_id: str = "snowflake"
    binding_id: str = "native-customers"
    operation_idempotency_sha256: str = _DIGEST


class _Authority(DataUseProviderAuditAuthorityStore):
    def __init__(self, *, read_valid_until: float = 8_000.0) -> None:
        self.record: _Record | None = None
        self.read_valid_until = read_valid_until
        self.calls: list[str] = []
        self.purge_calls: list[str] = []

    def get_control_authority_for_operation(self, *_args):
        self.calls.append("lookup")
        if self.record is None:
            raise DataUseProviderAuditAuthorityNotFound("missing")
        return self.record

    def resolve_read_authority(self, *_args):
        self.calls.append("read")
        return SimpleNamespace(valid_until=self.read_valid_until)

    def stage_operation(self, **kwargs):
        self.calls.append("stage")
        if self.record is None:
            self.record = _Record(
                provider_id=kwargs["provider_id"],
                binding_id=kwargs["binding_id"],
                operation_idempotency_sha256=kwargs["operation_idempotency_sha256"],
                authority_revision=kwargs["authority_revision"],
                valid_until=kwargs["valid_until"],
                retained_until=kwargs["retained_until"],
            )
        return self.record

    def get_control_authority_record(self, _authority_id):
        assert self.record is not None
        return self.record

    def finalize_operation(self, *_args, **_kwargs):
        self.calls.append("finalize")
        assert self.record is not None
        self.record = replace(self.record, state="finalized", revision=2)
        return self.record

    def mark_registered(self, *_args, **_kwargs):
        self.calls.append("mark")
        assert self.record is not None
        self.record = replace(self.record, state="registered", revision=3)
        return self.record

    def list_control_authorities(self, *, state, limit):
        assert 1 <= limit <= 500
        if self.record is not None and self.record.state == state:
            return (self.record,)
        return ()

    def next_control_authorities(self, *, state, limit):
        return self.list_control_authorities(state=state, limit=limit)

    def verify_integrity(self):
        return SimpleNamespace(control_authorities=int(self.record is not None), read_grants=1)

    def get_current_read_grant(self, provider_id, binding_id):
        return (provider_id, binding_id)

    def issue_read_grant(self, **kwargs):
        return kwargs

    def revoke_read_grant(self, **kwargs):
        return kwargs

    def purge_expired(self, *, cutoff, limit):
        self.purge_calls.append(f"authority:{cutoff}:{limit}")
        return SimpleNamespace(control_authorities=2, read_grants=3)


class _Store(DataUseProviderAuditStore):
    def __init__(self, *, fail_register_once: bool = False) -> None:
        self.expectation: _Expectation | None = None
        self.fail_register_once = fail_register_once
        self.calls: list[str] = []
        self.purge_calls: list[str] = []

    def get_expectation_for_registration(self, _key):
        self.calls.append("lookup")
        if self.expectation is None:
            raise DataUseProviderAuditNotFound("missing")
        return self.expectation

    def register_operation(self, **_kwargs):
        self.calls.append("register")
        if self.fail_register_once:
            self.fail_register_once = False
            raise DataUseProviderAuditConfigError("temporary composition failure")
        self.expectation = _Expectation()
        return self.expectation

    def state_counts(self):
        return {
            "queued": int(self.expectation is not None),
            "total": int(self.expectation is not None),
        }

    def purge_expired(self, *, cutoff, limit):
        self.purge_calls.append(f"audit:{cutoff}:{limit}")
        return 1


class _Runtime:
    def __init__(self, order: list[str]) -> None:
        self.order = order

    def run_once(self, **_kwargs):
        self.order.append("worker")
        return ProviderAuditWorkerResult(
            claimed=0,
            converged=0,
            no_change=0,
            findings=0,
            retried=0,
            dead_lettered=0,
            cancelled=0,
        )


def _composition(
    *,
    authority: _Authority | None = None,
    store: _Store | None = None,
    runtime=None,
) -> DataUseProviderAuditComposition:
    return DataUseProviderAuditComposition(
        authority=authority or _Authority(),
        store=store or _Store(),
        settings=ProviderAuditOperationSettings(
            audit_window_seconds=300,
            retention_seconds=3_600,
            max_attempts=4,
        ),
        tenant_id="tenant-sensitive",
        clock=lambda: 1_000.0,
        runtime=runtime,
    )


def test_settings_are_bounded_and_retention_covers_window() -> None:
    assert operation_settings(_config()).max_attempts == 4
    with pytest.raises(DataUseProviderAuditConfigError, match="retention"):
        operation_settings(_config(audit_window_seconds=600, retention_seconds=599))
    with pytest.raises(DataUseProviderAuditConfigError, match="outside"):
        operation_settings(_config(max_attempts=21))


def test_stage_requires_long_lived_read_authority_before_mutation() -> None:
    authority = _Authority(read_valid_until=4_899.0)
    composition = _composition(authority=authority)
    with pytest.raises(DataUseProviderAuditConfigError, match="expires"):
        composition.stage_operation(
            provider_id="snowflake",
            binding_id="native-customers",
            operation_idempotency_sha256=_DIGEST,
            control_ir={"schema": "server-compiled-only"},
            operation="apply",
        )
    assert authority.calls == ["lookup", "read"]
    assert authority.record is None


def test_post_write_registration_failure_is_recovered_without_duplicate_stage() -> None:
    authority = _Authority()
    store = _Store(fail_register_once=True)
    composition = _composition(authority=authority, store=store)
    staged = composition.stage_operation(
        provider_id="snowflake",
        binding_id="native-customers",
        operation_idempotency_sha256=_DIGEST,
        control_ir={"schema": "server-compiled-only"},
        operation="apply",
    )
    with pytest.raises(DataUseProviderAuditConfigError, match="temporary"):
        composition.complete_operation(staged.authority_id)
    assert authority.record is not None and authority.record.state == "finalized"

    recovery = composition.recover_pending(limit=10)
    assert recovery.finalized == 0
    assert recovery.registered == 1
    assert recovery.pending_or_failed == 0
    assert authority.record.state == "registered"
    assert store.calls.count("register") == 2

    replay = composition.stage_operation(
        provider_id="snowflake",
        binding_id="native-customers",
        operation_idempotency_sha256=_DIGEST,
        control_ir={"schema": "server-compiled-only"},
        operation="apply",
    )
    completed = composition.complete_operation(replay.authority_id)
    assert completed.expectation == store.expectation
    assert authority.calls.count("stage") == 2
    assert store.calls.count("register") == 2


def test_worker_recovers_before_read_and_purges_audit_before_authority() -> None:
    order: list[str] = []
    authority = _Authority()
    store = _Store()
    composition = _composition(
        authority=authority,
        store=store,
        runtime=_Runtime(order),
    )
    composition.stage_operation(
        provider_id="snowflake",
        binding_id="native-customers",
        operation_idempotency_sha256=_DIGEST,
        control_ir={"schema": "server-compiled-only"},
        operation="apply",
    )
    result = composition.worker.run_once(worker_id="worker-1", limit=7)
    assert result.claimed == 0
    # The staged outbox is registered before the provider read worker runs.
    assert authority.record is not None and authority.record.state == "registered"
    assert order == ["worker"]

    assert composition.worker.store.purge_expired(cutoff=2_000.0, limit=10) == 6
    assert store.purge_calls == ["audit:2000.0:10"]
    assert authority.purge_calls == ["authority:2000.0:10"]


def test_builder_without_worker_needs_no_transport(tmp_path: Path) -> None:
    bindings = ProviderBindingStore(tmp_path / "bindings.sqlite3", clock=lambda: 1_000.0)
    composition = build_provider_audit_composition(
        tenant_id="tenant-a",
        binding_store=bindings,
        config=_config(),
        authority_store_path=tmp_path / "authority.sqlite3",
        audit_store_path=tmp_path / "audit.sqlite3",
        require_worker=False,
        clock=lambda: 1_000.0,
    )
    assert composition.worker is None
    assert composition.store.state_counts()["total"] == 0
    worker_composition = build_provider_audit_composition(
        tenant_id="tenant-b",
        binding_store=ProviderBindingStore(tmp_path / "bindings-b.sqlite3", clock=lambda: 1_000.0),
        config=_config(),
        authority_store_path=tmp_path / "authority-b.sqlite3",
        audit_store_path=tmp_path / "audit-b.sqlite3",
        require_worker=True,
        clock=lambda: 1_000.0,
    )
    assert worker_composition.worker is not None
    assert worker_composition.status()["built_in_network_transport"] is True

    with pytest.raises(DataUseProviderAuditConfigError, match="transport"):
        build_provider_audit_composition(
            tenant_id="tenant-c",
            binding_store=ProviderBindingStore(
                tmp_path / "bindings-c.sqlite3", clock=lambda: 1_000.0
            ),
            config=_config(),
            authority_store_path=tmp_path / "authority-c.sqlite3",
            audit_store_path=tmp_path / "audit-c.sqlite3",
            transport=object(),
            require_worker=True,
            clock=lambda: 1_000.0,
        )
