"""Focused construction and lifespan tests for provider-audit app wiring."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from maverick import config as config_module
from maverick.data_use_provider_audit import (
    DataUseProviderAuditStore,
)
from maverick.data_use_provider_audit_authority import (
    DataUseProviderAuditAuthorityNotFound,
)
from maverick_dashboard import data_use_provider_audit_composition as composition
from maverick_dashboard.data_use_provider_audit_scheduler import (
    DataUseProviderAuditScheduler,
    DataUseProviderAuditSchedulerConfigurationError,
)


def _config(
    *,
    root: object = True,
    enforcement: object = True,
    audit: object = True,
    scheduler: object = True,
    provider: object = True,
) -> dict[str, Any]:
    return {
        "data_use_governance": {
            "enable": root,
            "compiler": {"enable": True},
            "enforcement": {"enable": enforcement},
            "provider_audit": {
                "enable": audit,
                "audit_window_seconds": 300,
                "retention_seconds": 3_600,
                "max_attempts": 4,
                "scheduler": {
                    "enable": scheduler,
                    "poll_seconds": 5.0,
                    "claim_limit": 2,
                    "tenant_limit": 2,
                    "lease_seconds": 60,
                    "event_limit": 10,
                    "retry_backoff_seconds": 1,
                    "purge_limit": 10,
                },
            },
            "snowflake": {"enable": provider},
            "databricks": {"enable": False},
        }
    }


def _wire_default_factory_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    config: dict[str, Any],
) -> FastAPI:
    monkeypatch.setattr(config_module, "config_source_errors", lambda *args, **kwargs: ())
    monkeypatch.setattr(config_module, "load_config", lambda: config)

    def isolated_data_dir(*parts: str, tenant: str | None = None) -> Path:
        return tmp_path / (tenant or "default") / Path(*parts)

    monkeypatch.setattr(composition, "data_dir", isolated_data_dir)
    app = FastAPI()
    composition.attach_data_use_provider_audit_composition(app)
    return app


class _CredentialOwnerProbe:
    def __init__(self) -> None:
        self.lease_calls = 0

    def lease(self, **_kwargs):
        self.lease_calls += 1
        raise AssertionError("composition construction must not resolve credentials")


class _TransportProbe:
    def __init__(self) -> None:
        self.read_calls = 0

    def read(self, *_args, **_kwargs):
        self.read_calls += 1
        raise AssertionError("composition construction must not perform provider reads")


def test_shipped_app_installs_default_factories_and_one_scheduler() -> None:
    from maverick_dashboard.app import app

    # Other focused API fixtures deliberately remove injected state on teardown;
    # the shipped attachment is idempotent and restores its defaults.
    composition.attach_data_use_provider_audit_composition(app)

    for name in (
        "data_use_provider_audit_composition_factory",
        "data_use_provider_audit_store_factory",
        "data_use_provider_audit_worker_factory",
        "data_use_provider_audit_read_grant_factory",
    ):
        assert callable(getattr(app.state, name, None))
    assert isinstance(
        app.state.data_use_provider_audit_scheduler,
        DataUseProviderAuditScheduler,
    )


def test_attach_is_idempotent_and_does_not_wrap_lifespan_twice() -> None:
    app = FastAPI()
    composition.attach_data_use_provider_audit_composition(app)
    selected = app.state.data_use_provider_audit_scheduler
    wrapped_lifespan = app.router.lifespan_context

    composition.attach_data_use_provider_audit_composition(app)

    assert app.state.data_use_provider_audit_scheduler is selected
    assert app.router.lifespan_context is wrapped_lifespan


def test_read_only_and_worker_default_factories_need_no_custom_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app = _wire_default_factory_environment(monkeypatch, tmp_path, _config())
    kwargs = {
        "tenant_id": "tenant-a",
        "principal_ref": "provider-audit-api.operator",
    }

    store = app.state.data_use_provider_audit_store_factory(**kwargs)
    assert isinstance(store, DataUseProviderAuditStore)
    assert store.state_counts()["total"] == 0
    read_manager = app.state.data_use_provider_audit_read_grant_factory(**kwargs)
    assert read_manager.worker is None
    assert callable(read_manager.get_current_read_grant)
    assert callable(read_manager.issue_read_grant)
    assert callable(read_manager.revoke_read_grant)
    with pytest.raises(DataUseProviderAuditAuthorityNotFound):
        read_manager.revoke_read_grant(
            "DUAR-missing",
            expected_revision=1,
            expected_integrity_sha256="a" * 64,
            reason_sha256="b" * 64,
            idempotency_key="revoke-missing-grant",
        )

    worker = app.state.data_use_provider_audit_worker_factory(**kwargs)
    assert worker is not None


def test_worker_construction_only_binds_injected_capabilities_without_using_them(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app = _wire_default_factory_environment(monkeypatch, tmp_path, _config())
    credential_owner = _CredentialOwnerProbe()
    transport = _TransportProbe()
    app.state.data_use_provider_credential_owner = credential_owner
    app.state.data_use_provider_audit_transport = transport

    worker = app.state.data_use_provider_audit_worker_factory(
        tenant_id="tenant-a",
        principal_ref="provider-audit-api.operator",
    )

    assert worker is not None
    assert credential_owner.lease_calls == 0
    assert transport.read_calls == 0


def test_app_factory_forwards_independent_databricks_watermark_resolver(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app = _wire_default_factory_environment(monkeypatch, tmp_path, _config())

    def resolver(*_args):
        return None

    app.state.data_use_provider_audit_watermark_authority_resolver = resolver
    captured: dict[str, object] = {}
    sentinel_worker = object()

    def fake_builder(**kwargs):
        captured.update(kwargs)
        return type("BuiltComposition", (), {"worker": sentinel_worker})()

    monkeypatch.setattr(composition, "build_provider_audit_composition", fake_builder)

    worker = app.state.data_use_provider_audit_worker_factory(
        tenant_id="tenant-a",
        principal_ref="provider-audit-api.operator",
    )

    assert worker is sentinel_worker
    assert captured["watermark_authority_resolver"] is resolver


def test_custom_factories_are_preserved_for_api_and_scheduler() -> None:
    app = FastAPI()
    sentinel_worker = object()

    def composition_factory(**_kwargs):
        raise AssertionError("scheduler must use the injected worker factory")

    def store_factory(**_kwargs):
        return object()

    def worker_factory(**kwargs):
        assert kwargs["tenant_id"] == "tenant-a"
        assert kwargs["principal_ref"] == "provider-audit-scheduler.operator"
        return sentinel_worker

    def read_grant_factory(**_kwargs):
        return object()

    app.state.data_use_provider_audit_composition_factory = composition_factory
    app.state.data_use_provider_audit_store_factory = store_factory
    app.state.data_use_provider_audit_worker_factory = worker_factory
    app.state.data_use_provider_audit_read_grant_factory = read_grant_factory

    composition.attach_data_use_provider_audit_composition(app)

    assert app.state.data_use_provider_audit_composition_factory is composition_factory
    assert app.state.data_use_provider_audit_store_factory is store_factory
    assert app.state.data_use_provider_audit_worker_factory is worker_factory
    assert app.state.data_use_provider_audit_read_grant_factory is read_grant_factory
    scheduler = app.state.data_use_provider_audit_scheduler
    assert (
        scheduler._worker_factory(  # noqa: SLF001 - integration seam under test
            "tenant-a",
            "provider-audit-scheduler.operator",
        )
        is sentinel_worker
    )


@pytest.mark.parametrize(
    "disabled",
    [
        {"root": False},
        {"enforcement": False},
        {"audit": False},
        {"scheduler": False},
        {"provider": False},
    ],
)
def test_attached_scheduler_lifespan_stays_stopped_unless_every_gate_is_true(
    disabled: dict[str, object],
) -> None:
    app = FastAPI()
    composition.attach_data_use_provider_audit_composition(app)
    scheduler = app.state.data_use_provider_audit_scheduler
    scheduler._config_loader = lambda: _config(**disabled)  # noqa: SLF001
    entered = threading.Event()
    scheduler._loop = entered.set  # noqa: SLF001

    async def exercise() -> None:
        async with app.router.lifespan_context(app):
            assert entered.is_set() is False
            assert scheduler.status()["running"] is False

    asyncio.run(exercise())
    assert entered.is_set() is False


def test_attached_scheduler_starts_and_stops_under_exact_enabled_config() -> None:
    app = FastAPI()
    composition.attach_data_use_provider_audit_composition(app)
    scheduler = app.state.data_use_provider_audit_scheduler
    scheduler._config_loader = _config  # noqa: SLF001
    entered = threading.Event()

    def bounded_loop() -> None:
        entered.set()
        scheduler._stop.wait(2.0)  # noqa: SLF001

    scheduler._loop = bounded_loop  # noqa: SLF001

    async def exercise() -> None:
        async with app.router.lifespan_context(app):
            assert entered.wait(1.0)
            assert scheduler.status()["running"] is True

    asyncio.run(exercise())
    assert scheduler.status()["running"] is False


def test_attached_scheduler_rejects_truthy_non_boolean_enable() -> None:
    app = FastAPI()
    composition.attach_data_use_provider_audit_composition(app)
    scheduler = app.state.data_use_provider_audit_scheduler
    scheduler._config_loader = lambda: _config(scheduler=1)  # noqa: SLF001
    with pytest.raises(DataUseProviderAuditSchedulerConfigurationError, match="boolean"):
        scheduler.start()
