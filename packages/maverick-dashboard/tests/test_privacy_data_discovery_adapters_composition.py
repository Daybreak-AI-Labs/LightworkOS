from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick import config as config_module
from maverick import privacy_data_discovery as discovery
from maverick.paths import current_tenant_id_strict, data_dir, tenant_scope
from maverick.privacy_data_discovery import PrivacyDataDiscoveryStore
from maverick.privacy_data_discovery_adapters import (
    AWS_S3,
    AZURE_BLOB,
    SERVICENOW_CMDB,
    DiscoveryHTTPResponse,
)
from maverick_dashboard import privacy_data_discovery_adapters_composition as composition


class LocalTransport:
    def __init__(self) -> None:
        self.requests = []

    def request(self, request):
        self.requests.append(request)
        return DiscoveryHTTPResponse(200, {}, b"{}")


class LocalRows:
    def iter_rows(self, *, source, credential_env, limits, deadline):
        del source, credential_env, limits, deadline
        yield discovery.StructuredRecord(
            "row-a",
            {"email": "approved@example.test"},
        )


def _config(
    *providers: str,
    remediation_enabled: bool = False,
    data_map_enabled: bool = False,
) -> dict[str, object]:
    return {
        "privacy_automation": {
            "enable": True,
            "data_discovery": {
                "enable": True,
                "adapters": {
                    "enable": True,
                    "enabled_providers": list(providers),
                    "timeout_seconds": 2,
                    "max_response_bytes": 65_536,
                    "page_size": 100,
                    "max_pages": 20,
                    "max_attempts": 2,
                    "max_polls": 3,
                },
                "remediation": {
                    "enable": remediation_enabled,
                    "max_attempts": 4,
                    "retention_seconds": 86_400,
                    "data_map": {
                        "enable": data_map_enabled,
                        "retention_seconds": 172_800,
                    },
                },
            },
        }
    }


def _app():
    return SimpleNamespace(state=SimpleNamespace())


def _store(path) -> PrivacyDataDiscoveryStore:
    return PrivacyDataDiscoveryStore(
        path,
        config_gate=lambda: None,
        evidence_key_resolver=lambda _name: b"e" * 32,
    )


def test_attach_is_lazy_and_installs_only_factories(monkeypatch) -> None:
    def forbidden(_tenant):
        raise AssertionError("attach must not resolve tenant configuration")

    monkeypatch.setattr(composition, "_load_tenant_config", forbidden)
    target = _app()
    composition.attach_privacy_data_discovery_adapters(target)

    for name in (
        "privacy_data_discovery_coordinator_factory",
        "privacy_data_discovery_remediation_runtime_factory",
        "privacy_data_discovery_review_callback_factory",
        "privacy_data_discovery_review_callback",
        "privacy_data_discovery_worker_factory",
        "privacy_data_discovery_data_map_reconciler_factory",
        "privacy_data_discovery_maintenance_factory",
        "privacy_data_discovery_readiness_probe",
    ):
        assert callable(getattr(target.state, name))
    assert not hasattr(target.state, "privacy_data_discovery_structured_sources")
    assert not hasattr(target.state, "privacy_data_discovery_unstructured_sources")


def test_coordinator_registry_is_tenant_exact_and_not_global(tmp_path, monkeypatch) -> None:
    seen: list[tuple[str | None, bool]] = []

    def tenant_config():
        tenant = current_tenant_id_strict()
        seen.append((tenant, True))
        return {
            "tenant-a": _config(AWS_S3),
            "tenant-b": _config(SERVICENOW_CMDB),
        }[tenant]

    monkeypatch.setattr(config_module, "load_config", tenant_config)
    monkeypatch.setattr(
        config_module,
        "config_source_errors",
        lambda *, include_tenant: {} if include_tenant else {"unexpected": "call"},
    )
    target = _app()
    transport = LocalTransport()
    target.state.privacy_data_discovery_stock_transport_factory = (
        lambda _tenant: transport
    )
    composition.attach_privacy_data_discovery_adapters(target)

    tenant_a = target.state.privacy_data_discovery_coordinator_factory(
        tenant_id="tenant-a",
        store=_store(tmp_path / "tenant-a.sqlite3"),
    )
    tenant_b = target.state.privacy_data_discovery_coordinator_factory(
        tenant_id="tenant-b",
        store=_store(tmp_path / "tenant-b.sqlite3"),
    )

    assert tenant_a.tenant_id == "tenant-a"
    assert tuple(tenant_a._unstructured) == (AWS_S3,)
    assert tenant_a._structured == {}
    assert tenant_b.tenant_id == "tenant-b"
    assert tuple(tenant_b._structured) == (SERVICENOW_CMDB,)
    assert tenant_b._unstructured == {}
    assert seen == [("tenant-a", True), ("tenant-b", True)]
    assert transport.requests == []
    assert not hasattr(target.state, "privacy_data_discovery_structured_sources")


def test_coordinator_rejects_tenant_config_drift_before_provider_io(
    tmp_path,
    monkeypatch,
) -> None:
    selected = {"value": _config(AWS_S3)}
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: selected["value"],
    )
    transport = LocalTransport()
    target = _app()
    target.state.privacy_data_discovery_stock_transport_factory = (
        lambda _tenant: transport
    )
    composition.attach_privacy_data_discovery_adapters(target)
    coordinator = target.state.privacy_data_discovery_coordinator_factory(
        tenant_id="tenant-a",
        store=_store(tmp_path / "tenant-a.sqlite3"),
    )

    selected["value"] = _config(AZURE_BLOB)
    with pytest.raises(
        composition.PrivacyDiscoveryAdapterCompositionError,
        match="configuration changed",
    ):
        coordinator.run_once("tenant-a", worker_id="worker-a")
    assert transport.requests == []


def test_config_source_error_fails_closed_inside_exact_tenant(monkeypatch) -> None:
    seen: list[str | None] = []

    def tenant_config():
        seen.append(current_tenant_id_strict())
        return _config(AWS_S3)

    monkeypatch.setattr(config_module, "load_config", tenant_config)
    monkeypatch.setattr(
        config_module,
        "config_source_errors",
        lambda *, include_tenant: {"tenant": "invalid"},
    )
    with pytest.raises(
        composition.PrivacyDiscoveryAdapterCompositionError,
        match="configuration source is invalid",
    ):
        composition.snapshot_for_tenant(_app(), "tenant-a")
    assert seen == ["tenant-a"]


def test_stock_remediation_requires_its_digest_target(monkeypatch) -> None:
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(
            AWS_S3,
            remediation_enabled=True,
            data_map_enabled=False,
        ),
    )
    target = _app()
    composition.attach_privacy_data_discovery_adapters(target)
    with pytest.raises(
        composition.PrivacyDiscoveryAdapterCompositionError,
        match="requires data_map.enable",
    ):
        composition.snapshot_for_tenant(target, "tenant-a")
    readiness = target.state.privacy_data_discovery_readiness_probe("tenant-a")
    assert readiness["ready"] is False
    assert readiness["configured"] is False


def test_readiness_is_content_free_and_does_not_open_store_or_provider(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(AWS_S3),
    )
    transport_factory_calls = []

    def forbidden_transport(tenant):
        transport_factory_calls.append(tenant)
        raise AssertionError("transport factory was invoked")

    target = _app()
    target.state.privacy_data_discovery_stock_transport_factory = forbidden_transport
    composition.attach_privacy_data_discovery_adapters(target)

    status = target.state.privacy_data_discovery_readiness_probe("tenant-a")
    assert status["ready"] is True
    assert status["unstructured_providers"] == [AWS_S3]
    assert status["source_credentials_checked_by_status"] is False
    assert status["status_probe_opened_store"] is False
    assert status["status_probe_invoked_provider"] is False
    assert status["approved_review_callback_durable_outbox"] is True
    assert status["retry_worker_factory_installed"] is True
    assert status["live_provider_acceptance_verified"] is False
    assert transport_factory_calls == []


def test_digest_only_remediation_runtime_is_tenant_private_and_maintainable(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(
            AWS_S3,
            remediation_enabled=True,
            data_map_enabled=True,
        ),
    )
    target = _app()
    composition.attach_privacy_data_discovery_adapters(target)
    discovery_store = _store(tmp_path / "tenant-a" / "discovery.sqlite3")
    runtime = composition.build_remediation_runtime(
        target,
        tenant_id="tenant-a",
        discovery_store=discovery_store,
        principal_ref="privacy-discovery-worker",
        outbox_path=tmp_path / "tenant-a" / "outbox.sqlite3",
        data_map_path=tmp_path / "tenant-a" / "data-map.sqlite3",
        clock=lambda: 1_000,
    )

    assert runtime.tenant_id == "tenant-a"
    assert runtime.outbox.path == tmp_path / "tenant-a" / "outbox.sqlite3"
    assert runtime.target.path == tmp_path / "tenant-a" / "data-map.sqlite3"
    assert callable(runtime.review_callback)
    assert callable(runtime.reconciler)
    boundaries = runtime.target.product_boundaries()
    assert boundaries["raw_values_persisted"] is False
    assert boundaries["article_30_ropa_completeness_claimed"] is False

    maintenance = runtime.maintenance(
        cutoff=999,
        idempotency_key="retention-1",
    )
    assert maintenance["tenant_id"] == "tenant-a"
    assert maintenance["outbox_purged"] == 0
    assert maintenance["data_map_purged"] == 0
    assert maintenance["raw_data_returned"] is False
    assert maintenance["provider_side_effect"] is False


def test_approved_review_callback_reaches_durable_outbox_and_digest_target(
    tmp_path,
    monkeypatch,
) -> None:
    selected_config = _config(
        AWS_S3,
        remediation_enabled=True,
        data_map_enabled=True,
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("DISCOVERY_EVIDENCE_KEY", "e" * 32)
    monkeypatch.setattr(config_module, "load_config", lambda: selected_config)
    monkeypatch.setattr(
        config_module,
        "config_source_errors",
        lambda *, include_tenant=True: {},
    )
    target = _app()
    composition.attach_privacy_data_discovery_adapters(target)

    with tenant_scope(tenant="tenant-a"):
        discovery_store = PrivacyDataDiscoveryStore(
            data_dir(
                "privacy_automation",
                "privacy-data-discovery.sqlite3",
                tenant="tenant-a",
            ),
            review_callback=target.state.privacy_data_discovery_review_callback,
        )
        discovery_store.enroll_source(
            "tenant-a",
            source_id="customer-db",
            kind="structured",
            provider="fixture",
            origin="https://data.example.test",
            resource_ref="customer-table",
            credential_env="DISCOVERY_CREDENTIAL",
            evidence_key_env="DISCOVERY_EVIDENCE_KEY",
            actor_ref="privacy-owner",
            idempotency_key="enroll-source",
        )
        discovery_store.enqueue_scan(
            "tenant-a",
            "customer-db",
            limits=discovery.ScanLimits(),
            max_attempts=2,
            retention_seconds=3_600,
            actor_ref="privacy-owner",
            idempotency_key="scan-source",
        )
        run = discovery.PrivacyDataDiscoveryCoordinator(
            discovery_store,
            structured_sources={"fixture": LocalRows()},
            credential_ref_present=lambda _name: True,
        ).run_once("tenant-a", worker_id="worker-a")
        report = run.completed_reports[0]
        finding = discovery_store.list_findings(
            "tenant-a",
            report_id=report.report_id,
        )[0]
        proposal = discovery_store.propose_review(
            "tenant-a",
            finding.finding_id,
            decision="confirmed",
            effective_category=finding.category,
            evidence_sha256=finding.evidence_sha256,
            freshness_seconds=600,
            expected_finding_revision=finding.revision,
            prepared_by="reviewer-a",
            idempotency_key="prepare-review",
        )
        discovery_store.approve_review(
            "tenant-a",
            proposal.review_id,
            approved_by="reviewer-b",
            expected_version=proposal.version,
            expected_integrity_sha256=proposal.integrity_sha256,
            idempotency_key="approve-review",
        )

        runtime = target.state.privacy_data_discovery_remediation_runtime_factory(
            tenant_id="tenant-a",
            discovery_store=discovery_store,
            principal_ref="remediation-worker",
        )
        queued = runtime.outbox.list_work(state="queued")
        assert len(queued) == 1
        result = runtime.worker.run_once(worker_id="remediation-worker")
        assert result.applied == 1
        observations = runtime.target.list_observations(queued[0].tenant_sha256)
        assert len(observations) == 1
        assert observations[0].category == finding.category
        assert b"approved@example.test" not in runtime.target.path.read_bytes()


def test_invalid_or_shadowed_factory_fails_closed() -> None:
    target = _app()
    target.state.privacy_data_discovery_coordinator_factory = object()
    with pytest.raises(TypeError, match="coordinator factory"):
        composition.attach_privacy_data_discovery_adapters(target)
