from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi import FastAPI
from maverick import unified_audit as audit
from maverick.paths import data_dir
from maverick_dashboard import unified_audit_composition as composition


def _config(*, enable: bool = True) -> dict:
    return {
        "audit": {
            "sign": True,
            "unified": {
                "enable": enable,
                "page_size": 100,
                "lease_seconds": 120,
                "max_lag_seconds": 300,
                "max_attempts": 5,
                "retry_backoff_seconds": 30,
                "poll_seconds": 60,
            },
        }
    }


class _Reader:
    def __init__(self, tenant_id: str, source_id: str) -> None:
        self.authority_value = audit.SourceAuthority(
            tenant_id=tenant_id,
            source_id=source_id,
            suite_id=source_id,
            authority_revision=1,
            authority_sha256=hashlib.sha256(
                f"authority:{tenant_id}:{source_id}".encode()
            ).hexdigest(),
        )

    def resolve_authority(self, **_kwargs):
        return self.authority_value

    def read_history_page(self, **_kwargs):
        raise AssertionError("registration must not read source history")


class _Verifier:
    def __init__(self, source_id: str) -> None:
        self._identity = hashlib.sha256(f"verifier:{source_id}".encode()).hexdigest()

    @property
    def verifier_identity_sha256(self) -> str:
        return self._identity

    def verify_page(self, **_kwargs):
        raise AssertionError("registration must not invoke the verifier")


def test_attach_is_lazy_idempotent_and_preserves_server_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()

    def no_paths(*_args, **_kwargs):
        raise AssertionError("attach opened a persistent authority")

    monkeypatch.setattr(composition, "data_dir", no_paths)
    composition.attach_unified_audit_composition(app)
    factory = app.state.unified_audit_projector_factory
    probe = app.state.unified_audit_enabled_probe
    composition.attach_unified_audit_composition(app)
    assert app.state.unified_audit_projector_factory is factory
    assert app.state.unified_audit_enabled_probe is probe

    def injected_factory(*_args):
        return object()

    def injected_probe(_tenant):
        return False

    other = FastAPI()
    other.state.unified_audit_projector_factory = injected_factory
    other.state.unified_audit_enabled_probe = injected_probe
    composition.attach_unified_audit_composition(other)
    assert other.state.unified_audit_projector_factory is injected_factory
    assert other.state.unified_audit_enabled_probe is injected_probe


def test_reconcile_then_fresh_status_preserves_persisted_core_completion() -> None:
    persisted = {"complete": False}

    class _PersistedCore(audit.UnifiedAuditProjector):
        def __init__(self) -> None:
            self.store = object()

        def run_all(self, *, worker_id: str):
            assert worker_id == "worker-a"
            persisted["complete"] = True
            return ()

        def status(self):
            return {
                "enabled": True,
                "complete": persisted["complete"],
                "sources": [
                    {"source_id": source_id, "current": True} for source_id in audit.REQUIRED_SUITES
                ],
            }

    first = composition.DashboardUnifiedAuditProjector(
        projector=_PersistedCore(),
        source_composition=composition.build_unified_audit_source_composition(
            tenant_id="tenant-a",
            readers={},
            verifiers={},
        ),
    )
    first.run_all(worker_id="worker-a")
    fresh = composition.DashboardUnifiedAuditProjector(
        projector=_PersistedCore(),
        source_composition=composition.build_unified_audit_source_composition(
            tenant_id="tenant-a",
            readers={},
            verifiers={},
        ),
    )
    status = fresh.status()
    assert status["complete"] is True
    assert status["source_adapter_coverage"]["complete"] is False


def test_disabled_default_factory_refuses_before_paths_or_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    reader_calls: list[object] = []
    app.state.unified_audit_source_readers_factory = lambda *_args: (
        reader_calls.append(object()) or {}
    )
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(enable=False),
    )

    def no_paths(*_args, **_kwargs):
        raise AssertionError("disabled factory resolved a data path")

    monkeypatch.setattr(composition, "data_dir", no_paths)
    composition.attach_unified_audit_composition(app)
    with pytest.raises(audit.UnifiedAuditConfigError, match="disabled"):
        app.state.unified_audit_projector_factory(
            "tenant-a",
            "principal-a",
            object(),
        )
    assert reader_calls == []


def test_reader_factory_is_exactly_tenant_and_request_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    request = object()
    calls: list[tuple[str, object]] = []
    sentinel = object()
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda tenant: _config(enable=tenant == "tenant-a"),
    )

    def readers_factory(tenant_id: str, received_request: object):
        calls.append((tenant_id, received_request))
        return {}

    def verifiers_factory(tenant_id: str, received_request: object):
        calls.append((tenant_id, received_request))
        return {}

    def builder(**kwargs):
        assert kwargs["tenant_id"] == "tenant-a"
        assert kwargs["readers"] == {}
        assert kwargs["verifiers"] == {}
        assert kwargs["config"] == _config()
        return sentinel

    app.state.unified_audit_source_readers_factory = readers_factory
    app.state.unified_audit_source_verifiers_factory = verifiers_factory
    monkeypatch.setattr(composition, "build_unified_audit_projector", builder)
    composition.attach_unified_audit_composition(app)
    result = app.state.unified_audit_projector_factory(
        "tenant-a",
        "principal-a",
        request,
    )
    assert result is sentinel
    assert calls == [("tenant-a", request), ("tenant-a", request)]


def test_injected_authority_failure_is_generic_and_precedes_store_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    monkeypatch.setattr(
        composition,
        "_load_tenant_config",
        lambda _tenant: _config(),
    )
    build_calls: list[object] = []

    def broken_readers(_tenant, _request):
        raise ValueError("raw-customer-secret")

    def builder(**_kwargs):
        build_calls.append(object())
        return object()

    app.state.unified_audit_source_readers_factory = broken_readers
    monkeypatch.setattr(composition, "build_unified_audit_projector", builder)
    composition.attach_unified_audit_composition(app)
    with pytest.raises(audit.UnifiedAuditConfigError) as error:
        app.state.unified_audit_projector_factory(
            "tenant-a",
            "principal-a",
            object(),
        )
    assert str(error.value) == "unified-audit source readers are unavailable"
    assert "raw-customer-secret" not in str(error.value)
    assert build_calls == []


def test_absent_readers_build_six_explicitly_incomplete_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    projector = composition.build_unified_audit_projector(
        tenant_id="tenant-a",
        readers={},
        verifiers={},
        config=_config(),
        clock=lambda: 1_800_000_000.0,
    )
    status = projector.status()
    assert status["enabled"] is True
    assert status["complete"] is False
    assert status["registered_sources"] == []
    assert len(status["sources"]) == 6
    assert all(source["complete"] is False for source in status["sources"])
    coverage = status["source_adapter_coverage"]
    assert coverage["source_count"] == 0
    assert coverage["required_source_count"] == 6
    assert coverage["complete"] is False
    assert all(source["available"] is False for source in coverage["sources"])
    assert status["live_source_interoperability_verified"] is False
    assert status["live_customer_acceptance_verified"] is False
    assert status["limits"]["raw_source_payloads_persisted"] is False
    assert projector.store.path.is_file()
    assert tmp_path in projector.store.path.parents
    # AuditLog is lazy: a status read does not fabricate signed evidence.
    assert not data_dir("audit", tenant="tenant-a").exists()


def test_only_exact_reader_verifier_pairs_enter_the_core_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    source_id = "ai_governance"
    unpaired = composition.build_unified_audit_projector(
        tenant_id="tenant-a",
        readers={source_id: _Reader("tenant-a", source_id)},
        verifiers={},
        config=_config(),
    )
    unpaired_status = unpaired.status()
    assert unpaired_status["registered_sources"] == []
    assert unpaired_status["source_adapter_coverage"]["reader_count"] == 1
    assert unpaired_status["source_adapter_coverage"]["verifier_count"] == 0

    paired = composition.build_unified_audit_projector(
        tenant_id="tenant-b",
        readers={source_id: _Reader("tenant-b", source_id)},
        verifiers={source_id: _Verifier(source_id)},
        config=_config(),
    )
    paired_status = paired.status()
    assert paired_status["registered_sources"] == [source_id]
    assert paired_status["source_adapter_coverage"]["source_count"] == 1
    assert paired_status["source_adapter_coverage"]["verifier_count"] == 1
    assert paired_status["complete"] is False


def test_tenants_get_distinct_projection_and_audit_authorities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    projectors = {}
    for tenant in ("tenant-a", "tenant-b"):
        projectors[tenant] = composition.build_unified_audit_projector(
            tenant_id=tenant,
            readers={},
            verifiers={},
            config=_config(),
            clock=lambda: 1_800_000_000.0,
        )
    assert projectors["tenant-a"].store.path != projectors["tenant-b"].store.path
    assert (
        projectors["tenant-a"].status()["tenant_sha256"]
        != projectors["tenant-b"].status()["tenant_sha256"]
    )


def test_unknown_reader_source_fails_before_projection_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    with pytest.raises(RuntimeError, match="source_id_invalid"):
        composition.build_unified_audit_projector(
            tenant_id="tenant-a",
            readers={"caller_source": object()},
            verifiers={},
            config=_config(),
        )
    assert not tuple(tmp_path.rglob("*.sqlite3"))


def test_shipped_app_mounts_unified_audit_without_source_registration() -> None:
    from maverick_dashboard.app import app

    paths = set(app.openapi()["paths"])
    assert "/api/v1/audit/unified/status" in paths
    assert "/api/v1/audit/unified/reconcile" in paths
    assert not any(
        path.startswith("/api/v1/audit/unified")
        and any(word in path for word in ("ingest", "register", "credential"))
        for path in paths
    )
    assert callable(app.state.unified_audit_enabled_probe)
    assert callable(app.state.unified_audit_projector_factory)
    assert getattr(app.state, "unified_audit_source_readers_factory", None) is None
    assert getattr(app.state, "unified_audit_source_verifiers_factory", None) is None
