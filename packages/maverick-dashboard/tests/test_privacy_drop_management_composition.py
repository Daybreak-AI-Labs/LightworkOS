from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick.privacy_drop_management import DROPDSARReceipt, DROPRecordAuthority
from maverick_dashboard import privacy_drop_management_api as drop_api
from maverick_dashboard import privacy_drop_management_composition as composition

TENANT = "tenant-drop-composition"
NOW = 2_100_000_000.0
TEMPLATE = "550e8400-e29b-41d4-a716-446655440000"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(*, enabled: bool = True) -> dict[str, object]:
    return {
        "privacy_automation": {
            "enable": enabled,
            "rights_orchestration": {"enable": enabled},
            "drop_management": {
                "enable": enabled,
                "retention_seconds": 86_400,
            },
        }
    }


def _request(app: FastAPI) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": "/api/v1/privacy/drop/41001/request",
            "raw_path": b"/api/v1/privacy/drop/41001/request",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1),
            "server": ("127.0.0.1", 443),
            "app": app,
        }
    )


class _RightsStore:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def open_case(self, tenant_id: str, case_id: str, **kwargs):
        self.calls.append({"tenant_id": tenant_id, "case_id": case_id, **kwargs})
        return SimpleNamespace(
            tenant_id=tenant_id,
            case_id=case_id,
            rights=tuple(kwargs["rights"]),
            identity_status="unverified",
            created_at=NOW,
        )


def _environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    enabled: bool = True,
) -> tuple[FastAPI, _RightsStore, Path, Path]:
    registry_path = tmp_path / "drop-authority.sqlite3"
    management_path = tmp_path / "drop-management.sqlite3"
    rights = _RightsStore()
    monkeypatch.setenv("MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY", "r" * 48)
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config(enabled=enabled))
    app = FastAPI()
    app.state.privacy_drop_management_clock = lambda: NOW
    app.state.privacy_drop_authority_registry_path_factory = lambda **_kwargs: registry_path
    app.state.privacy_drop_management_path_factory = lambda **_kwargs: management_path
    app.state.privacy_drop_principal_key_authority_path_factory = (
        lambda **_kwargs: tmp_path / "drop-keys.sqlite3"
    )
    app.state.privacy_drop_authority_proposal_path_factory = (
        lambda **_kwargs: tmp_path / "drop-proposals.sqlite3"
    )
    app.state.privacy_rights_orchestration_store_factory = lambda **_kwargs: rights
    composition.attach_privacy_drop_management_composition(app)
    return app, rights, registry_path, management_path


def _enroll_and_import(app: FastAPI, request: Request) -> DROPRecordAuthority:
    registry = app.state.privacy_drop_authority_registry_factory(
        tenant_id=TENANT,
        request=request,
    )
    registry.enroll_broker(
        broker_ref="broker-ca-001",
        registration_sha256=_digest("broker-registration"),
        evidence_sha256=_digest("broker-evidence"),
        valid_until=NOW + 3_600,
        expected_version=0,
        actor_ref="broker-enroller",
        reviewer_ref="broker-reviewer",
        idempotency_key="enroll-broker",
    )
    authority = DROPRecordAuthority(
        tenant_id=TENANT,
        drop_id=41_001,
        broker_registration_sha256=_digest("broker-registration"),
        subject_binding_sha256=_digest("subject-binding"),
        request_type="DataDeletion",
        template_id=TEMPLATE,
        language="en-us",
        record_revision=1,
        valid_until=NOW + 1_800,
    ).normalized()
    return registry.import_record(
        authority,
        broker_ref="broker-ca-001",
        import_evidence_sha256=_digest("record-import-evidence"),
        expected_version=0,
        actor_ref="record-importer",
        reviewer_ref="record-reviewer",
        idempotency_key="import-record",
    )


def test_attach_is_lazy_and_operational_probe_opens_and_verifies_stores(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _rights, registry_path, management_path = _environment(tmp_path, monkeypatch)

    assert not registry_path.exists()
    assert not management_path.exists()
    assert app.state.privacy_drop_management_enabled_probe(TENANT) is True
    assert app.state.privacy_drop_management_readiness_probe(TENANT) is True
    assert callable(app.state.privacy_drop_authority_registry_factory)
    assert callable(app.state.privacy_drop_record_authority_resolver)
    assert callable(app.state.privacy_drop_management_store_factory)
    assert callable(app.state.privacy_drop_management_reconciliation_runner)
    assert callable(app.state.privacy_drop_management_maintenance_runner)
    assert callable(app.state.privacy_drop_management_maintenance_cycle_runner)
    assert registry_path.exists()
    assert management_path.exists()


def test_stock_composition_creates_unverified_rights_case_and_terminal_update(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, rights, _registry_path, _management_path = _environment(tmp_path, monkeypatch)
    request = _request(app)
    authority = _enroll_and_import(app, request)
    resolved = app.state.privacy_drop_record_authority_resolver(
        tenant_id=TENANT,
        drop_id=authority.drop_id,
        request_type="DataDeletion",
        template_id=TEMPLATE,
        language="en-US",
        request=request,
    )
    store = app.state.privacy_drop_management_store_factory(
        tenant_id=TENANT,
        actor_ref="drop-principal-operator",
        request=request,
    )

    pending = store.create_request(
        resolved,
        expected_revision=0,
        idempotency_key="create-drop-41001",
    )

    assert pending.status == "PENDING"
    assert len(rights.calls) == 1
    assert rights.calls[0]["rights"] == ("erasure",)
    assert rights.calls[0]["subject_reference"] == authority.subject_binding_sha256
    case_id = str(rights.calls[0]["case_id"])
    assert case_id == pending.internal_case_id
    assert rights.calls[0]["idempotency_key"].startswith("drop-rights-drop-dsar-")
    assert "identity" not in rights.calls[0]

    receipt = DROPDSARReceipt(
        tenant_id=TENANT,
        drop_id=authority.drop_id,
        authority_sha256=authority.authority_sha256,
        subject_binding_sha256=authority.subject_binding_sha256,
        request_type=authority.request_type,
        request_queue_id=pending.request_queue_id,
        request_queue_ref_id=pending.request_queue_ref_id,
        internal_case_id=pending.internal_case_id,
        created_at=pending.created_at,
    ).normalized()
    registry = app.state.privacy_drop_authority_registry_factory(
        tenant_id=TENANT,
        request=request,
    )
    registry.approve_outcome(
        authority,
        receipt,
        status="DELETED",
        reviewer_ref="outcome-reviewer",
        evidence_sha256=_digest("terminal-deletion-evidence"),
        evidence_revision=1,
        observed_at=NOW,
        valid_until=NOW + 600,
        deletion_verified=True,
        search_complete=True,
        provider_operations_complete=True,
        expected_version=0,
        actor_ref="outcome-proposer",
        idempotency_key="approve-terminal-outcome",
    )
    terminal = store.update_status(
        authority,
        status="DELETED",
        expected_revision=1,
        idempotency_key="finish-drop-41001",
        actor_ref="drop-principal-operator",
    )

    assert terminal.status == "DELETED"
    assert terminal.revision == 2
    assert store.verify_integrity() is True
    reconciliation = app.state.privacy_drop_management_reconciliation_runner(TENANT)
    assert reconciliation["registry_integrity_valid"] is True
    assert reconciliation["active_records"] == 1
    assert reconciliation["approved_outcomes"] == 1
    assert reconciliation["management_store_opened"] is False
    assert reconciliation["external_completeness_claimed"] is False
    assert reconciliation["live_interoperability_verified"] is False
    assert reconciliation["legal_acceptance_verified"] is False


def test_composition_is_default_off_and_key_failure_is_not_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled, _rights, _registry, _management = _environment(
        tmp_path / "disabled",
        monkeypatch,
        enabled=False,
    )
    assert disabled.state.privacy_drop_management_enabled_probe(TENANT) is False
    assert disabled.state.privacy_drop_management_readiness_probe(TENANT) is False

    enabled, _rights, registry_path, management_path = _environment(
        tmp_path / "missing-key",
        monkeypatch,
    )
    monkeypatch.delenv("MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY")
    assert enabled.state.privacy_drop_management_readiness_probe(TENANT) is False
    assert not registry_path.exists()
    assert not management_path.exists()


def test_stock_maintenance_runner_has_narrow_internal_purge_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _rights, registry_path, management_path = _environment(tmp_path, monkeypatch)

    result = app.state.privacy_drop_management_maintenance_runner(
        TENANT,
        before=NOW,
        limit=10,
    )

    assert result == {
        "schema": "lightwork.privacy-drop-maintenance.v1",
        "tenant_id": TENANT,
        "requests_purged": 0,
        "registry_objects_purged": 0,
        "authority_proposals_purged": 0,
        "external_side_effects": False,
    }
    assert registry_path.exists()
    assert management_path.exists()


def test_explicit_rights_intake_submitter_is_supported_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, rights, _registry_path, _management_path = _environment(tmp_path, monkeypatch)
    request = _request(app)
    authority = _enroll_and_import(app, request)
    calls: list[dict[str, object]] = []

    def submitter(**kwargs):
        calls.append(kwargs)
        return DROPDSARReceipt(
            tenant_id=TENANT,
            drop_id=authority.drop_id,
            authority_sha256=authority.authority_sha256,
            subject_binding_sha256=authority.subject_binding_sha256,
            request_type=authority.request_type,
            request_queue_id="8af319f0-38a5-4ddd-bc0b-bb2d00c9a011",
            request_queue_ref_id="deployment-rights-intake",
            internal_case_id="DROP-41001-deployment",
            created_at=NOW,
        ).normalized()

    app.state.privacy_drop_rights_intake_submitter = submitter
    store = app.state.privacy_drop_management_store_factory(
        tenant_id=TENANT,
        actor_ref="drop-principal-operator",
        request=request,
    )
    pending = store.create_request(
        authority,
        expected_revision=0,
        idempotency_key="create-with-explicit-intake",
    )

    assert pending.request_queue_ref_id == "deployment-rights-intake"
    assert len(calls) == 1
    assert calls[0]["authority"] == authority
    assert isinstance(calls[0]["request"], Request)
    assert rights.calls == []


def test_strict_api_uses_attached_stock_seams_without_test_dependency_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, rights, registry_path, management_path = _environment(tmp_path, monkeypatch)
    monkeypatch.setattr(drop_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(drop_api, "require_permission", lambda *_args: None)

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(sub="verified-operator-subject")
        return await call_next(request)

    app.include_router(drop_api.create_privacy_drop_management_router(), prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    status = client.get("/api/v1/privacy/drop/status")
    assert status.status_code == 200
    assert status.json()["enabled"] is True
    assert status.json()["configured"] is True
    assert status.json()["ready"] is True
    assert status.json()["configured_for_attempt"] is True
    assert status.json()["locally_operational"] is True
    assert status.json()["request_executable"] is False
    assert status.json()["request_execution_blocker"] == "no_active_drop_record_authority"
    assert status.json()["configuration"]["store_opened_for_status"] is True
    assert registry_path.exists()
    assert management_path.exists()

    registry = app.state.privacy_drop_authority_registry_factory(
        tenant_id=TENANT,
        request=None,
    )
    registry.enroll_broker(
        broker_ref="broker-ca-001",
        registration_sha256=_digest("broker-registration"),
        evidence_sha256=_digest("broker-evidence"),
        valid_until=NOW + 3_600,
        expected_version=0,
        actor_ref="broker-enroller",
        reviewer_ref="broker-reviewer",
        idempotency_key="api-enroll-broker",
    )
    authority = DROPRecordAuthority(
        tenant_id=TENANT,
        drop_id=41_001,
        broker_registration_sha256=_digest("broker-registration"),
        subject_binding_sha256=_digest("subject-binding"),
        request_type="DataDeletion",
        template_id=TEMPLATE,
        language="en-us",
        record_revision=1,
        valid_until=NOW + 1_800,
    ).normalized()
    registry.import_record(
        authority,
        broker_ref="broker-ca-001",
        import_evidence_sha256=_digest("record-import-evidence"),
        expected_version=0,
        actor_ref="record-importer",
        reviewer_ref="record-reviewer",
        idempotency_key="api-import-record",
    )

    created = client.post(
        "/api/v1/privacy/drop/41001/request",
        json={
            "request_type": "DataDeletion",
            "template_id": TEMPLATE,
            "language": "en-US",
            "expected_revision": 0,
            "idempotency_key": "api-create-drop-41001",
        },
    )

    assert created.status_code == 201, created.text
    assert created.json()["status"] == "PENDING"
    assert len(rights.calls) == 1
    assert management_path.exists()
