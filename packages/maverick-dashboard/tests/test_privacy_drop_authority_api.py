from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick_dashboard import privacy_drop_authority_api as authority_api
from maverick_dashboard import privacy_drop_management_api as management_api
from maverick_dashboard import privacy_drop_management_composition as composition

TENANT = "tenant-drop-api"
NOW = 2_100_000_000.0
TEMPLATE = "550e8400-e29b-41d4-a716-446655440000"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _RightsStore:
    def open_case(self, tenant_id: str, case_id: str, **kwargs):
        return SimpleNamespace(
            tenant_id=tenant_id,
            case_id=case_id,
            rights=tuple(kwargs["rights"]),
            identity_status="unverified",
            created_at=NOW,
        )


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    config = {
        "privacy_automation": {
            "enable": True,
            "rights_orchestration": {"enable": True},
            "drop_management": {
                "enable": True,
                "retention_seconds": 86_400,
                "principal_binding_key_ref": "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY",
                "scheduler_interval_seconds": 3_600,
                "scheduler_jitter_seconds": 60,
                "scheduler_retry_max_seconds": 900,
            },
        }
    }
    monkeypatch.setenv("MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY", "k" * 48)
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: config)
    monkeypatch.setattr(authority_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(management_api, "_tenant_id", lambda: TENANT)
    monkeypatch.setattr(authority_api, "require_global_permission", lambda *_args: None)
    monkeypatch.setattr(management_api, "require_global_permission", lambda *_args: None)
    monkeypatch.setattr(management_api, "require_permission", lambda *_args: None)
    app = FastAPI()
    app.state.privacy_drop_management_clock = lambda: NOW
    secrets = {
        "env:MAVERICK_PRIVACY_RIGHTS_DIGEST_KEY": b"k" * 48,
        "kms://drop/key-two": b"2" * 48,
    }
    app.state.privacy_drop_secret_resolver = (
        lambda *, tenant_id, key_ref, request: secrets[key_ref]
    )
    app.state.privacy_drop_authority_registry_path_factory = (
        lambda **_kwargs: tmp_path / "registry.sqlite3"
    )
    app.state.privacy_drop_management_path_factory = (
        lambda **_kwargs: tmp_path / "management.sqlite3"
    )
    app.state.privacy_drop_principal_key_authority_path_factory = (
        lambda **_kwargs: tmp_path / "keys.sqlite3"
    )
    app.state.privacy_drop_authority_proposal_path_factory = (
        lambda **_kwargs: tmp_path / "proposals.sqlite3"
    )
    app.state.privacy_rights_orchestration_store_factory = lambda **_kwargs: _RightsStore()
    composition.attach_privacy_drop_management_composition(app)

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            sub=request.headers.get("X-Test-Principal", "operator-a")
        )
        return await call_next(request)

    app.include_router(authority_api.create_privacy_drop_authority_router(), prefix="/api/v1")
    app.include_router(management_api.create_privacy_drop_management_router(), prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _approve(client: TestClient, proposal: dict[str, object], *, reviewer: str = "reviewer-b"):
    return client.post(
        f"/api/v1/privacy/drop/authority/proposals/{proposal['proposal_id']}/approve",
        headers={"X-Test-Principal": reviewer},
        json={"expected_revision": 1, "idempotency_key": f"approve-{proposal['proposal_id']}"},
    )


def test_fresh_tenant_full_lifecycle_uses_only_mounted_apis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(tmp_path, monkeypatch)
    broker = client.post(
        "/api/v1/privacy/drop/authority/brokers/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "action": "enroll_broker",
            "broker_ref": "broker-ca-001",
            "registration_sha256": _digest("registration"),
            "evidence_sha256": _digest("broker-evidence"),
            "valid_until": NOW + 3_600,
            "expected_version": 0,
            "idempotency_key": "propose-broker",
        },
    )
    assert broker.status_code == 201, broker.text
    assert _approve(client, broker.json()).status_code == 200

    record = client.post(
        "/api/v1/privacy/drop/authority/records/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "action": "import_record",
            "drop_id": 41_001,
            "broker_ref": "broker-ca-001",
            "broker_registration_sha256": _digest("registration"),
            "subject_binding_sha256": _digest("subject-binding"),
            "request_type": "DataDeletion",
            "template_id": TEMPLATE,
            "language": "en-US",
            "record_revision": 1,
            "valid_until": NOW + 1_800,
            "evidence_sha256": _digest("record-evidence"),
            "expected_version": 0,
            "idempotency_key": "propose-record",
        },
    )
    assert record.status_code == 201, record.text
    assert _approve(client, record.json()).status_code == 200

    created = client.post(
        "/api/v1/privacy/drop/41001/request",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "request_type": "DataDeletion",
            "template_id": TEMPLATE,
            "language": "en-US",
            "expected_revision": 0,
            "idempotency_key": "create-request",
        },
    )
    assert created.status_code == 201, created.text

    outcome = client.post(
        "/api/v1/privacy/drop/authority/outcomes/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "drop_id": 41_001,
            "status": "DELETED",
            "evidence_sha256": _digest("outcome-evidence"),
            "evidence_revision": 1,
            "observed_at": NOW,
            "valid_until": NOW + 600,
            "deletion_verified": True,
            "search_complete": True,
            "provider_operations_complete": True,
            "expected_version": 0,
            "idempotency_key": "propose-outcome",
        },
    )
    assert outcome.status_code == 201, outcome.text
    assert _approve(client, outcome.json()).status_code == 200

    completed = client.put(
        "/api/v1/privacy/drop/41001",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "status": "DELETED",
            "expected_revision": 1,
            "idempotency_key": "complete-request",
        },
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "DELETED"
    listed = client.get(
        "/api/v1/privacy/drop/authority/authorities",
        headers={"X-Test-Principal": "auditor"},
    )
    assert listed.status_code == 200
    assert len(listed.json()["authorities"]) == 3
    assert "subject_binding_sha256" not in listed.text

    rotation = client.post(
        "/api/v1/privacy/drop/authority/keys/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "action": "rotate_key",
            "new_key_ref": "kms://drop/key-two",
            "expected_current_revision": 1,
            "idempotency_key": "propose-key-two",
        },
    )
    assert rotation.status_code == 201, rotation.text
    assert _approve(client, rotation.json()).status_code == 200
    after_rotation = client.get(
        "/api/v1/privacy/drop/41001",
        headers={"X-Test-Principal": "auditor"},
    )
    assert after_rotation.status_code == 200
    assert after_rotation.json()["status"] == "DELETED"

    retirement = client.post(
        "/api/v1/privacy/drop/authority/keys/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json={
            "action": "retire_key",
            "key_revision": 1,
            "idempotency_key": "propose-retire-one",
        },
    )
    assert retirement.status_code == 201
    blocked = _approve(client, retirement.json())
    assert blocked.status_code == 409


def test_same_person_approval_fails_closed_and_replay_is_stable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(tmp_path, monkeypatch)
    body = {
        "action": "enroll_broker",
        "broker_ref": "broker-ca-001",
        "registration_sha256": _digest("registration"),
        "evidence_sha256": _digest("broker-evidence"),
        "valid_until": NOW + 3_600,
        "expected_version": 0,
        "idempotency_key": "propose-broker",
    }
    first = client.post(
        "/api/v1/privacy/drop/authority/brokers/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json=body,
    )
    replay = client.post(
        "/api/v1/privacy/drop/authority/brokers/proposals",
        headers={"X-Test-Principal": "operator-a"},
        json=body,
    )
    assert replay.json() == first.json()
    denied = _approve(client, first.json(), reviewer="operator-a")
    assert denied.status_code == 409


def test_overview_lists_requests_brokers_and_waiting_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(authority_api, "has_global_permission", lambda *_args: True)
    monkeypatch.setattr(authority_api, "has_permission", lambda *_args: True)
    broker = client.post(
        "/api/v1/privacy/drop/authority/brokers/proposals",
        json={
            "action": "enroll_broker",
            "broker_ref": "broker-ca-001",
            "registration_sha256": _digest("registration"),
            "evidence_sha256": _digest("broker-evidence"),
            "valid_until": NOW + 3_600,
            "expected_version": 0,
            "idempotency_key": "propose-broker",
        },
    )
    waiting = client.get("/api/v1/privacy/drop/authority/overview").json()["waiting"]
    assert waiting[0]["kind"] == "enroll_broker"
    assert waiting[0]["proposed_by_you"] is True
    assert waiting[0]["summary"] == {"broker_ref": "broker-ca-001", "valid_until": NOW + 3_600}
    other = client.get(
        "/api/v1/privacy/drop/authority/overview", headers={"X-Test-Principal": "reviewer-b"}
    ).json()["waiting"]
    assert other[0]["proposed_by_you"] is False
    assert _approve(client, broker.json()).status_code == 200
    record = client.post(
        "/api/v1/privacy/drop/authority/records/proposals",
        json={
            "action": "import_record",
            "drop_id": 41_002,
            "broker_ref": "broker-ca-001",
            "broker_registration_sha256": _digest("registration"),
            "subject_binding_sha256": _digest("subject-binding"),
            "request_type": "OptOut",
            "template_id": TEMPLATE,
            "language": "es",
            "record_revision": 1,
            "valid_until": NOW + 1_800,
            "evidence_sha256": _digest("record-evidence"),
            "expected_version": 0,
            "idempotency_key": "propose-record",
        },
    )
    assert _approve(client, record.json()).status_code == 200

    listed = client.get("/api/v1/privacy/drop/authority/overview")
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["waiting"] == []
    assert body["brokers"][0]["broker_ref"] == "broker-ca-001"
    assert body["brokers"][0]["registration_sha256"] == _digest("registration")
    row = body["requests"][0]
    assert row["drop_id"] == 41_002
    assert row["request_type"] == "OptOut"
    assert row["template_id"] == TEMPLATE
    assert row["language"] == "es"
    assert row["usable"] is True
    assert row["request"] is None
    assert row["outcomes"] == []
    assert _digest("subject-binding") not in listed.text

    created = client.post(
        "/api/v1/privacy/drop/41002/request",
        json={
            "request_type": "OptOut",
            "template_id": TEMPLATE,
            "language": "es",
            "expected_revision": 0,
            "idempotency_key": "create-request",
        },
    )
    assert created.status_code == 201, created.text
    row = client.get("/api/v1/privacy/drop/authority/overview").json()["requests"][0]
    assert row["request"]["status"] == "PENDING"
    assert row["request"]["revision"] == 1


def test_overview_hides_setup_from_operators_and_refuses_viewers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setattr(authority_api, "has_global_permission", lambda *_args: False)
    monkeypatch.setattr(authority_api, "has_permission", lambda *_args: True)
    body = client.get("/api/v1/privacy/drop/authority/overview").json()
    assert body["brokers"] == [] and body["waiting"] == []
    monkeypatch.setattr(authority_api, "has_permission", lambda *_args: False)
    assert client.get("/api/v1/privacy/drop/authority/overview").status_code == 403
