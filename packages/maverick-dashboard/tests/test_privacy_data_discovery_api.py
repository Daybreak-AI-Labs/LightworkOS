from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import privacy_data_discovery as discovery
from maverick_dashboard import privacy_data_discovery_api

NOW = 1_800_000_000.0
API = "/api/v1/privacy/data-discovery"


class Clock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class Rows:
    def __init__(self) -> None:
        self.rows: list[discovery.StructuredRecord] = []
        self.calls: list[tuple[str, str, float]] = []

    def iter_rows(self, *, source, credential_env, limits, deadline):
        del limits
        self.calls.append((source.origin, credential_env, deadline))
        yield from tuple(self.rows)


class Documents:
    def __init__(self) -> None:
        self.documents: list[discovery.UnstructuredDocument] = []

    def iter_documents(self, *, source, credential_env, limits, deadline):
        del source, credential_env, limits, deadline
        yield from tuple(self.documents)


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[privacy_automation]\n"
        "enable = true\n"
        "[privacy_automation.data_discovery]\n"
        "enable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()

    clock = Clock()
    rows = Rows()
    documents = Documents()
    callbacks: list[discovery.ReviewedClassification] = []
    database = tmp_path / "privacy-discovery.sqlite3"

    def store_factory(_ops, tenant_id: str, request: Request):
        return discovery.PrivacyDataDiscoveryStore(
            database,
            config_gate=lambda: None,
            clock=clock,
            evidence_key_resolver=lambda _name: b"test-evidence-key-material-32-bytes",
            review_callback=privacy_data_discovery_api._callback_authority(
                request,
                tenant_id,
            ),
        )

    monkeypatch.setattr(privacy_data_discovery_api, "_store", store_factory)
    monkeypatch.setattr(
        privacy_data_discovery_api,
        "require_global_permission",
        lambda _request, _permission: None,
    )
    monkeypatch.setattr(
        privacy_data_discovery_api,
        "require_permission",
        lambda _request, _permission: None,
    )

    app = FastAPI()

    @app.middleware("http")
    async def test_principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            sub=request.headers.get("X-Test-Subject", "operator-a"),
            principal="user:" + request.headers.get("X-Test-Subject", "operator-a"),
        )
        return await call_next(request)

    app.state.privacy_data_discovery_structured_sources = {"fixture": rows}
    app.state.privacy_data_discovery_unstructured_sources = {"fixture": documents}
    app.state.privacy_data_discovery_credential_ref_present = lambda _name: True
    app.state.privacy_data_discovery_review_callback = callbacks.append
    app.include_router(privacy_data_discovery_api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "operator-a"},
    )
    yield client, database, rows, documents, callbacks, clock, config_path, app
    config.reset_config_cache()


def _ok(response, expected: int = 200):
    assert response.status_code == expected, response.text
    return response.json()


def _saved_setup(environment, monkeypatch):
    from maverick import config, connections
    from maverick.paths import tenant_scope
    from maverick.tenant import kms

    client, database, rows, _, _, clock, config_path, app = environment
    with config_path.open("a", encoding="utf-8") as stream:
        stream.write('[privacy_automation.data_discovery.adapters]\nenable=true\nenabled_providers=["servicenow_cmdb"]\n[connections]\nenable=true\n')
    monkeypatch.setenv("MAVERICK_CONNECTIONS", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ac" * 32)
    config.reset_config_cache()
    kms._clear_cache()
    monkeypatch.setattr(privacy_data_discovery_api, "_store", lambda ops, tenant, request:
        discovery.PrivacyDataDiscoveryStore(database, config_gate=lambda: None, clock=clock))
    with tenant_scope(tenant="tenant-a"):
        saved = connections.set_connection("discovery", connector="servicenow_cmdb", base_url="https://data.example.com",
                                           token="synthetic-private-token", owner="user:operator-a")
    app.state.privacy_data_discovery_structured_sources["servicenow_cmdb"] = rows
    created = _ok(client.put(f"{API}/evidence-keys/inventory", json={"expected_revision":0,"idempotency_key":"create-key"}))
    payload = dict(_source_payload(), provider="servicenow_cmdb", credential_env="connection:discovery:" + saved["revision"], evidence_key_env=created["reference"])
    return payload, created


def test_saved_setup_seals_keys_filters_connection_choices_and_rejects_forged_origin(environment, monkeypatch):
    client, *_ = environment
    payload, created = _saved_setup(environment, monkeypatch)
    assert created["secret_returned"] is False and created["sources_updated"] is False
    assert "key_hex" not in json.dumps(created)
    setup = _ok(client.get(f"{API}/setup"))
    assert setup["connections"][0]["reference"] == payload["credential_env"]
    assert [provider["provider"] for provider in setup["providers"]] == ["servicenow_cmdb"]
    assert "synthetic-private-token" not in json.dumps(setup)
    _ok(client.put(f"{API}/sources/customers", json=payload))
    forged = dict(payload, origin="https://attacker.example", idempotency_key="forged-source")
    assert client.put(f"{API}/sources/forged", json=forged).status_code == 403
    other = client.get(f"{API}/setup", headers={"X-Test-Subject":"operator-b"})
    assert _ok(other)["connections"] == []
    assert _ok(other)["evidence_keys"] == []


def test_key_rotation_requires_explicit_source_update_and_binds_execution_principal(environment, monkeypatch):
    from maverick import connections
    from maverick.paths import current_tenant_id_strict

    client, _, rows, _, _, _, _, _ = environment
    payload, created = _saved_setup(environment, monkeypatch)
    _ok(client.put(f"{API}/sources/customers", json=payload))
    calls = []

    def scoped_rows(**kwargs):
        calls.append((connections.current_principal(), current_tenant_id_strict()))
        yield discovery.StructuredRecord("row", {"email":"one@example.com"})

    rows.iter_rows = scoped_rows
    first = _run_manual(client, rows, values=[], operation="saved-key-first")
    assert calls == [("user:operator-a", "tenant-a")]
    rotated = _ok(client.put(f"{API}/evidence-keys/inventory", json={"expected_revision":1,"idempotency_key":"rotate-key"}))
    assert _ok(client.put(f"{API}/evidence-keys/inventory", json={"expected_revision":1,"idempotency_key":"rotate-key"})) == rotated
    unchanged = _ok(client.get(f"{API}/sources/customers"))
    assert unchanged["revision"] == 1 and unchanged["evidence_key_env"] == created["reference"]
    _ok(client.post(f"{API}/sources/customers/jobs", json=_manual_payload("old-key-scan")))
    job = _ok(client.post(f"{API}/jobs/claim", json={"limit":1,"lease_seconds":60.0}))["items"][0]
    blocked = client.post(f"{API}/jobs/{job['job_id']}/execute")
    assert blocked.status_code == 403 and "rotated" in blocked.text
    assert len(calls) == 1
    updated = dict(payload, expected_revision=1, evidence_key_env=rotated["reference"], idempotency_key="rebind-source-key")
    _ok(client.put(f"{API}/sources/customers", json=updated))
    second = _ok(client.post(f"{API}/jobs/{job['job_id']}/execute"))
    assert first["report"]["evidence_key_fingerprint"] != second["report"]["evidence_key_fingerprint"]


def test_source_access_test_uses_saved_scope_and_returns_no_sample_or_report(environment, monkeypatch):
    from maverick_dashboard import privacy_data_discovery_adapters_composition as composition

    client, database, rows, _, _, clock, _, _ = environment
    payload, _ = _saved_setup(environment, monkeypatch)
    _ok(client.put(f"{API}/sources/customers", json=payload))
    monkeypatch.setattr(composition, "snapshot_for_tenant", lambda *args, **kwargs: SimpleNamespace(
        registry=SimpleNamespace(structured={"servicenow_cmdb":rows}, unstructured={})))
    rows.rows = [discovery.StructuredRecord("row", {"email":"never-return@example.com"})]
    assert client.post(f"{API}/sources/customers/test-access", json={"expected_revision":1,"confirm":False}).status_code == 422
    result = _ok(client.post(f"{API}/sources/customers/test-access", json={"expected_revision":1,"confirm":True}))
    assert result["access"] == "readable" and result["report_created"] is False
    assert result["raw_data_returned"] is False
    assert "never-return" not in json.dumps(result)
    assert rows.calls[0][0] == payload["origin"]
    assert discovery.PrivacyDataDiscoveryStore(database, config_gate=lambda: None, clock=clock).list_reports("tenant-a") == ()


def _source_payload(*, kind: str = "structured") -> dict[str, object]:
    return {
        "kind": kind,
        "provider": "fixture",
        "origin": "https://data.example.com",
        "resource_ref": "customer-records",
        "credential_env": "PRIVACY_SOURCE_TOKEN",
        "evidence_key_env": "PRIVACY_EVIDENCE_HMAC_KEY",
        "expected_revision": 0,
        "idempotency_key": f"enroll-{kind}-v1",
    }


def _stock_readiness(_tenant_id: str) -> dict[str, object]:
    return {
        "configured": True,
        "ready": True,
        "structured_providers": ["servicenow_cmdb"],
        "unstructured_providers": ["aws_s3"],
        "remediation_outbox_enabled": True,
        "data_map_target_enabled": True,
        "approved_review_callback_durable_outbox": True,
        "retry_worker_factory_installed": True,
        "remediation_scheduler_enabled": True,
        "status_probe_opened_store": False,
        "status_probe_invoked_provider": False,
    }


def _enroll(client: TestClient, source_id: str = "customers") -> dict[str, object]:
    return _ok(client.put(f"{API}/sources/{source_id}", json=_source_payload()))


def _manual_payload(
    operation: str,
    *,
    max_attempts: int = 3,
    retention_seconds: int = 3_600,
) -> dict[str, object]:
    return {
        "limits": {
            "max_records": 100,
            "max_files": 10,
            "max_bytes": 1_000_000,
            "max_seconds": 30.0,
            "max_findings": 100,
            "max_fields_per_record": 20,
            "max_record_bytes": 100_000,
            "max_document_bytes": 100_000,
        },
        "max_attempts": max_attempts,
        "retention_seconds": retention_seconds,
        "idempotency_key": operation,
    }


def _run_manual(
    client: TestClient,
    rows: Rows,
    *,
    operation: str,
    values: list[discovery.StructuredRecord],
    retention_seconds: int = 3_600,
) -> dict[str, object]:
    rows.rows = values
    _ok(
        client.post(
            f"{API}/sources/customers/jobs",
            json=_manual_payload(operation, retention_seconds=retention_seconds),
        )
    )
    claim = _ok(
        client.post(
            f"{API}/jobs/claim",
            json={"limit": 1, "lease_seconds": 60.0},
        )
    )["items"][0]
    return _ok(client.post(f"{API}/jobs/{claim['job_id']}/execute"))


def test_source_contract_is_strict_tenant_bound_and_default_closed(environment) -> None:
    client, _database, _rows, _documents, _callbacks, _clock, config_path, _app = (
        environment
    )
    enrolled = _enroll(client)
    assert enrolled["tenant_id"] == "tenant-a"
    assert enrolled["credential_value_persisted"] is False
    assert enrolled["external_side_effect"] is False
    assert _ok(client.get(f"{API}/sources"))["items"][0]["source_id"] == "customers"

    forged = _source_payload()
    forged["tenant_id"] = "tenant-b"
    response = client.put(f"{API}/sources/forged", json=forged)
    assert response.status_code == 422

    raw_secret = _source_payload()
    raw_secret["credential_env"] = "sk-live-secret-value"
    response = client.put(f"{API}/sources/raw-secret", json=raw_secret)
    assert response.status_code == 422

    config_path.write_text(
        "[privacy_automation]\n"
        "enable = true\n"
        "[privacy_automation.data_discovery]\n"
        "enable = false\n",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    assert client.get(f"{API}/status").status_code == 403


def test_schedule_claim_execute_reports_inventory_and_digest_only_diff(environment) -> None:
    client, database, rows, _documents, _callbacks, _clock, _config, _app = environment
    _enroll(client)
    schedule = _ok(
        client.put(
            f"{API}/schedules/hourly",
            json={
                "source_id": "customers",
                "interval_seconds": 3_600,
                "limits": _manual_payload("unused")["limits"],
                "max_attempts": 3,
                "retention_seconds": 3_600,
                "active": True,
                "expected_revision": 0,
                "idempotency_key": "schedule-hourly-v1",
                "next_run_at": NOW,
            },
        )
    )
    assert schedule["schedule_id"] == "hourly"
    assert _ok(client.get(f"{API}/schedules"))["items"][0]["active"] is True
    assert _ok(
        client.post(f"{API}/schedules/enqueue-due", json={"limit": 10})
    )["enqueued"] == 1

    secret = "alice.private@example.com"
    rows.rows = [
        discovery.StructuredRecord(
            "row-1",
            {"email": secret, "phone": "+1 212-555-0199"},
        )
    ]
    claim = _ok(
        client.post(
            f"{API}/jobs/claim",
            json={"limit": 1, "lease_seconds": 60.0},
        )
    )
    assert claim["lease_owner_bound_to_request_principal"] is True
    job = claim["items"][0]
    completed = _ok(client.post(f"{API}/jobs/{job['job_id']}/execute"))
    assert completed["external_side_effect"] is True
    assert completed["provider_network_io_possible"] is True
    assert completed["raw_data_returned"] is False
    assert completed["live_provider_acceptance_verified"] is False
    assert completed["report"]["absence_is_proven"] is False
    assert completed["report"]["completeness"] == "complete_within_declared_bounds"
    report_a = completed["report"]
    assert rows.calls[0][0:2] == (
        "https://data.example.com",
        "PRIVACY_SOURCE_TOKEN",
    )
    assert secret not in json.dumps(completed)
    assert secret.encode() not in database.read_bytes()

    findings = _ok(
        client.get(f"{API}/reports/{report_a['report_id']}/findings")
    )
    assert findings["digest_only_evidence"] is True
    assert findings["raw_values_returned"] is False
    assert all(len(item["evidence_sha256"]) == 64 for item in findings["items"])
    inventory = _ok(client.get(f"{API}/inventory"))
    assert inventory["absence_is_proven"] is False
    assert inventory["approved_findings_only_are_authoritative_updates"] is True

    report_b = _run_manual(
        client,
        rows,
        operation="manual-second",
        values=[
            discovery.StructuredRecord(
                "row-1",
                {"email": secret, "phone": "+1 212-555-0199", "dob": "1990-01-01"},
            )
        ],
    )["report"]
    diff = _ok(
        client.get(
            f"{API}/reports/diff",
            params={
                "base_report_id": report_a["report_id"],
                "target_report_id": report_b["report_id"],
            },
        )
    )
    assert diff["digest_only"] is True
    assert diff["absence_is_proven"] is False
    assert diff["added_finding_sha256"]
    assert _ok(client.get(f"{API}/reports"))["items"]


def test_fail_dead_letter_replay_and_revoked_source_are_controlled(environment) -> None:
    client, _database, _rows, _documents, _callbacks, _clock, _config, _app = environment
    source = _enroll(client)
    job = _ok(
        client.post(
            f"{API}/sources/customers/jobs",
            json=_manual_payload("manual-dead-letter", max_attempts=1),
        )
    )
    claim = _ok(
        client.post(
            f"{API}/jobs/claim",
            json={"limit": 1, "lease_seconds": 60.0},
        )
    )["items"][0]
    assert claim["job_id"] == job["job_id"]
    failed = _ok(
        client.post(
            f"{API}/jobs/{job['job_id']}/fail",
            json={"error_code": "adapter_error", "base_backoff_seconds": 1.0},
        )
    )
    assert failed["state"] == "dead_letter"
    replayed = _ok(
        client.post(
            f"{API}/jobs/{job['job_id']}/replay",
            json={
                "expected_revision": failed["revision"],
                "idempotency_key": "replay-manual-v1",
            },
        )
    )
    assert replayed["state"] == "queued"

    unsafe_failure = client.post(
        f"{API}/jobs/{job['job_id']}/fail",
        json={
            "error_code": "alice_private_value",
            "base_backoff_seconds": 1.0,
        },
    )
    assert unsafe_failure.status_code == 422

    revoked = _ok(
        client.post(
            f"{API}/sources/customers/state",
            json={
                "state": "revoked",
                "expected_revision": source["revision"],
                "idempotency_key": "revoke-customers-v1",
            },
        )
    )
    assert revoked["state"] == "revoked"
    assert (
        client.post(
            f"{API}/sources/customers/jobs",
            json=_manual_payload("blocked-after-revocation"),
        ).status_code
        == 409
    )


def test_four_eyes_review_uses_server_evidence_and_approved_only_callback(
    environment,
) -> None:
    client, _database, rows, _documents, callbacks, _clock, _config, app = environment
    _enroll(client)
    report = _run_manual(
        client,
        rows,
        operation="review-scan",
        values=[
            discovery.StructuredRecord("row-1", {"email": "review@example.com"})
        ],
    )["report"]
    finding = _ok(
        client.get(f"{API}/reports/{report['report_id']}/findings")
    )["items"][0]

    forged = client.post(
        f"{API}/findings/{finding['finding_id']}/reviews",
        json={
            "decision": "confirmed",
            "effective_category": finding["category"],
            "freshness_seconds": 300,
            "expected_finding_revision": finding["revision"],
            "idempotency_key": "review-forged-evidence",
            "evidence_sha256": "0" * 64,
        },
    )
    assert forged.status_code == 422

    proposal = _ok(
        client.post(
            f"{API}/findings/{finding['finding_id']}/reviews",
            json={
                "decision": "confirmed",
                "effective_category": finding["category"],
                "freshness_seconds": 300,
                "expected_finding_revision": finding["revision"],
                "idempotency_key": "review-proposal-v1",
            },
        )
    )
    assert proposal["evidence_sha256"] == finding["evidence_sha256"]
    assert proposal["evidence_bound_from_authoritative_finding"] is True
    assert proposal["data_map_callback_invoked"] is False
    assert callbacks == []

    same_reviewer = client.post(
        f"{API}/reviews/{proposal['review_id']}/approve",
        json={
            "expected_version": proposal["version"],
            "expected_integrity_sha256": proposal["integrity_sha256"],
            "idempotency_key": "review-self-approval",
        },
    )
    assert same_reviewer.status_code == 409

    app.state.privacy_data_discovery_readiness_probe = _stock_readiness

    approved = _ok(
        client.post(
            f"{API}/reviews/{proposal['review_id']}/approve",
            headers={"X-Test-Subject": "operator-b"},
            json={
                "expected_version": proposal["version"],
                "expected_integrity_sha256": proposal["integrity_sha256"],
                "idempotency_key": "review-approval-v1",
            },
        )
    )
    assert approved["four_eyes_enforced"] is True
    assert approved["approved_only_callback"] is True
    assert approved["callback_attempted_this_request"] is True
    assert approved["callback_acknowledged"] is True
    assert approved["callback_durable_outbox"] is True
    assert approved["callback_enqueued_durably"] is True
    assert approved["data_map_target_configured"] is True
    assert approved["bounded_retry_worker_available"] is True
    assert approved["automatic_retry_available"] is False
    assert approved["target_applied_synchronously"] is False
    assert len(callbacks) == 1
    assert callbacks[0].finding_id == finding["finding_id"]
    assert not hasattr(callbacks[0], "raw_value")
    replayed = _ok(
        client.post(
            f"{API}/reviews/{proposal['review_id']}/approve",
            headers={"X-Test-Subject": "operator-b"},
            json={
                "expected_version": proposal["version"],
                "expected_integrity_sha256": proposal["integrity_sha256"],
                "idempotency_key": "review-approval-v1",
            },
        )
    )
    assert replayed["callback_attempted_this_request"] is False
    assert replayed["callback_acknowledged"] is None
    assert len(callbacks) == 1
    reviews = _ok(client.get(f"{API}/findings/{finding['finding_id']}/reviews"))
    assert reviews["items"][0]["status"] == "approved"


def test_callback_failure_is_generic_after_durable_approval(environment) -> None:
    client, database, rows, _documents, _callbacks, _clock, _config, app = environment
    _enroll(client)
    report = _run_manual(
        client,
        rows,
        operation="callback-failure-scan",
        values=[discovery.StructuredRecord("row", {"phone": "212-555-0199"})],
    )["report"]
    finding = _ok(
        client.get(f"{API}/reports/{report['report_id']}/findings")
    )["items"][0]
    proposal = _ok(
        client.post(
            f"{API}/findings/{finding['finding_id']}/reviews",
            json={
                "decision": "confirmed",
                "effective_category": finding["category"],
                "freshness_seconds": 300,
                "expected_finding_revision": finding["revision"],
                "idempotency_key": "callback-failure-proposal",
            },
        )
    )

    def broken_callback(_update):
        raise RuntimeError("private callback payload alice@example.com")

    app.state.privacy_data_discovery_review_callback = broken_callback
    response = client.post(
        f"{API}/reviews/{proposal['review_id']}/approve",
        headers={"X-Test-Subject": "operator-b"},
        json={
            "expected_version": proposal["version"],
            "expected_integrity_sha256": proposal["integrity_sha256"],
            "idempotency_key": "callback-failure-approval",
        },
    )
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "privacy data discovery external adapter or callback failed"
    )
    assert b"alice@example.com" not in database.read_bytes()
    reviews = _ok(client.get(f"{API}/findings/{finding['finding_id']}/reviews"))
    assert reviews["items"][0]["status"] == "approved"
    assert _ok(client.get(f"{API}/audit"))["items"][-1]["action"] == (
        "review_callback_failed"
    )


def test_posture_audit_chain_and_retention_are_explicit(environment) -> None:
    client, _database, rows, _documents, _callbacks, clock, _config, _app = environment
    _enroll(client)
    _run_manual(
        client,
        rows,
        operation="short-retention-scan",
        values=[],
        retention_seconds=10,
    )
    status = _ok(client.get(f"{API}/status"))
    assert status["live_provider_acceptance_verified"] is False
    assert status["completeness_claim"] is False
    assert status["callback_delivery"]["durable_outbox"] is False
    posture = _ok(client.get(f"{API}/posture"))
    assert posture["raw_values_persisted"] is False
    assert posture["document_text_persisted"] is False
    assert posture["callback_outbox_available"] is False
    assert _ok(client.get(f"{API}/audit"))["items"]
    assert _ok(client.get(f"{API}/audit/verify"))["verified"] is True

    clock.advance(11)
    purged = _ok(
        client.post(
            f"{API}/retention/purge",
            json={"idempotency_key": "retention-window-v1"},
        )
    )
    assert purged["purged_reports"] == 1
    assert purged["raw_data_purged"] is False
    assert purged["digest_only_audit_tombstones_retained"] is True


def test_audit_routes_require_tenant_audit_permission(environment, monkeypatch) -> None:
    client = environment[0]
    checked: list[str] = []

    def require(_request, permission: str) -> None:
        checked.append(permission)
        if permission == "audit":
            raise HTTPException(status_code=403, detail="audit permission required")

    monkeypatch.setattr(privacy_data_discovery_api, "require_permission", require)

    assert client.get(f"{API}/audit").status_code == 403
    assert client.get(f"{API}/audit/verify").status_code == 403
    assert checked == ["audit", "audit"]


def test_tenant_readiness_probe_drives_stock_status_without_provider_io(
    environment,
) -> None:
    client, _database, _rows, _documents, _callbacks, _clock, _config, app = (
        environment
    )
    app.state.privacy_data_discovery_readiness_probe = _stock_readiness

    status = _ok(client.get(f"{API}/status"))
    assert status["runtime_source"] == "tenant_readiness_probe"
    assert status["structured_provider_adapters"] == ["servicenow_cmdb"]
    assert status["unstructured_provider_adapters"] == ["aws_s3"]
    assert status["status_probe_opened_store"] is False
    assert status["status_probe_invoked_provider"] is False
    delivery = status["callback_delivery"]
    assert delivery["durable_outbox"] is True
    assert delivery["data_map_target"] is True
    assert delivery["bounded_retry_worker_available"] is True
    assert delivery["automatic_retry"] is False
    assert delivery["worker_scheduler_operational"] is False
    assert delivery["retry_execution_requires_worker_invocation"] is True

    posture = _ok(client.get(f"{API}/posture"))
    assert posture["callback_outbox_available"] is True
    assert posture["data_map_target_available"] is True
    assert posture["bounded_retry_worker_available"] is True
    assert posture["automatic_retry_available"] is False
    assert posture["posture_opened_store"] is False
    assert posture["posture_invoked_provider"] is False

    app.state.privacy_data_discovery_worker_scheduler_operational = True
    scheduled = _ok(client.get(f"{API}/status"))["callback_delivery"]
    assert scheduled["automatic_retry"] is True
    assert scheduled["worker_scheduler_operational"] is True
    assert scheduled["retry_execution_requires_worker_invocation"] is False


def test_scheduler_status_is_closed_tenant_specific_and_recovery_visible(
    environment,
) -> None:
    client, _database, _rows, _documents, _callbacks, _clock, _config, app = (
        environment
    )
    app.state.privacy_data_discovery_readiness_probe = _stock_readiness
    app.state.privacy_data_discovery_worker_scheduler_status = lambda: {
        "installed": True,
        "configured_enabled": True,
        "running": True,
        "healthy": False,
        "consecutive_failures": 1,
        "interrupted_cycles_recovered": 2,
        "last_error_code": "tenant_cycle_incomplete",
        "last_cycle": None,
        "process_concurrency_excluded": True,
        "cross_process_concurrency_excluded": True,
        "status_opened_tenant_store": False,
        "status_invoked_provider": False,
        "digest_only_data_map_target": True,
        "provider_network_io": False,
        "provider_writes": False,
        "estate_completeness_claimed": False,
        "live_provider_acceptance_verified": False,
    }

    payload = _ok(client.get(f"{API}/status"))
    delivery = payload["callback_delivery"]
    scheduler = payload["worker_scheduler"]
    assert delivery["worker_scheduler_configured_for_tenant"] is True
    assert delivery["worker_scheduler_operational"] is True
    assert delivery["automatic_retry"] is True
    assert scheduler["interrupted_cycles_recovered"] == 2
    assert scheduler["consecutive_failures"] == 1
    assert scheduler["status_opened_tenant_store"] is False
    assert scheduler["status_invoked_provider"] is False
    assert scheduler["provider_network_io"] is False
    assert scheduler["provider_writes"] is False
    assert scheduler["estate_completeness_claimed"] is False


def test_admin_remediation_routes_use_tenant_factories_and_closed_bodies(
    environment,
) -> None:
    client, _database, _rows, _documents, _callbacks, _clock, _config, app = (
        environment
    )
    app.state.privacy_data_discovery_readiness_probe = _stock_readiness
    unavailable = client.post(
        f"{API}/remediation/worker/run-once",
        json={"limit": 1, "lease_seconds": 30},
    )
    assert unavailable.status_code == 503

    calls: dict[str, list[object]] = {
        "factory": [],
        "worker": [],
        "list": [],
        "reconcile": [],
        "maintenance": [],
    }

    class Worker:
        def run_once(self, **kwargs):
            calls["worker"].append(kwargs)
            return {
                "claimed": 1,
                "applied": 1,
                "no_change": 0,
                "retried": 0,
                "ambiguous": 0,
                "dead_lettered": 0,
                "cancelled": 0,
            }

    class Outbox:
        def list_work(self, **kwargs):
            calls["list"].append(kwargs)
            return (
                {
                    "work_id": "PDRW-work-1",
                    "state": "ambiguous",
                    "revision": 3,
                    "attempts": 1,
                    "max_attempts": 3,
                    "next_attempt_at": NOW,
                    "ambiguous_at": NOW,
                    "retained_until": NOW + 3_600,
                    "created_at": NOW - 60,
                    "updated_at": NOW,
                    "authority_sha256": "a" * 64,
                    "receipt_sha256": None,
                    "last_error_code": "callback_outcome_unknown",
                    "raw_value": "must-not-cross-the-api-boundary",
                    "source_id": "must-not-cross-the-api-boundary",
                },
                {
                    "work_id": "PDRW-work-2",
                    "state": "ambiguous",
                    "revision": 1,
                    "attempts": 1,
                    "max_attempts": 3,
                },
            )

        def reconcile_ambiguous(self, work_id, **kwargs):
            calls["reconcile"].append((work_id, kwargs))
            return {"work_id": work_id, "state": "applied", "revision": 4}

    class Runtime:
        tenant_id = "tenant-a"
        worker = Worker()
        outbox = Outbox()
        reconciler = staticmethod(lambda _probe: None)
        digest_only_target = True
        external_side_effect = False
        provider_network_io = False
        provider_writes = False

        def maintenance(self, **kwargs):
            calls["maintenance"].append(kwargs)
            return {
                "schema": "lightwork.privacy-discovery-maintenance.v1",
                "tenant_id": "tenant-a",
                "outbox_purged": 0,
                "data_map_purged": 0,
                "outbox_integrity": {"current_records": 0},
                "data_map_integrity": {"observations": 0, "tombstones": 0},
                "raw_data_returned": False,
                "provider_side_effect": False,
            }

    runtime = Runtime()

    def runtime_factory(**kwargs):
        calls["factory"].append(kwargs)
        return runtime

    app.state.privacy_data_discovery_remediation_runtime_factory = runtime_factory

    forged = client.post(
        f"{API}/remediation/worker/run-once",
        json={"limit": 1, "lease_seconds": 30, "tenant_id": "tenant-b"},
    )
    assert forged.status_code == 422
    worker = _ok(
        client.post(
            f"{API}/remediation/worker/run-once",
            json={"limit": 2, "lease_seconds": 30},
        )
    )
    assert worker["claimed"] == 1
    assert worker["external_side_effect"] is False
    assert worker["provider_network_io"] is False
    assert worker["provider_writes"] is False
    assert calls["worker"][0]["limit"] == 2
    assert str(calls["worker"][0]["worker_id"]).startswith("pdd-worker-")

    work = _ok(
        client.get(f"{API}/remediation/work?state=ambiguous&limit=1")
    )
    assert work["truncated"] is True
    assert work["operational_metadata_only"] is True
    assert work["raw_data_returned"] is False
    assert work["provider_network_io"] is False
    assert work["items"][0]["work_id"] == "PDRW-work-1"
    assert work["items"][0]["state"] == "ambiguous"
    assert "raw_value" not in work["items"][0]
    assert "source_id" not in work["items"][0]
    assert calls["list"] == [{"state": "ambiguous", "limit": 2}]

    reconciled = _ok(
        client.post(
            f"{API}/remediation/work/PDRW-work-1/reconcile",
            json={
                "expected_revision": 3,
                "absent_backoff_seconds": 10,
                "idempotency_key": "reconcile-work-1",
            },
        )
    )
    assert reconciled["state"] == "applied"
    assert reconciled["digest_only_reconciliation"] is True
    assert reconciled["optimistic_replay_performed"] is False
    work_id, reconcile_kwargs = calls["reconcile"][0]
    assert work_id == "PDRW-work-1"
    assert reconcile_kwargs["reconciler"] is runtime.reconciler

    rejected_path = client.post(
        f"{API}/remediation/maintenance",
        json={"idempotency_key": "maintenance-1", "path": "C:/forbidden"},
    )
    assert rejected_path.status_code == 422
    maintenance = _ok(
        client.post(
            f"{API}/remediation/maintenance",
            json={"idempotency_key": "maintenance-1", "target_limit": 25},
        )
    )
    assert maintenance["cutoff_server_derived"] is True
    assert maintenance["integrity_verified"] is True
    assert maintenance["external_side_effect"] is False
    assert calls["maintenance"][0]["target_limit"] == 25
    assert calls["maintenance"][0]["cutoff"] > 0

    runtime.external_side_effect = True
    unsafe_runtime = client.post(
        f"{API}/remediation/worker/run-once",
        json={"limit": 1, "lease_seconds": 30},
    )
    assert unsafe_runtime.status_code == 503

    assert len(calls["factory"]) == 5
    assert all(call["tenant_id"] == "tenant-a" for call in calls["factory"])
    assert all("path" not in call for call in calls["factory"])
    assert all("credential" not in repr(call) for call in calls["factory"])


def test_admin_worker_and_maintenance_run_with_stock_local_composition(
    environment,
) -> None:
    client, _database, _rows, _documents, _callbacks, _clock, config_path, app = (
        environment
    )
    config_path.write_text(
        "[privacy_automation]\n"
        "enable = true\n"
        "[privacy_automation.data_discovery]\n"
        "enable = true\n"
        "[privacy_automation.data_discovery.adapters]\n"
        "enable = true\n"
        'enabled_providers = ["aws_s3"]\n'
        "[privacy_automation.data_discovery.remediation]\n"
        "enable = true\n"
        "max_attempts = 3\n"
        "retention_seconds = 86400\n"
        "[privacy_automation.data_discovery.remediation.data_map]\n"
        "enable = true\n"
        "retention_seconds = 172800\n",
        encoding="utf-8",
    )
    from maverick import config
    from maverick_dashboard import privacy_data_discovery_adapters_composition

    config.reset_config_cache()
    privacy_data_discovery_adapters_composition.attach_privacy_data_discovery_adapters(
        app
    )

    worker = _ok(
        client.post(
            f"{API}/remediation/worker/run-once",
            json={"limit": 5, "lease_seconds": 30},
        )
    )
    assert worker["claimed"] == 0
    assert worker["digest_only_data_map_target"] is True
    assert worker["external_side_effect"] is False

    work = _ok(client.get(f"{API}/remediation/work?state=ambiguous&limit=5"))
    assert work["items"] == []
    assert work["truncated"] is False
    assert work["operational_metadata_only"] is True
    assert work["raw_data_returned"] is False

    maintenance = _ok(
        client.post(
            f"{API}/remediation/maintenance",
            json={"idempotency_key": "stock-maintenance-1", "target_limit": 10},
        )
    )
    assert maintenance["outbox_purged"] == 0
    assert maintenance["data_map_purged"] == 0
    assert maintenance["outbox_integrity"]["current_records"] == 0
    assert maintenance["data_map_integrity"]["observations"] == 0
    assert maintenance["integrity_verified"] is True
    assert maintenance["provider_network_io"] is False


def test_unstructured_unsupported_format_is_reported_not_claimed_complete(
    environment,
) -> None:
    client, _database, _rows, documents, _callbacks, _clock, _config, _app = environment
    payload = _source_payload(kind="unstructured")
    _ok(client.put(f"{API}/sources/documents", json=payload))
    documents.documents = [
        discovery.UnstructuredDocument(
            "doc-1",
            "application/pdf",
            b"raw unsupported pdf with alice@example.com",
        )
    ]
    _ok(
        client.post(
            f"{API}/sources/documents/jobs",
            json=_manual_payload("unstructured-unsupported"),
        )
    )
    job = _ok(
        client.post(
            f"{API}/jobs/claim",
            json={"limit": 1, "lease_seconds": 60.0},
        )
    )["items"][0]
    completed = _ok(client.post(f"{API}/jobs/{job['job_id']}/execute"))
    assert "unsupported_media_type" in completed["report"]["error_codes"]
    assert completed["report"]["completeness"] == "bounded_partial"
    assert completed["report"]["absence_is_proven"] is False


def test_review_queue_lists_pending_proposals_across_findings(environment) -> None:
    client, _database, rows, _documents, _callbacks, _clock, _config, _app = environment
    assert _ok(client.get(f"{API}/reviews?status=pending"))["items"] == []
    _enroll(client)
    report = _run_manual(
        client,
        rows,
        operation="queue-scan",
        values=[discovery.StructuredRecord("row-1", {"email": "queue@example.com"})],
    )["report"]
    finding = _ok(client.get(f"{API}/reports/{report['report_id']}/findings"))["items"][0]
    proposal = _ok(
        client.post(
            f"{API}/findings/{finding['finding_id']}/reviews",
            json={
                "decision": "confirmed",
                "effective_category": finding["category"],
                "freshness_seconds": 300,
                "expected_finding_revision": finding["revision"],
                "idempotency_key": "queue-review-v1",
            },
        )
    )
    queue = _ok(client.get(f"{API}/reviews?status=pending"))["items"]
    assert [row["review_id"] for row in queue] == [proposal["review_id"]]
    assert queue[0]["integrity_sha256"] == proposal["integrity_sha256"]
    assert _ok(client.get(f"{API}/reviews?status=approved"))["items"] == []
    assert client.get(f"{API}/reviews?status=bogus").status_code == 422
