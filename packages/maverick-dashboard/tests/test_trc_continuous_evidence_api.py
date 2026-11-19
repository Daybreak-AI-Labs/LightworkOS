from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from maverick import trc_continuous_evidence as evidence
from maverick_dashboard import trc_continuous_evidence_api as api

API = "/api/v1/compliance/continuous-evidence"
SHA_A = "a" * 64
SHA_B = "b" * 64


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "permission_calls": [],
        "allowed_collectors": ["local_soc2_v1"],
    }
    database = tmp_path / "continuous-evidence.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise evidence.ContinuousEvidenceConfigError("disabled for test")

    def permission(_request, permission_name):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(permission_name)

    monkeypatch.setattr(evidence, "require_enabled", require_enabled)
    monkeypatch.setattr(evidence, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", permission)
    monkeypatch.setattr(api, "require_global_permission", permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(
            principal=request.headers.get("X-Test-Subject", "author")
        )
        return await call_next(request)

    def store_factory(**kwargs):
        return evidence.ContinuousEvidenceStore(
            database,
            tenant_id=kwargs["tenant_id"],
            principal_resolver=kwargs["principal_resolver"],
            config_gate=lambda: None,
            clock=lambda: 1_800_000_000.0,
            lease_token_factory=lambda: "lwtrc1." + "x" * 43,
        )

    app.state.trc_continuous_evidence_store_factory = store_factory
    app.state.trc_continuous_evidence_config_loader = lambda: {
        "tech_risk_compliance": {
            "enable": True,
            "continuous_evidence": {
                "enable": True,
                "enabled_collectors": list(state["allowed_collectors"]),
            },
        }
    }
    app.state.trc_stock_evidence_readiness_probe = lambda tenant: {
        "schema": "lightwork.trc-stock-collector-production-readiness.v1",
        "tenant_seen": tenant,
        "enabled": True,
        "ready": False,
        "missing_stock_collector_ids": ["aws_security_hub_v1"],
        "status_secret_resolution": False,
        "status_provider_network_io": False,
        "live_provider_acceptance_verified": False,
    }
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "author"},
    )
    return client, database, state


def test_status_is_candid_and_does_not_open_store(environment):
    client, database, _state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True
    assert body["collector_dependency_injection_supported"] is True
    assert body["custom_collector_dependencies_injected"] is False
    assert body["stock_collectors"]["tenant_seen"] == "tenant-a"
    assert body["stock_collectors"]["ready"] is False
    assert body["stock_collectors"]["status_secret_resolution"] is False
    assert body["compliance_conclusions_written"] is False
    assert body["control_implementation_mutated"] is False
    assert body["certification_performed"] is False
    assert body["live_provider_acceptance_verified"] is False
    assert database.exists() is False


def test_manual_scheduler_cycle_uses_only_server_installed_runtime(environment):
    client, _database, state = environment
    calls = []

    class Scheduler:
        def status(self):
            return {"custom_collector_dependencies_injected": True}

        def run_once(self):
            calls.append("run")
            return {"jobs_completed": 2, "jobs_incomplete": 1}

    client.app.state.trc_continuous_evidence_scheduler = Scheduler()
    response = client.post(f"{API}/scheduler/run-once")
    assert response.status_code == 200
    assert response.json() == {
        "schema": "lightwork.trc-continuous-evidence-manual-cycle.v1",
        "executed": True,
        "cycle": {"jobs_completed": 2, "jobs_incomplete": 1},
        "provider_acceptance_claimed": False,
        "estate_completeness_claimed": False,
    }
    assert calls == ["run"]
    assert state["permission_calls"][-1] == "admin"


def test_definition_approval_enrollment_and_job_operator_flow(environment):
    client, _database, state = environment
    created = client.put(
        f"{API}/definitions/local-definition/versions/1",
        json={
            "collector_id": "local_soc2_v1",
            "collector_schema_version": 1,
            "collector_key_id": "local_key_v1",
            "capability_revision": 1,
            "allowed_control_refs": ["audit_log", "tenant_isolation"],
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["state"] == "pending"

    self_approval = client.post(
        f"{API}/definitions/local-definition/versions/1/approve",
        json={"expected_integrity_sha256": created.json()["integrity_sha256"]},
    )
    assert self_approval.status_code == 403

    approved = client.post(
        f"{API}/definitions/local-definition/versions/1/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={"expected_integrity_sha256": created.json()["integrity_sha256"]},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["state"] == "approved"

    enrolled = client.put(
        f"{API}/enrollments/local-enrollment",
        headers={"X-Test-Subject": "operator"},
        json={
            "definition_id": "local-definition",
            "definition_version": 1,
            "expected_definition_integrity_sha256": approved.json()["integrity_sha256"],
            "asset_scope_sha256": SHA_A,
            "credential_profile_sha256": SHA_B,
            "control_refs": ["tenant_isolation", "audit_log"],
            "interval_seconds": 60,
            "operation_id": "enroll-local",
            "retention_seconds": 86_400,
        },
    )
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["control_refs"] == ["audit_log", "tenant_isolation"]

    enqueued = client.post(
        f"{API}/jobs/enqueue-due",
        headers={"X-Test-Subject": "operator"},
        json={"limit": 10, "max_attempts": 3},
    )
    assert enqueued.status_code == 200, enqueued.text
    assert enqueued.json()["count"] == 1
    jobs = client.get(f"{API}/jobs?state=queued")
    assert jobs.status_code == 200
    assert jobs.json()["count"] == 1
    assert "lease_token" not in jobs.json()["items"][0]
    assert jobs.json()["items"][0]["lease_token_sha256"] is None

    integrity = client.get(f"{API}/integrity")
    assert integrity.status_code == 200, integrity.text
    assert integrity.json()["valid"] is True
    assert integrity.json()["jobs"] == 1
    assert "admin" in state["permission_calls"]
    assert "audit" in state["permission_calls"]


def test_api_rejects_tenant_actor_provider_url_and_credentials(environment):
    client, database, _state = environment
    response = client.put(
        f"{API}/definitions/hostile-definition/versions/1",
        json={
            "collector_id": "local_soc2_v1",
            "collector_schema_version": 1,
            "collector_key_id": "local_key_v1",
            "capability_revision": 1,
            "allowed_control_refs": ["audit_log"],
            "tenant_id": "victim",
            "actor": "admin",
            "provider_url": "https://attacker.test",
            "credential": "secret-value",
        },
    )
    assert response.status_code == 422
    if database.exists():
        payload = database.read_bytes()
        assert b"attacker.test" not in payload
        assert b"secret-value" not in payload
        assert b"victim" not in payload


def test_disabled_feature_fails_closed(environment):
    client, _database, state = environment
    state["enabled"] = False
    response = client.get(f"{API}/definitions")
    assert response.status_code == 403


def test_definition_and_enrollment_require_tenant_collector_allowlist(environment):
    client, database, state = environment
    rejected = client.put(
        f"{API}/definitions/not-allowed/versions/1",
        json={
            "collector_id": "external_soc2_v1",
            "collector_schema_version": 1,
            "collector_key_id": "external_key_v1",
            "capability_revision": 1,
            "allowed_control_refs": ["audit_log"],
        },
    )
    assert rejected.status_code == 403
    assert database.exists() is False

    created = client.put(
        f"{API}/definitions/local-definition/versions/1",
        json={
            "collector_id": "local_soc2_v1",
            "collector_schema_version": 1,
            "collector_key_id": "local_key_v1",
            "capability_revision": 1,
            "allowed_control_refs": ["audit_log"],
        },
    )
    state["allowed_collectors"] = ["external_soc2_v1"]
    blocked_approval = client.post(
        f"{API}/definitions/local-definition/versions/1/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={"expected_integrity_sha256": created.json()["integrity_sha256"]},
    )
    assert blocked_approval.status_code == 403
    state["allowed_collectors"] = ["local_soc2_v1"]
    approved = client.post(
        f"{API}/definitions/local-definition/versions/1/approve",
        headers={"X-Test-Subject": "reviewer"},
        json={"expected_integrity_sha256": created.json()["integrity_sha256"]},
    )
    assert approved.status_code == 200
    state["allowed_collectors"] = ["external_soc2_v1"]
    enrolled = client.put(
        f"{API}/enrollments/local-enrollment",
        headers={"X-Test-Subject": "operator"},
        json={
            "definition_id": "local-definition",
            "definition_version": 1,
            "expected_definition_integrity_sha256": approved.json()["integrity_sha256"],
            "asset_scope_sha256": SHA_A,
            "credential_profile_sha256": SHA_B,
            "control_refs": ["audit_log"],
            "interval_seconds": 60,
            "operation_id": "enroll-local",
            "retention_seconds": 86_400,
        },
    )
    assert enrolled.status_code == 403


def test_on_with_no_sources_chosen_reads_as_no_sources_not_an_outage(environment):
    # Live: Settings allows continuous evidence on with "Where evidence is
    # collected from" left empty (its default). Every read then answered 503
    # "collector allowlist is unavailable". Nothing chosen means nothing may
    # be collected: an empty allowlist, said plainly.
    client, _database, state = environment
    state["allowed_collectors"] = []
    assert api._collector_ids(SimpleNamespace(app=client.app)) == frozenset()
    rejected = client.put(
        f"{API}/definitions/local-definition/versions/1",
        json={
            "collector_id": "local_soc2_v1",
            "collector_schema_version": 1,
            "collector_key_id": "local_key_v1",
            "capability_revision": 1,
            "allowed_control_refs": ["audit_log"],
        },
    )
    assert rejected.status_code == 403


def test_a_malformed_source_list_stays_a_logged_outage(environment, caplog):
    client, _database, state = environment
    state["allowed_collectors"] = ["Not A Collector!"]
    with caplog.at_level("WARNING", logger=api.__name__):
        with pytest.raises(HTTPException) as failed:
            api._collector_ids(SimpleNamespace(app=client.app))
    assert failed.value.status_code == 503
    assert any("TrcEvidenceSchedulerConfigurationError" in row.getMessage() for row in caplog.records)


def _on_event_loop() -> bool:
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


def test_reads_check_the_gate_and_open_the_store_off_the_event_loop(environment, monkeypatch):
    """Opening the tenant store runs SQLite work with a 30 s busy timeout; on the
    hosted demo this page's lists did that on the event loop and every other
    request, health checks included, waited about 45 seconds."""
    client, _database, state = environment
    seen: list[tuple[str, bool]] = []
    gate, enabled = evidence.require_enabled, evidence.enabled

    def watched_gate() -> None:
        seen.append(("gate", _on_event_loop()))
        gate()

    def watched_enabled() -> bool:
        seen.append(("enabled", _on_event_loop()))
        return enabled()

    factory = client.app.state.trc_continuous_evidence_store_factory

    def watched_factory(**kwargs):
        seen.append(("store", _on_event_loop()))
        return factory(**kwargs)

    monkeypatch.setattr(evidence, "require_enabled", watched_gate)
    monkeypatch.setattr(evidence, "enabled", watched_enabled)
    client.app.state.trc_continuous_evidence_store_factory = watched_factory
    for path in ("/definitions", "/enrollments", "/jobs?state=dead_letter", "/runs?limit=50",
                 "/alerts?limit=100", "/integrity", "/status"):
        assert client.get(f"/api/v1/compliance/continuous-evidence{path}").status_code == 200, path
    assert {kind for kind, _loop in seen} == {"gate", "enabled", "store"}
    assert not any(loop for _kind, loop in seen)
    state["enabled"] = False
    assert client.get("/api/v1/compliance/continuous-evidence/definitions").status_code == 403


def test_a_waiting_store_does_not_stop_the_server_answering(environment):
    import threading
    import time

    client, _database, _state = environment
    app = client.app

    @app.get("/livez")
    async def livez() -> dict[str, str]:
        return {"status": "ok"}

    factory = app.state.trc_continuous_evidence_store_factory
    entered, release = threading.Event(), threading.Event()

    def waiting_factory(**kwargs):
        entered.set()
        release.wait(timeout=10)
        return factory(**kwargs)

    app.state.trc_continuous_evidence_store_factory = waiting_factory
    with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as shared:
        listing: list[int] = []
        worker = threading.Thread(
            target=lambda: listing.append(
                shared.get("/api/v1/compliance/continuous-evidence/definitions").status_code
            ),
            daemon=True,
        )
        worker.start()
        try:
            assert entered.wait(timeout=10)
            started = time.monotonic()
            assert shared.get("/livez").status_code == 200
            assert time.monotonic() - started < 2, "the waiting store blocked the event loop"
            assert not release.is_set() and worker.is_alive()
        finally:
            release.set()
            worker.join(timeout=15)
    assert listing == [200]
