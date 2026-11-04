from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import privacy_rights_orchestration as rights
from maverick import privacy_rights_source_worker as source_worker
from maverick_dashboard import privacy_rights_orchestration_api as api

API = "/api/v1/privacy/rights-orchestration"
NOW = 2_000_000_000.0


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
        "token": 0,
    }
    database = tmp_path / "privacy-rights.sqlite3"

    def require_enabled() -> None:
        if not state["enabled"]:
            raise rights.PrivacyRightsConfigError("disabled for test")

    def tenant_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("tenant", permission))

    def global_permission(_request, permission):
        calls = state["permission_calls"]
        assert isinstance(calls, list)
        calls.append(("global", permission))

    def token() -> str:
        state["token"] = int(state["token"]) + 1
        return f"lease-token-{state['token']}"

    monkeypatch.setattr(rights, "require_enabled", require_enabled)
    monkeypatch.setattr(rights, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))
    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        subject = request.headers.get("X-Test-Subject", "case-owner")
        request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def store_factory(**kwargs):
        calls = state["factory_calls"]
        assert isinstance(calls, list)
        calls.append(kwargs)
        return rights.PrivacyRightsOrchestrationStore(
            database,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
            digest_key_resolver=lambda _tenant: b"k" * 32,
            clock=lambda: NOW,
            token_factory=token,
        )

    app.state.privacy_rights_orchestration_store_factory = store_factory
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "case-owner"},
    )
    return client, database, state


def _principal(client: TestClient, subject: str = "case-owner") -> str:
    return client.get(f"{API}/status", headers={"X-Test-Subject": subject}).json()["principal_ref"]


def _open_body(
    *,
    raw_subject: str = "private.person@example.test",
    raw_request: str = "external-ticket-private-123",
    requested_rights: list[str] | None = None,
) -> dict:
    return {
        "request_version": 1,
        "external_request_ref": raw_request,
        "subject_reference": raw_subject,
        "rights": requested_rights or ["access"],
        "retained_until": NOW + 600,
        "idempotency_key": f"open-{hashlib.sha256(raw_request.encode()).hexdigest()[:16]}",
    }


def _enroll(client: TestClient, capabilities: list[str]) -> dict:
    response = client.put(
        f"{API}/sources/crm",
        json={
            "adapter_ref": "provider-adapter-v1",
            "credential_ref": "env:PROVIDER_RIGHTS_TOKEN",
            "capabilities": capabilities,
            "expected_revision": 0,
            "idempotency_key": "source-enroll",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _open_and_verify(client: TestClient, case_id: str, rights_list: list[str]) -> dict:
    opened = client.put(
        f"{API}/cases/{case_id}",
        json=_open_body(
            raw_subject=f"subject/{case_id}",
            raw_request=f"request/{case_id}",
            requested_rights=rights_list,
        ),
    )
    assert opened.status_code == 200, opened.text
    verified = client.post(
        f"{API}/cases/{case_id}/identity-verification",
        json={
            "status": "verified",
            "evidence_sha256": "a" * 64,
            "evidence_ref": "identity-receipt",
            "expected_revision": opened.json()["revision"],
            "idempotency_key": f"identity-{case_id}",
        },
    )
    assert verified.status_code == 200, verified.text
    return verified.json()


def test_status_is_store_free_honest_and_feature_off_is_403(environment) -> None:
    client, _database, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    status = response.json()
    assert status["network_io"] is False
    assert status["provider_writes"] is False
    assert status["identity_verification_performed"] is False
    assert status["response_delivery_performed"] is False
    assert status["estate_completeness_claimed"] is False
    assert status["live_provider_acceptance_verified"] is False
    assert status["live_customer_acceptance_verified"] is False
    assert status["callback_transport_worker_implemented"] is True
    assert status["callbacks_are_worker_intent_only"] is False
    assert status["source_runtime"]["ready"] is False
    assert status["status_request_opened_store"] is False
    assert status["status_request_resolved_secret"] is False
    assert state["factory_calls"] == []

    state["enabled"] = False
    assert client.get(f"{API}/status").json()["enabled"] is False
    assert client.get(f"{API}/sources").status_code == 403
    assert client.post(
        f"{API}/source-runtime/run",
        json={"run_id": "disabled-source-run"},
    ).status_code == 403
    assert client.post(
        f"{API}/source-runtime/reconcile",
        json={"run_id": "disabled-source-reconcile"},
    ).status_code == 403


def test_exact_tenant_principal_and_raw_to_hmac_non_echo_boundary(environment) -> None:
    client, database, state = environment
    raw_subject = "very.private.person@example.test"
    raw_request = "external-provider-ticket-PII-12345"
    expected_principal = (
        "pro-principal-"
        + hashlib.sha256(
            b"lightwork.privacy-rights.identity.v1:tenant-a:user:case-owner"
        ).hexdigest()[:32]
    )
    assert _principal(client) == expected_principal

    response = client.put(
        f"{API}/cases/case-private",
        json=_open_body(raw_subject=raw_subject, raw_request=raw_request),
    )
    assert response.status_code == 200, response.text
    assert raw_subject not in response.text
    assert raw_request not in response.text
    case = response.json()
    assert case["tenant_id"] == "tenant-a"
    assert case["opened_by"] == expected_principal
    assert case["subject_sha256"] != hashlib.sha256(raw_subject.encode()).hexdigest()
    assert case["external_request_sha256"] != hashlib.sha256(raw_request.encode()).hexdigest()
    calls = state["factory_calls"]
    assert isinstance(calls, list) and calls
    assert calls[-1]["tenant_id"] == "tenant-a"
    assert calls[-1]["principal_ref"] == expected_principal
    assert calls[-1]["principal_resolver"]() == expected_principal

    persisted = database.read_bytes()
    wal = Path(f"{database}-wal")
    if wal.exists():
        persisted += wal.read_bytes()
    assert raw_subject.encode() not in persisted
    assert raw_request.encode() not in persisted

    repeated = client.get(f"{API}/cases/case-private")
    assert repeated.status_code == 200
    assert raw_subject not in repeated.text
    assert raw_request not in repeated.text
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/cases/case-private").status_code == 404


@pytest.mark.parametrize("field", ["tenant", "tenant_id", "actor", "actor_ref"])
def test_strict_case_body_rejects_identity_spoofing_without_raw_echo(environment, field) -> None:
    client, _database, _state = environment
    raw_subject = "never-echo-subject"
    raw_request = "never-echo-request"
    response = client.put(
        f"{API}/cases/case-spoof",
        json={
            **_open_body(raw_subject=raw_subject, raw_request=raw_request),
            field: "forged",
        },
    )
    assert response.status_code == 422
    assert raw_subject not in response.text
    assert raw_request not in response.text


def test_raw_refs_are_bounded_strict_and_only_case_open_accepts_them(environment) -> None:
    client, _database, _state = environment
    oversized = "s" * 1_025
    response = client.put(
        f"{API}/cases/case-oversized",
        json=_open_body(raw_subject=oversized),
    )
    assert response.status_code == 422
    assert oversized not in response.text
    assert response.json()["detail"] == "case-open body is invalid"
    string_version = client.put(
        f"{API}/cases/case-string-version",
        json={**_open_body(), "request_version": "1"},
    )
    assert string_version.status_code == 422
    source = client.put(
        f"{API}/sources/crm",
        json={
            "adapter_ref": "adapter",
            "credential_ref": "env:RIGHTS_TOKEN",
            "capabilities": ["discover"],
            "expected_revision": 0,
            "idempotency_key": "source",
            "subject_reference": "forbidden-outside-case-open",
        },
    )
    assert source.status_code == 422


def test_claim_is_only_live_lease_response_and_exports_omit_callbacks(environment) -> None:
    client, _database, state = environment
    _enroll(client, ["discover"])
    case = _open_and_verify(client, "case-callback", ["access"])
    planned = client.post(
        f"{API}/cases/case-callback/sources/crm/plan",
        json={
            "phases": ["discover"],
            "max_attempts": 1,
            "expected_case_revision": case["revision"],
            "idempotency_key": "plan-callback",
        },
    )
    assert planned.status_code == 200, planned.text
    assert (
        client.post(
            f"{API}/callbacks/claim",
            json={
                "limit": 1,
                "lease_seconds": 30.0,
                "idempotency_key": "float-lease",
            },
        ).status_code
        == 422
    )
    claim = client.post(
        f"{API}/callbacks/claim",
        headers={"X-Test-Subject": "worker"},
        json={
            "limit": 1,
            "lease_seconds": 30,
            "idempotency_key": "claim-1",
        },
    )
    assert claim.status_code == 200, claim.text
    callback = claim.json()["items"][0]
    live_token = callback["lease_token"]
    assert live_token
    listed = client.get(f"{API}/callbacks")
    assert listed.status_code == 200, listed.text
    assert listed.json()["count"] == 1
    assert "lease_token" not in listed.json()["items"][0]

    exported = client.put(
        f"{API}/cases/case-callback/exports/export-callback",
        json={
            "retained_until": NOW + 120,
            "idempotency_key": "export-callback",
        },
    )
    assert exported.status_code == 200, exported.text
    assert live_token not in exported.text
    assert "callbacks" not in exported.json()["body"]

    wrong_type = client.post(
        f"{API}/callbacks/{callback['callback_id']}/fail",
        headers={"X-Test-Subject": "worker"},
        json={
            "lease_token": live_token,
            "error_code": "provider_unavailable",
            "retry_delay_seconds": 0.0,
            "expected_revision": callback["revision"],
            "idempotency_key": "float-delay",
        },
    )
    assert wrong_type.status_code == 422
    assert live_token not in wrong_type.text
    failed = client.post(
        f"{API}/callbacks/{callback['callback_id']}/fail",
        headers={"X-Test-Subject": "worker"},
        json={
            "lease_token": live_token,
            "error_code": "provider_unavailable",
            "retry_delay_seconds": 0,
            "expected_revision": callback["revision"],
            "idempotency_key": "fail-1",
        },
    )
    assert failed.status_code == 200, failed.text
    assert "lease_token" not in failed.json()
    requeued = client.post(
        f"{API}/callbacks/{callback['callback_id']}/requeue",
        headers={"X-Test-Subject": "worker"},
        json={
            "expected_revision": failed.json()["revision"],
            "idempotency_key": "requeue-1",
        },
    )
    assert requeued.status_code == 200, requeued.text
    assert "lease_token" not in requeued.json()
    second_claim = client.post(
        f"{API}/callbacks/claim",
        headers={"X-Test-Subject": "worker"},
        json={
            "limit": 1,
            "lease_seconds": 30,
            "idempotency_key": "claim-2",
        },
    ).json()["items"][0]
    acked = client.post(
        f"{API}/callbacks/{callback['callback_id']}/acknowledge",
        headers={"X-Test-Subject": "worker"},
        json={
            "lease_token": second_claim["lease_token"],
            "acknowledgement_sha256": "b" * 64,
            "acknowledgement_ref": "provider-ack",
            "expected_revision": second_claim["revision"],
            "idempotency_key": "ack-1",
        },
    )
    assert acked.status_code == 200, acked.text
    assert "lease_token" not in acked.json()
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert calls.count(("global", "admin")) >= 6
    assert ("global", "audit") in calls
    assert ("tenant", "operate") in calls


def test_stock_source_worker_and_reconciler_are_admin_wired_without_route_secrets(
    environment,
) -> None:
    client, _database, state = environment
    calls: list[tuple[str, dict[str, object]]] = []
    factory_calls: list[dict[str, object]] = []

    class Runtime(source_worker.PrivacyRightsSourceWorker):
        def __init__(self) -> None:
            pass

        def run_once(self, tenant_id: str, **kwargs):
            calls.append((tenant_id, kwargs))
            return source_worker.WorkBatchResult(
                tenant_id=tenant_id,
                claimed=2,
                completed=1,
                not_found=1,
                retried=0,
                dead_lettered=0,
                ambiguous=0,
                provider_writes_possible=True,
            )

        def reconcile_once(self, tenant_id: str, **kwargs):
            calls.append((tenant_id, kwargs))
            return source_worker.ReconciliationBatchResult(
                tenant_id=tenant_id,
                inspected=1,
                resolved=1,
                requeued=0,
                still_ambiguous=0,
                errors=0,
            )

    def factory(**kwargs):
        factory_calls.append(kwargs)
        return Runtime()

    client.app.state.privacy_rights_source_worker_factory = factory
    client.app.state.privacy_rights_source_readiness_probe = lambda tenant: {
        "schema": "lightwork.privacy-rights-source-readiness.v1",
        "tenant_id": tenant,
        "enabled": True,
        "configured": True,
        "ready": True,
        "status_probe_opened_store": False,
        "status_probe_invoked_provider": False,
        "status_probe_resolved_secret": False,
        "live_provider_acceptance_verified": False,
    }
    status = client.get(f"{API}/status").json()
    assert status["source_runtime"]["ready"] is True

    run = client.post(
        f"{API}/source-runtime/run",
        json={
            "run_id": "provider-run-1",
            "limit": 2,
            "lease_seconds": 45,
            "retry_delay_seconds": 10,
        },
    )
    assert run.status_code == 200, run.text
    assert run.json()["completed"] == 1
    assert run.json()["raw_subject_persisted"] is False
    reconcile = client.post(
        f"{API}/source-runtime/reconcile",
        json={
            "run_id": "provider-reconcile-1",
            "limit": 2,
            "retry_delay_seconds": 10,
        },
    )
    assert reconcile.status_code == 200, reconcile.text
    assert reconcile.json()["resolved"] == 1
    assert reconcile.json()["provider_writes_performed"] is False
    assert len(factory_calls) == 2
    assert all(call["tenant_id"] == "tenant-a" for call in factory_calls)
    assert all("credential" not in call for call in factory_calls)
    assert calls[0][0] == "tenant-a"
    permission_calls = state["permission_calls"]
    assert isinstance(permission_calls, list)
    assert permission_calls.count(("global", "admin")) >= 2


def test_operate_opener_can_close_after_distinct_admin_approval(environment) -> None:
    client, _database, state = environment
    _enroll(client, ["discover", "retrieve", "redact"])
    case = _open_and_verify(client, "case-close", ["access"])
    planned = client.post(
        f"{API}/cases/case-close/sources/crm/plan",
        json={
            "phases": None,
            "max_attempts": 3,
            "expected_case_revision": case["revision"],
            "idempotency_key": "plan-close",
        },
    )
    assert planned.status_code == 200, planned.text
    tasks = {item["phase"]: item for item in planned.json()["items"]}
    for phase in ("discover", "retrieve"):
        claim = client.post(
            f"{API}/callbacks/claim",
            headers={"X-Test-Subject": "worker"},
            json={
                "limit": 1,
                "lease_seconds": 30,
                "idempotency_key": f"claim-{phase}",
            },
        ).json()["items"][0]
        assert claim["phase"] == phase
        ack = client.post(
            f"{API}/callbacks/{claim['callback_id']}/acknowledge",
            headers={"X-Test-Subject": "worker"},
            json={
                "lease_token": claim["lease_token"],
                "acknowledgement_sha256": "c" * 64,
                "acknowledgement_ref": f"ack-{phase}",
                "expected_revision": claim["revision"],
                "idempotency_key": f"ack-{phase}",
            },
        )
        assert ack.status_code == 200, ack.text
        evidence = client.put(
            f"{API}/cases/case-close/sources/crm/phases/{phase}/evidence/evidence-{phase}",
            json={
                "manual_attestation": True,
                "status": "complete",
                "provider_evidence_sha256": "d" * 64,
                "record_count": 1,
                "opaque_ref": f"receipt-{phase}",
                "expected_task_revision": tasks[phase]["revision"],
                "idempotency_key": f"evidence-{phase}",
            },
        )
        assert evidence.status_code == 200, evidence.text
    redaction = client.put(
        f"{API}/cases/case-close/sources/crm/phases/redact/evidence/evidence-redact",
        json={
            "manual_attestation": True,
            "status": "complete",
            "provider_evidence_sha256": "e" * 64,
            "record_count": 1,
            "opaque_ref": "receipt-redact",
            "expected_task_revision": tasks["redact"]["revision"],
            "idempotency_key": "evidence-redact",
        },
    )
    assert redaction.status_code == 200, redaction.text
    manifest = client.put(
        f"{API}/cases/case-close/manifests/manifest-close",
        json={
            "expected_case_revision": case["revision"] + 1,
            "idempotency_key": "manifest-close",
        },
    )
    assert manifest.status_code == 200, manifest.text
    package = client.put(
        f"{API}/cases/case-close/packages/package-close",
        json={
            "object_ref": "encrypted-object",
            "package_sha256": "f" * 64,
            "encryption_key_ref": "vault:response-key",
            "expires_at": NOW + 60,
            "expected_case_revision": case["revision"] + 2,
            "idempotency_key": "package-close",
        },
    )
    assert package.status_code == 200, package.text
    approval = client.post(
        f"{API}/cases/case-close/closure/approve",
        headers={"X-Test-Subject": "closure-reviewer"},
        json={
            "expected_revision": case["revision"] + 3,
            "idempotency_key": "closure-approve",
        },
    )
    assert approval.status_code == 200, approval.text
    closed = client.post(
        f"{API}/cases/case-close/close",
        json={
            "expected_revision": approval.json()["revision"],
            "idempotency_key": "case-close",
        },
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "closed"
    calls = state["permission_calls"]
    assert isinstance(calls, list)
    assert ("global", "admin") in calls
    assert calls[-1] == ("tenant", "operate")


def test_major_routes_and_network_free_adapter_surface(environment) -> None:
    client, _database, _state = environment
    paths = set(client.app.openapi()["paths"])
    expected = {
        f"{API}/sources/{{source_id}}",
        f"{API}/sources",
        f"{API}/cases/{{case_id}}",
        f"{API}/cases/{{case_id}}/identity-verification",
        f"{API}/cases/{{case_id}}/legal-hold",
        f"{API}/cases/{{case_id}}/retention-gate",
        f"{API}/cases/{{case_id}}/sources/{{source_id}}/plan",
        f"{API}/tasks/{{task_id}}/approve-destructive",
        f"{API}/callbacks/claim",
        f"{API}/callbacks",
        f"{API}/callbacks/{{callback_id}}/fail",
        f"{API}/callbacks/{{callback_id}}/acknowledge",
        f"{API}/callbacks/{{callback_id}}/requeue",
        f"{API}/source-runtime/run",
        f"{API}/source-runtime/reconcile",
        f"{API}/cases/{{case_id}}/sources/{{source_id}}/phases/{{phase}}/evidence/{{evidence_id}}",
        f"{API}/cases/{{case_id}}/manifests/{{manifest_id}}",
        f"{API}/cases/{{case_id}}/packages/{{package_id}}",
        f"{API}/packages/{{package_id}}",
        f"{API}/cases/{{case_id}}/closure/approve",
        f"{API}/cases/{{case_id}}/close",
        f"{API}/cases/{{case_id}}/exports/{{export_id}}",
        f"{API}/retention/purge",
        f"{API}/integrity",
    }
    assert expected <= paths
    source = Path(api.__file__).read_text(encoding="utf-8")
    for primitive in ("requests.", "httpx.", "urllib.request", "socket."):
        assert primitive not in source


def test_case_list_and_case_work_are_workspace_scoped_and_never_echo_raw_refs(
    environment,
) -> None:
    client, _database, state = environment
    assert client.get(f"{API}/cases").json() == {"items": [], "count": 0}
    _enroll(client, ["discover", "retrieve", "redact"])
    case = _open_and_verify(client, "case-list", ["access"])
    client.post(
        f"{API}/cases/case-list/sources/crm/plan",
        json={"phases": None, "max_attempts": 3,
              "expected_case_revision": case["revision"], "idempotency_key": "plan-list"},
    )
    listed = client.get(f"{API}/cases")
    assert listed.status_code == 200
    body = listed.json()
    assert body["count"] == 1 and body["items"][0]["case_id"] == "case-list"
    assert "subject/case-list" not in listed.text and "request/case-list" not in listed.text
    work = client.get(f"{API}/cases/case-list/work").json()
    assert {task["phase"] for task in work["tasks"]} == {"discover", "retrieve", "redact"}
    assert work["evidence"] == [] and work["packages"] == []
    assert ("tenant", "view") in state["permission_calls"]
    assert client.get(f"{API}/cases/nope/work").status_code == 404
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/cases").json()["count"] == 0
