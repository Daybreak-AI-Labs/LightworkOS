from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import consent_bulk_jobs as bulk
from maverick_dashboard import consent_bulk_jobs_api as api
from maverick_dashboard import consent_bulk_jobs_composition as composition

BASE = "/api/v1/consent/bulk-jobs"
NOW = 2_000_000_000.0


class FakePreferences:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def export_profile(self, tenant: str, profile: str, **kwargs):
        del kwargs
        self.calls.append("export_profile")
        return {"tenant_sha256": hashlib.sha256(tenant.encode()).hexdigest(), "profile_id": profile, "receipts": []}

    def record_preferences(self, *args, **kwargs):
        del args, kwargs
        self.calls.append("record_preferences")
        return {"receipt_id": "receipt-1", "profile_revision": 2}


@pytest.fixture()
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state = SimpleNamespace(
        tenant="tenant-a",
        principal="consent-bulk-principal-test",
        enabled=True,
        ready=True,
        factory_calls=[],
        permission_calls=[],
        now=NOW,
    )
    preference_store = FakePreferences()
    store = bulk.ConsentBulkJobStore(
        tmp_path / "jobs.sqlite3",
        limits=bulk.ConsentBulkJobLimits(
            max_jobs=100,
            max_items_per_job=100,
            max_artifact_bytes=64 * 1024,
            lease_seconds=30,
            retention_seconds=86_400,
        ),
        clock=lambda: state.now,
    )
    store.ensure_credit_account(state.tenant, initial_credits=20)
    executor = composition.ConsentBulkExecutor(
        tenant_id=state.tenant,
        actor_sha256="a" * 64,
        preference_store=preference_store,
    )
    runtime = composition.ConsentBulkJobsRuntime(
        tenant_id=state.tenant,
        principal_ref=state.principal,
        actor_sha256="a" * 64,
        store=store,
        executor=executor,
        worker_sha256="b" * 64,
        worker_batch_size=10,
        clock=lambda: state.now,
    )

    monkeypatch.setattr(api, "_tenant_id", lambda: state.tenant)
    monkeypatch.setattr(api, "_principal_ref", lambda _request, _tenant: state.principal)
    monkeypatch.setattr(
        api,
        "require_permission",
        lambda _request, permission: state.permission_calls.append(("tenant", permission)),
    )
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, permission: state.permission_calls.append(("global", permission)),
    )

    def factory(**kwargs):
        state.factory_calls.append(kwargs)
        return runtime

    def readiness(_tenant: str):
        return {
            "enabled": state.enabled,
            "configured": True,
            "ready": state.ready,
            "operations": runtime.operation_capabilities(),
            "status_probe_opened_store": False,
            "status_probe_seeded_credits": False,
            "status_probe_invoked_provider": False,
        }

    dependencies = api.ConsentBulkJobsDependencies(
        runtime_factory=factory,
        enabled_probe=lambda _tenant: state.enabled,
        readiness_probe=readiness,
    )
    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        request.state.principal = SimpleNamespace(principal="user:operator")
        return await call_next(request)

    app.include_router(api.create_consent_bulk_jobs_router(dependencies), prefix="/api/v1")
    return TestClient(app, base_url="http://127.0.0.1"), state, runtime, preference_store


def _export_body(**updates: object) -> dict[str, object]:
    body: dict[str, object] = {
        "items": [{"item_id": "item-1", "profile_id": "profile-1", "receipt_limit": 10}],
        "idempotency_key": "create-export-api-1",
    }
    body.update(updates)
    return body


def _edit_body() -> dict[str, object]:
    return {
        "operation": "edit_preferences",
        "items": [
            {
                "item_id": "edit-1",
                "profile_id": "profile-1",
                "expected_revision": 1,
                "policy_id": "policy-1",
                "policy_version": 1,
                "context": {
                    "jurisdiction": "us",
                    "country_code": "US",
                    "region_code": "NY",
                    "collection_point": "admin",
                    "asserted_source": "operator",
                },
                "choices": [{"purpose_id": "analytics", "action": "deny"}],
            }
        ],
        "idempotency_key": "create-action-api-1",
    }


def test_exact_reviewed_part_cannot_advance_another_part_and_run_next_ignores_no_revision(environment):
    from dataclasses import replace

    client, _state, runtime, preferences = environment
    bounded = replace(runtime, worker_batch_size=1)
    client.app.state.consent_bulk_jobs_runtime_factory = lambda **_kwargs: bounded
    body = _export_body(items=[{"item_id": f"item-{n}", "profile_id": f"profile-{n}"} for n in (1, 2)])
    job = client.post(BASE + "/exports", json=body).json()
    run_path = BASE + "/" + job["job_id"] + "/run"
    reviewed = {"expected_revision":job["revision"]}
    first = client.post(run_path, json=reviewed)
    assert first.status_code == 200 and first.json()["processed_items"] == 1
    assert first.json()["state"] == "running"
    assert client.post(run_path, json=reviewed).status_code == 409
    assert client.get(BASE + "/" + job["job_id"]).json()["processed_items"] == 1
    assert preferences.calls == ["export_profile"]
    assert client.post(BASE + "/worker/run-next", json=reviewed).status_code == 422
    second = client.post(run_path, json={"expected_revision":first.json()["revision"]})
    assert second.status_code == 200 and second.json()["state"] == "succeeded"
    assert preferences.calls == ["export_profile", "export_profile"]


def test_status_is_store_free_bounded_and_reports_partial_executors(environment) -> None:
    client, state, _runtime, _preferences = environment

    response = client.get(f"{BASE}/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["ready"] is True
    assert payload["operations"]["export_receipts"] is True
    assert payload["operations"]["delete_subject"] is False
    assert payload["configuration"]["caller_tenant_actor_worker_path_provider_fields_accepted"] is False
    assert payload["status_probe_opened_store"] is False
    assert payload["status_probe_seeded_credits"] is False
    assert state.factory_calls == []
    assert response.headers["cache-control"].startswith("no-store")


def test_export_run_progress_download_history_integrity_and_credits(environment) -> None:
    client, state, _runtime, preferences = environment
    created = client.post(f"{BASE}/exports", json=_export_body())
    assert created.status_code == 201
    job = created.json()
    state.now += 60
    replay = client.post(f"{BASE}/exports", json=_export_body())
    assert replay.status_code == 201 and replay.json() == job
    recovered = client.post(f"{BASE}/requests/check", json={"idempotency_key": "create-export-api-1"})
    assert recovered.status_code == 200
    assert recovered.json()["job"]["job_id"] == job["job_id"]
    assert state.permission_calls[-2:] == [("tenant", "operate"), ("global", "admin")]

    listed = client.get(BASE)
    assert listed.status_code == 200
    assert listed.json()["jobs"][0]["job_id"] == job["job_id"]
    detail = client.get(f"{BASE}/{job['job_id']}")
    assert detail.status_code == 200
    progress = client.get(f"{BASE}/{job['job_id']}/progress")
    assert progress.json()["progress_percent"] == 0.0

    ran = client.post(f"{BASE}/worker/run-next", json={})
    assert ran.status_code == 200
    assert ran.json()["job"]["state"] == "succeeded"
    assert preferences.calls == ["export_profile"]
    progress = client.get(f"{BASE}/{job['job_id']}/progress")
    assert progress.json()["progress_percent"] == 100.0

    downloaded = client.get(f"{BASE}/{job['job_id']}/download")
    assert downloaded.status_code == 200
    assert downloaded.json()["item_count"] == 1
    assert "attachment" in downloaded.headers["content-disposition"]
    history = client.get(f"{BASE}/{job['job_id']}/history")
    assert history.status_code == 200
    assert history.json()["events"]
    first = client.get(f"{BASE}/{job['job_id']}/history?limit=1").json()
    next_sequence = first["next_before_sequence"]
    second = client.get(f"{BASE}/{job['job_id']}/history", params={"limit": 1, "before_sequence": next_sequence}).json()
    assert second["events"][0]["sequence"] < first["events"][0]["sequence"]
    assert client.get(f"{BASE}/{job['job_id']}/history?before_sequence=0").status_code == 422
    integrity = client.get(f"{BASE}/operations/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["integrity_valid"] is True

    credits = client.get(f"{BASE}/credits/detail")
    assert credits.json()["consumed"] == 1
    granted = client.post(
        f"{BASE}/credits/grant",
        json={
            "amount": 5,
            "expected_revision": credits.json()["revision"],
            "idempotency_key": "grant-credit-api-1",
        },
    )
    assert granted.status_code == 200
    assert granted.json()["available"] == credits.json()["available"] + 5
    assert ("global", "admin") in state.permission_calls
    assert ("global", "audit") in state.permission_calls

    later = client.post(f"{BASE}/exports", json={**_export_body(), "idempotency_key": "create-export-api-2"}).json()
    first_page = client.get(BASE, params={"limit": 1}).json()
    assert first_page["jobs"][0]["job_id"] == later["job_id"]
    older_page = client.get(BASE, params={"limit": 1, "before_job_id": first_page["next_before_job_id"]}).json()
    assert older_page["jobs"][0]["job_id"] == job["job_id"]
    assert older_page["next_before_job_id"] is None
    assert client.get(BASE, params={"before_job_id": "other-tenant-or-missing"}).status_code == 404
    assert client.get(BASE, params={"before_job_id": "../../private"}).status_code == 422


def test_edit_action_runs_existing_primitive_and_missing_mutation_fails_closed(environment) -> None:
    client, _state, _runtime, preferences = environment

    created = client.post(f"{BASE}/actions", json=_edit_body())
    assert created.status_code == 201
    job_id = created.json()["job_id"]
    ran = client.post(f"{BASE}/{job_id}/run", json={})
    assert ran.status_code == 200
    assert ran.json()["state"] == "succeeded"
    assert preferences.calls == ["record_preferences"]

    delete_body = {
        "operation": "delete_subject",
        "items": [
            {
                "item_id": "delete-1",
                "profile_id": "profile-1",
                "expected_revision": 2,
                "reason_code": "subject_request",
            }
        ],
        "idempotency_key": "create-delete-api-1",
    }
    unavailable = client.post(f"{BASE}/actions", json=delete_body)
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"] == (
        "the requested consent bulk-job executor is unavailable"
    )


def test_cancel_recovery_retention_and_purge_are_permissioned(environment) -> None:
    client, state, _runtime, _preferences = environment
    created = client.post(
        f"{BASE}/exports",
        json=_export_body(
            scheduled_for=NOW + 1_000.0,
            idempotency_key="create-export-api-2",
        ),
    ).json()
    cancelled = client.post(
        f"{BASE}/{created['job_id']}/cancel",
        json={
            "expected_revision": created["revision"],
            "idempotency_key": "cancel-export-api-1",
        },
    )
    assert cancelled.status_code == 200
    assert cancelled.json()["state"] == "cancelled"
    recovered = client.post(f"{BASE}/operations/recover", json={"limit": 10})
    assert recovered.status_code == 200
    assert recovered.json()["recovered_count"] == 0

    state.now = NOW + 86_401.0
    due = client.get(f"{BASE}/operations/retention")
    assert due.status_code == 200
    assert [job["job_id"] for job in due.json()["jobs"]] == [created["job_id"]]
    purged = client.post(
        f"{BASE}/operations/retention/purge",
        json={"limit": 10},
    )
    assert purged.status_code == 200
    assert purged.json()["jobs_purged"] == 1
    assert client.get(f"{BASE}/{created['job_id']}").status_code == 404


def test_strict_schema_rejects_authority_and_operation_shape_injection(environment) -> None:
    client, state, _runtime, _preferences = environment
    injected = _export_body(
        tenant_id="tenant-b",
        actor_sha256="f" * 64,
        worker_sha256="e" * 64,
        database_path="C:/private/jobs.sqlite3",
        provider={"url": "https://example.invalid"},
    )
    assert client.post(f"{BASE}/exports", json=injected).status_code == 422
    assert state.factory_calls == []
    oversized_receipt_page = _export_body(
        items=[
            {
                "item_id": "export-too-wide",
                "profile_id": "profile-1",
                "receipt_limit": 501,
            }
        ]
    )
    too_many = client.post(f"{BASE}/exports", json=oversized_receipt_page)
    assert too_many.status_code == 422
    assert too_many.json()["detail"][0]["loc"] == ["body", "items", 0, "receipt_limit"]
    saved_position = client.post(
        f"{BASE}/exports",
        json=_export_body(items=[{
            "item_id": "export-position",
            "profile_id": "profile-1",
            "after_sequence": 0,
        }]),
    )
    assert saved_position.status_code == 422
    assert saved_position.json()["detail"][0]["loc"] == ["body", "items", 0, "after_sequence"]


    malformed = _edit_body()
    malformed["items"][0]["reason_code"] = "cross-operation-field"
    response = client.post(f"{BASE}/actions", json=malformed)
    assert response.status_code == 422

    old_reactivation_shape = _edit_body()
    old_reactivation_shape["operation"] = "reactivate"
    old_reactivation_shape["idempotency_key"] = "old-reactivate-shape"
    assert client.post(f"{BASE}/actions", json=old_reactivation_shape).status_code == 422
    exact_reactivation = {
        "operation": "reactivate",
        "items": [
            {
                "item_id": "reactivate-1",
                "profile_id": "profile-1",
                "expected_revision": 2,
                "receipt_id": "receipt-1",
                "reactivation_at": NOW + 100.0,
            }
        ],
        "idempotency_key": "exact-reactivate-shape",
    }
    # Schema admission succeeds; the injected fake authority intentionally lacks
    # the explicit receipt-reactivation primitive and therefore fails closed.
    assert client.post(f"{BASE}/actions", json=exact_reactivation).status_code == 503

    assert client.post(f"{BASE}/worker/run-next", json={"tenant_id": "tenant-b"}).status_code == 422


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("receipt_limit is outside its bound", "Choose between 1 and 500 records per person."),
        (
            "Receipt exports from a saved position are not supported. "
            "Select up to the latest 500 records per person.",
            "Starting from a saved position is not available. Choose up to the latest 500 records per person.",
        ),
        ("private-subject-value", "consent bulk-job request is invalid"),
    ],
)
def test_store_export_validation_returns_only_safe_detail(
    environment, monkeypatch, reason: str, expected: str,
) -> None:
    client, _state, runtime, _preferences = environment

    def reject(*_args, **_kwargs):
        raise bulk.ConsentBulkJobValidationError(reason)

    monkeypatch.setattr(runtime.store, "create_job", reject)
    response = client.post(f"{BASE}/exports", json=_export_body())
    assert response.status_code == 422
    assert response.json()["detail"] == expected
    assert "private-subject-value" not in response.text


def test_disabled_unready_and_factory_failure_do_not_leak_details(environment) -> None:
    client, state, _runtime, _preferences = environment
    state.ready = False
    response = client.post(f"{BASE}/exports", json=_export_body())
    assert response.status_code == 503
    assert state.factory_calls == []

    state.ready = True
    state.enabled = False
    response = client.post(f"{BASE}/exports", json=_export_body())
    assert response.status_code == 403
    assert state.factory_calls == []

    state.enabled = True

    def explode(**_kwargs):
        raise RuntimeError("secret token and C:/private/path")

    client.app.state.consent_bulk_jobs_runtime_factory = explode
    response = client.post(f"{BASE}/exports", json=_export_body())
    assert response.status_code == 503
    assert response.json()["detail"] == "consent bulk-job runtime is unavailable"
    assert "secret" not in response.text
    assert "private/path" not in response.text
