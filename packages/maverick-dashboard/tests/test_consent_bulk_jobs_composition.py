from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import consent_bulk_jobs as bulk
from maverick import consent_preferences as preferences
from maverick_dashboard import consent_bulk_jobs_composition as composition
from starlette.requests import Request

NOW = 2_000_000_000.0


def _config(**updates: object) -> dict[str, object]:
    section: dict[str, object] = {
        "enable": True,
        "initial_credits": 9,
        "max_jobs": 20,
        "max_items_per_job": 30,
        "max_artifact_bytes": 4_096,
        "lease_seconds": 30,
        "retention_seconds": 86_400,
        "worker_batch_size": 5,
    }
    section.update(updates)
    return {"consent_preferences": {"enable": True, "bulk_jobs": section}}


def _request(app: FastAPI) -> Request:
    request = Request({"type": "http", "app": app, "state": {}})
    request.state.principal = SimpleNamespace(principal="user:operator")
    return request


class FakePreferences:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...], dict[str, object]]] = []

    def export_profile(self, *args, **kwargs):
        self.calls.append(("export_profile", args, kwargs))
        return {"profile_id": args[1], "receipts": []}

    def record_preferences(self, *args, **kwargs):
        self.calls.append(("record_preferences", args, kwargs))
        return {"receipt_id": "receipt-1", "profile_revision": 2}


class LifecyclePreferences(FakePreferences):
    def delete_subject(self, *args, **kwargs):
        self.calls.append(("delete_subject", args, kwargs))
        return {"status": "deleted"}

    def change_identifier_type(self, *args, **kwargs):
        self.calls.append(("change_identifier_type", args, kwargs))
        return {"identity_kind": kwargs["identity_kind"]}

    def set_receipt_reactivation(self, *args, **kwargs):
        self.calls.append(("set_receipt_reactivation", args, kwargs))
        return {"reactivation_at": args[3]}

    def clear_receipt_expiration(self, *args, **kwargs):
        self.calls.append(("clear_receipt_expiration", args, kwargs))
        return {"clear_expiration": True}


def test_settings_are_nested_closed_bounded_and_default_off() -> None:
    settings = composition.consent_bulk_jobs_settings(_config())
    assert settings == composition.ConsentBulkJobsSettings(
        initial_credits=9,
        max_jobs=20,
        max_items_per_job=30,
        max_artifact_bytes=4_096,
        lease_seconds=30,
        retention_seconds=86_400,
        worker_batch_size=5,
    )
    assert composition.consent_bulk_jobs_settings({}) is None
    assert (
        composition.consent_bulk_jobs_settings(
            {"consent_preferences": {"enable": True}}
        )
        is None
    )
    with pytest.raises(composition.ConsentBulkJobsCompositionError, match="unknown"):
        composition.consent_bulk_jobs_settings(_config(unknown=True))
    with pytest.raises(composition.ConsentBulkJobsCompositionError, match="bound"):
        composition.consent_bulk_jobs_settings(_config(worker_batch_size=501))


def test_install_is_lazy_idempotent_and_readiness_does_not_seed_credits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    database = tmp_path / "jobs.sqlite3"
    app.state.consent_bulk_jobs_job_store_path_factory = lambda **_: database
    monkeypatch.setattr(composition, "consent_bulk_jobs_enabled", lambda _tenant: True)

    composition.install_consent_bulk_jobs_composition(app)
    composition.install_consent_bulk_jobs_composition(app)
    status = app.state.consent_bulk_jobs_readiness_probe("tenant-a")

    assert status["enabled"] is True
    assert status["ready"] is True
    assert status["status_probe_opened_store"] is False
    assert status["status_probe_seeded_credits"] is False
    assert status["operations"]["export_receipts"] is True
    assert database.exists() is False
    assert app.state.consent_bulk_jobs_composition_installed is True


def test_runtime_binds_principal_and_seeds_credits_only_once(tmp_path: Path) -> None:
    app = FastAPI()
    request = _request(app)
    principal = composition.expected_principal_ref(request, "tenant-a")
    database = tmp_path / "jobs.sqlite3"

    first = composition.build_consent_bulk_jobs_runtime(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
        config=_config(initial_credits=9),
        job_store_path=database,
        preference_store=FakePreferences(),
        worker_sha256="f" * 64,
        clock=lambda: NOW,
    )
    second = composition.build_consent_bulk_jobs_runtime(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
        config=_config(initial_credits=999),
        job_store_path=database,
        preference_store=FakePreferences(),
        worker_sha256="f" * 64,
        clock=lambda: NOW,
    )

    assert first.tenant_id == "tenant-a"
    assert first.principal_ref == principal
    assert first.store.credit_detail("tenant-a")["available"] == 9
    assert second.store.credit_detail("tenant-a")["available"] == 9
    assert database.exists() is True


def test_installed_factory_keeps_one_private_worker_identity_per_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    app.state.consent_bulk_jobs_clock = lambda: NOW
    app.state.consent_bulk_jobs_job_store_path_factory = (
        lambda **_: tmp_path / "jobs.sqlite3"
    )
    app.state.consent_bulk_jobs_preference_store_factory = lambda **_: FakePreferences()
    monkeypatch.setattr(composition, "_load_tenant_config", lambda _tenant: _config())
    monkeypatch.setattr(composition, "consent_bulk_jobs_enabled", lambda _tenant: True)
    composition.install_consent_bulk_jobs_composition(app)
    request = _request(app)
    principal = composition.expected_principal_ref(request, "tenant-a")

    first = app.state.consent_bulk_jobs_runtime_factory(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
    )
    second = app.state.consent_bulk_jobs_runtime_factory(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
    )

    assert first.worker_sha256 == second.worker_sha256
    assert len(first.worker_sha256) == 64
    assert first.worker_sha256 != hashlib.sha256(b"tenant-a").hexdigest()


def test_executor_maps_existing_export_and_edit_and_fails_closed_on_missing_hook() -> None:
    preference_store = FakePreferences()
    executor = composition.ConsentBulkExecutor(
        tenant_id="tenant-a",
        actor_sha256="a" * 64,
        preference_store=preference_store,
    )

    exported = executor(
        "export_receipts",
        {"item_id": "item-1", "profile_id": "profile-1", "receipt_limit": 10},
    )
    edited = executor(
        "edit_preferences",
        {
            "item_id": "item-2",
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
            "choices": [
                {
                    "purpose_id": "analytics",
                    "action": "deny",
                    "channel": "all",
                    "vendor_id": "all",
                    "expires_at": None,
                }
            ],
        },
    )

    assert exported["profile_id"] == "profile-1"
    assert edited["receipt_id"] == "receipt-1"
    assert [call[0] for call in preference_store.calls] == [
        "export_profile",
        "record_preferences",
    ]
    assert executor.capabilities()["delete_subject"] is False
    with pytest.raises(composition.ConsentBulkExecutorUnavailable):
        executor(
            "delete_subject",
            {
                "item_id": "item-3",
                "profile_id": "profile-1",
                "expected_revision": 2,
                "reason_code": "subject_request",
            },
        )


def test_executor_maps_exact_subject_and_receipt_lifecycle_primitives() -> None:
    preference_store = LifecyclePreferences()
    executor = composition.ConsentBulkExecutor(
        tenant_id="tenant-a",
        actor_sha256="a" * 64,
        preference_store=preference_store,
    )
    items = {
        "delete_subject": {
            "item_id": "delete-1",
            "profile_id": "profile-1",
            "expected_revision": 2,
            "reason_code": "subject_request",
        },
        "change_identifier_type": {
            "item_id": "change-1",
            "profile_id": "profile-1",
            "expected_revision": 2,
            "identity_kind": "anonymous",
            "subject_sha256": "f" * 64,
        },
        "reactivate": {
            "item_id": "reactivate-1",
            "profile_id": "profile-1",
            "expected_revision": 2,
            "receipt_id": "receipt-1",
            "reactivation_at": NOW + 60,
        },
        "clear_expiration": {
            "item_id": "clear-1",
            "profile_id": "profile-1",
            "expected_revision": 2,
            "receipt_id": "receipt-1",
        },
    }

    results = {operation: executor(operation, item) for operation, item in items.items()}

    assert results["delete_subject"]["status"] == "deleted"
    assert results["change_identifier_type"]["identity_kind"] == "anonymous"
    assert results["reactivate"]["reactivation_at"] == NOW + 60
    assert results["clear_expiration"]["clear_expiration"] is True
    assert executor.capabilities() == {
        "export_receipts": True,
        "export_after_sequence": False,
        "edit_preferences": True,
        "delete_subject": True,
        "change_identifier_type": True,
        "reactivate": True,
        "clear_expiration": True,
    }
    assert [call[0] for call in preference_store.calls] == [
        "delete_subject",
        "change_identifier_type",
        "set_receipt_reactivation",
        "clear_receipt_expiration",
    ]


def test_executor_interoperates_with_real_consent_preference_authority(
    tmp_path: Path,
) -> None:
    store = preferences.ConsentPreferenceStore(
        tmp_path / "consent.sqlite3",
        clock=lambda: NOW,
    )
    store.publish_policy(
        "tenant-a",
        "policy-1",
        1,
        {"analytics": "consent"},
        "a" * 64,
        NOW - 60,
        expected_current_version=0,
    )
    store.create_profile(
        "tenant-a",
        "profile-1",
        "known",
        "b" * 64,
        "create-profile-1",
    )
    initial = store.record_preferences(
        "tenant-a",
        "profile-1",
        "policy-1",
        1,
        preferences.ConsentContext(
            jurisdiction="us",
            country_code="US",
            asserted_source="operator",
        ),
        [
            preferences.PreferenceChoice(
                purpose_id="analytics",
                action="grant",
                expires_at=NOW + 30,
            )
        ],
        expected_revision=0,
        idempotency_key="initial-preference-1",
        actor_sha256="c" * 64,
        retention_until=NOW + 86_400,
    )
    store.create_profile(
        "tenant-a",
        "profile-2",
        "anonymous",
        "d" * 64,
        "create-profile-2",
    )
    executor = composition.ConsentBulkExecutor(
        tenant_id="tenant-a",
        actor_sha256="e" * 64,
        preference_store=store,
    )

    exported = executor(
        "export_receipts",
        {"item_id": "export-1", "profile_id": "profile-1"},
    )
    edited = executor(
        "edit_preferences",
        {
            "item_id": "edit-1",
            "profile_id": "profile-2",
            "expected_revision": 0,
            "policy_id": "policy-1",
            "policy_version": 1,
            "context": {
                "jurisdiction": "us",
                "country_code": "US",
                "region_code": "",
                "collection_point": "admin",
                "asserted_source": "operator",
            },
            "choices": [{"purpose_id": "analytics", "action": "deny"}],
        },
    )
    reactivated = executor(
        "reactivate",
        {
            "item_id": "reactivate-1",
            "profile_id": "profile-1",
            "expected_revision": 1,
            "receipt_id": initial["receipt_id"],
            "reactivation_at": NOW + 60,
        },
    )
    cleared = executor(
        "clear_expiration",
        {
            "item_id": "clear-1",
            "profile_id": "profile-1",
            "expected_revision": 2,
            "receipt_id": initial["receipt_id"],
        },
    )
    changed = executor(
        "change_identifier_type",
        {
            "item_id": "change-1",
            "profile_id": "profile-1",
            "expected_revision": 3,
            "identity_kind": "known",
            "subject_sha256": "f" * 64,
        },
    )
    deleted = executor(
        "delete_subject",
        {
            "item_id": "delete-1",
            "profile_id": "profile-1",
            "expected_revision": 4,
            "reason_code": "subject_request",
        },
    )

    assert exported["receipts"][0]["receipt_id"] == initial["receipt_id"]
    assert edited["profile_revision"] == 1
    assert reactivated["profile_revision"] == 2
    assert cleared["profile_revision"] == 3
    assert changed["revision"] == 4
    assert deleted["revision"] == 5
    assert deleted["status"] == "deleted"

    # The workbench numbers each job's rows from item-1. Separate jobs for the
    # same person must apply separately, while a resumed job retains its key.
    jobs = bulk.ConsentBulkJobStore(tmp_path / "repeat-jobs.sqlite3", clock=lambda: NOW)
    jobs.ensure_credit_account("tenant-a", initial_credits=2)
    runtime = composition.ConsentBulkJobsRuntime("tenant-a", "operator", "e" * 64,
        jobs, executor, "f" * 64, 5, lambda: NOW)
    for revision, action in ((1, "grant"), (2, "deny")):
        job = jobs.create_job("tenant-a", kind="mutation", operation="edit_preferences",
            items=[{"item_id": "item-1", "profile_id": "profile-2", "expected_revision": revision,
                    "policy_id": "policy-1", "policy_version": 1,
                    "context": {"jurisdiction": "us", "country_code": "US", "asserted_source": "operator"},
                    "choices": [{"purpose_id": "analytics", "action": action}]}],
            actor_sha256="e" * 64, scheduled_for=None, idempotency_key=f"repeated-bulk-job-{revision}")
        assert jobs.job_executor_scope("tenant-a", job["job_id"]) == "job"
        assert runtime.run_job(job["job_id"])["state"] == "succeeded"


@pytest.mark.parametrize("operation", ["reactivate", "clear_expiration"])
@pytest.mark.parametrize("outside_edit", [None, "before", "between"])
def test_selected_receipts_follow_confirmed_versions_only(
    tmp_path: Path, operation: str, outside_edit: str | None,
) -> None:
    native = preferences.ConsentPreferenceStore(tmp_path / "receipts.sqlite3", clock=lambda: NOW)
    native.publish_policy("tenant-a", "policy-1", 1, {"analytics": "consent"},
                          "a" * 64, NOW - 60, expected_current_version=0)
    native.create_profile("tenant-a", "profile-1", "known", "b" * 64, "create-profile-1")
    receipts = [native.record_preferences(
        "tenant-a", "profile-1", "policy-1", 1,
        preferences.ConsentContext(jurisdiction="us", country_code="US", asserted_source="operator"),
        [preferences.PreferenceChoice(purpose_id="analytics", action="grant", expires_at=NOW + 30)],
        expected_revision=version, idempotency_key=f"initial-choice-{version}", actor_sha256="c" * 64,
    )["receipt_id"] for version in range(2)]
    jobs = bulk.ConsentBulkJobStore(tmp_path / "jobs.sqlite3", clock=lambda: NOW)
    jobs.ensure_credit_account("tenant-a", initial_credits=2)
    executor = composition.ConsentBulkExecutor(tenant_id="tenant-a", actor_sha256="e" * 64,
                                                preference_store=native)
    runtime = composition.ConsentBulkJobsRuntime("tenant-a", "operator", "e" * 64,
        jobs, executor, "f" * 64, 1, lambda: NOW)
    job = jobs.create_job("tenant-a", kind="mutation", operation=operation,
        items=[{"item_id": f"item-{index}", "profile_id": "profile-1", "expected_revision": 2,
                "receipt_id": receipt, **({"reactivation_at": NOW + 60} if operation == "reactivate" else {})}
               for index, receipt in enumerate(receipts)],
        actor_sha256="e" * 64, scheduled_for=None, idempotency_key="selected-receipts-1")

    def edit(version):
        native.set_receipt_reactivation("tenant-a", "profile-1", receipts[0], NOW + 120,
            expected_revision=version, idempotency_key="other-reviewed-change", actor_sha256="d" * 64)

    if outside_edit == "before":
        edit(2)
    runtime.run_job(job["job_id"])
    if outside_edit == "between":
        edit(3)
    # A new runtime resumes from durable predecessor results, not memory.
    resumed = composition.ConsentBulkJobsRuntime("tenant-a", "operator", "e" * 64,
        jobs, executor, "f" * 64, 1, lambda: NOW)
    result = resumed.run_job(job["job_id"])
    assert result["processed_items"] == 2
    if outside_edit is None:
        assert result["state"] == "succeeded"
        for receipt in receipts:
            assert native.get_receipt_lifecycle("tenant-a", receipt)["revision"] == 1
    else:
        assert result["state"] == "failed"
        assert result["failed_items"] == (2 if outside_edit == "before" else 1)
        with pytest.raises(preferences.ConsentNotFound):
            native.get_receipt_lifecycle("tenant-a", receipts[1])


def test_run_next_executes_one_bounded_export_job(tmp_path: Path) -> None:
    app = FastAPI()
    request = _request(app)
    principal = composition.expected_principal_ref(request, "tenant-a")
    runtime = composition.build_consent_bulk_jobs_runtime(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
        config=_config(worker_batch_size=5),
        job_store_path=tmp_path / "jobs.sqlite3",
        preference_store=FakePreferences(),
        worker_sha256="f" * 64,
        clock=lambda: NOW,
    )
    job = runtime.store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=[{"item_id": "item-1", "profile_id": "profile-1"}],
        actor_sha256=runtime.actor_sha256,
        scheduled_for=None,
        idempotency_key="create-export-1",
    )

    result = runtime.run_next()

    assert result["ran"] is True
    assert result["job"]["job_id"] == job["job_id"]
    assert result["job"]["state"] == "succeeded"
    artifact = runtime.store.download_artifact("tenant-a", job["job_id"])
    assert artifact["item_count"] == 1


def test_run_next_resumes_its_owned_running_job_before_claiming_more(
    tmp_path: Path,
) -> None:
    app = FastAPI()
    request = _request(app)
    principal = composition.expected_principal_ref(request, "tenant-a")
    runtime = composition.build_consent_bulk_jobs_runtime(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
        config=_config(worker_batch_size=1),
        job_store_path=tmp_path / "jobs.sqlite3",
        preference_store=FakePreferences(),
        worker_sha256="f" * 64,
        clock=lambda: NOW,
    )
    job = runtime.store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=[
            {"item_id": "item-1", "profile_id": "profile-1"},
            {"item_id": "item-2", "profile_id": "profile-2"},
        ],
        actor_sha256=runtime.actor_sha256,
        scheduled_for=None,
        idempotency_key="create-export-resume",
    )

    first = runtime.run_next()
    second = runtime.run_next()

    assert first["job"]["job_id"] == job["job_id"]
    assert first["job"]["state"] == "running"
    assert first["job"]["processed_items"] == 1
    assert second["job"]["job_id"] == job["job_id"]
    assert second["job"]["state"] == "succeeded"
    assert second["job"]["processed_items"] == 2


def test_runtime_rejects_caller_selected_principal(tmp_path: Path) -> None:
    app = FastAPI()
    request = _request(app)
    with pytest.raises(composition.ConsentBulkJobsCompositionError, match="principal"):
        composition.build_consent_bulk_jobs_runtime(
            tenant_id="tenant-a",
            principal_ref="consent-bulk-principal-attacker",
            request=request,
            config=_config(),
            job_store_path=tmp_path / "jobs.sqlite3",
            preference_store=FakePreferences(),
            worker_sha256="f" * 64,
            clock=lambda: NOW,
        )


def test_worker_errors_are_closed_and_never_persist_exception_text(tmp_path: Path) -> None:
    class ExplodingPreferences(FakePreferences):
        def export_profile(self, *args, **kwargs):
            del args, kwargs
            raise RuntimeError("secret=/private/path token=do-not-store")

    app = FastAPI()
    request = _request(app)
    principal = composition.expected_principal_ref(request, "tenant-a")
    runtime = composition.build_consent_bulk_jobs_runtime(
        tenant_id="tenant-a",
        principal_ref=principal,
        request=request,
        config=_config(),
        job_store_path=tmp_path / "jobs.sqlite3",
        preference_store=ExplodingPreferences(),
        worker_sha256="f" * 64,
        clock=lambda: NOW,
    )
    job = runtime.store.create_job(
        "tenant-a",
        kind="export",
        operation="export_receipts",
        items=[{"item_id": "item-1", "profile_id": "profile-1"}],
        actor_sha256=runtime.actor_sha256,
        scheduled_for=None,
        idempotency_key="create-export-2",
    )

    result = runtime.run_job(job["job_id"])
    history = runtime.store.history("tenant-a", job["job_id"], limit=100)
    encoded = repr(history)

    assert result["state"] == "failed"
    assert "worker_failure" in encoded
    assert "do-not-store" not in encoded
    assert "/private/path" not in encoded
    assert type(runtime.store) is bulk.ConsentBulkJobStore
