from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from maverick.trc_continuous_evidence import ContinuousEvidenceStore
from maverick.trc_evidence_collectors import (
    CollectionRequest,
    CollectorRegistry,
    ControlEvidence,
    EvidencePage,
)
from maverick_dashboard import trc_continuous_evidence_scheduler as scheduler_module
from maverick_dashboard.trc_continuous_evidence_scheduler import (
    TrcContinuousEvidenceScheduler,
    TrcEvidenceSchedulerConfigurationError,
    TrcEvidenceSchedulerError,
    attach_trc_continuous_evidence_scheduler,
    scheduler_settings,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


class Collector:
    collector_id = "scheduler_test_v1"

    def fetch(self, request: CollectionRequest, cursor: str | None) -> EvidencePage:
        assert cursor is None
        return EvidencePage(
            items=(
                ControlEvidence(
                    control_ref=request.control_refs[0],
                    status="observed",
                    reason_code="technical_test_result",
                    evidence_sha256=SHA_A,
                    source_revision_sha256=SHA_B,
                ),
            ),
            next_cursor=None,
            terminal=True,
            complete=True,
            incomplete_reason=None,
            source_revision_sha256=SHA_B,
            artifact_sha256=SHA_C,
            bytes_read=32,
            provider_request_sha256=SHA_D,
        )


class Clock:
    def __init__(self) -> None:
        self.value = 1_800_000_000.0

    def __call__(self) -> float:
        return self.value


def config(
    *,
    root=True,
    feature=True,
    scheduler=True,
    collectors=("scheduler_test_v1",),
):
    return {
        "tech_risk_compliance": {
            "enable": root,
            "continuous_evidence": {
                "enable": feature,
                "enabled_collectors": list(collectors),
                "scheduler": {
                    "enable": scheduler,
                    "poll_seconds": 60,
                    "enqueue_limit": 10,
                    "claim_limit": 5,
                    "tenant_limit": 10,
                    "lease_seconds": 60,
                    "retry_backoff_seconds": 5,
                },
            },
        }
    }


def make_ready_store(path, tenant: str, clock: Clock):
    actor = ["maker@example.test"]
    store = ContinuousEvidenceStore(
        path,
        tenant_id=tenant,
        principal_resolver=lambda: actor[0],
        config_gate=lambda: None,
        clock=clock,
        lease_token_factory=lambda: "lwtrc1." + "x" * 43,
    )
    definition = store.register_definition(
        definition_id="scheduler_definition",
        version=1,
        collector_id="scheduler_test_v1",
        collector_schema_version=1,
        collector_key_id="key_v1",
        capability_revision=1,
        allowed_control_refs=("control-a",),
    )
    actor[0] = "approver@example.test"
    definition = store.approve_definition(
        definition.definition_id,
        definition.version,
        expected_integrity_sha256=definition.integrity_sha256,
    )
    store.enroll(
        enrollment_id="scheduler_enrollment",
        definition_id=definition.definition_id,
        definition_version=definition.version,
        expected_definition_integrity_sha256=definition.integrity_sha256,
        asset_scope_sha256=SHA_A,
        credential_profile_sha256=SHA_B,
        control_refs=("control-a",),
        interval_seconds=60,
        operation_id="scheduler_enroll",
    )
    return store


def test_settings_are_default_off_and_fail_closed():
    assert scheduler_settings({}) is None
    assert scheduler_settings(config(root=False)) is None
    assert scheduler_settings(config(feature=False)) is None
    assert scheduler_settings(config(scheduler=False)) is None
    settings = scheduler_settings(config())
    assert settings is not None
    assert settings.enabled_collectors == ("scheduler_test_v1",)
    malformed = config()
    malformed["tech_risk_compliance"]["continuous_evidence"]["scheduler"]["url"] = (
        "https://attacker.test"
    )
    with pytest.raises(TrcEvidenceSchedulerConfigurationError):
        scheduler_settings(malformed)
    for collectors in ((), ("duplicate", "duplicate"), ("NOT_CLOSED",)):
        with pytest.raises(TrcEvidenceSchedulerConfigurationError, match="allowlist"):
            scheduler_settings(config(collectors=collectors))


def test_cycle_respects_tenant_opt_out_and_processes_bounded_work(tmp_path):
    clock = Clock()
    stores = {
        "tenant-a": make_ready_store(tmp_path / "a.sqlite3", "tenant-a", clock),
        "tenant-b": make_ready_store(tmp_path / "b.sqlite3", "tenant-b", clock),
    }
    active = [""]

    @contextmanager
    def tenant_context(tenant_id):
        prior = active[0]
        active[0] = tenant_id
        try:
            yield
        finally:
            active[0] = prior

    def tenant_config():
        return config(scheduler=active[0] == "tenant-a")

    collector = Collector()
    scheduler = TrcContinuousEvidenceScheduler(
        authority_factory=lambda tenant, _principal: stores[tenant],
        registry_factory=lambda _tenant: CollectorRegistry({collector.collector_id: collector}),
        credential_resolver=lambda *_args: None,
        tenant_supplier=lambda: ("tenant-a", "tenant-b"),
        tenant_context=tenant_context,
        config_loader=lambda: config(),
        tenant_config_loader=tenant_config,
        clock=clock,
        worker_id="scheduler-worker",
    )
    cycle = scheduler.run_once()
    assert cycle is not None
    assert cycle.tenants_considered == 2
    assert cycle.tenants_enabled == 1
    assert cycle.tenants_failed == 0
    assert cycle.jobs_enqueued == 1
    assert cycle.jobs_claimed == 1
    assert cycle.jobs_completed == 1
    assert cycle.jobs_incomplete == 0
    assert len(stores["tenant-a"].list_runs()) == 1
    assert len(stores["tenant-b"].list_runs()) == 0
    status = scheduler.status()
    assert status["cycles"] == 1
    assert status["custom_collector_dependencies_injected"] is True
    assert "tenant-a" not in repr(status)
    assert "tenant-b" not in repr(status)


def test_one_tenant_failure_does_not_stop_another(tmp_path):
    clock = Clock()
    good = make_ready_store(tmp_path / "good.sqlite3", "tenant-good", clock)

    def authority(tenant_id, _principal):
        if tenant_id == "tenant-bad":
            raise RuntimeError("secret-provider-detail")
        return good

    scheduler = TrcContinuousEvidenceScheduler(
        authority_factory=authority,
        registry_factory=lambda _tenant: CollectorRegistry({"scheduler_test_v1": Collector()}),
        credential_resolver=lambda *_args: None,
        tenant_supplier=lambda: ("tenant-bad", "tenant-good"),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        clock=clock,
        worker_id="scheduler-worker",
    )
    cycle = scheduler.run_once()
    assert cycle is not None
    assert cycle.tenants_failed == 1
    assert cycle.jobs_completed == 1
    assert "secret-provider-detail" not in repr(scheduler.status())


def test_tenant_allowlist_blocks_collector_before_credential_or_adapter_io(tmp_path):
    clock = Clock()
    store = make_ready_store(tmp_path / "excluded.sqlite3", "tenant-excluded", clock)
    credential_calls = []
    collector = Collector()
    scheduler = TrcContinuousEvidenceScheduler(
        authority_factory=lambda _tenant, _principal: store,
        registry_factory=lambda _tenant: CollectorRegistry({collector.collector_id: collector}),
        credential_resolver=lambda *_args: credential_calls.append("credential"),
        tenant_supplier=lambda: ("tenant-excluded",),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(collectors=("different_collector_v1",)),
        clock=clock,
        worker_id="scheduler-worker",
    )

    cycle = scheduler.run_once()
    assert cycle is not None
    assert cycle.jobs_enqueued == 0
    assert cycle.jobs_claimed == 0
    assert cycle.jobs_completed == 0
    assert credential_calls == []
    jobs = store.list_jobs(limit=10)
    assert jobs == ()
    enrollment = store.get_enrollment("scheduler_enrollment")
    assert enrollment.state == "paused"


@contextmanager
def _null_context():
    yield


def test_disabled_scheduler_does_not_touch_tenants():
    touched = []
    scheduler = TrcContinuousEvidenceScheduler(
        authority_factory=lambda *_args: touched.append("authority"),
        registry_factory=lambda *_args: touched.append("registry"),
        credential_resolver=lambda *_args: None,
        tenant_supplier=lambda: touched.append("tenants") or (),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(scheduler=False),
        tenant_config_loader=lambda: config(scheduler=False),
        worker_id="scheduler-worker",
    )
    assert scheduler.run_once() is None
    assert scheduler.start() is False
    assert touched == []


def test_one_job_failure_does_not_abandon_the_remaining_claims(monkeypatch):
    class Authority:
        tenant_id = "tenant-a"

        @staticmethod
        def enqueue_due(*, limit, allowed_collector_ids):
            assert limit == 10
            assert allowed_collector_ids == ("scheduler_test_v1",)
            return ()

        @staticmethod
        def claim_jobs(*, worker_id, limit, lease_seconds):
            assert worker_id == "scheduler-worker"
            assert limit == 5
            assert lease_seconds == 60
            return ("bad-claim", "good-claim")

    calls = []

    def run(_authority, claim, **_kwargs):
        calls.append(claim)
        if claim == "bad-claim":
            raise RuntimeError("provider-secret-must-not-escape")
        return SimpleNamespace(job=SimpleNamespace(state="completed"))

    monkeypatch.setattr(scheduler_module, "run_claimed_collection", run)
    scheduler = TrcContinuousEvidenceScheduler(
        authority_factory=lambda *_args: Authority(),
        registry_factory=lambda _tenant: object(),
        credential_resolver=lambda *_args: None,
        tenant_supplier=lambda: ("tenant-a",),
        tenant_context=lambda _tenant: _null_context(),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="scheduler-worker",
    )
    cycle = scheduler.run_once()
    assert cycle is not None
    assert calls == ["bad-claim", "good-claim"]
    assert cycle.jobs_claimed == 2
    assert cycle.jobs_completed == 1
    assert cycle.tenants_failed == 1
    assert scheduler.status()["last_error_code"] == "tenant_cycle_failed"
    assert "provider-secret-must-not-escape" not in repr(scheduler.status())


def test_scheduler_rejects_overlapping_cycles_and_invalid_tenant_aliases():
    scheduler = TrcContinuousEvidenceScheduler(
        tenant_supplier=lambda: ("tenant-a",),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="scheduler-worker",
    )
    assert scheduler._cycle_lock.acquire(blocking=False)
    try:
        with pytest.raises(TrcEvidenceSchedulerError, match="already_running"):
            scheduler.run_once()
    finally:
        scheduler._cycle_lock.release()

    invalid = TrcContinuousEvidenceScheduler(
        tenant_supplier=lambda: ("tenant-with-trailing-space ",),
        config_loader=lambda: config(),
        tenant_config_loader=lambda: config(),
        worker_id="scheduler-worker",
    )
    with pytest.raises(TrcEvidenceSchedulerError, match="tenant_supplier_invalid"):
        invalid.run_once()


def test_lifespan_attachment_starts_stops_and_exposes_scheduler_status():
    class Runtime:
        def __init__(self):
            self.started = False
            self.stopped = False

        def start(self):
            self.started = True
            return True

        def stop(self):
            self.stopped = True

        def status(self):
            return {"running": self.started and not self.stopped}

    runtime = Runtime()
    app = FastAPI()
    attached = attach_trc_continuous_evidence_scheduler(app, runtime=runtime)
    assert attached is runtime
    assert attach_trc_continuous_evidence_scheduler(app, runtime=runtime) is runtime
    assert app.state.trc_continuous_evidence_scheduler is runtime

    with TestClient(app, base_url="http://127.0.0.1") as client:
        assert client.get("/openapi.json").status_code == 200
        assert runtime.started is True
        assert runtime.stopped is False

    assert runtime.stopped is True


def test_attachment_prefers_installed_stock_scheduler_factory():
    app = FastAPI()
    runtime = TrcContinuousEvidenceScheduler(
        tenant_supplier=lambda: (),
        config_loader=dict,
        tenant_config_loader=dict,
    )
    calls = []
    app.state.trc_stock_evidence_scheduler_factory = (
        lambda: calls.append("factory") or runtime
    )

    assert attach_trc_continuous_evidence_scheduler(app) is runtime
    assert calls == ["factory"]
    assert app.state.trc_continuous_evidence_scheduler is runtime
