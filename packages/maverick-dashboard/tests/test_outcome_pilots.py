"""Frozen samples, private observations, and honest denominators."""
import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick import audit, config, world_model
from maverick.candidate_promotion import DeploymentObservation
from maverick.outcome_accounting import COST_COVERAGE_FAMILIES
from maverick.outcome_pilot_start_gate import (
    OutcomePilotAdmissionRequired,
    require_work_item_admission,
)
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import outcome_accounting_bridge as accounting_bridge
from maverick_dashboard import outcome_pilot_releases as releases
from maverick_dashboard import outcome_pilot_sources as sources
from maverick_dashboard import outcome_pilots as pilots
from maverick_dashboard import outcome_pilots_api as api
from maverick_dashboard.app import app

from test_support.starlette_state import patch_state


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *a, **k: True)
    monkeypatch.setattr(audit, "record_global", lambda *a, **k: True)
    monkeypatch.setattr(config, "get_features", lambda: {"outcome_measurement": True})
    monkeypatch.setattr(config, "config_source_errors", lambda **k: [])
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def plan():
    return {"title": "Vendor evidence pilot", "customer": "Example team", "workflow": "Review evidence",
        "criteria": "Complete citations and correct decision", "operation_id": "frozen-pilot-operation",
        "cases": [{"kind": "goal", "reference": str(i), "label": "Case " + str(i)} for i in range(1, 5)]}


@pytest.fixture
def records():
    return {str(i): {"unstarted": True, "input_version": "input-" + str(i), "version": "a" * 64,
        "finished": False, "accepted": False, "first_started_at": None, "sample": False,
        "title": "Private case " + str(i), "runtime_cost_usd": None} for i in range(1, 5)}


def create(records):
    return finish_admission(
        pilots.create(plan(), context="alice", actor="user:alice",
                      resolve=lambda k, r: records[r]),
        records,
    )


def finish_admission(record, records):
    def resolve(_kind, reference):
        return records[reference]

    manifest = accounting_bridge.admit_pilot(record, resolve=resolve)
    return pilots.complete_admission(
        record["id"], manifest, context="alice", actor=record["actor"],
        resolve=resolve,
    )


def create_protected(records):
    return finish_admission(
        pilots.create(protected_plan(), context="alice", actor="user:alice",
                      resolve=lambda k, r: records[r]),
        records,
    )


def observation(revision, **kwargs):
    return api.ObservationIn(expected_revision=revision, operation_id="first-observation-operation",
        source_version="b" * 64, baseline_minutes=90., ai_hands_on_minutes=20., review_minutes=10.,
        rework_minutes=5., corrections=1, evidence="Observed timing sheet, row 1", note="Same case and scope.",
        **kwargs).model_dump()


def test_plan_freezes_groups_and_exact_retries_do_not_reallocate(records):
    record = create(records)
    assert sum(c["allocation"] == "holdout" for c in record["cases"]) == 2
    assert create(records)["plan_version"] == record["plan_version"]
    changed = plan()
    changed["criteria"] = "easier criteria after viewing results"
    with pytest.raises(RecordConflict):
        pilots.create(changed, context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    assert pilots.get(record["id"], "alice")["criteria"] == plan()["criteria"]


def _candidate_release():
    return {"candidate_id": "candidate-one", "state": "authorized", "revision": 3,
        "manifest_sha256": "c" * 64,
        "manifest": {"target": {"target_id": "installed-lightwork",
            "expected_active_sha256": "a" * 64, "state_schema": "state.v1",
            "queued_intent_schema": "queue.v1", "external_reconciliation_schema": "external.v1"},
            "run": {"run_id": "research-run-one", "output_artifact_sha256": "b" * 64}}}


def _deployment(active="a" * 64, *, compatible=True):
    return DeploymentObservation(tenant="tenant-one", target_id="installed-lightwork",
        active_artifact_sha256=active, state_schema="state.v1",
        queued_intent_schema="queue.v1", external_state_sha256="d" * 64,
        pending_intents_sha256="e" * 64, rollback_handle="retained-baseline",
        rollback_compatible=compatible, evidence_sha256="f" * 64)


@pytest.mark.parametrize(("release_decisions", "deployed_release_check", "expected"), [
    (False, False, (False, False)),
    (True, False, (True, False)),
    (False, True, (False, True)),
])
def test_release_choices_explain_missing_setup_without_listing_candidates(
    monkeypatch, release_decisions, deployed_release_check, expected,
):
    service = SimpleNamespace(list=lambda *_args, **_kwargs: pytest.fail("listed before readiness"))
    adapter = SimpleNamespace(observe=lambda *_args: _deployment())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        candidate_promotion_deployment_adapter=adapter if deployed_release_check else None,
    )))
    monkeypatch.setattr(releases, "_identity", lambda _request: ("tenant-one", "user:alice"))
    monkeypatch.setattr(releases, "_service", lambda _request, required=False:
                        service if release_decisions else None)
    response = releases.choices(request)
    assert response["available"] is False
    assert response["items"] == []
    assert response["readiness"]["status"] == "setup_required"
    assert (response["readiness"]["release_decisions"],
            response["readiness"]["deployed_release_check"]) == expected
    assert "normal workflow pilot" in response["readiness"]["next_action"]


def test_release_choices_need_named_account_and_explain_empty_ready_state(monkeypatch):
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        candidate_promotion_deployment_adapter=SimpleNamespace(observe=lambda *_args: _deployment()),
    )))
    def unnamed(_request):
        raise PermissionError("A named account is required.")

    monkeypatch.setattr(releases, "_identity", unnamed)
    denied = releases.choices(request)
    assert denied["readiness"]["status"] == "sign_in_required"
    assert denied["items"] == []
    monkeypatch.setattr(releases, "_identity", lambda _request: ("tenant-one", "user:alice"))
    monkeypatch.setattr(releases, "_service", lambda _request, required=False:
                        SimpleNamespace(list=lambda *_args, **_kwargs: []))
    ready = releases.choices(request)
    assert ready["available"] is True
    assert ready["items"] == []
    assert ready["readiness"]["status"] == "ready"
    assert "no candidate" in ready["readiness"]["next_action"]


def test_release_readiness_route_explains_missing_setup_without_exposing_candidates(monkeypatch):
    patch_state(monkeypatch, app.state, "candidate_promotion_deployment_adapter", None,
                raising=False)
    monkeypatch.setattr(releases, "_identity", lambda _request: ("tenant-one", "user:alice"))
    monkeypatch.setattr(releases, "_service", lambda _request, required=False: None)
    monkeypatch.setattr(api, "context_for", lambda _request: "alice")
    monkeypatch.setattr(api, "require_permission", lambda *_args: None)
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(
        "/api/v1/outcome-pilots/release-candidates",
    )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "private, no-store"
    assert response.json()["context"] == "alice"
    assert response.json()["items"] == []
    assert response.json()["readiness"]["status"] == "setup_required"
    assert "normal workflow pilot" in response.json()["readiness"]["next_action"]


def test_non_ascii_pilot_context_header_is_refused_as_changed_context(monkeypatch):
    monkeypatch.setattr(api, "context_for", lambda _request: "alice")
    monkeypatch.setattr(api, "require_permission", lambda *_args: None)
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(
        "/api/v1/outcome-pilots/release-candidates",
        headers={"X-Lightwork-Pilot-Context": "alicé".encode()},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "pilot_context_changed"


def test_improvement_plan_freezes_trusted_versions_but_never_claims_causal_lift(records, monkeypatch):
    value = _candidate_release()
    adapter = SimpleNamespace(observe=lambda tenant, target: _deployment())
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        candidate_promotion_deployment_adapter=adapter)))
    service = SimpleNamespace(inspect=lambda tenant, actor, candidate: value,
        list=lambda tenant, actor, limit: [value])
    monkeypatch.setattr(releases, "_identity", lambda request: ("tenant-one", "user:alice"))
    monkeypatch.setattr(releases, "_service", lambda request, required=True: service)
    assert releases.choices(request)["items"][0]["candidate_id"] == "candidate-one"
    frozen = releases.bind(request, "candidate-one")
    body = {**protected_plan(), "operation_id": "improvement-pilot-operation",
            "candidate_id": "candidate-one"}
    record = pilots.create(body, context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
        resolve_release=lambda _id: frozen)
    assert record["release_binding"]["baseline_sha256"] == "a" * 64
    assert record["release_binding"]["candidate_sha256"] == "b" * 64
    assert record["release_binding"]["deployment_observation_sha256"] == "f" * 64
    assert record["plan_version"] != pilots.digest({key: record[key] for key in (
        "title", "customer", "workflow", "criteria", "cases", "frozen_at",
        "learning_mode", "prior_exposure_statement")})
    # A retry uses the exact frozen record even if the deployment changed.
    adapter.observe = lambda tenant, target: _deployment("b" * 64)
    assert pilots.create(body, context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
        resolve_release=lambda _id: pytest.fail("exact retry re-resolved the release"))["plan_version"] == record["plan_version"]
    result = pilots.report(record, resolve=lambda _kind, reference: records[reference])
    assert result["release_binding"]["promotion_manifest_sha256"] == "c" * 64
    assert result["measurement_basis"] == "operator_reported"
    assert result["case_exposure_verified"] is False
    assert result["causal_lift_qualified"] is False
    assert "cannot establish release lift" in result["limitations"][-1]
    current = releases.status(request, frozen)
    assert current["deployment_state"] == "candidate_active"
    assert current["case_exposure_verified"] is False
    assert current["causal_lift_qualified"] is False


def test_improvement_plan_refuses_untrusted_or_changed_release(records, monkeypatch):
    body = {**protected_plan(), "operation_id": "improvement-refusal-operation",
            "candidate_id": "candidate-one"}
    def resolve(_kind, reference):
        return records[reference]
    with pytest.raises(PermissionError, match="trusted release"):
        pilots.create(body, context="alice", actor="user:alice", resolve=resolve)
    with pytest.raises(ValueError, match="could not be bound"):
        pilots.create(body, context="alice", actor="user:alice", resolve=resolve,
            resolve_release=lambda _id: {"baseline_sha256": "a" * 64})
    with pytest.raises(ValueError, match="protected evaluation"):
        pilots.create({**body, "learning_mode": "observational"}, context="alice",
            actor="user:alice", resolve=resolve, resolve_release=lambda _id: None)
    assert pilots.STORE.list() == []
    value = _candidate_release()
    adapter = SimpleNamespace(observe=lambda tenant, target: _deployment("b" * 64))
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        candidate_promotion_deployment_adapter=adapter)))
    monkeypatch.setattr(releases, "_identity", lambda request: ("tenant-one", "user:alice"))
    monkeypatch.setattr(releases, "_service", lambda request, required=True:
        SimpleNamespace(inspect=lambda tenant, actor, candidate: value))
    with pytest.raises(ValueError, match="deployed release"):
        releases.bind(request, "candidate-one")
    adapter.observe = lambda tenant, target: _deployment(compatible=False)
    with pytest.raises(ValueError, match="rollback compatibility"):
        releases.bind(request, "candidate-one")
    adapter.observe = lambda tenant, target: _deployment()
    frozen = releases.bind(request, "candidate-one")
    value["manifest_sha256"] = "9" * 64
    assert releases.status(request, frozen)["deployment_state"] == "candidate_changed"
    assert releases.status(request, frozen)["release_evidence_current"] is False
    value["manifest_sha256"] = "c" * 64
    adapter.observe = lambda tenant, target: _deployment(compatible=False)
    incompatible = releases.status(request, frozen)
    assert incompatible["deployment_state"] == "rollback_unavailable"
    assert incompatible["release_evidence_current"] is False


def test_operator_score_arrays_cannot_be_submitted_as_improvement_proof():
    body = {**protected_plan(), "candidate_id": "candidate-one", "scores": [0.8, 0.9]}
    with pytest.raises(ValueError):
        api.PlanIn.model_validate(body)
    with pytest.raises(ValueError):
        api.ObservationIn.model_validate({**observation(1), "score_array": [0.8, 0.9]})


def test_improvement_routes_bind_server_observed_release_and_scope_status(records, monkeypatch):
    value = _candidate_release()
    adapter = SimpleNamespace(observe=lambda tenant, target: _deployment())
    service = SimpleNamespace(inspect=lambda tenant, actor, candidate: value,
        list=lambda tenant, actor, limit: [value])
    patch_state(monkeypatch, app.state, "candidate_promotion_deployment_adapter", adapter,
                raising=False)
    monkeypatch.setattr(releases, "_identity", lambda request: ("tenant-one", "user:alice"))
    monkeypatch.setattr(releases, "_service", lambda request, required=True: service)
    monkeypatch.setattr(api, "context_for", lambda request: "alice")
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    monkeypatch.setattr(api, "_resolver", lambda request: lambda _kind, reference: records[reference])
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1",
        "X-Lightwork-Pilot-Context": "alice"})
    choices = client.get("/api/v1/outcome-pilots/release-candidates")
    assert choices.status_code == 200
    assert choices.json()["items"][0]["candidate_id"] == "candidate-one"
    assert choices.json()["readiness"]["status"] == "ready"
    assert choices.headers["cache-control"] == "private, no-store"
    body = {**protected_plan(), "operation_id": "improvement-route-operation",
        "candidate_id": "candidate-one"}
    saved = client.post("/api/v1/outcome-pilots", json=body)
    assert saved.status_code == 200, saved.text
    identifier = saved.json()["id"]
    status = client.get(f"/api/v1/outcome-pilots/{identifier}/release-status")
    assert status.status_code == 200, status.text
    assert status.json()["deployment_state"] == "baseline_active"
    assert status.json()["binding"]["baseline_sha256"] == "a" * 64
    assert status.json()["checked_at"] is not None
    assert status.json()["case_exposure_verified"] is False
    assert status.json()["causal_lift_qualified"] is False
    assert status.headers["cache-control"] == "private, no-store"
    monkeypatch.setattr(api, "context_for", lambda request: "another-account")
    assert client.get(f"/api/v1/outcome-pilots/{identifier}/release-status",
        headers={"X-Lightwork-Pilot-Context": "another-account"}).status_code == 404


def test_concurrent_pilots_cannot_claim_the_same_tenant_work_items(records):
    barrier = threading.Barrier(2)

    def attempt(number):
        body = {**plan(), "title": f"Competing pilot {number}",
                "operation_id": f"competing-pilot-operation-{number}"}
        barrier.wait()
        try:
            return pilots.create(
                body, context=f"workspace-{number}", actor=f"user:owner-{number}",
                resolve=lambda _kind, reference: records[reference],
            )
        except RecordConflict as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, (1, 2)))
    assert sum(isinstance(result, dict) for result in results) == 1
    refused = next(result for result in results if isinstance(result, RecordConflict))
    assert "No allocation model is configured" in str(refused)
    assert len(pilots.STORE.list()) == 1
    claims = pilots.ADMISSION_INDEX.get("OPI-active-work-items")["claims"]
    assert len(claims) == 4
    assert len({claim["pilot_id"] for claim in claims.values()}) == 1


def test_completion_refuses_work_starting_at_the_admission_timestamp(records):
    record = pilots.create(
        plan(), context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    manifest = accounting_bridge.admit_pilot(
        record, resolve=lambda _kind, reference: records[reference],
    )
    first = manifest["entries"][0]
    records[first["case_id"]].update(
        unstarted=False, first_started_at=first["admitted_at"],
    )

    with pytest.raises(RecordConflict, match="Work started before"):
        pilots.complete_admission(
            record["id"], manifest, context="alice", actor=record["actor"],
            resolve=lambda _kind, reference: records[reference],
        )


def test_exact_work_item_claims_are_isolated_between_tenants(records):
    body = {**plan(), "operation_id": "tenant-isolated-pilot-operation"}
    with tenant_scope(tenant="tenant-one"):
        first = pilots.create(
            body, context="alice", actor="user:alice",
            resolve=lambda _kind, reference: records[reference],
        )
        assert len(pilots.ADMISSION_INDEX.get("OPI-active-work-items")["claims"]) == 4
    with tenant_scope(tenant="tenant-two"):
        second = pilots.create(
            body, context="alice", actor="user:alice",
            resolve=lambda _kind, reference: records[reference],
        )
        assert len(pilots.ADMISSION_INDEX.get("OPI-active-work-items")["claims"]) == 4
    assert first["id"] == second["id"]


def test_conflicting_same_operation_cannot_poison_unrelated_work_item_claims(
    records, monkeypatch,
):
    expanded = {**records, **{
        str(number): {**records["1"], "input_version": f"input-{number}"}
        for number in range(5, 9)
    }}
    def resolve(_kind, reference):
        return expanded[reference]

    different = {
        **plan(),
        "title": "Conflicting operation body",
        "cases": [
            {"kind": "goal", "reference": str(number), "label": f"Case {number}"}
            for number in range(5, 9)
        ],
    }
    original_create = pilots.STORE.create
    claim_ready, allow_save = threading.Event(), threading.Event()
    pause_lock, paused = threading.Lock(), []

    def paused_create(*args, **kwargs):
        with pause_lock:
            should_pause = not paused
            paused.append(True)
        if should_pause:
            claim_ready.set()
            assert allow_save.wait(timeout=5)
        return original_create(*args, **kwargs)

    monkeypatch.setattr(pilots.STORE, "create", paused_create)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(
            pilots.create, plan(), context="alice", actor="user:alice",
            resolve=resolve,
        )
        assert claim_ready.wait(timeout=5)
        conflicting = pool.submit(
            pilots.create, different, context="alice", actor="user:alice",
            resolve=resolve,
        )
        conflict = None
        try:
            conflicting.result(timeout=5)
        except RecordConflict as exc:
            conflict = exc
        finally:
            allow_save.set()
        assert conflict is not None and "operation reference" in str(conflict)
        first.result(timeout=5)
    monkeypatch.setattr(pilots.STORE, "create", original_create)
    admitted = pilots.create(
        {**different, "operation_id": "independent-unrelated-operation"},
        context="alice", actor="user:alice", resolve=resolve,
    )
    assert {case["reference"] for case in admitted["cases"]} == {"5", "6", "7", "8"}


def test_interrupted_case_admission_stays_pending_and_exact_retry_completes_once(
    records, monkeypatch,
):
    record = pilots.create(
        plan(), context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    original = accounting_bridge._admit
    admitted = []

    def interrupt(*args, **kwargs):
        saved = original(*args, **kwargs)
        admitted.append(saved["id"])
        if len(admitted) == 2:
            raise OSError("synthetic crash after strict admission prefix")
        return saved

    monkeypatch.setattr(accounting_bridge, "_admit", interrupt)
    with pytest.raises(OSError, match="strict admission prefix"):
        accounting_bridge.admit_pilot(
            record, resolve=lambda _kind, reference: records[reference],
        )
    pending = pilots.get(record["id"], "alice")
    assert pending["admission_manifest"]["status"] == "pending"
    assert accounting_bridge.default_service.portfolio_report()["admitted"] == 2
    with pytest.raises(OutcomePilotAdmissionRequired):
        require_work_item_admission("goal", "1")
    with pytest.raises(RecordConflict, match="Every frozen case"):
        pilots.observe(
            record["id"], "1", {}, context="alice", actor="user:alice",
            resolve=lambda _kind, reference: records[reference],
        )

    monkeypatch.setattr(accounting_bridge, "_admit", original)
    manifest = accounting_bridge.admit_pilot(
        pending, resolve=lambda _kind, reference: records[reference],
    )
    completed = pilots.complete_admission(
        record["id"], manifest, context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    assert completed["admission_manifest"]["status"] == "complete"
    assert completed["admission_manifest"]["admitted_count"] == 4
    assert accounting_bridge.default_service.portfolio_report()["admitted"] == 4
    assert require_work_item_admission("goal", "1")["pilot_id"] == record["id"]
    replayed = pilots.create(
        plan(), context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    replay_manifest = accounting_bridge.admit_pilot(
        replayed, resolve=lambda _kind, reference: records[reference],
    )
    replayed = pilots.complete_admission(
        replayed["id"], replay_manifest, context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    assert replayed["revision"] == completed["revision"]
    assert replay_manifest == manifest


def test_start_gate_allows_unclaimed_work_and_requires_every_durable_admission(records):
    pending = pilots.create(
        plan(), context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    assert require_work_item_admission("goal", "unclaimed-task") is None
    with pytest.raises(OutcomePilotAdmissionRequired, match="complete accounting admission"):
        require_work_item_admission("goal", "1")

    completed = finish_admission(pending, records)
    binding = require_work_item_admission("goal", "1")
    assert binding == {
        "pilot_id": completed["id"],
        "plan_version": completed["plan_version"],
        "completion_sha256": completed["admission_manifest"]["completion_sha256"],
    }

    entry = completed["admission_manifest"]["entries"][1]
    accounting = accounting_bridge.default_service.store.get(
        entry["accounting_record_id"],
    )
    assert accounting is not None
    assert accounting_bridge.default_service.store.delete(
        accounting["id"], expected_revision=accounting["revision"],
    )
    with pytest.raises(OutcomePilotAdmissionRequired, match="complete accounting admission"):
        require_work_item_admission("goal", "1")


def test_start_gate_claims_are_tenant_isolated(records):
    with tenant_scope(tenant="pilot-tenant"):
        pilots.create(
            plan(), context="alice", actor="user:alice",
            resolve=lambda _kind, reference: records[reference],
        )
        with pytest.raises(OutcomePilotAdmissionRequired):
            require_work_item_admission("goal", "1")
    with tenant_scope(tenant="different-tenant"):
        assert require_work_item_admission("goal", "1") is None


def test_common_goal_runtime_refuses_pending_pilot_before_any_episode(records):
    from maverick.budget import Budget
    from maverick.orchestrator import run_goal_sync

    world = world_model.WorldModel(world_model.DEFAULT_DB)
    goal_id = world.create_goal("Prepared pilot task", "Do not start yet")
    world.set_goal_status(goal_id, "blocked", result=sources.PREPARED)
    references = [str(goal_id), "runtime-extra-2", "runtime-extra-3", "runtime-extra-4"]
    runtime_records = {
        reference: {**records[str(index)], "input_version": f"runtime-{index}"}
        for index, reference in enumerate(references, start=1)
    }
    body = {
        **plan(),
        "operation_id": "runtime-start-gate-operation",
        "cases": [
            {"kind": "goal", "reference": reference, "label": f"Runtime case {index}"}
            for index, reference in enumerate(references, start=1)
        ],
    }
    pilots.create(
        body, context="alice", actor="user:alice",
        resolve=lambda _kind, reference: runtime_records[reference],
    )

    result = run_goal_sync(None, world, Budget(max_dollars=1), goal_id)
    current = world.get_goal(goal_id)
    assert result.startswith("BLOCKED: This work item belongs to an outcome pilot")
    assert current.status == "blocked" and current.result == sources.PREPARED
    assert world.list_episodes(goal_id=goal_id) == []
    world.close()


def test_goal_resume_api_blocks_pending_pilot_without_state_change_and_allows_exact_recovery(
    records, monkeypatch,
):
    from maverick_dashboard import api as dashboard_api

    world = world_model.WorldModel(world_model.DEFAULT_DB)
    goal_id = world.create_goal("Prepared pilot task", "Start only after admission")
    world.set_goal_status(goal_id, "blocked", result=sources.PREPARED)
    references = [str(goal_id), "resume-extra-2", "resume-extra-3", "resume-extra-4"]
    runtime_records = {
        reference: {**records[str(index)], "input_version": f"resume-{index}"}
        for index, reference in enumerate(references, start=1)
    }
    body = {
        **plan(),
        "operation_id": "resume-start-gate-operation",
        "cases": [
            {"kind": "goal", "reference": reference, "label": f"Resume case {index}"}
            for index, reference in enumerate(references, start=1)
        ],
    }
    pending = pilots.create(
        body, context="alice", actor="user:alice",
        resolve=lambda _kind, reference: runtime_records[reference],
    )
    dispatched = []

    async def run(*args, **kwargs):
        dispatched.append((args, kwargs))

    monkeypatch.setattr(dashboard_api, "_world", lambda: world)
    from maverick_dashboard import _shared
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    refused = client.post(f"/api/v1/goals/{goal_id}/resume")
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["code"] == "admission_hold"
    assert world.get_goal(goal_id).status == "blocked"
    assert world.get_goal(goal_id).result == sources.PREPARED
    assert not dispatched and world.list_episodes(goal_id=goal_id) == []

    finish_admission(pending, runtime_records)
    review = client.get(f"/api/v1/goals/{goal_id}/resume-review")
    assert review.status_code == 200, review.text
    state = review.json()
    body = {"operation_id": "e" * 32, "expected_context": state["context"],
            "expected_updated_at": state["expected_updated_at"],
            "expected_owner": state["expected_owner"]}
    resumed = client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["admitted"]
    assert world.get_goal(goal_id).status == "pending"
    assert len(dispatched) == 1
    world.close()


def protected_plan():
    return {**plan(), "learning_mode": "exclude_local_learning",
            "prior_exposure_statement": "Fresh task inputs checked against the local corpus; provider prior exposure remains unverified."}


def test_protected_plan_binds_exclusions_to_only_frozen_holdout_goals(records):
    from maverick import pilot_learning
    record = create_protected(records)
    assert record["state"] == "frozen"
    for case in record["cases"]:
        assert pilot_learning.excluded(int(case["reference"])) is (case["allocation"] == "holdout")
    report = pilots.report(record, resolve=lambda k, r: records[r])
    assert report["learning_policy"]["automatic_local_exclusion_enforced"] is True
    assert report["holdout_exposure_verified"] is False
    assert report["learning_policy"]["provider_training_verified"] is False
    held = next(case for case in record["cases"] if case["allocation"] == "holdout")
    records[held["reference"]]["input_version"] = "changed"
    assert not pilots.report(record, resolve=lambda k, r: records[r])["learning_policy"]["automatic_local_exclusion_enforced"]


def test_protected_preparation_resumes_exact_plan_after_interrupted_policy_publication(records, monkeypatch):
    from maverick import pilot_learning
    original = pilot_learning.protect
    failed = []
    def interrupt(*args, **kwargs):
        saved = original(*args, **kwargs)
        if not failed:
            failed.append(True)
            raise OSError("synthetic interruption after exclusion publication")
        return saved
    monkeypatch.setattr(pilot_learning, "protect", interrupt)
    with pytest.raises(OSError):
        pilots.create(protected_plan(), context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    pending = pilots.STORE.list()[0]
    assert pending["state"] == "preparing"
    assert not pilots.report(pending, resolve=lambda k, r: records[r])["learning_policy"]["automatic_local_exclusion_enforced"]
    resumed = create_protected(records)
    assert resumed["state"] == "frozen" and resumed["plan_version"] == pending["plan_version"]
    assert [case["allocation"] for case in resumed["cases"]] == [case["allocation"] for case in pending["cases"]]


@pytest.mark.parametrize("change,actor", [({"prior_exposure_statement": ""}, "user:alice"), ({}, "local:dashboard"),
    ({"cases": [{"kind": "vendor", "reference": str(i), "label": "Vendor"} for i in range(4)]}, "user:alice")])
def test_unsupported_protected_plan_cannot_claim_local_exclusion(records, change, actor):
    with pytest.raises(ValueError):
        pilots.create({**protected_plan(), **change}, context="alice", actor=actor, resolve=lambda k, r: records[r])
    assert pilots.listing("alice")["items"] == []


def test_independent_policy_review_requires_different_named_actor_current_evidence_and_confirmation(records):
    record = create_protected(records)
    report = pilots.report(record, resolve=lambda k, r: records[r])
    body = {"expected_revision": record["revision"], "operation_id": "independent-review-operation",
            "evidence_version": report["learning_policy"]["evidence_version"], "decision": "accepted_local_scope",
            "notes": "Checked frozen task exclusions and the owner's prior-exposure limits.", "confirm": True}
    with pytest.raises(PermissionError):
        pilots.independent_review(record["id"], body, actor="user:alice", resolve=lambda k, r: records[r])
    with pytest.raises(ValueError, match="confirm"):
        pilots.independent_review(record["id"], {**body, "confirm": False}, actor="user:bob", resolve=lambda k, r: records[r])
    saved = pilots.independent_review(record["id"], body, actor="user:bob", resolve=lambda k, r: records[r])
    assert pilots.report(saved, resolve=lambda k, r: records[r])["learning_policy"]["independent_review"]["current"]
    assert pilots.independent_review(record["id"], body, actor="user:bob", resolve=lambda k, r: records[r])["revision"] == saved["revision"]
    records["1"]["version"] = "changed-source"
    assert not pilots.report(saved, resolve=lambda k, r: records[r])["learning_policy"]["independent_review"]["current"]
    with pytest.raises(RecordConflict):
        pilots.independent_review(record["id"], {**body, "operation_id": "different-review-operation", "expected_revision": saved["revision"]}, actor="user:bob", resolve=lambda k, r: records[r])


def test_independent_review_api_requires_global_admin_and_reauthorizes_every_source(records, monkeypatch):
    from fastapi import HTTPException
    record = create_protected(records)
    monkeypatch.setattr(api, "context_for", lambda request: "bob")
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:bob")
    monkeypatch.setattr(api, "require_permission", lambda *a: None)
    resolutions = []

    def resolve_source(request, kind, reference, *, independent_review=False):
        resolutions.append((kind, reference, independent_review))
        return records[reference]

    # Exercise the native resolver's independent-review dispatch rather than
    # replacing it with a mock that silently omits the authority mode.
    monkeypatch.setattr(sources, "resolve", resolve_source)
    route = "/api/v1/outcome-pilots/independent-review/" + record["id"]
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Lightwork-Pilot-Context": "bob"})
    def denied(*_a):
        raise HTTPException(403, "Global administrator required")
    monkeypatch.setattr(api, "require_global_permission", denied)
    assert client.get(route).status_code == 403
    assert resolutions == []
    monkeypatch.setattr(api, "require_global_permission", lambda *a: None)
    packet = client.get(route)
    assert packet.status_code == 200 and packet.json()["context"] == "bob"
    assert {reference for _, reference, _ in resolutions} == set(records)
    resolutions.clear()
    body = {"expected_revision": record["revision"], "operation_id": "actual-api-review-operation",
            "evidence_version": packet.json()["learning_policy"]["evidence_version"], "decision": "accepted_local_scope",
            "notes": "Independent local policy evidence checked; provider limitations retained.", "confirm": True}
    assert client.post(route, json=body).status_code == 200
    assert {(kind, reference) for kind, reference, _ in resolutions} == {
        ("goal", reference) for reference in records
    }
    assert all(independent for _, _, independent in resolutions)

    def source_revoked(*_a, **_kwargs):
        raise PermissionError("Revoked source")
    monkeypatch.setattr(sources, "resolve", source_revoked)
    assert client.get(route).status_code == 403
    assert client.post(route, json=body).status_code == 403
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:alice")
    assert client.get(route).status_code == 403


@pytest.mark.parametrize("problem", ["started", "duplicate"])
def test_plan_refuses_post_outcome_selection_or_repeated_case(records, problem):
    body = plan()
    if problem == "started":
        records["1"]["unstarted"] = False
    else:
        body["cases"][1] = body["cases"][0]
    with pytest.raises(ValueError):
        pilots.create(body, context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    assert pilots.listing("alice")["items"] == []


def test_rejected_and_missing_cases_stay_in_denominator_cost_not_invented(records):
    record = create(records)
    records["1"].update(finished=True, accepted=False, version="b" * 64)
    saved = pilots.observe(record["id"], "1", observation(record["revision"]),
        context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    result = pilots.report(saved, resolve=lambda k, r: records[r])
    assert result["groups"]["all"]["planned"] == 4
    assert result["groups"]["all"]["paired"] == 1
    assert result["groups"]["all"]["accepted"] == 0
    assert result["groups"]["all"]["reported_minutes_difference"] == 55
    assert result["groups"]["all"]["reported_cost_difference"] is None
    assert result["evidence_readiness"]["reported_effort_comparison_ready"] is False
    assert result["evidence_readiness"]["reported_cost_comparison_ready"] is False
    assert result["provider_invoice_verified"] is False
    assert result["holdout_exposure_verified"] is False
    records["1"]["version"] = "c" * 64
    assert pilots.report(saved, resolve=lambda k, r: records[r])["cases"][0]["status"] == "stale"


def test_observation_cas_and_retry_identity_preserve_history(records):
    record = create(records)
    records["1"].update(finished=True, version="b" * 64)
    body = observation(record["revision"])
    saved = pilots.observe(record["id"], "1", body, context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    assert pilots.observe(record["id"], "1", body, context="alice", actor="user:alice", resolve=lambda k, r: records[r])["revision"] == saved["revision"]
    with pytest.raises(RecordConflict):
        pilots.observe(record["id"], "1", {**body, "note": "Different measurement"}, context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    with pytest.raises(RecordConflict):
        pilots.observe(record["id"], "1", {**body, "operation_id": "new-observation-operation"}, context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    revised = pilots.observe(record["id"], "1", {**body, "operation_id": "new-observation-operation", "expected_revision": saved["revision"], "review_minutes": 20.},
        context="alice", actor="user:alice", resolve=lambda k, r: records[r])
    assert revised["cases"][0]["history"][0]["review_minutes"] == 10
    assert revised["cases"][0]["measurement"]["review_minutes"] == 20


def test_account_tenant_and_revoked_source_never_expose_observations(records):
    record = create(records)
    with pytest.raises(LookupError):
        pilots.get(record["id"], "bob")
    assert not pilots.listing("bob")["items"]
    with tenant_scope(tenant="other-tenant"):
        with pytest.raises(LookupError):
            pilots.get(record["id"], "alice")
    def revoked(*args):
        raise PermissionError("Private customer data")
    result = pilots.report(record, resolve=revoked)
    assert result["cases"][0] == {"id": "1", "allocation": record["cases"][0]["allocation"], "status": "unavailable"}
    assert result["groups"]["all"]["unavailable"] == 4
    assert "Private customer data" not in str(result)


def test_listing_filters_before_paging_through_interleaved_foreign_contexts(monkeypatch):
    records = {}
    identifiers = []
    alice_indexes = {3, 204, 249}
    for index in range(250):
        record_id = f"OPL-page-{index:04d}"
        backend_cursor = record_id + ".json"
        identifiers.append((backend_cursor, record_id))
        records[record_id] = {
            "id": record_id,
            "title": f"Pilot {index}",
            "revision": 1,
            "created_at": float(index + 1),
            "cases": [{"id": "one"}],
            "context": "alice" if index in alice_indexes else f"foreign-{index}",
        }

    def iter_record_ids(*, start_after="", limit=100):
        pivot = next(
            (position for position, row in enumerate(identifiers) if row[0] > start_after),
            len(identifiers),
        )
        yield from (identifiers[pivot:] + identifiers[:pivot])[:limit]

    monkeypatch.setattr(pilots.STORE, "iter_record_ids", iter_record_ids)
    monkeypatch.setattr(pilots.STORE, "get", records.get)

    first = pilots.listing("alice", limit=2)
    assert [row["id"] for row in first["items"]] == [
        "OPL-page-0003", "OPL-page-0204",
    ]
    assert first["partial"] is True
    assert first["page"] == {
        "has_more": True,
        "next_cursor": "OPL-page-0204.json",
    }
    assert "foreign-" not in str(first)

    second = pilots.listing(
        "alice", limit=2, cursor=first["page"]["next_cursor"],
    )
    assert [row["id"] for row in second["items"]] == ["OPL-page-0249"]
    assert second["partial"] is False
    assert second["page"] == {"has_more": False, "next_cursor": None}
    assert "foreign-" not in str(second)


@pytest.mark.parametrize("change,expected", [({"input_version": "changed"}, "inputs_changed"),
    ({"first_started_at": 1}, "started_before_plan"), ({"sample": True}, "sample")])
def test_invalid_pairs_do_not_enter_comparison(records, change, expected):
    record = create(records)
    records["1"].update(change)
    result = pilots.report(record, resolve=lambda k, r: records[r])
    assert result["cases"][0]["status"] == expected
    assert result["groups"]["all"]["paired"] == 0


@pytest.mark.parametrize("values", [{"baseline_minutes": float("nan")}, {"corrections": 1.5},
    {"baseline_cost": "100"}, {"ai_total_cost": "-1", "currency": "USD"}, {"baseline_cost": "1e8", "currency": "USD"}])
def test_invalid_or_ambiguous_measurements_are_rejected(values):
    body = observation(1)
    body.update(values)
    with pytest.raises(ValueError):
        api.ObservationIn.model_validate(body)


def test_api_context_validation_and_rendered_page(records, monkeypatch):
    monkeypatch.setattr(api, "context_for", lambda request: "alice")
    monkeypatch.setattr(api, "require_permission", lambda *a: None)
    monkeypatch.setattr(api, "_resolver", lambda request: lambda k, r: records[r])
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/outcome-pilots").status_code == 200
    assert client.post("/api/v1/outcome-pilots", json=plan()).status_code == 409
    response = client.post("/api/v1/outcome-pilots", json=plan(), headers={"X-Lightwork-Pilot-Context": "alice"})
    assert response.status_code == 200
    identifier = response.json()["id"]
    stored = pilots.get(identifier, "alice")
    page = client.get("/api/v1/outcome-pilots?limit=1").json()
    assert page["items"][0]["id"] == identifier
    assert page["page"] == {"has_more": False, "next_cursor": None}
    assert client.get("/api/v1/outcome-pilots?cursor=%2Fprivate").status_code == 422
    assert stored["admission_manifest"]["status"] == "complete"
    assert stored["admission_manifest"]["admitted_count"] == len(stored["cases"])
    report = client.get("/api/v1/outcome-pilots/" + identifier)
    assert report.status_code == 200 and report.headers["Cache-Control"] == "private, no-store", report.text
    assert report.json()["groups"]["all"]["planned"] == 4
    assert report.json()["admission"] == {
        "status": "complete", "expected_count": 4, "admitted_count": 4,
        "manifest_sha256": stored["admission_manifest"]["manifest_sha256"],
        "completion_sha256": stored["admission_manifest"]["completion_sha256"],
    }
    monkeypatch.setattr(api, "context_for", lambda request: "bob")
    assert client.get("/api/v1/outcome-pilots/" + identifier).status_code == 404
    assert client.get("/static/lightwork-outcome-pilots.js").status_code == 200


def test_observation_api_refuses_pending_manifest_before_mutating_pilot(records, monkeypatch):
    monkeypatch.setattr(api, "context_for", lambda request: "alice")
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    # Observations are recorded by the pilot's own account.
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:alice")
    monkeypatch.setattr(api, "_resolver", lambda request: lambda kind, reference: records[reference])
    record = pilots.create(
        plan(), context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={
        "Origin": "http://127.0.0.1", "X-Lightwork-Pilot-Context": "alice",
    })
    response = client.put(
        f"/api/v1/outcome-pilots/{record['id']}/cases/1",
        json=observation(record["revision"]),
    )
    assert response.status_code == 409
    assert "Every frozen case must be admitted" in response.json()["detail"]
    current = pilots.get(record["id"], "alice")
    assert current["revision"] == record["revision"]
    assert all(case["measurement"] is None for case in current["cases"])


def test_report_api_resumes_a_pending_all_case_admission_inside_the_app(records, monkeypatch):
    monkeypatch.setattr(api, "context_for", lambda request: "alice")
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    monkeypatch.setattr(api, "_resolver", lambda request: lambda kind, reference: records[reference])
    pending = pilots.create(
        plan(), context="alice", actor="user:alice",
        resolve=lambda _kind, reference: records[reference],
    )
    client = TestClient(app, base_url="http://127.0.0.1", headers={
        "Origin": "http://127.0.0.1", "X-Lightwork-Pilot-Context": "alice",
    })
    response = client.get(f"/api/v1/outcome-pilots/{pending['id']}")
    assert response.status_code == 200, response.text
    completed = pilots.get(pending["id"], "alice")
    assert completed["admission_manifest"]["status"] == "complete"
    assert completed["admission_manifest"]["admitted_count"] == 4
    assert response.json()["revision"] == completed["revision"]


def test_create_api_exact_retry_repairs_interrupted_all_case_admission(records, monkeypatch):
    monkeypatch.setattr(api, "context_for", lambda request: "alice")
    monkeypatch.setattr(api, "require_permission", lambda *args: None)
    monkeypatch.setattr(api, "_resolver", lambda request: lambda kind, reference: records[reference])
    original = accounting_bridge._admit
    admitted = []

    def interrupt(*args, **kwargs):
        saved = original(*args, **kwargs)
        admitted.append(saved["id"])
        if len(admitted) == 2:
            raise OSError("synthetic API admission crash")
        return saved

    monkeypatch.setattr(accounting_bridge, "_admit", interrupt)
    client = TestClient(app, base_url="http://127.0.0.1", headers={
        "Origin": "http://127.0.0.1", "X-Lightwork-Pilot-Context": "alice",
    })
    failed = client.post("/api/v1/outcome-pilots", json=plan())
    assert failed.status_code == 503
    pending = pilots.STORE.list()
    assert len(pending) == 1
    assert pending[0]["admission_manifest"]["status"] == "pending"
    assert accounting_bridge.default_service.portfolio_report()["admitted"] == 2

    monkeypatch.setattr(accounting_bridge, "_admit", original)
    # An exact retry is a read of the original request, never a second
    # admission: while the original is unconfirmed it says so and repeats nothing.
    unconfirmed = client.post("/api/v1/outcome-pilots", json=plan())
    assert unconfirmed.status_code == 503
    assert accounting_bridge.default_service.portfolio_report()["admitted"] == 2
    # Opening the pilot's report repairs the interrupted all-case admission
    # inside the app; the exact retry then confirms the same original pilot.
    assert client.get("/api/v1/outcome-pilots/" + pending[0]["id"]).status_code == 200
    recovered = client.post("/api/v1/outcome-pilots", json=plan())
    assert recovered.status_code == 200, recovered.text
    saved = pilots.get(recovered.json()["id"], "alice")
    assert saved["admission_manifest"]["status"] == "complete"
    assert saved["admission_manifest"]["admitted_count"] == 4
    assert accounting_bridge.default_service.portfolio_report()["admitted"] == 4
    replayed = client.post("/api/v1/outcome-pilots", json=plan())
    assert replayed.status_code == 200
    assert replayed.json()["id"] == recovered.json()["id"]
    assert replayed.json()["revision"] == recovered.json()["revision"]


def test_goal_acceptance_requires_current_human_signoff_and_suite(monkeypatch):
    goal = SimpleNamespace(id=1, title="Private", description="Evidence", domain="privacy", result="Answer", status="done")
    decision = {"decision": "approved", "decided_by": "agent:reviewer"}
    world = SimpleNamespace(get_goal=lambda i: goal, list_episodes=lambda **k: [], signoff_for=lambda i: copy.deepcopy(decision))
    monkeypatch.setattr("maverick_dashboard.app._world", lambda: world)
    monkeypatch.setattr(sources, "domain_suites_allowed", lambda *a: True)
    monkeypatch.setattr(sources, "can_access_goal", lambda *a: True)
    monkeypatch.setattr(sources, "suite_allowed", lambda *a: True)
    monkeypatch.setattr(sources, "caller_principal", lambda *a: "user:alice")
    assert not sources.goal_source(None, "1")["accepted"]
    decision["decided_by"] = "user:bob"
    old = sources.goal_source(None, "1")
    assert old["accepted"]
    goal.result = "Revised result"
    decision.clear()
    assert not sources.goal_source(None, "1")["accepted"]
    assert sources.goal_source(None, "1")["version"] != old["version"]
    monkeypatch.setattr(sources, "domain_suites_allowed", lambda *a: False)
    with pytest.raises(LookupError):
        sources.goal_source(None, "1")


def test_prepare_task_in_app_is_private_idempotent_and_does_not_run(monkeypatch):
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    monkeypatch.setattr("maverick_dashboard.app._world", lambda: world)
    monkeypatch.setattr("maverick_dashboard.app._deliverable_specs", lambda: [{"domain": "finance_sox", "gate": "human", "suite": "finance"}])
    monkeypatch.setattr("maverick.domain.enabled_domains", lambda: {
        "finance_sox": SimpleNamespace(name="finance_sox"),
    })
    monkeypatch.setattr(sources, "suite_allowed", lambda *a: True)
    monkeypatch.setattr(sources, "caller_principal", lambda *a: "user:alice")
    monkeypatch.setattr(sources, "can_access_goal", lambda request, goal: goal.owner == "user:alice")
    body = {"operation_id": "prepare-task-reference", "title": "Assess controls", "description": "Review the supplied control evidence.", "domain": "finance_sox"}
    saved = sources.prepare_task(None, body, "alice")
    assert sources.prepare_task(None, body, "alice")["id"] == saved["id"]
    goal = world.get_goal(saved["id"])
    assert goal.owner == "user:alice"
    assert goal.status == "blocked" and goal.result == sources.PREPARED
    assert world.list_episodes(goal_id=goal.id) == []
    source = sources.goal_source(None, str(goal.id))
    assert source["unstarted"] and not source["finished"] and not source["accepted"]
    with pytest.raises(ValueError, match="different task inputs"):
        sources.prepare_task(None, {**body, "description": "Changed after an uncertain response"}, "alice")
    assert len(world.list_goals()) == 1
    monkeypatch.setattr(sources, "suite_allowed", lambda *a: False)
    with pytest.raises(PermissionError):
        sources.prepare_task(None, body, "alice")


def test_total_cost_per_accepted_includes_rejected_cases_and_requires_complete_coverage(records):
    record = create(records)
    coverage = {family: {"status": "included", "note": "Recorded in the total-cost source."}
                for family in COST_COVERAGE_FAMILIES}
    for number in range(1, 5):
        records[str(number)].update(finished=True, accepted=number == 1, version="b" * 64)
        body = observation(record["revision"], baseline_cost="100", ai_total_cost="25", currency="USD", criteria_met=number == 1,
                           cost_coverage=coverage)
        body["operation_id"] = "observation-operation-" + str(number)
        record = pilots.observe(record["id"], str(number), body, context="alice", actor="user:alice", resolve=lambda k, r: records[r])
        group = pilots.report(record, resolve=lambda k, r: records[r])["groups"]["all"]
        if number < 4:
            assert group["reported_ai_cost_per_accepted"] is None
    assert group["accepted"] == 1 and group["criteria_met"] == 1
    assert group["reported_ai_cost_per_accepted"] == "100"
    assert group["reported_cost_difference"] == "300"
    assert group["acceptance_rate"] == .25
    readiness = pilots.report(record, resolve=lambda k, r: records[r])["evidence_readiness"]
    assert readiness["reported_effort_comparison_ready"] is True
    assert readiness["frozen_criteria_review_ready"] is True
    assert readiness["reported_cost_comparison_ready"] is True
    assert readiness["causal_release_lift_qualified"] is False


def test_review_queue_lists_other_peoples_protected_pilots_in_this_workspace_only(records, monkeypatch):
    from fastapi import HTTPException
    protected = create_protected(records)
    assert protected["state"] == "frozen"
    queue = pilots.review_queue("user:bob")
    assert [item["id"] for item in queue] == [protected["id"]]
    assert set(queue[0]) == {"id", "title", "frozen_at", "decision"}
    assert pilots.review_queue("user:alice") == []          # never your own pilot
    assert pilots.review_queue("local:dashboard") == []     # a named account only
    with tenant_scope(tenant="different-tenant"):
        assert pilots.review_queue("user:bob") == []

    monkeypatch.setattr(api, "context_for", lambda request: "bob")
    monkeypatch.setattr(api, "caller_principal", lambda request: "user:bob")
    monkeypatch.setattr(api, "require_permission", lambda *a: None)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "X-Lightwork-Pilot-Context": "bob"})
    route = "/api/v1/outcome-pilots/independent-review"

    def denied(*_a):
        raise HTTPException(403, "Global administrator required")

    monkeypatch.setattr(api, "require_global_permission", denied)
    assert client.get(route).status_code == 403
    monkeypatch.setattr(api, "require_global_permission", lambda *a: None)
    listed = client.get(route)
    assert listed.status_code == 200
    assert listed.headers["cache-control"] == "private, no-store"
    assert listed.json() == {"items": queue, "context": "bob"}
    monkeypatch.setattr(api, "caller_principal", lambda request: "local:dashboard")
    assert client.get(route).status_code == 403


def test_goal_choices_match_goal_by_goal_reads(tmp_path, monkeypatch):
    # The goal branch reads each visible goal's newest run in one batch. The
    # goals it offers, and the coverage, must equal the goal-by-goal reads.
    from maverick.world_model import WorldModel
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import vendor_onboarding_api

    world = WorldModel(tmp_path / "w.db")
    prepared = [world.create_goal(f"prepared {i}", owner="user:alice") for i in range(6)]
    busy = [world.create_goal(f"busy {i}", owner="user:alice") for i in range(3)]
    with world._writing() as conn:
        for gid in prepared[:2]:   # blocked and prepared for a pilot, with no runs
            conn.execute("UPDATE goals SET status = 'blocked', result = ? WHERE id = ?",
                         (sources.PREPARED, gid))
        for gid in busy:           # pending goals that already have a run
            conn.execute("INSERT INTO episodes(goal_id, started_at, cost_dollars, outcome) "
                         "VALUES (?, ?, ?, ?)", (gid, 1_000.0, 0.02, "done"))
    request = SimpleNamespace()
    monkeypatch.setattr(dashboard_app, "_world", lambda: world)
    monkeypatch.setattr(dashboard_app, "_deliverable_specs", list)
    monkeypatch.setattr(sources, "goal_owner_filter", lambda _request: None)
    monkeypatch.setattr(sources, "can_access_goal", lambda _request, goal: goal.id % 5 != 0)
    monkeypatch.setattr(sources, "domain_suites_allowed", lambda _request, _domain: True)
    monkeypatch.setattr(vendor_onboarding_api, "_binding", lambda _request: None)
    monkeypatch.setattr(vendor_onboarding_api, "_call", lambda *_args, **_kwargs: [])
    batched = sources.choices(request)
    monkeypatch.setattr(world_model, "episodes_by_goal_batch", lambda *_args, **_kwargs: None)
    goal_by_goal = sources.choices(request)
    assert batched == goal_by_goal
    offered = [item["reference"] for item in batched["items"] if item["kind"] == "goal"]
    assert offered == [str(gid) for gid in sorted(prepared, reverse=True) if gid % 5 != 0]
    assert offered
