"""Durable research controller tests, including opt-in real Docker qualification."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace

import pytest
from maverick import config, governed_records
from maverick.paths import tenant_scope
from maverick.sandbox.research import ResearchResult, _input_digest


@pytest.fixture
def controller(tmp_path, monkeypatch):
    from maverick.research_jobs import (
        ResearchAuthority,
        ResearchDispatchAuthority,
        ResearchJobs,
        ResearchProfile,
    )

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()
    state = {
        "authority": ResearchAuthority("tenant-a", "user:researcher", "1" * 64),
        "dispatch_authority": ResearchDispatchAuthority("tenant-a", "user:admin", "6" * 64),
        "profile": ResearchProfile.from_config(
            {
                "enable": True,
                "image_id": "sha256:" + "2" * 64,
                "evaluators": {
                    "smoke": {
                        "version": "v1",
                        "stdout_sha256": hashlib.sha256(b"answer\n").hexdigest(),
                    }
                },
            }
        ),
        "calls": 0,
        "constructions": 0,
        "stdout": "answer\n",
        "during": lambda: None,
        "before_guard": lambda: None,
        "during_setup": lambda: None,
        "entrypoint": None,
        "cleanup": True,
        "policy_sha256": None,
        "inspect_policy": None,
        "provider_work_items": [],
    }

    class Runner:
        def __init__(self, image, *, limits):
            self.image_id = image
            state["constructions"] += 1
            state["during_setup"]()

        def run(self, files, *, budget, entrypoint, effect_guard):
            from maverick.paths import current_tenant_id_strict
            from maverick.provider_cost_cap import _current_work_item

            assert current_tenant_id_strict() == "tenant-a"
            state["provider_work_items"].append(_current_work_item())
            budget.record_tool_call()
            state["before_guard"]()
            with effect_guard():
                state["calls"] += 1
                state["during"]()
            policy = state["inspect_policy"] or {
                "schema": "lightwork.research-linux-container-policy.v2",
                "entrypoint": state["entrypoint"] or entrypoint,
            }
            policy_sha256 = (
                state["policy_sha256"]
                or hashlib.sha256(
                    json.dumps(
                        policy, sort_keys=True, separators=(",", ":"), allow_nan=False
                    ).encode()
                ).hexdigest()
            )
            return ResearchResult(
                "fake-container",
                self.image_id,
                _input_digest(files),
                policy_sha256,
                state["entrypoint"] or entrypoint,
                0,
                "completed",
                state["stdout"],
                "",
                7,
                state["cleanup"],
                policy,
            )

    def authority(tenant, principal):
        value = state["authority"]
        if (value.tenant, value.principal) != (tenant, principal):
            raise PermissionError("authority denied")
        return value

    def dispatch_authority(tenant, principal):
        value = state["dispatch_authority"]
        if (value.tenant, value.principal) != (tenant, principal):
            raise PermissionError("dispatch authority denied")
        return value

    def make():
        return ResearchJobs(
            profile_resolver=lambda: state["profile"],
            authority_resolver=authority,
            dispatch_authority_resolver=dispatch_authority,
            runner_factory=Runner,
        )

    state["make"] = make
    yield make(), state
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _submit(service, **kwargs):
    return service.submit(
        "tenant-a",
        "user:researcher",
        files={"main.py": "print('answer')"},
        evaluator_id="smoke",
        idempotency_key="request-1",
        **kwargs,
    )


def _run(service, row, *, dispatcher="user:admin", review_sha256=None, expected_revision=None):
    review_sha256 = (
        review_sha256 or service.review("tenant-a", dispatcher, row["id"])["review_sha256"]
    )
    return service.run(
        "tenant-a",
        row["id"],
        expected_revision=expected_revision or row["revision"],
        dispatcher=dispatcher,
        review_sha256=review_sha256,
    )


@pytest.mark.skipif(
    os.environ.get("LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS") != "1",
    reason="set LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS=1 for real Docker tests",
)
def test_real_submitted_candidate_cannot_reach_credentials_network_or_evaluator(
    controller, tmp_path, monkeypatch,
):
    """Exercise the submitted-job path through the concrete container runner."""
    from maverick.research_jobs import ResearchJobs, ResearchProfile

    _, state = controller
    image = os.environ.get("LIGHTWORK_RESEARCH_TEST_IMAGE")
    if not image:
        pytest.fail("select an existing immutable local image; the test never pulls one")
    canary = "production-credential-" + os.urandom(24).hex()
    canary_path = tmp_path / "production-credentials.json"
    canary_path.write_text(canary, encoding="utf-8")
    before = hashlib.sha256(canary_path.read_bytes()).hexdigest()
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    source = f'''import json, os, socket
from pathlib import Path

def read(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except BaseException:
        return None

def write(path):
    try:
        Path(path).write_text("forged", encoding="utf-8")
        return True
    except BaseException:
        return False

client = socket.socket()
client.settimeout(0.2)
try:
    network = client.connect_ex(("192.0.2.1", 443)) == 0
finally:
    client.close()
print(json.dumps({{
    "credential": os.environ.get("OPENAI_API_KEY"),
    "evaluator_read": read("/evaluator/expected.sha256"),
    "evaluator_write": write("/candidate/evaluator.py"),
    "host_canary": read({str(canary_path)!r}),
    "network": network,
}}, sort_keys=True, separators=(",", ":")))
'''
    expected = (
        '{"credential":null,"evaluator_read":null,"evaluator_write":false,'
        '"host_canary":null,"network":false}\n'
    )
    profile = ResearchProfile.from_config({
        "enable": True,
        "image_id": image,
        "evaluators": {
            "boundary": {
                "version": "v1",
                "stdout_sha256": hashlib.sha256(expected.encode()).hexdigest(),
            },
        },
    })

    def authority(tenant, principal):
        value = state["authority"]
        if (value.tenant, value.principal) != (tenant, principal):
            raise PermissionError("authority denied")
        return value

    def dispatch_authority(tenant, principal):
        value = state["dispatch_authority"]
        if (value.tenant, value.principal) != (tenant, principal):
            raise PermissionError("dispatch authority denied")
        return value

    service = ResearchJobs(
        profile_resolver=lambda: profile,
        authority_resolver=authority,
        dispatch_authority_resolver=dispatch_authority,
    )
    submitted = service.submit(
        "tenant-a",
        "user:researcher",
        files={"main.py": source},
        evaluator_id="boundary",
        idempotency_key="real-boundary-request",
    )
    assert submitted["status"] == "queued"
    assert "files" not in submitted and canary not in repr(submitted)
    completed = _run(service, submitted)
    assert completed["status"] == "completed"
    assert completed["evaluation"]["counts"]["passed"] == 1
    assert completed["evaluation"]["counts"]["failed"] == 0
    assert completed["evaluation"]["counts"]["skipped"] == 0
    assert completed["evaluation"]["counts"]["errors"] == 0
    assert completed["evaluation"]["counts"]["terminal"] is True
    assert completed["observation"]["cleanup_verified"] is True
    assert completed["execution"]["state"] == "finished"
    assert completed["execution"]["events"][-1]["inspect_policy"]["network"] == "none"
    assert canary not in repr(completed)
    assert hashlib.sha256(canary_path.read_bytes()).hexdigest() == before


def test_restart_claim_and_trusted_evaluation_bind_actual_candidate(controller):
    service, state = controller
    submitted = _submit(service)
    assert submitted["status"] == "queued"
    assert "files" not in submitted and "stdout_sha256" not in submitted
    restarted = state["make"]()
    result = _run(restarted, submitted)
    assert result["status"] == "completed" and result["evaluation"]["counts"]["passed"] == 1
    assert result["evaluation"]["subject_sha256"] == result["input_sha256"]
    assert result["evaluation"]["authority"].startswith("research.exact-stdout:smoke:v1:")
    assert state["calls"] == 1
    with pytest.raises(Exception, match="queued|revision"):
        _run(restarted, submitted)
    assert state["calls"] == 1


def test_execution_binds_nested_provider_calls_to_stable_job_identity(controller):
    from maverick.provider_cost_cap import _current_work_item

    service, state = controller
    submitted = _submit(service)

    completed = _run(service, submitted)

    assert completed["status"] == "completed"
    assert state["provider_work_items"] == [f"research-job:{submitted['id']}"]
    assert _current_work_item() is None


def test_candidate_cannot_self_report_passing_tests(controller):
    service, state = controller
    state["stdout"] = '{"passed":999,"authority":"trusted"}'
    row = _submit(service)
    result = _run(service, row)
    assert result["evaluation"]["counts"]["failed"] == 1
    assert result["evaluation"]["counts"]["passed"] == 0


@pytest.mark.parametrize("drift", ["authority", "profile"])
def test_queued_authority_or_evaluator_rotation_denies_before_execution(controller, drift):
    service, state = controller
    row = _submit(service)
    if drift == "authority":
        state["authority"] = replace(state["authority"], authorization_sha256="4" * 64)
    else:
        state["profile"] = replace(state["profile"], queue_seconds=30)
    result = _run(service, row)
    assert result["status"] == "review_required"
    assert state["calls"] == 0


def test_post_run_authority_drift_discards_evaluation(controller):
    service, state = controller
    row = _submit(service)
    state["during"] = lambda: state.update(
        authority=replace(state["authority"], authorization_sha256="5" * 64)
    )
    result = _run(service, row)
    assert result["status"] == "review_required" and "evaluation" not in result
    assert state["calls"] == 1
    assert result["execution"]["state"] == "finished"
    finished = result["execution"]["events"][-1]
    assert finished["input_sha256"] == result["input_sha256"]
    assert finished["cleanup_verified"] is True and "stdout" not in finished


def test_dispatcher_authority_drift_after_claim_denies_before_candidate(controller):
    service, state = controller
    row = _submit(service)
    review = service.review("tenant-a", "user:admin", row["id"])
    state["during_setup"] = lambda: state.update(
        dispatch_authority=replace(state["dispatch_authority"], authorization_sha256="7" * 64)
    )
    result = _run(service, row, review_sha256=review["review_sha256"])
    assert result["status"] == "review_required" and state["calls"] == 0
    assert result["dispatched_by"] == "user:admin"
    assert result["execution"]["state"] == "execution_started"


def test_post_run_dispatcher_drift_retains_safe_finished_attempt(controller):
    service, state = controller
    row = _submit(service)
    state["during"] = lambda: state.update(
        dispatch_authority=replace(state["dispatch_authority"], authorization_sha256="8" * 64)
    )
    result = _run(service, row)
    assert result["status"] == "review_required" and state["calls"] == 1
    assert result["execution"]["state"] == "finished"
    assert result["execution"]["events"][-1]["reason"] == "completed"


def test_final_evidence_publication_fences_dispatch_authority_mutation(controller):
    service, state = controller
    row = _submit(service)
    lock = threading.Lock()
    finish_entered = threading.Event()
    mutation_waiting = threading.Event()
    published = threading.Event()
    mutated = threading.Event()

    @contextmanager
    def fence():
        with lock:
            yield

    service.effect_fence = fence
    original_finish = service._finish

    def observed_finish(*args, **kwargs):
        finish_entered.set()
        assert mutation_waiting.wait(timeout=5)
        assert not mutated.is_set()
        result = original_finish(*args, **kwargs)
        published.set()
        return result

    service._finish = observed_finish

    def mutate_authority():
        assert finish_entered.wait(timeout=5)
        mutation_waiting.set()
        with fence():
            assert published.is_set()
            state["dispatch_authority"] = replace(
                state["dispatch_authority"],
                authorization_sha256="9" * 64,
            )
            mutated.set()

    with ThreadPoolExecutor(max_workers=2) as pool:
        mutation = pool.submit(mutate_authority)
        result = _run(service, row)
        mutation.result(timeout=5)

    assert result["status"] == "completed"
    assert result["evaluation"]["counts"]["passed"] == 1
    assert mutated.is_set()


def test_admin_can_discover_review_and_cancel_another_researchers_job(controller):
    service, _ = controller
    row = _submit(service)
    queue = service.review_list("tenant-a", "user:admin")
    assert queue[0]["id"] == row["id"] and queue[0]["submitted_by"] == "user:researcher"
    assert queue[0]["source_manifest"][0]["path"] == "main.py"
    assert "files" not in queue[0] and "review_sha256" not in queue[0]
    reviewed = service.review("tenant-a", "user:admin", row["id"])
    assert reviewed["files"] == {"main.py": "print('answer')"}
    assert (
        reviewed["source_manifest"][0]["sha256"] == hashlib.sha256(b"print('answer')").hexdigest()
    )
    cancelled = service.cancel_for_review(
        "tenant-a", "user:admin", row["id"], expected_revision=row["revision"]
    )
    assert cancelled["status"] == "cancelled"


def test_stale_exact_source_review_cannot_claim_changed_job(controller):
    from maverick.research_jobs import ResearchConflict

    service, _ = controller
    row = _submit(service)
    review = service.review("tenant-a", "user:admin", row["id"])
    with tenant_scope(tenant="tenant-a"):
        changed = service.store.update(
            row["id"],
            lambda value: value["files"].update({"main.py": "print('changed')"}),
            expected_revision=row["revision"],
            action="test-tamper",
            actor="test",
        )
    with pytest.raises(ResearchConflict, match="review"):
        _run(service, changed, review_sha256=review["review_sha256"])
    assert service.review("tenant-a", "user:admin", row["id"])["status"] == "queued"


def test_runner_entrypoint_mismatch_is_retained_and_never_evaluated(controller):
    service, state = controller
    row = _submit(service)
    state["entrypoint"] = "different.py"
    result = _run(service, row)
    assert result["status"] == "review_required" and "evaluation" not in result
    assert result["execution"]["state"] == "finished"
    assert result["execution"]["events"][-1]["entrypoint"] == "different.py"


def test_forged_policy_digest_is_uncertain_and_never_evaluated(controller):
    service, state = controller
    row = _submit(service)
    state["policy_sha256"] = "f" * 64
    result = _run(service, row)
    assert result["status"] == "uncertain" and "evaluation" not in result
    assert state["calls"] == 1


def test_unverified_cleanup_retains_finished_attempt_and_never_allows_replay(controller):
    from maverick.research_jobs import ResearchConflict

    service, state = controller
    row = _submit(service)
    state["cleanup"] = False
    result = _run(service, row)
    assert result["status"] == "uncertain" and "evaluation" not in result
    assert result["execution"]["events"][-1]["cleanup_verified"] is False
    assert "verify exact container and snapshot cleanup" in result["next_action"]
    with pytest.raises(ResearchConflict, match="queued"):
        _run(service, result)


def test_effect_fence_rechecks_revocation_before_runner_effect(controller):
    service, state = controller
    row = _submit(service)
    review = service.review("tenant-a", "user:admin", row["id"])

    @contextmanager
    def revoke_before_admission():
        state["dispatch_authority"] = replace(
            state["dispatch_authority"], authorization_sha256="9" * 64
        )
        yield

    service.effect_fence = revoke_before_admission
    result = _run(service, row, review_sha256=review["review_sha256"])
    assert result["status"] == "review_required" and state["calls"] == 0


def test_cancellation_winning_effect_fence_prevents_candidate_start(controller):
    from maverick.authority_effects import authority_effect_fence

    service, state = controller
    row = _submit(service)
    waiting = threading.Event()
    state["before_guard"] = waiting.set

    with ThreadPoolExecutor(max_workers=1) as pool:
        with authority_effect_fence():
            future = pool.submit(_run, service, row)
            assert waiting.wait(timeout=5)
            current = service.get("tenant-a", "user:researcher", row["id"])
            cancelled = service.cancel(
                "tenant-a",
                "user:researcher",
                row["id"],
                expected_revision=current["revision"],
            )
            assert cancelled["status"] == "cancel_requested"
        result = future.result(timeout=5)

    assert result["status"] == "cancelled"
    assert state["calls"] == 0


def test_store_uses_deployment_selected_backend_instead_of_forcing_local(controller):
    service, _ = controller
    assert service.store._required_backend is None


def test_idempotency_does_not_resubmit_changed_source(controller):
    from maverick.research_jobs import ResearchConflict

    service, _ = controller
    assert _submit(service)["id"] == _submit(service)["id"]
    with pytest.raises(ResearchConflict, match="idempotency"):
        service.submit(
            "tenant-a",
            "user:researcher",
            files={"main.py": "print('different')"},
            evaluator_id="smoke",
            idempotency_key="request-1",
        )


def test_foreign_tenant_and_principal_cannot_read_or_cancel(controller):
    from maverick.research_jobs import ResearchNotFound

    service, state = controller
    row = _submit(service)
    with pytest.raises(ResearchNotFound):
        service.get("tenant-b", "user:researcher", row["id"])
    with pytest.raises(ResearchNotFound):
        service.cancel("tenant-a", "user:other", row["id"], expected_revision=row["revision"])
    review = service.review("tenant-a", "user:admin", row["id"])
    with pytest.raises(ResearchNotFound):
        service.run(
            "tenant-b",
            row["id"],
            expected_revision=row["revision"],
            dispatcher="user:admin",
            review_sha256=review["review_sha256"],
        )
    assert state["constructions"] == 0
    assert state["calls"] == 0


def test_cancel_queued_and_running_never_evaluates_or_replays(controller):
    service, state = controller
    row = _submit(service)
    cancelled = service.cancel(
        "tenant-a", "user:researcher", row["id"], expected_revision=row["revision"]
    )
    assert cancelled["status"] == "cancelled"
    row = service.submit(
        "tenant-a",
        "user:researcher",
        files={"main.py": "pass"},
        evaluator_id="smoke",
        idempotency_key="request-2",
    )

    def cancel_running():
        current = service.get("tenant-a", "user:researcher", row["id"])
        service.cancel(
            "tenant-a", "user:researcher", row["id"], expected_revision=current["revision"]
        )

    state["during"] = cancel_running
    result = _run(service, row)
    assert result["status"] == "cancelled" and "evaluation" not in result


@pytest.mark.parametrize("uncertainty", ["cleanup", "provenance"])
def test_cancel_running_never_overrides_uncertain_cleanup_or_provenance(controller, uncertainty):
    service, state = controller
    row = _submit(service)

    def cancel_running():
        current = service.get("tenant-a", "user:researcher", row["id"])
        service.cancel(
            "tenant-a", "user:researcher", row["id"], expected_revision=current["revision"]
        )

    state["during"] = cancel_running
    if uncertainty == "cleanup":
        state["cleanup"] = False
    else:
        state["policy_sha256"] = "f" * 64

    result = _run(service, row)

    assert result["status"] == "uncertain"
    assert "evaluation" not in result
    assert "verify" in result["next_action"].lower()
    assert "will not run again" in result["next_action"]


def test_worker_loss_keeps_uncertain_claim_durable_without_automatic_replay(controller):
    class WorkerLost(BaseException):
        pass

    service, state = controller
    row = _submit(service)

    def die():
        raise WorkerLost

    state["during"] = die
    with pytest.raises(WorkerLost):
        _run(service, row)
    restarted = state["make"]()
    current = restarted.get("tenant-a", "user:researcher", row["id"])
    assert current["status"] == "running"
    with pytest.raises(Exception, match="queued"):
        _run(restarted, current)
    assert state["calls"] == 1


def test_tampered_durable_candidate_never_reaches_runner(controller):
    service, state = controller
    row = _submit(service)
    with tenant_scope(tenant="tenant-a"):
        service.store.update(
            row["id"],
            lambda value: value["files"].update({"main.py": "bad"}),
            expected_revision=row["revision"],
            action="test-tamper",
            actor="test",
        )
    current = service.get("tenant-a", "user:researcher", row["id"])
    result = _run(service, current)
    assert result["status"] == "review_required" and state["calls"] == 0


@pytest.mark.parametrize("loser_reads_after_claim", [False, True])
def test_concurrent_workers_only_one_claim_enters_candidate(
    controller, monkeypatch, loser_reads_after_claim,
):
    from maverick.privacy_ops import RecordConflict
    from maverick.research_jobs import ResearchConflict

    service, state = controller
    row = _submit(service)
    review_sha256 = service.review("tenant-a", "user:admin", row["id"])["review_sha256"]
    winner, loser = state["make"](), state["make"]()
    loser_read = threading.Event()
    winner_entered = threading.Event()
    original_record = loser._record

    def read_loser(record_id):
        # Force both valid interleavings: the loser either reads the reviewed
        # revision before the claim, or reads the newly claimed revision.
        if loser_reads_after_claim:
            assert winner_entered.wait(timeout=5)
        current = original_record(record_id)
        loser_read.set()
        assert winner_entered.wait(timeout=5)
        return current

    monkeypatch.setattr(loser, "_record", read_loser)
    state["during"] = winner_entered.set

    def dispatch(worker):
        if worker is winner and not loser_reads_after_claim:
            assert loser_read.wait(timeout=5)
        try:
            return _run(worker, row, review_sha256=review_sha256)
        except (RecordConflict, ResearchConflict) as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(dispatch, worker) for worker in (winner, loser)]
        results = [future.result(timeout=10) for future in futures]
    assert (
        sum(isinstance(result, dict) and result["status"] == "completed" for result in results) == 1
    )
    # A fresh read rejects the now-stale review; an older snapshot reaches
    # the CAS and rejects the stale revision. Neither path may run a candidate.
    expected_conflict = ResearchConflict if loser_reads_after_claim else RecordConflict
    assert type(results[1]) is expected_conflict
    if loser_reads_after_claim:
        assert "review the exact source again" in str(results[1])
    assert state["calls"] == 1 and state["constructions"] == 1


def test_queue_expiry_denies_before_candidate_effect(controller, monkeypatch):
    service, state = controller
    authoritative_now = [1_000.0]
    monkeypatch.setattr(service.store, "authoritative_time", lambda: authoritative_now[0])
    row = _submit(service)
    assert row["expires_at"] == authoritative_now[0] + state["profile"].queue_seconds
    authoritative_now[0] = row["expires_at"] + 1
    result = _run(service, row)
    assert result["status"] == "review_required" and state["calls"] == 0


@pytest.mark.parametrize(
    "files",
    [
        [],
        {},
        {"../host.py": "pass"},
        {"main.py": "x" * 262145},
        {"main.py": "\ud800"},
        {"main.py": 4},
        {"main.py": "é" * 140000},
    ],
)
def test_malformed_and_oversized_submissions_leave_no_queue_record(controller, files):
    service, state = controller
    with pytest.raises(ValueError):
        service.submit(
            "tenant-a",
            "user:researcher",
            files=files,
            evaluator_id="smoke",
            idempotency_key="invalid",
        )
    assert service.list("tenant-a", "user:researcher") == [] and state["calls"] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("queue_seconds", True),
        ("queue_seconds", 0),
        ("limits", {"cpus": float("nan")}),
        ("image_id", "mutable-tag"),
        ("environment", {}),
        ("evaluators", {"bad": {"command": "host-shell"}}),
    ],
)
def test_operator_profiles_reject_unbounded_or_executable_oracle_configuration(field, value):
    from maverick.research_jobs import ResearchProfile

    raw = {
        "enable": True,
        "image_id": "sha256:" + "1" * 64,
        "evaluators": {"smoke": {"version": "v1", "stdout_sha256": "2" * 64}},
    }
    raw[field] = value
    with pytest.raises(ValueError):
        ResearchProfile.from_config(raw)


def test_tenant_overlay_cannot_enable_research_or_replace_operator_oracle(controller):
    from maverick.paths import data_dir
    from maverick.research_jobs import ResearchUnavailable, configured_profile

    with tenant_scope(tenant="tenant-a"):
        path = data_dir() / "config.toml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            '[research_execution]\nenable = true\nimage_id = "untrusted"\n', encoding="utf-8"
        )
        config.reset_config_cache()
        with pytest.raises(ResearchUnavailable):
            configured_profile()


def test_dashboard_research_profile_replaces_base_evaluators_instead_of_merging(controller):
    from maverick.research_jobs import configured_profile

    config.config_path().write_text(
        '[research_execution]\nenable = true\nimage_id = "sha256:' + "2" * 64 + '"\n'
        '[research_execution.evaluators.stale]\nversion = "v1"\nstdout_sha256 = "'
        + "3" * 64
        + '"\n',
        encoding="utf-8",
    )
    config.dashboard_overrides_path().write_text(
        '[research_execution]\nenable = true\nimage_id = "sha256:' + "4" * 64 + '"\n'
        '[research_execution.evaluators.current]\nversion = "v2"\nstdout_sha256 = "'
        + "5" * 64
        + '"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    profile = configured_profile()
    assert profile.image_id == "sha256:" + "4" * 64
    assert [item.id for item in profile.evaluators] == ["current"]


def test_separate_jobs_receive_non_replayable_evaluation_requests(controller):
    service, _ = controller
    first = _submit(service)
    first = _run(service, first)
    second = service.submit(
        "tenant-a",
        "user:researcher",
        files={"main.py": "print('answer')"},
        evaluator_id="smoke",
        idempotency_key="second",
    )
    second = _run(service, second)
    assert first["evaluation"]["subject_sha256"] == second["evaluation"]["subject_sha256"]
    for field in ("request_id", "request_sha256", "execution_context_sha256"):
        assert first["evaluation"][field] != second["evaluation"][field]


def test_actual_worker_process_exit_leaves_claim_durable_and_non_replayable(controller):
    from maverick.research_jobs import ResearchConflict

    service, state = controller
    row = _submit(service)
    script = """
import hashlib, os, sys
from maverick.research_jobs import ResearchAuthority, ResearchDispatchAuthority, ResearchJobs, ResearchProfile
class LostRunner:
    def __init__(self, image, *, limits):
        self.image_id = image
    def run(self, files, *, budget, entrypoint, effect_guard):
        with effect_guard():
            os._exit(73)
profile = ResearchProfile.from_config({"enable": True, "image_id": "sha256:" + "2" * 64,
    "evaluators": {"smoke": {"version": "v1", "stdout_sha256": hashlib.sha256(b"answer\\n").hexdigest()}}})
service = ResearchJobs(authority_resolver=lambda t, p: ResearchAuthority(t, p, "1" * 64),
    dispatch_authority_resolver=lambda t, p: ResearchDispatchAuthority(t, p, "6" * 64),
    profile_resolver=lambda: profile, runner_factory=LostRunner)
review = service.review("tenant-a", "user:admin", sys.argv[1])
service.run("tenant-a", sys.argv[1], expected_revision=int(sys.argv[2]), dispatcher="user:admin",
    review_sha256=review["review_sha256"])
"""
    exited = subprocess.run(
        [sys.executable, "-c", script, row["id"], str(row["revision"])],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert exited.returncode == 73, exited.stdout + exited.stderr
    restarted = state["make"]()
    current = restarted.get("tenant-a", "user:researcher", row["id"])
    assert current["status"] == "running"
    with pytest.raises(ResearchConflict, match="queued"):
        _run(restarted, current)
    assert state["calls"] == 0
