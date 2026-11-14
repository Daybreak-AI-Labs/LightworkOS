"""Acceptance tests for the concrete evaluator-container boundary."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest
from maverick import self_harness_isolation as isolation
from maverick.self_harness_holdout import (
    AlphaBudget,
    BoundaryAttempt,
    EvaluationCost,
    FinalSetRetired,
    HoldoutBudgetExhausted,
    HoldoutLedgerError,
    HoldoutQuery,
    HoldoutQueryLedger,
    fingerprint_manifest,
)
from maverick.self_harness_isolation import (
    EvaluationIsolationError,
    EvaluatorVerdict,
    IsolatedEvaluator,
    ObservationProtocol,
    ResearchContainerCandidate,
)


def _protocol() -> ObservationProtocol:
    return ObservationProtocol(
        protocol_id="arithmetic-v1",
        allowed_fields=("question", "operands"),
        required_for_solution=("question", "operands"),
        allowed_artifact_exports=("trace",),
        timeout_seconds=10.0,
    )


def _query(
    private_task, protocol, query_id="q-1", signature="candidate-v1",
    *, declared_cost: EvaluationCost | None = None,
):
    return HoldoutQuery(
        holdout_sha256=fingerprint_manifest({"study": "f08"}),
        final_set_sha256=fingerprint_manifest(private_task),
        protocol_sha256=protocol.sha256,
        view_sha256=fingerprint_manifest({"view": "arithmetic-final"}),
        query_id=query_id,
        cycle_id="registered-study-v1",
        signature=signature,
        evaluator_epoch="evaluator-worker",
        declared_cost=declared_cost or EvaluationCost(compute_millis=60_000),
    )


def _contained_candidate(
    monkeypatch, *, output=None, artifacts=None,
    attempts: tuple[BoundaryAttempt, ...] = (), status="ok", elapsed=0.0,
    on_run=None, runner_error: BaseException | None = None,
):
    """Mock the Docker primitive while retaining the concrete broker type."""
    seen = {}
    image_id = "sha256:" + "a" * 64

    class Runner:
        def __init__(self, image, *, limits):
            seen["image"] = image
            seen["limits"] = limits

        def run(self, files, *, budget, entrypoint):
            if on_run is not None:
                on_run()
            if runner_error is not None:
                raise runner_error
            payload = json.loads(files[isolation._OBSERVATIONS])
            seen["payload"] = payload
            value = output(payload["observations"]) if callable(output) else output
            envelope = {
                "schema": isolation._RESULT_SCHEMA,
                "status": status,
                "output": value,
                "artifact_exports": artifacts or {},
                "boundary_attempts": [
                    {"surface": attempt.surface} for attempt in attempts
                ],
            }
            policy = {
                "schema": isolation._CONTAINER_BOUNDARY,
                "image_id": image_id,
                "user": "65532:65532",
                "network": "none",
                "readonly_root": True,
                "mounts": [{
                    "destination": "/candidate", "type": "bind", "rw": False,
                }],
                "security_opt": ["no-new-privileges"],
                "cap_drop": ["ALL"],
                "command": [f"/candidate/{entrypoint}"],
                "elapsed_seconds": elapsed,
            }
            return SimpleNamespace(
                cleanup_verified=True,
                reason="completed",
                exit_code=0,
                entrypoint=entrypoint,
                input_sha256=isolation._input_digest(files),
                image_id=image_id,
                policy_sha256=fingerprint_manifest(policy),
                inspect_policy=policy,
                stdout=json.dumps(envelope),
            )

    monkeypatch.setattr(isolation, "ResearchContainerRunner", Runner)
    candidate = ResearchContainerCandidate(
        candidate_identity="candidate-worker",
        image="python:unit-test",
        files={"main.py": b"def evaluate(observations): return observations\n"},
    )
    return candidate, seen


def test_private_state_is_absent_attempts_are_recorded_and_task_is_solvable(
    tmp_path, monkeypatch,
):
    ledger_path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(ledger_path, now=lambda: 100.0)
    protocol = _protocol()
    secret = "production-evaluator-secret-9f812"  # pragma: allowlist secret -- synthetic isolation canary
    private_task = {
        "question": "Add the two operands.",
        "operands": [2, 3],
        "answer_key": 5,
        "evaluator_credential": secret,
        "private_reference_response": "five is correct",
    }
    attempts = (
        BoundaryAttempt("filesystem"),
        BoundaryAttempt("environment"),
        BoundaryAttempt("network"),
        BoundaryAttempt("error_message"),
        BoundaryAttempt("evaluator_response"),
        BoundaryAttempt("evaluator_storage"),
        BoundaryAttempt("credential"),
        BoundaryAttempt("control_path"),
    )
    sandbox, seen = _contained_candidate(
        monkeypatch,
        output=lambda observed: {"answer": sum(observed["operands"])},
        artifacts={
            "trace": {"operation": "addition"},
            "private-evaluator-response": "blocked-export",
        },
        attempts=attempts,
    )

    def evaluator(task, output):
        assert task["answer_key"] == output["answer"]
        return EvaluatorVerdict(
            accepted=True,
            private_response={"credential": secret, "analysis": "private"},
        )

    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(family_alpha=0.02, query_alpha=0.01, max_queries=2),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol),
        private_task=private_task,
        protocol=protocol,
        sandbox=sandbox,
        evaluator=evaluator,
    )

    assert seen["payload"]["observations"] == {
        "question": "Add the two operands.", "operands": [2, 3],
    }
    assert not ({"answer_key", "evaluator_credential", "private_reference_response"}
                & seen["payload"]["observations"].keys())
    assert result.status == "accepted" and result.accepted is True
    assert secret not in repr(result)
    assert result.receipt.custody == "local-controller"
    assert [(item.name, item.value) for item in result.artifacts] == [
        ("trace", {"operation": "addition"}),
    ]
    assert result.receipt.denied_attempts == len(attempts) + 1
    status = ledger.status(_query(private_task, protocol).holdout_sha256)
    assert status.queries == 1
    assert status.retired_final_sets == 1
    assert status.boundary_attempts == len(attempts) + 1
    with sqlite3.connect(ledger_path) as conn:
        events = [json.loads(row[0]) for row in conn.execute(
            "SELECT payload FROM events")]
    recorded = [event for event in events if event["event"] == "boundary_attempt"]
    assert {event["surface"] for event in recorded} == (
        {attempt.surface for attempt in attempts} | {"artifact_export"})
    assert all("target" not in event for event in recorded)
    raw = ledger_path.read_bytes()
    assert secret.encode() not in raw
    assert b"five is correct" not in raw

    revised = ObservationProtocol(
        protocol_id="arithmetic-v2",
        allowed_fields=("question", "operands"),
        required_for_solution=("question", "operands"),
    )
    with pytest.raises(FinalSetRetired, match="fresh final challenges"):
        ledger.authorize(
            _query(private_task, revised, "q-2", "candidate-v2"),
            AlphaBudget(family_alpha=0.02, query_alpha=0.01, max_queries=2),
        )


def test_candidate_and_evaluator_share_exact_provider_work_item(
    tmp_path, monkeypatch,
):
    from maverick import provider_cost_cap

    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [2, 2], "answer_key": 4}
    seen = []

    def current_binding():
        operation = provider_cost_cap.current_provider_operation()
        assert operation is not None
        return (
            provider_cost_cap._current_work_item(), operation.category,
            operation.service, operation.operation_id,
        )

    candidate, _ = _contained_candidate(
        monkeypatch, output={"answer": 4},
        on_run=lambda: seen.append(current_binding()),
    )

    def evaluator(_task, _output):
        seen.append(current_binding())
        return EvaluatorVerdict(True)

    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=evaluator,
        work_item_id="outcome-work:sealed-eval-17",
    )
    assert result.status == "accepted"
    assert [(item[0], item[1], item[2]) for item in seen] == [
        ("outcome-work:sealed-eval-17", "generation", "sealed-candidate"),
        ("outcome-work:sealed-eval-17", "evaluation", "sealed-evaluator"),
    ]
    assert provider_cost_cap._current_work_item() is None
    assert provider_cost_cap.current_provider_operation() is None


def test_self_attested_generic_sandbox_is_refused_before_query_spend(tmp_path):
    class ClaimedSandbox:
        candidate_identity = "candidate-worker"
        host_visible_fs = False
        evaluator_storage_mounted = False
        production_credentials_mounted = False
        allow_network = False
        bounded_output = True
        boundary_audit_complete = True

        def run_candidate(self, *_args, **_kwargs):
            raise AssertionError("must not run")

        def read_boundary_attempts(self):
            return ()

    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [1, 1], "answer_key": 2}
    with pytest.raises(EvaluationIsolationError, match="concrete"):
        IsolatedEvaluator(
            ledger=ledger,
            policy=AlphaBudget(),
            evaluator_identity="evaluator-worker",
            final_set_generator_identity="final-set-generator",
        ).evaluate(
            query=_query(private_task, protocol),
            private_task=private_task,
            protocol=protocol,
            sandbox=ClaimedSandbox(),
            evaluator=lambda *_: EvaluatorVerdict(True),
        )
    assert ledger.verify().queries == 0


def test_candidate_identity_cannot_alias_evaluator(tmp_path, monkeypatch):
    candidate, _ = _contained_candidate(monkeypatch, output={"answer": 2})
    candidate.candidate_identity = "evaluator-worker"
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [1, 1], "answer_key": 2}
    with pytest.raises(EvaluationIsolationError, match="separate candidate"):
        IsolatedEvaluator(
            ledger=ledger,
            policy=AlphaBudget(),
            evaluator_identity="evaluator-worker",
            final_set_generator_identity="final-set-generator",
        ).evaluate(
            query=_query(private_task, protocol),
            private_task=private_task,
            protocol=protocol,
            sandbox=candidate,
            evaluator=lambda *_: EvaluatorVerdict(True),
        )
    assert ledger.verify().queries == 0


def test_missing_solution_observation_fails_before_spend(tmp_path, monkeypatch):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "answer_key": 2}
    candidate, seen = _contained_candidate(monkeypatch, output={"answer": 2})
    with pytest.raises(EvaluationIsolationError, match="insufficient"):
        IsolatedEvaluator(
            ledger=ledger,
            policy=AlphaBudget(),
            evaluator_identity="evaluator-worker",
            final_set_generator_identity="final-set-generator",
        ).evaluate(
            query=_query(private_task, protocol),
            private_task=private_task,
            protocol=protocol,
            sandbox=candidate,
            evaluator=lambda *_: EvaluatorVerdict(True),
        )
    assert ledger.verify().queries == 0
    assert "payload" not in seen


def test_evaluator_exception_is_redacted_and_final_set_stays_retired(
    tmp_path, monkeypatch,
):
    ledger_path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(ledger_path)
    protocol = _protocol()
    private_task = {"question": "q", "operands": [1, 1], "answer_key": 2}
    candidate, _ = _contained_candidate(
        monkeypatch, output={"answer": 2},
        attempts=(BoundaryAttempt("network"),),
    )

    def broken_evaluator(*_):
        raise RuntimeError("secret-evaluator-trace-token")

    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(family_alpha=0.02, query_alpha=0.01, max_queries=2),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=broken_evaluator,
    )
    assert result.status == "evaluator_error"
    assert result.receipt.actual_cost == result.receipt.declared_cost
    assert b"secret-evaluator-trace-token" not in ledger_path.read_bytes()
    with pytest.raises(FinalSetRetired):
        ledger.authorize(
            _query(private_task, protocol, "q-2", "candidate-v2"),
            AlphaBudget(family_alpha=0.02, query_alpha=0.01, max_queries=2),
        )


def test_candidate_error_is_charged_retired_and_audited(tmp_path, monkeypatch):
    ledger_path = tmp_path / "holdout.db"
    ledger = HoldoutQueryLedger.provision(ledger_path)
    protocol = _protocol()
    private_task = {"question": "q", "operands": [1, 1], "answer_key": 2}
    attempts = (BoundaryAttempt("filesystem"), BoundaryAttempt("credential"))
    candidate, _ = _contained_candidate(
        monkeypatch, output=None, attempts=attempts, status="candidate_error")
    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=lambda *_: pytest.fail("evaluator must not run"),
    )
    assert result.status == "candidate_error" and result.accepted is None
    assert result.receipt.denied_attempts == 2
    assert ledger.status(_query(private_task, protocol).holdout_sha256).queries == 1


def test_query_must_bind_exact_evaluator_epoch_before_spend(tmp_path, monkeypatch):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [1, 1], "answer_key": 2}
    query = replace(_query(private_task, protocol), evaluator_epoch="other-evaluator")
    candidate, _ = _contained_candidate(monkeypatch, output={"answer": 2})
    with pytest.raises(EvaluationIsolationError, match="evaluator epoch"):
        IsolatedEvaluator(
            ledger=ledger,
            policy=AlphaBudget(),
            evaluator_identity="evaluator-worker",
            final_set_generator_identity="final-set-generator",
        ).evaluate(
            query=query,
            private_task=private_task,
            protocol=protocol,
            sandbox=candidate,
            evaluator=lambda *_: EvaluatorVerdict(True),
        )
    assert ledger.verify().queries == 0


def test_atomic_resource_reservations_prevent_concurrent_cost_overspend(tmp_path):
    path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(path)
    policy = AlphaBudget(
        family_alpha=0.02,
        query_alpha=0.01,
        max_queries=2,
        max_provider_calls=1,
        max_input_tokens=10,
        max_output_tokens=10,
        max_compute_millis=100,
        max_dollars="0.01",
    )
    study = fingerprint_manifest({"study": "resource-race"})
    barrier = threading.Barrier(2)

    def reserve(index):
        query = HoldoutQuery(
            holdout_sha256=study,
            final_set_sha256=fingerprint_manifest({"case": index}),
            protocol_sha256=fingerprint_manifest({"protocol": 1}),
            query_id=f"q-{index}", cycle_id=f"cycle-{index}",
            signature=f"candidate-{index}", evaluator_epoch="eval-v1",
            declared_cost=EvaluationCost(
                provider_calls=1, input_tokens=10, output_tokens=10,
                compute_millis=100, dollars="0.01"),
        )
        barrier.wait(timeout=10)
        try:
            HoldoutQueryLedger(path).authorize(query, policy)
        except HoldoutBudgetExhausted:
            return "exhausted"
        return "authorized"

    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(reserve, (1, 2)))
    assert sorted(results) == ["authorized", "exhausted"]
    status = HoldoutQueryLedger(path).status(study)
    assert status.queries == 1
    assert status.reserved_cost.provider_calls == 1
    assert status.cost_remaining.provider_calls == 0


def test_actual_cost_is_bound_to_receipt_and_cannot_exceed_reservation(
    tmp_path, monkeypatch,
):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [2, 3], "answer_key": 5}
    declared = EvaluationCost(
        provider_calls=2, input_tokens=100, output_tokens=20,
        compute_millis=1000, dollars="0.05")
    policy = AlphaBudget(
        family_alpha=0.05, query_alpha=0.025, max_queries=2)
    candidate, _ = _contained_candidate(
        monkeypatch, output={"answer": 5}, elapsed=0.1)
    result = IsolatedEvaluator(
        ledger=ledger,
        policy=policy,
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol, declared_cost=declared),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=lambda *_: EvaluatorVerdict(
            True,
            resource_cost=EvaluationCost(
                provider_calls=2, input_tokens=10, output_tokens=3,
                compute_millis=200, dollars="0.01"),
        ),
    )
    assert result.receipt.declared_cost == declared
    assert result.receipt.actual_cost == EvaluationCost(
        provider_calls=2, input_tokens=10, output_tokens=3,
        compute_millis=300, dollars="0.01")

    second_task = {"question": "q2", "operands": [1, 1], "answer_key": 2}
    second = _query(
        second_task, protocol, query_id="q-2", signature="candidate-v2",
        declared_cost=EvaluationCost(provider_calls=1),
    )
    permit = ledger.authorize(second, policy)
    with pytest.raises(HoldoutBudgetExhausted, match="exceeded its reservation"):
        ledger.finalize_evaluation(
            permit,
            outcome="accepted",
            public_result={"accepted": True},
            actual_cost=EvaluationCost(provider_calls=2),
        )
    assert ledger.status(second.holdout_sha256).retired_final_sets == 1
    assert ledger.status(second.holdout_sha256).reserved_cost.provider_calls == 1


def test_local_windows_custody_is_honest_and_confirmatory_mode_fails_closed(
    tmp_path,
):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    custody = ledger.custody_status()
    assert custody.local_path_identity_verified is True
    assert custody.independent_custody_verified is False
    assert "separate evaluator" in custody.limitation.lower()
    with pytest.raises(HoldoutLedgerError, match="independent evaluator custody"):
        IsolatedEvaluator(
            ledger=ledger,
            policy=AlphaBudget(),
            evaluator_identity="evaluator-worker",
            final_set_generator_identity="final-set-generator",
            require_independent_custody=True,
        )


def test_tampered_permit_cannot_publish_or_retire_a_result(tmp_path):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db", now=lambda: 4.0)
    protocol = _protocol()
    private_task = {"question": "q", "operands": [3, 4], "answer_key": 7}
    query = _query(private_task, protocol)
    permit = ledger.authorize(query, AlphaBudget())
    with pytest.raises(HoldoutLedgerError, match="committed query"):
        ledger.finalize_evaluation(
            replace(permit, event_sequence=permit.event_sequence + 1),
            outcome="accepted", public_result={"accepted": True},
        )
    receipt = ledger.finalize_evaluation(
        permit, outcome="accepted", public_result={"accepted": True})
    assert receipt.protocol_sha256 == protocol.sha256


def test_access_authorization_cannot_be_misreported_as_completed_evaluation(
    tmp_path,
):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [3, 4], "answer_key": 7}
    query = _query(private_task, protocol)
    permit = ledger.authorize(query, AlphaBudget())
    with pytest.raises(ValueError, match="only after scoring"):
        ledger.finalize_evaluation(
            permit,
            outcome="access_authorized",
            public_result={"status": "access_authorized"},
        )
    status = ledger.status(query.holdout_sha256)
    assert status.retired_final_sets == 0
    assert status.reserved_cost == permit.declared_cost


def test_tampered_two_phase_permit_is_refused_before_candidate_execution(
    tmp_path, monkeypatch,
):
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {"question": "q", "operands": [3, 4], "answer_key": 7}
    query = _query(private_task, protocol)
    permit = ledger.authorize(query, AlphaBudget())
    candidate, seen = _contained_candidate(monkeypatch, output={"answer": 7})
    with pytest.raises(HoldoutLedgerError, match="committed query"):
        IsolatedEvaluator(
            ledger=ledger,
            policy=AlphaBudget(),
            evaluator_identity="evaluator-worker",
            final_set_generator_identity="final-set-generator",
        ).evaluate(
            query=query,
            private_task=private_task,
            protocol=protocol,
            sandbox=candidate,
            evaluator=lambda *_: EvaluatorVerdict(True),
            permit=replace(permit, event_sequence=permit.event_sequence + 1),
        )
    assert "payload" not in seen


def test_production_authorizer_finalizes_only_after_scoring_through_container(
    tmp_path, monkeypatch,
):
    from maverick import self_improvement_runner as runner

    ledger_path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(ledger_path)
    scored = {"done": False}
    _contained_candidate(
        monkeypatch,
        output=lambda observed: {
            field: observed[field]
            for field in (
                "case_count", "purpose",
            )
        },
        on_run=lambda: scored["done"] is True
        or pytest.fail("container completion ran before scoring"),
    )
    authorizer = runner._build_holdout_authorizer(
        {
            "holdout_ledger": str(ledger_path),
            "holdout_family_alpha": 0.05,
            "holdout_query_alpha": 0.025,
            "holdout_max_queries": 2,
            "judge_samples": 3,
            "metamorphic": False,
            "eval_budget_dollars": 5.0,
        },
        corpus_path="unused.json",
        model_id="M",
        evaluation_system="deployed prompt",
        verifier_model="verifier-v1",
        corpus_manifest={"M": [{"goal": "sealed", "expected": "ok"}]},
    )
    authorizer("confirmation", "sig", ["sealed"])
    with sqlite3.connect(ledger_path) as connection:
        before = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM events ORDER BY seq")]
    assert [event["event"] for event in before] == ["policy", "query"]

    # This call stands in for the scorer returning. The production wrapper calls
    # the same method at the promotion boundary or after a rejected pass.
    scored["done"] = True
    assert authorizer.finalize_for_promotion() is True
    with sqlite3.connect(ledger_path) as connection:
        after = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM events ORDER BY seq")]
    retirements = [
        event for event in after if event["event"] == "retire_final_set"
    ]
    assert len(retirements) == 1
    assert retirements[0]["outcome"] == "accepted"
    assert all(event.get("outcome") != "access_authorized" for event in after)
    status = HoldoutQueryLedger(ledger_path).verify()
    assert status.reserved_final_sets == 1
    assert status.retired_final_sets == 1
    assert status.reserved_cost == EvaluationCost()
    assert status.actual_cost.provider_calls == 8


def test_production_builder_fails_closed_when_independent_custody_is_required(
    tmp_path, monkeypatch,
):
    from maverick import self_improvement_runner as runner

    ledger_path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(ledger_path)
    monkeypatch.setenv("MAVERICK_SELF_HARNESS_REQUIRE_INDEPENDENT_CUSTODY", "1")
    with pytest.raises(HoldoutLedgerError, match="independent evaluator custody"):
        runner._build_holdout_authorizer(
            {
                "holdout_ledger": str(ledger_path),
                "holdout_family_alpha": 0.05,
                "holdout_query_alpha": 0.025,
                "holdout_max_queries": 2,
                "judge_samples": 3,
                "metamorphic": False,
            },
            corpus_path="unused.json",
            model_id="M",
            evaluation_system="deployed prompt",
            verifier_model="verifier-v1",
            corpus_manifest={"M": [{"goal": "sealed", "expected": "ok"}]},
        )


def test_configured_custody_and_image_reach_the_production_builder(
    tmp_path, monkeypatch,
):
    from maverick import config
    from maverick import self_improvement_runner as runner

    ledger_path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(ledger_path)
    image_id = "sha256:" + "a" * 64
    monkeypatch.delenv(
        "MAVERICK_SELF_HARNESS_REQUIRE_INDEPENDENT_CUSTODY", raising=False,
    )
    monkeypatch.delenv("MAVERICK_SELF_HARNESS_EVALUATOR_IMAGE", raising=False)
    monkeypatch.setattr(config, "load_config", lambda: {
        "self_harness": {
            "holdout_ledger": str(ledger_path),
            "holdout_container_image": image_id,
            "holdout_require_independent_custody": True,
            "holdout_family_alpha": 0.05,
            "holdout_query_alpha": 0.025,
            "holdout_max_queries": 2,
            "judge_samples": 3,
            "metamorphic": False,
            "eval_budget_dollars": 5.0,
        },
    })
    settings = config.get_self_harness()
    assert settings["holdout_container_image"] == image_id
    assert settings["holdout_require_independent_custody"] is True
    kwargs = {
        "corpus_path": "unused.json",
        "model_id": "M",
        "evaluation_system": "deployed prompt",
        "verifier_model": "verifier-v1",
        "corpus_manifest": {"M": [{"goal": "sealed", "expected": "ok"}]},
    }
    with pytest.raises(HoldoutLedgerError, match="independent evaluator custody"):
        runner._build_holdout_authorizer(settings, **kwargs)

    # The image choice is also consumed from resolved config, rather than only
    # from an environment variable or a hand-built unit-test settings mapping.
    settings["holdout_require_independent_custody"] = False
    authorizer = runner._build_holdout_authorizer(settings, **kwargs)
    assert authorizer.image == image_id


@pytest.mark.parametrize(
    "configured",
    [None, "", "   ", 7, "python:3.12-slim", "sha256:" + "A" * 64],
)
def test_invalid_configured_holdout_image_fails_closed(monkeypatch, configured):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {
        "self_harness": {"holdout_container_image": configured},
    })
    with pytest.raises(ValueError, match="immutable local sha256 image ID"):
        config.get_self_harness()


def test_metamorphic_check_continues_same_reserved_final_query(
    tmp_path, monkeypatch,
):
    from maverick import self_improvement_runner as runner

    ledger_path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(ledger_path)
    _contained_candidate(
        monkeypatch,
        output=lambda observed: dict(observed),
    )
    authorizer = runner._build_holdout_authorizer(
        {
            "holdout_ledger": str(ledger_path),
            "holdout_family_alpha": 0.05,
            "holdout_query_alpha": 0.025,
            "holdout_max_queries": 2,
            "judge_samples": 3,
            "metamorphic": True,
        },
        corpus_path="unused.json",
        model_id="M",
        evaluation_system="deployed prompt",
        verifier_model="verifier-v1",
        metamorphic_model="paraphraser-v1",
        corpus_manifest={"M": [{"goal": "sealed", "expected": "ok"}]},
    )
    confirmation_z = authorizer("confirmation", "sig", ["sealed"])
    metamorphic_z = authorizer("metamorphic", "sig", ["sealed"])
    assert metamorphic_z == confirmation_z
    before = HoldoutQueryLedger(ledger_path).verify()
    assert before.queries == 1 and before.retired_final_sets == 0
    assert authorizer.finalize_remaining() is True
    after = HoldoutQueryLedger(ledger_path).verify()
    assert after.queries == 1 and after.retired_final_sets == 1
    assert after.actual_cost.provider_calls == 17


_RUN_DOCKER = os.environ.get("LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS") == "1"


@pytest.mark.skipif(
    not _RUN_DOCKER,
    reason="set LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS=1 for real Docker tests",
)
def test_real_docker_executes_hostile_candidate_and_enforces_boundary(tmp_path):
    image = os.environ.get("LIGHTWORK_RESEARCH_TEST_IMAGE", "python:3.12-slim")
    source = rb'''
import os
import socket

def _attempt(fn):
    try:
        return fn()
    except BaseException:
        return None

def evaluate(observations):
    print("candidate-console-must-not-cross-boundary")
    host = _attempt(lambda: open("/host-custody-canary", encoding="utf-8").read())
    control = _attempt(lambda: open("/var/run/docker.sock", "rb").read(1))
    final_set = _attempt(lambda: open("/evaluator/final_set.db", "rb").read(1))
    write = _attempt(lambda: open("/candidate/escape.txt", "w").write("escape"))
    credential = os.environ.get("PRODUCTION_EVALUATOR_TOKEN")
    network = _attempt(lambda: socket.create_connection(("192.0.2.1", 443), 0.2))
    return {
        "output": {
            "answer": sum(observations["operands"]),
            "host": host, "control": control, "final_set": final_set,
            "write": write, "credential": credential,
            "network": network is not None,
            "environment_keys": sorted(os.environ.keys()),
        },
        "artifacts": {"forbidden_export": "candidate-artifact-must-not-cross"},
    }
'''
    candidate = ResearchContainerCandidate(
        candidate_identity="hostile-candidate",
        image=image,
        files={"main.py": source},
    )
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {
        "question": "Add.", "operands": [4, 5], "answer_key": 9,
        "evaluator_credential": "never-mounted",
    }

    def evaluator(task, output):
        assert output["answer"] == task["answer_key"]
        assert all(output[key] is None for key in (
            "host", "control", "final_set", "write", "credential"))
        assert output["network"] is False
        assert output["environment_keys"] == [
            "HOME", "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE",
            "TMPDIR",
        ]
        return EvaluatorVerdict(True)

    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(
            private_task, protocol,
            declared_cost=EvaluationCost(compute_millis=30_000)),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=evaluator,
    )
    assert result.accepted is True
    assert result.artifacts == ()
    with sqlite3.connect(ledger.path) as connection:
        events = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM events")]
    surfaces = {
        event["surface"] for event in events
        if event["event"] == "boundary_attempt"
    }
    assert {"filesystem", "control_path", "evaluator_storage", "credential",
            "environment", "network", "artifact_export"}.issubset(surfaces)
    ledger_bytes = ledger.path.read_bytes()
    assert b"candidate-artifact-must-not-cross" not in ledger_bytes
    assert b"candidate-console-must-not-cross-boundary" not in ledger_bytes
    assert result.receipt.actual_cost.compute_millis > 0


@pytest.mark.skipif(
    not _RUN_DOCKER,
    reason="set LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS=1 for real Docker tests",
)
def test_real_docker_records_enumeration_and_socket_creation_probes(tmp_path):
    """Successful read-only probes remain visible in the audit receipt."""
    image = os.environ.get("LIGHTWORK_RESEARCH_TEST_IMAGE", "python:3.12-slim")
    candidate = ResearchContainerCandidate(
        candidate_identity="enumerating-candidate",
        image=image,
        files={
            "main.py": b'''
import os
import socket

def evaluate(observations):
    os.listdir("/")
    os.environ.copy()
    probe = socket.socket()
    probe.close()
    return {"answer": sum(observations["operands"])}
''',
        },
    )
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {
        "question": "Add.", "operands": [7, 8], "answer_key": 15,
    }

    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=lambda task, output: EvaluatorVerdict(
            output["answer"] == task["answer_key"]),
    )

    assert result.accepted is True
    with sqlite3.connect(ledger.path) as connection:
        events = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM events")]
    surfaces = {
        event["surface"] for event in events
        if event["event"] == "boundary_attempt"
    }
    assert {"filesystem", "environment", "network"}.issubset(surfaces)


@pytest.mark.skipif(
    not _RUN_DOCKER,
    reason="set LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS=1 for real Docker tests",
)
def test_real_docker_redacts_hostile_candidate_exception(tmp_path):
    image = os.environ.get("LIGHTWORK_RESEARCH_TEST_IMAGE", "python:3.12-slim")
    marker = "candidate-private-error-text-must-not-cross"
    candidate = ResearchContainerCandidate(
        candidate_identity="throwing-candidate",
        image=image,
        files={
            "main.py": (
                "def evaluate(observations):\n"
                f"    raise RuntimeError({marker!r})\n"
            ).encode(),
        },
    )
    ledger = HoldoutQueryLedger.provision(tmp_path / "holdout.db")
    protocol = _protocol()
    private_task = {
        "question": "Add.", "operands": [4, 5], "answer_key": 9,
    }

    result = IsolatedEvaluator(
        ledger=ledger,
        policy=AlphaBudget(),
        evaluator_identity="evaluator-worker",
        final_set_generator_identity="final-set-generator",
    ).evaluate(
        query=_query(private_task, protocol),
        private_task=private_task,
        protocol=protocol,
        sandbox=candidate,
        evaluator=lambda *_: pytest.fail(
            "private evaluator must not run after a candidate exception"),
    )

    assert result.status == "candidate_error"
    assert result.accepted is None
    assert result.artifacts == ()
    assert marker.encode("utf-8") not in ledger.path.read_bytes()
    with sqlite3.connect(ledger.path) as connection:
        events = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM events")]
    assert "error_message" in {
        event["surface"] for event in events
        if event["event"] == "boundary_attempt"
    }


@pytest.mark.skipif(
    not _RUN_DOCKER,
    reason="set LIGHTWORK_RUN_RESEARCH_CONTAINER_TESTS=1 for real Docker tests",
)
def test_real_docker_is_the_production_authorizer_completion_path(
    tmp_path, monkeypatch,
):
    from maverick import self_improvement_runner as runner

    image = os.environ.get("LIGHTWORK_RESEARCH_TEST_IMAGE", "python:3.12-slim")
    monkeypatch.setenv("MAVERICK_SELF_HARNESS_EVALUATOR_IMAGE", image)
    ledger_path = tmp_path / "holdout.db"
    HoldoutQueryLedger.provision(ledger_path)
    authorizer = runner._build_holdout_authorizer(
        {
            "holdout_ledger": str(ledger_path),
            "holdout_family_alpha": 0.05,
            "holdout_query_alpha": 0.025,
            "holdout_max_queries": 2,
            "judge_samples": 3,
            "metamorphic": False,
            "eval_budget_dollars": 5.0,
        },
        corpus_path="unused.json",
        model_id="M",
        evaluation_system="deployed prompt",
        verifier_model="verifier-v1",
        corpus_manifest={"M": [{"goal": "sealed", "expected": "ok"}]},
    )
    authorizer("confirmation", "sig", ["sealed"])
    assert HoldoutQueryLedger(ledger_path).verify().retired_final_sets == 0
    assert authorizer.finalize_for_promotion() is True
    status = HoldoutQueryLedger(ledger_path).verify()
    assert status.retired_final_sets == 1
    assert status.actual_cost.provider_calls == 8
    assert status.actual_cost.compute_millis > 0


def test_unrecordable_artifact_name_still_yields_a_recordable_attempt():
    # A NUL or over-long export name made finalize_evaluation raise after the
    # permit was spent, so no receipt was written.
    from maverick.self_harness_holdout import _boundary_attempt_fields
    attempts: list[BoundaryAttempt] = []
    execution = isolation.CandidateExecution(
        output=None, artifact_exports={"bad\x00name": "x", "y" * 5000: "x", "other": "x"})
    assert isolation._collect_artifacts(execution, _protocol(), attempts) == ()
    fields = _boundary_attempt_fields(attempts)
    assert len(fields) == 3
    assert sorted(a.target for a in attempts) == ["invalid-name", "invalid-name", "other"]
