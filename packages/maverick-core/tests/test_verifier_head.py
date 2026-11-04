"""Tests for the torch-free CPU verifier-head training (judgment rung)."""
from __future__ import annotations

import random

import pytest
from maverick.self_improvement import PromotionLedger, SelfImprovementController
from maverick.verifier_head import LinearHead


def _ctrl(tmp_path, *, ledger=None, max_auto_rung="policy"):
    return SelfImprovementController(
        frozen_fn=lambda: False, audit_fn=lambda **k: None,
        ledger=ledger or PromotionLedger(path=tmp_path / "led.json"),
        max_auto_rung=max_auto_rung,
    )


def _journal_events(tmp_path):
    import json

    journal = tmp_path / "led.json.journal"
    return [
        json.loads(line)["event"]
        for line in journal.read_text(encoding="utf-8").splitlines()
    ]


def _linear_examples(n=80, seed=0):
    """Promise is a clean linear function of the features -> learnable."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        x = [rng.uniform(-1, 1) for _ in range(12)]
        promise = 0.5 * x[0] - 0.3 * x[3]
        out.append({"features": x, "promise": promise, "progress": 0.0})
    return out


def test_head_learns_a_linear_signal():
    from maverick.verifier_head import train_and_evaluate
    res = train_and_evaluate(_linear_examples(), split=0.3, seed=1)
    # A trained linear head should beat the trivial mean predictor on held-out.
    assert res["test_mse"] < res["baseline_test_mse"]
    # And it should separate promising from unpromising steps.
    assert res["discrimination"] > 0.0


def test_group_temporal_split_keeps_all_task_attempts_out_of_the_other_arm():
    from maverick.verifier_head import group_temporal_split

    rows = []
    # Two episodes/attempts per task.  A task, not an individual step or
    # episode, is the leakage boundary.
    for task in range(4):
        for episode in range(2):
            rows.append({
                "features": [0.0] * 12,
                "promise": float(task % 2),
                "progress": None,
                "task_id": f"task-{task}",
                "goal_id": task,
                "episode_id": episode,
                "outcome_verified_at": float(10 + task),
            })
    train_rows, test_rows = group_temporal_split(rows, split=0.25)
    train_tasks = {row["task_id"] for row in train_rows}
    test_tasks = {row["task_id"] for row in test_rows}
    assert train_tasks.isdisjoint(test_tasks)
    assert test_tasks == {"task-3"}  # newest verified task is held out
    assert {row["episode_id"] for row in test_rows} == {0, 1}


def test_train_and_evaluate_refuses_one_task_with_many_steps():
    from maverick.verifier_head import train_and_evaluate

    rows = [
        {
            "features": [float(i % 2)] + [0.0] * 11,
            "promise": float(i % 2),
            "progress": None,
            "task_id": "one-task",
            "episode_id": i // 3,
            "outcome_verified_at": float(10 + i // 3),
        }
        for i in range(30)
    ]
    with pytest.raises(ValueError, match="two independent task groups"):
        train_and_evaluate(rows)


class _PredictionHead:
    def __init__(self, feature_index):
        self.feature_index = feature_index

    def promise(self, features):
        return float(features[self.feature_index])


def _paired_rows(incumbent, challenger, *, target=1.0):
    return [
        {
            "features": [float(old), float(new)] + [0.0] * 10,
            "promise": float(target),
            "progress": None,
            "weight": 1.0,
            "task_id": f"task-{index}",
            "goal_id": index,
            "episode_id": 0,
            "step": 0,
            "outcome_verified_at": float(index),
        }
        for index, (old, new) in enumerate(zip(incumbent, challenger, strict=True))
    ]


def test_paired_evidence_uses_task_lcb_not_positive_mean_alone():
    from maverick.verifier_head import compare_verifiers, freeze_confirmation_anchor

    # Seven wins and five losses have a positive point estimate, but the
    # heterogeneous task-paired lower bound correctly crosses zero.
    rows, digest = freeze_confirmation_anchor(
        _paired_rows([0.5] * 12, [1.0] * 7 + [0.0] * 5),
    )
    evidence = compare_verifiers(
        _PredictionHead(0), _PredictionHead(1), rows,
        cohort_sha256=digest,
    )
    assert evidence.quality_delta > 0.0
    assert evidence.quality_lcb <= 0.0
    assert not evidence.quality_ok

    uniform, uniform_digest = freeze_confirmation_anchor(
        _paired_rows([0.5] * 12, [0.8] * 12),
    )
    decisive = compare_verifiers(
        _PredictionHead(0), _PredictionHead(1), uniform,
        cohort_sha256=uniform_digest, margin=0.1,
    )
    assert decisive.quality_lcb == pytest.approx(0.3)
    assert decisive.quality_ok


def test_paired_evidence_rejects_mse_regression_hidden_by_clipping():
    from maverick.verifier_head import compare_verifiers, freeze_confirmation_anchor

    # Both challenger values clip to the correct probability zero, but ten
    # extreme raw outputs make its verifier-scale MSE worse than incumbent.
    rows, digest = freeze_confirmation_anchor(
        _paired_rows([0.2] * 100, [0.0] * 90 + [-1.0] * 10, target=0.0),
    )
    evidence = compare_verifiers(
        _PredictionHead(0), _PredictionHead(1), rows,
        cohort_sha256=digest,
    )
    assert evidence.quality_ok and evidence.brier_ok
    assert evidence.mse_delta_ucb > 0.0
    assert not evidence.mse_ok and not evidence.promotable


def test_paired_evidence_rejects_brier_regression_despite_quality_win():
    from maverick.verifier_head import compare_verifiers, freeze_confirmation_anchor

    rows, digest = freeze_confirmation_anchor(
        _paired_rows([0.7] * 100, [1.0] * 90 + [0.0] * 10),
    )
    evidence = compare_verifiers(
        _PredictionHead(0), _PredictionHead(1), rows,
        cohort_sha256=digest,
    )
    assert evidence.quality_lcb > 0.0
    assert evidence.brier_delta_ucb > 0.0
    assert not evidence.brier_ok and not evidence.promotable


def test_paired_evidence_counts_verbose_task_once_and_anchor_is_order_stable():
    from maverick.verifier_head import compare_verifiers, freeze_confirmation_anchor

    base = _paired_rows([0.2, 0.2], [0.8, 0.8])
    verbose = [dict(base[0], step=index, weight=1 / 1000) for index in range(1000)]
    rows, digest = freeze_confirmation_anchor(verbose + [base[1]])
    reordered, reordered_digest = freeze_confirmation_anchor(list(reversed(rows)))
    evidence = compare_verifiers(
        _PredictionHead(0), _PredictionHead(1), rows,
        cohort_sha256=digest,
    )
    assert evidence.samples == 2
    assert reordered_digest == digest
    assert reordered == rows


def test_predict_and_save_load_roundtrip(tmp_path):
    import json

    from maverick.prm import LinearPRM, StepContext, step_features
    from maverick.verifier_head import train

    head = train(_linear_examples(40), seed=2)
    p = tmp_path / "head.json"
    head.save(p)
    reloaded = LinearHead.load(p)
    x = [0.5] + [0.0] * 11
    assert abs(reloaded.promise(x) - head.promise(x)) < 1e-9
    # Training serialization is the serving schema, not a trainer-only shape.
    payload = json.loads(p.read_text(encoding="utf-8"))
    assert payload["kind"] == "linear"
    assert set(payload) >= {"feature_names", "role_vocab", "promise", "progress"}
    ctx = StepContext(goal_id=1, step_index=2, role="coder", is_final=True)
    assert LinearPRM(str(p)).score(ctx).promise == pytest.approx(
        head.promise(step_features(ctx)), abs=1e-12,
    )


def test_head_reads_legacy_schema_but_rewrites_serving_schema(tmp_path):
    import json

    legacy = {
        "w": [[0.0] * 12, [0.0] * 12],
        "b": [0.25, -0.5],
        "feature_dim": 12,
        "out_dim": 2,
    }
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    head = LinearHead.load(path)
    assert head.promise([0.0] * 12) == pytest.approx(0.2449186624)
    head.save(path)
    assert "promise" in json.loads(path.read_text(encoding="utf-8"))


def test_content_addressed_artifact_activation_and_rollback(tmp_path):
    import hashlib

    from maverick.prm import LinearPRM, StepContext, step_features
    from maverick.verifier_head import VerifierArtifactDeployment

    active = tmp_path / "serving" / "prm.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    first = LinearHead()
    first.w[0][0] = 0.8
    first_plan = deployment.stage(first)
    assert first_plan.artifact.path.name.startswith("linear-v1-")
    assert first_plan.artifact.sha256 == hashlib.sha256(
        first_plan.artifact.path.read_bytes(),
    ).hexdigest()
    first_plan.activate()
    with pytest.raises(RuntimeError, match="single-use"):
        first_plan.activate()

    ctx = StepContext(goal_id=1, step_index=1, role="coder", is_final=True)
    authority = [first_plan.after_revision]
    serving = LinearPRM(str(active), authority=lambda: authority[0])
    assert serving.score(ctx).promise == pytest.approx(
        first.promise(step_features(ctx)), abs=1e-12,
    )

    second = LinearHead()
    second.w[0][0] = -0.8
    second_plan = deployment.stage(second)
    assert second_plan.artifact.version != first_plan.artifact.version
    second_plan.activate()
    authority[0] = second_plan.after_revision
    assert hashlib.sha256(active.read_bytes()).hexdigest() == second_plan.artifact.sha256
    assert serving.score(ctx).promise == pytest.approx(
        second.promise(step_features(ctx)), abs=1e-12,
    )
    with pytest.raises(RuntimeError, match="refusing to clobber"):
        first_plan.rollback()
    assert hashlib.sha256(active.read_bytes()).hexdigest() == second_plan.artifact.sha256
    second_plan.rollback()
    authority[0] = first_plan.after_revision
    assert hashlib.sha256(active.read_bytes()).hexdigest() == first_plan.artifact.sha256
    assert serving.score(ctx).promise == pytest.approx(
        first.promise(step_features(ctx)), abs=1e-12,
    )
    first_plan.rollback()
    assert not active.exists()


def test_linear_prm_rejects_schema_valid_out_of_band_replacement(tmp_path):
    from maverick.prm import HeuristicPRM, LinearPRM, StepContext
    from maverick.verifier_head import VerifierArtifactDeployment

    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    first = LinearHead()
    first.b[0] = -0.25
    first_plan = deployment.stage(first)
    first_plan.activate()
    authority = [first_plan.after_revision]
    serving = LinearPRM(str(active), authority=lambda: authority[0])
    ctx = StepContext(goal_id=1, step_index=1, role="coder")
    assert serving.score(ctx).promise == pytest.approx(first.promise([0.0] * 12))

    attacker = LinearHead()
    attacker.b[0] = 0.9
    attacker_plan = deployment.stage(attacker)
    # Even an atomic, serving-schema-valid replacement has no authority until
    # its exact digest/revision is committed in the promotion ledger.
    active.write_bytes(attacker_plan.artifact.path.read_bytes())
    assert serving.score(ctx) == HeuristicPRM().score(ctx)

    active.write_bytes(first_plan.artifact.path.read_bytes())
    assert serving.score(ctx).promise == pytest.approx(first.promise([0.0] * 12))


def test_activation_rejects_staged_artifact_tampering(tmp_path):
    from maverick.verifier_head import VerifierArtifactDeployment

    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    plan = deployment.stage(LinearHead())
    plan.artifact.path.write_bytes(plan.artifact.path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="digest mismatch"):
        plan.activate()
    assert not active.exists()


def test_confirmation_head_is_bound_to_exact_staged_digest(tmp_path):
    from maverick.verifier_head import VerifierArtifactDeployment

    deployment = VerifierArtifactDeployment(
        tmp_path / "artifacts", tmp_path / "active.json",
    )
    plan = deployment.stage(LinearHead())
    replacement = LinearHead()
    replacement.b[0] = 0.5
    other = deployment.stage(replacement)
    plan.artifact.path.write_bytes(other.artifact.path.read_bytes())
    with pytest.raises(ValueError, match="digest mismatch"):
        plan.evaluation_head()


def test_save_is_atomic_no_torn_read(tmp_path):
    """A serving process re-loading the head while a training run writes it must
    never see a half-written file. With the atomic temp+replace save, a reader
    concurrent with repeated saves always loads a valid head."""
    import threading

    from maverick.verifier_head import train

    p = tmp_path / "head.json"
    train(_linear_examples(20), seed=3).save(p)  # seed a valid file
    errors: list[Exception] = []
    stop = threading.Event()

    def writer():
        for s in range(150):
            train(_linear_examples(20), seed=s).save(p)

    def reader():
        while not stop.is_set():
            try:
                LinearHead.load(p)  # must never see a torn file
            except (ValueError, OSError) as e:
                errors.append(e)

    rt = threading.Thread(target=reader)
    wt = threading.Thread(target=writer)
    rt.start()
    wt.start()
    wt.join()
    stop.set()
    rt.join()
    assert not errors, errors[:3]
    assert list(tmp_path.glob("*.tmp")) == []


def test_empty_examples_is_safe():
    from maverick.verifier_head import discrimination, train
    head = train([])
    assert head.promise([0.0] * 12) == 0.0
    assert discrimination(head, []) == 0.0


# -- end-to-end: trajectory store -> trained head -> governed adoption -------

class _Store:
    """Yields independently verified task episodes with a learnable signal."""

    def __init__(self, n):
        from maverick.trajectory_store import TrajectoryStep
        self._steps = []
        steps_per_task = 5
        for i in range(n):
            task = i // steps_per_task
            step = i % steps_per_task
            ok = bool(task % 2)
            final = step == steps_per_task - 1
            self._steps.append(TrajectoryStep(
                ts=float(i), goal_id=task + 1, episode_id=0, step=step,
                task_id=f"task-{task}", role="coder",
                tool="shell" if ok else "", tool_succeeded=ok, is_final=final,
                error="" if ok else "boom",
                # Deliberately contrary current-PRM predictions: the builder
                # must train from the independently verified outcome instead.
                promise=(0.1 if ok else 0.9), progress=(0.1 if ok else 0.9),
                outcome=float(ok) if final else None,
                outcome_source="tests" if final else "",
                outcome_verified_at=float(n + task + 1) if final else None,
            ))

    def iter_steps(self, *, limit=10_000):
        return iter(self._steps)


def test_train_and_propose_too_few_examples(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", tmp_path / "active.json")
    assert train_and_propose(
        _Store(5), controller=_ctrl(tmp_path), deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    ) is None


def test_train_and_propose_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.prm import HeuristicPRM, LinearPRM, StepContext
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    class _RecordingDeployment:
        def __init__(self):
            self.inner = VerifierArtifactDeployment(
                tmp_path / "artifacts", tmp_path / "active.json",
            )
            self.plan = None

        def stage(self, head):
            self.plan = self.inner.stage(head)
            return self.plan

        def snapshot_for_evaluation(self, controller):
            return self.inner.snapshot_for_evaluation(controller)

        def consume_confirmation(self, controller, **kwargs):
            return self.inner.consume_confirmation(controller, **kwargs)

    controller = _ctrl(tmp_path, max_auto_rung="evaluator")
    captured = []
    real_prepare = controller.prepare_promotion

    def capture_prepare(candidate, **kwargs):
        captured.append(candidate)
        return real_prepare(candidate, **kwargs)

    controller.prepare_promotion = capture_prepare
    deployment = _RecordingDeployment()
    verdict = train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    )
    assert verdict is not None
    assert verdict.rung == "evaluator"
    assert verdict.ok
    assert len(captured) == 1
    assert 0.0 < captured[0].baseline_score < captured[0].candidate_score <= 1.0
    assert captured[0].effect_ci_low is not None and captured[0].effect_ci_low > 0.0
    assert captured[0].payload["artifact_before"]["version"] == "absent"
    assert captured[0].provenance["evidence_protocol"] == "paired-task-v1"
    assert deployment.plan is not None
    assert (tmp_path / "active.json").read_bytes() == (
        deployment.plan.artifact.path.read_bytes()
    )
    # The activated artifact is accepted and scored by the serving implementation.
    assert LinearPRM.validate_artifact(
        tmp_path / "active.json",
        expected_sha256=deployment.plan.artifact.sha256,
    ) == deployment.plan.artifact.sha256
    reward = LinearPRM(str(tmp_path / "active.json")).score(
        StepContext(goal_id=1, step_index=1, role="coder", is_final=True),
    )
    assert -1.0 <= reward.promise <= 1.0
    governed = LinearPRM(
        str(tmp_path / "active.json"),
        authority=deployment.inner.authority_resolver(controller),
    )
    assert governed.score(
        StepContext(goal_id=1, step_index=1, role="coder", is_final=True),
    ).confidence == 0.6
    promoted_bytes = (tmp_path / "active.json").read_bytes()
    unrecognized = LinearHead()
    unrecognized.b[0] = 0.9
    third = deployment.inner.stage(unrecognized)
    (tmp_path / "active.json").write_bytes(third.artifact.path.read_bytes())
    governed_ctx = StepContext(
        goal_id=1, step_index=1, role="coder", is_final=True,
    )
    assert governed.score(governed_ctx) == HeuristicPRM().score(governed_ctx)
    (tmp_path / "active.json").write_bytes(promoted_bytes)
    assert governed.score(
        StepContext(goal_id=1, step_index=1, role="coder", is_final=True),
    ).confidence == 0.6
    record = controller.ledger.get(verdict.candidate_id)
    assert record is not None
    assert deployment.plan.artifact.version in record.summary
    assert _journal_events(tmp_path) == ["prepare", "commit", "audit_ack"]
    receipts = list((tmp_path / "artifacts" / "evaluations").glob("*.json"))
    assert len(receipts) == 1
    # The governance rollback invokes the concrete deployment undo and records it.
    assert controller.rollback(verdict.candidate_id, undo=deployment.plan.rollback)
    assert not (tmp_path / "active.json").exists()


def test_confirmation_cohort_is_durably_one_use(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    deployment = VerifierArtifactDeployment(
        tmp_path / "artifacts", tmp_path / "active.json",
    )
    controller = _ctrl(tmp_path, max_auto_rung="evaluator")
    first = train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    )
    assert first is not None and first.ok
    transactions_before = controller.ledger.transactions(
        artifact_identity=deployment.identity,
    )

    # A second candidate cannot adapt to the same newest temporal holdout,
    # even after the incumbent changed and the first attempt committed.
    assert train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    ) is None
    assert controller.ledger.transactions(
        artifact_identity=deployment.identity,
    ) == transactions_before
    assert len(list((tmp_path / "artifacts" / "evaluations").glob("*.json"))) == 1


def test_active_swap_after_confirmation_prevents_prepare(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    controller = _ctrl(tmp_path, max_auto_rung="evaluator")

    def swap_after_evaluation(_request):
        unrelated = LinearHead()
        unrelated.b[0] = 0.75
        plan = deployment.stage(unrelated)
        active.write_bytes(plan.artifact.path.read_bytes())
        return None

    verdict = train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
        approve=swap_after_evaluation,
    )
    assert verdict is not None and not verdict.ok
    assert verdict.blocking_reason == "active verifier changed after paired confirmation"
    assert controller.ledger.transactions(
        artifact_identity=deployment.identity,
    ) == []


def test_committed_verifier_rollback_survives_restart(tmp_path, monkeypatch):
    import hashlib

    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    active = tmp_path / "active.json"
    bootstrap = LinearHead()
    bootstrap.save(active)
    bootstrap_bytes = active.read_bytes()
    bootstrap_digest = hashlib.sha256(bootstrap_bytes).hexdigest()
    deployment = VerifierArtifactDeployment(
        tmp_path / "artifacts", active, bootstrap_sha256=bootstrap_digest,
    )
    controller = _ctrl(tmp_path, max_auto_rung="evaluator")
    verdict = train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    )
    assert verdict is not None and verdict.ok
    promoted_bytes = active.read_bytes()
    assert promoted_bytes != bootstrap_bytes

    restarted_ledger = PromotionLedger(path=tmp_path / "led.json")
    restarted_controller = _ctrl(tmp_path, ledger=restarted_ledger)
    restarted = VerifierArtifactDeployment(
        tmp_path / "artifacts", active, bootstrap_sha256=bootstrap_digest,
    )
    restarted.recover_for_serving(restarted_controller)
    assert restarted.rollback_committed(restarted_controller, verdict.candidate_id)
    assert active.read_bytes() == bootstrap_bytes
    assert restarted.authoritative_revision(restarted_controller) == (
        restarted.bootstrap_revision
    )
    record = restarted_ledger.get(verdict.candidate_id)
    assert record is not None and record.rolled_back
    restarted.recover_for_serving(restarted_controller)


def test_unrecognized_valid_incumbent_requires_explicit_bootstrap(tmp_path):
    import hashlib

    from maverick.verifier_head import (
        VerifierArtifactDeployment,
        VerifierRecoveryRequired,
    )

    active = tmp_path / "active.json"
    LinearHead().save(active)
    digest = hashlib.sha256(active.read_bytes()).hexdigest()
    controller = _ctrl(tmp_path)
    unprovisioned = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    with pytest.raises(VerifierRecoveryRequired, match="not authorized"):
        unprovisioned.recover_for_serving(controller)

    provisioned = VerifierArtifactDeployment(
        tmp_path / "artifacts", active, bootstrap_sha256=digest,
    )
    provisioned.recover_for_serving(controller)
    assert provisioned.snapshot_for_evaluation(controller)[2] == "deployed_authorized"


def test_train_and_propose_default_policy_ceiling_does_not_activate_verifier(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    active = tmp_path / "active.json"
    controller = _ctrl(tmp_path)  # production default: policy ceiling
    verdict = train_and_propose(
        _Store(200), controller=controller,
        deployment=VerifierArtifactDeployment(tmp_path / "artifacts", active),
        trusted_outcome_sources=frozenset({"tests"}),
    )

    assert verdict is not None and verdict.rung == "evaluator" and not verdict.ok
    assert any(gate.gate == "human_approval" and not gate.ok
               for gate in verdict.gates)
    assert not active.exists()
    assert controller.ledger.in_doubt() == []


def test_train_and_propose_accepts_external_signed_evaluator_approval(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick import approval_signing
    from maverick.verifier_head import VerifierArtifactDeployment, train_and_propose

    monkeypatch.setattr(approval_signing, "signing_enforced", lambda: True)
    monkeypatch.setattr(
        approval_signing, "verify_candidate",
        lambda candidate: "approver-key" if candidate.approval_signature == "signed" else None,
    )
    requests = []

    def approve(request):
        requests.append(request)
        return "signed"

    active = tmp_path / "active.json"
    controller = _ctrl(tmp_path)  # evaluator is above this policy ceiling
    verdict = train_and_propose(
        _Store(200), controller=controller,
        deployment=VerifierArtifactDeployment(tmp_path / "artifacts", active),
        trusted_outcome_sources=frozenset({"tests"}), approve=approve,
    )

    assert verdict is not None and verdict.ok
    assert verdict.rung == "evaluator" and verdict.approver_id == "approver-key"
    assert active.exists()
    assert len(requests) == 1 and requests[0].rung == "evaluator"
    record = controller.ledger.get(verdict.candidate_id)
    assert record is not None
    assert record.approval_signature == "signed"
    assert record.payload_sha256 == requests[0].payload_sha256


def test_train_and_propose_requires_real_deployment(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import train_and_propose

    assert train_and_propose(
        _Store(200), controller=_ctrl(tmp_path), deployment=None,
        trusted_outcome_sources=frozenset({"tests"}),
    ) is None


def test_activation_failure_returns_rejection_and_rolls_back_receipt(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import (
        VerifierActivation,
        VerifierArtifactDeployment,
        train_and_propose,
    )

    # Fail at the post-PREPARE application seam.  An invalid serving-path
    # parent is now rejected earlier while acquiring the cross-process lock,
    # before there is a transaction to roll back.
    def fail_activation(self, *, expected_before=None):
        raise OSError("simulated verifier activation failure")

    monkeypatch.setattr(VerifierActivation, "_activate_locked", fail_activation)
    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    controller = _ctrl(tmp_path, max_auto_rung="evaluator")
    verdict = train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    )
    assert verdict is not None and not verdict.ok
    assert any(gate.gate == "application" and not gate.ok for gate in verdict.gates)
    assert not active.exists()
    assert controller.ledger.get(verdict.candidate_id) is None
    transaction = controller.ledger.transaction(f"promotion:{verdict.candidate_id}")
    assert transaction is not None and transaction.state == "aborted"


def test_halt_after_prepare_aborts_before_verifier_activation(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick import learning_guard
    from maverick.verifier_head import (
        VerifierActivation,
        VerifierArtifactDeployment,
        train_and_propose,
    )

    activated = []

    def refuse_after_prepare(_job, phase):
        if phase == "before-activation":
            raise learning_guard.Halted("operator stop", "test")

    monkeypatch.setattr(learning_guard, "check_learning_halt", refuse_after_prepare)
    monkeypatch.setattr(
        VerifierActivation,
        "_activate_locked",
        lambda *args, **kwargs: activated.append(True),
    )
    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    controller = _ctrl(tmp_path, max_auto_rung="evaluator")

    verdict = train_and_propose(
        _Store(200), controller=controller, deployment=deployment,
        trusted_outcome_sources=frozenset({"tests"}),
    )

    assert verdict is not None and not verdict.ok
    assert "learning safety check" in verdict.blocking_reason
    assert activated == [] and not active.exists()
    transaction = controller.ledger.transaction(f"promotion:{verdict.candidate_id}")
    assert transaction is not None and transaction.state == "aborted"


def test_restart_recovery_aborts_prepare_when_crash_precedes_activation(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import (
        VerifierActivation,
        VerifierArtifactDeployment,
        train_and_propose,
    )

    def crash_before_activation(self, *, expected_before=None):
        raise SystemExit("simulated crash before verifier activation")

    monkeypatch.setattr(
        VerifierActivation, "_activate_locked", crash_before_activation,
    )
    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    with pytest.raises(SystemExit, match="before verifier activation"):
        train_and_propose(
            _Store(200),
            controller=_ctrl(tmp_path, max_auto_rung="evaluator"),
            deployment=deployment,
            trusted_outcome_sources=frozenset({"tests"}),
        )

    restarted_ledger = PromotionLedger(path=tmp_path / "led.json")
    in_doubt = restarted_ledger.in_doubt()
    assert len(in_doubt) == 1
    assert restarted_ledger.get(in_doubt[0].record.id) is None
    assert not active.exists()
    assert deployment.inspect(deployment.identity) == in_doubt[0].before
    assert _journal_events(tmp_path) == ["prepare"]

    restarted = _ctrl(tmp_path, ledger=restarted_ledger)
    recovered = VerifierArtifactDeployment(
        tmp_path / "artifacts", active,
    ).recover(restarted)
    assert [transaction.state for transaction in recovered] == ["aborted"]
    assert _journal_events(tmp_path) == ["prepare", "abort"]
    assert PromotionLedger(path=tmp_path / "led.json").get(
        in_doubt[0].record.id,
    ) is None


def test_restart_recovery_commits_prepare_when_crash_follows_activation(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.verifier_head import (
        VerifierActivation,
        VerifierArtifactDeployment,
        train_and_propose,
    )

    real_activate = VerifierActivation._activate_locked

    def crash_after_activation(self, *, expected_before=None):
        real_activate(self, expected_before=expected_before)
        raise SystemExit("simulated crash after verifier activation")

    monkeypatch.setattr(
        VerifierActivation, "_activate_locked", crash_after_activation,
    )
    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    with pytest.raises(SystemExit, match="after verifier activation"):
        train_and_propose(
            _Store(200),
            controller=_ctrl(tmp_path, max_auto_rung="evaluator"),
            deployment=deployment,
            trusted_outcome_sources=frozenset({"tests"}),
        )

    restarted_ledger = PromotionLedger(path=tmp_path / "led.json")
    in_doubt = restarted_ledger.in_doubt()
    assert len(in_doubt) == 1
    assert restarted_ledger.get(in_doubt[0].record.id) is None
    assert deployment.inspect(deployment.identity) == in_doubt[0].after
    assert _journal_events(tmp_path) == ["prepare"]

    # Exercise the real Agent construction seam: build_from_env must reconcile
    # the durable PREPARE before returning a servable LinearPRM.
    from maverick.prm import LinearPRM, build_from_env

    monkeypatch.setenv("MAVERICK_PRM", "linear")
    monkeypatch.setenv("MAVERICK_PRM_PATH", str(active))
    restarted = _ctrl(tmp_path, ledger=restarted_ledger)
    model = build_from_env(recovery_controller=restarted)
    assert isinstance(model, LinearPRM)
    assert _journal_events(tmp_path) == ["prepare", "commit", "audit_ack"]
    record = PromotionLedger(path=tmp_path / "led.json").get(
        in_doubt[0].record.id,
    )
    assert record is not None
    assert in_doubt[0].after.version in record.summary


def test_startup_refuses_linear_prm_when_prepare_observes_unknown_revision(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    from maverick.prm import HeuristicPRM, build_from_env
    from maverick.verifier_head import (
        LinearHead,
        VerifierActivation,
        VerifierArtifactDeployment,
        train_and_propose,
    )

    real_activate = VerifierActivation._activate_locked

    def crash_after_activation(self, *, expected_before=None):
        real_activate(self, expected_before=expected_before)
        raise SystemExit("simulated crash after verifier activation")

    monkeypatch.setattr(
        VerifierActivation, "_activate_locked", crash_after_activation,
    )
    active = tmp_path / "active.json"
    deployment = VerifierArtifactDeployment(tmp_path / "artifacts", active)
    with pytest.raises(SystemExit, match="after verifier activation"):
        train_and_propose(
            _Store(200),
            controller=_ctrl(tmp_path, max_auto_rung="evaluator"),
            deployment=deployment,
            trusted_outcome_sources=frozenset({"tests"}),
        )

    # Simulate an out-of-band third revision after PREPARE. Recovery can prove
    # neither commit nor abort, so startup must not expose the linear backend.
    third_head = LinearHead()
    third_head.b[0] = 0.321
    third = deployment.stage(third_head)
    active.write_bytes(third.artifact.path.read_bytes())
    restarted_ledger = PromotionLedger(path=tmp_path / "led.json")
    monkeypatch.setenv("MAVERICK_PRM", "linear")
    monkeypatch.setenv("MAVERICK_PRM_PATH", str(active))

    model = build_from_env(
        recovery_controller=_ctrl(tmp_path, ledger=restarted_ledger),
    )
    assert isinstance(model, HeuristicPRM)
    unresolved = restarted_ledger.in_doubt(
        artifact_identity=deployment.identity,
    )
    assert len(unresolved) == 1 and unresolved[0].recovery_attempts == 1
    assert _journal_events(tmp_path) == ["prepare", "recovery_conflict"]
