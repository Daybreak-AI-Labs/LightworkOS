"""Tests for the model-agnostic self-improvement glue (Phases 0/1/3/4)."""
from __future__ import annotations

import pytest
from maverick.self_improvement import PromotionLedger, SelfImprovementController
from maverick.self_improvement_runner import (
    build_prm_examples,
    collect_calibration,
    emit_strategy_candidate,
    review_generated_tools,
    should_retire,
)
from maverick.si_producers import ToolOutcomeTracker
from maverick.trajectory_store import TrajectoryStep


def _ctrl(tmp_path):
    return SelfImprovementController(
        frozen_fn=lambda: False, audit_fn=lambda **k: None,
        ledger=PromotionLedger(path=tmp_path / "led.json"))


# -- calibration capture ----------------------------------------------------

def test_collect_calibration_off_is_noop():
    assert collect_calibration(0.9, True, enabled_fn=lambda: False) is False


def test_collect_calibration_records_when_on(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # conftest already isolates HOME; be explicit
    assert collect_calibration(0.8, True, source="test", enabled_fn=lambda: True) is True


# -- tool retire/promote loop ----------------------------------------------

def test_should_retire_on_low_rate_with_evidence(tmp_path):
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(6):
        t.record("dud", False)
    assert should_retire("dud", t)


def test_should_not_retire_a_good_or_unproven_tool(tmp_path):
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(6):
        t.record("good", True)
    t.record("new", False)  # only 1 sample
    assert not should_retire("good", t)
    assert not should_retire("new", t)


def test_review_generated_tools_promotes_retires_holds(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    t = ToolOutcomeTracker(path=tmp_path / "to.json")
    for _ in range(6):
        t.record("good", True)
    for _ in range(6):
        t.record("bad", False)
    actions = review_generated_tools(
        ["good", "bad"], t, baseline_success=0.5, controller=_ctrl(tmp_path))
    assert actions["good"] == "promoted"
    assert actions["bad"] == "retire"


# -- judgment dataset builder ----------------------------------------------

class _Store:
    def __init__(self, steps):
        self._s = steps

    def iter_steps(self, *, limit=10_000):
        return iter(self._s)


def test_build_prm_examples_rejects_prm_self_labels_and_unverified_outcome():
    steps = [
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=0, step=0, role="coder",
                       tool="shell", tool_succeeded=True, promise=0.6, progress=0.1),
        # This is the legacy automatic terminal value: the current verifier's
        # confidence, with no independent source/time provenance.
        TrajectoryStep(ts=2.0, goal_id=1, episode_id=0, step=1, role="coder",
                       is_final=True, promise=0.9, progress=0.8, outcome=0.9),
    ]
    assert build_prm_examples(_Store(steps)) == []


def test_build_prm_examples_uses_delayed_verified_outcome_and_preserves_identity():
    steps = [
        TrajectoryStep(ts=1.0, goal_id=7, episode_id=3, step=0, role="coder",
                       task_id="task-A", promise=0.99, progress=0.91),
        TrajectoryStep(
            ts=2.0, goal_id=7, episode_id=3, step=1, role="coder", is_final=True,
            task_id="task-A", promise=0.98, progress=0.92, outcome=0.25,
            outcome_source="tests", outcome_verified_at=3.0,
        ),
    ]
    # Native trajectory metadata is not self-authenticating; this test models
    # a caller that independently authenticated the test producer.
    rows = build_prm_examples(
        _Store(steps), trusted_outcome_sources=frozenset({"tests"}))
    assert len(rows) == 2
    assert all(len(row["features"]) == 12 for row in rows)
    assert {row["promise"] for row in rows} == {0.25}
    assert {row["progress"] for row in rows} == {None}
    assert {(row["task_id"], row["episode_id"]) for row in rows} == {("task-A", 3)}
    assert all(row["outcome_source"] == "tests" for row in rows)
    assert all(row["label_kind"] == "verified_outcome" for row in rows)
    assert build_prm_examples(
        _Store(steps), trusted_outcome_sources=frozenset(),
    ) == []


def test_build_prm_examples_rejects_conflicting_task_identity():
    steps = [
        TrajectoryStep(ts=1.0, goal_id=7, episode_id=3, step=0, role="coder",
                       task_id="task-A"),
        TrajectoryStep(ts=2.0, goal_id=7, episode_id=3, step=1, role="coder",
                       task_id="task-B", is_final=True, outcome=1.0,
                       outcome_source="tests", outcome_verified_at=3.0),
    ]
    assert build_prm_examples(
        _Store(steps), trusted_outcome_sources=frozenset({"tests"})) == []


def test_build_prm_examples_normalizes_each_task_to_equal_total_weight():
    steps = []
    for task, count in (("verbose", 10), ("concise", 2)):
        for index in range(count):
            final = index == count - 1
            steps.append(TrajectoryStep(
                ts=float(len(steps) + 1), goal_id=1 if task == "verbose" else 2,
                episode_id=0, step=index, role="coder", task_id=task,
                is_final=final, outcome=1.0 if final else None,
                outcome_source="tests" if final else "",
                outcome_verified_at=100.0 if final else None,
            ))
    rows = build_prm_examples(
        _Store(steps), trusted_outcome_sources=frozenset({"tests"}))
    totals = {}
    for row in rows:
        totals[row["task_id"]] = totals.get(row["task_id"], 0.0) + row["weight"]
    assert totals == {"verbose": pytest.approx(1.0), "concise": pytest.approx(1.0)}


def test_build_prm_examples_accepts_explicit_trusted_labels_only_with_provenance():
    steps = [
        TrajectoryStep(ts=2.0, goal_id=9, episode_id=4, step=0, role="coder",
                       promise=0.99, progress=0.99),
    ]
    labels = {(9, 4): {
        "outcome": 0.0, "promise": 0.1, "progress": 0.2,
        "source": "signed-human-review", "verified_at": 4.0,
    }}
    rows = build_prm_examples(_Store(steps), trusted_labels=labels)
    assert len(rows) == 1
    assert rows[0]["promise"] == 0.1
    assert rows[0]["progress"] == 0.2
    assert rows[0]["outcome"] == 0.0
    assert rows[0]["label_kind"] == "explicit_trusted"

    labels[(9, 4)] = {"outcome": 1.0, "source": "", "verified_at": 4.0}
    assert build_prm_examples(_Store(steps), trusted_labels=labels) == []


# -- strategy candidates ----------------------------------------------------

def test_emit_strategy_prompt_and_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_SELF_IMPROVEMENT", "1")
    vp = emit_strategy_candidate("prompt", "new system preamble", 0.5, 0.7, 6,
                                 rollback="r", controller=_ctrl(tmp_path))
    assert vp.ok and vp.rung == "prompt"
    vq = emit_strategy_candidate("policy", "route hard tasks to opus", 0.5, 0.7, 8,
                                 rollback="r", controller=_ctrl(tmp_path))
    assert vq.ok and vq.rung == "policy"
