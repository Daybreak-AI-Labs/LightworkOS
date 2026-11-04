"""Learning-proof harness: paired-lift statistics, the forced-freeze A/B
control, and the dependency-injected measure_lift runner.

These prove the apparatus that makes self-learning *provable*: a clean A/B
(learning live vs forced-frozen) scored for success, with a reproducible
effect-size + CI. No live LLM/GPU -- run/score are injected.
"""
from __future__ import annotations

import pytest
from maverick import calibration
from maverick.learning_proof import (
    FROZEN_ENV,
    forced_freeze,
    measure_lift,
    paired_lift,
)

# ---------- paired_lift statistics ----------

def test_clear_improvement_is_significant():
    r = paired_lift([0.0] * 10, [1.0] * 10)
    assert r.n == 10
    assert r.delta == pytest.approx(1.0)
    assert r.baseline_mean == 0.0 and r.treatment_mean == 1.0
    assert r.wins == 10 and r.losses == 0 and r.ties == 10 - 10
    assert r.significant and r.improved
    assert r.ci_low > 0
    assert "IMPROVED" in r.summary()


def test_no_change_is_not_significant():
    r = paired_lift([0.5] * 8, [0.5] * 8)
    assert r.delta == 0.0
    assert not r.significant and not r.improved
    assert r.ties == 8
    assert "no significant change" in r.summary()


def test_regression_is_flagged_not_improved():
    r = paired_lift([1.0] * 10, [0.0] * 10)
    assert r.delta == pytest.approx(-1.0)
    assert r.significant and not r.improved
    assert "REGRESSED" in r.summary()


def test_single_observation_never_significant():
    r = paired_lift([0.0], [1.0])
    assert r.n == 1
    assert not r.significant and not r.improved


def test_wins_losses_ties_counts():
    r = paired_lift([0.0, 1.0, 0.5, 0.2], [1.0, 0.0, 0.5, 0.9])
    assert r.wins == 2  # 0->1 and 0.2->0.9
    assert r.losses == 1  # 1->0
    assert r.ties == 1  # 0.5->0.5


def test_paired_lift_is_deterministic_for_a_seed():
    a = [0.0, 1.0, 0.0, 1.0, 0.0, 1.0]
    b = [1.0, 1.0, 1.0, 0.0, 1.0, 1.0]
    r1 = paired_lift(a, b, seed=7)
    r2 = paired_lift(a, b, seed=7)
    assert (r1.ci_low, r1.ci_high) == (r2.ci_low, r2.ci_high)


def test_mismatched_lengths_raise():
    with pytest.raises(ValueError):
        paired_lift([0.0, 1.0], [1.0])


def test_empty_raises():
    with pytest.raises(ValueError):
        paired_lift([], [])


# ---------- forced_freeze A/B control ----------

def test_forced_freeze_sets_and_restores(monkeypatch):
    monkeypatch.delenv(FROZEN_ENV, raising=False)
    with forced_freeze(True):
        assert calibration.learning_frozen() is True
    # restored to absent
    import os
    assert FROZEN_ENV not in os.environ
    with forced_freeze(False):
        assert calibration.learning_frozen() is False
    assert FROZEN_ENV not in os.environ


def test_forced_freeze_restores_prior_value(monkeypatch):
    monkeypatch.setenv(FROZEN_ENV, "1")
    with forced_freeze(False):
        assert calibration.learning_frozen() is False
    import os
    assert os.environ[FROZEN_ENV] == "1"  # prior value restored


def test_calibration_override_forces_state(monkeypatch):
    monkeypatch.setenv(FROZEN_ENV, "1")
    assert calibration.learning_frozen() is True  # even with enforcement off
    monkeypatch.setenv(FROZEN_ENV, "off")
    assert calibration.learning_frozen() is False
    monkeypatch.delenv(FROZEN_ENV, raising=False)
    assert calibration.learning_frozen() is False  # default fall-through


# ---------- measure_lift end-to-end (injected run/score) ----------

def test_measure_lift_detects_learning_gain(monkeypatch):
    monkeypatch.delenv(FROZEN_ENV, raising=False)
    tasks = list(range(12))

    def run(task, frozen):
        # Prove the env toggling actually drives calibration during each arm.
        assert calibration.learning_frozen() is frozen
        return {"task": task, "frozen": frozen}

    def score(task, output):
        # Learning helps: live arm succeeds, frozen arm fails.
        return 0.0 if output["frozen"] else 1.0

    r = measure_lift(tasks, run=run, score=score)
    assert r.n == 12
    assert r.improved and r.delta == pytest.approx(1.0)
    # env left clean afterward
    import os
    assert FROZEN_ENV not in os.environ


def test_measure_lift_no_gain_when_learning_inert(monkeypatch):
    monkeypatch.delenv(FROZEN_ENV, raising=False)
    tasks = list(range(10))
    r = measure_lift(
        tasks,
        run=lambda task, frozen: task,
        score=lambda task, output: 0.7,  # same regardless of arm
    )
    assert not r.improved and not r.significant


# ---------- maverick prove-learning CLI ----------

def _scores_file(tmp_path, baseline, treatment):
    import json
    p = tmp_path / "scores.json"
    p.write_text(json.dumps({"baseline": baseline, "treatment": treatment}))
    return p


def test_cli_prove_learning_reports_improvement(tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    p = _scores_file(tmp_path, [0.0] * 8, [1.0] * 8)
    res = CliRunner().invoke(main, ["prove-learning", "--scores", str(p)])
    assert res.exit_code == 0, res.output
    assert "IMPROVED" in res.output


def test_cli_prove_learning_strict_gate_fails_without_lift(tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    p = _scores_file(tmp_path, [0.5] * 8, [0.5] * 8)
    res = CliRunner().invoke(
        main, ["prove-learning", "--scores", str(p), "--strict"])
    assert res.exit_code != 0


def test_cli_prove_learning_json_output(tmp_path):
    import json

    from click.testing import CliRunner
    from maverick.cli import main
    p = _scores_file(tmp_path, [0.0, 1.0, 0.0, 1.0], [1.0, 1.0, 1.0, 1.0])
    res = CliRunner().invoke(
        main, ["prove-learning", "--scores", str(p), "--json"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.output)
    assert "delta" in data and "ci_low" in data and "ci_high" in data


def test_cli_prove_learning_rejects_mismatched_lengths(tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    p = _scores_file(tmp_path, [1.0, 0.0], [1.0])
    res = CliRunner().invoke(main, ["prove-learning", "--scores", str(p)])
    assert res.exit_code != 0
    assert "equal-length" in res.output or "paired" in res.output
