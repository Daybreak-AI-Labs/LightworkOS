"""Torch-free linear AgentPRM (L2 self-learning): a real learned step signal.

Covers the pure-Python CPU trainer (training.prm_linear) and the JSON-weights
LinearPRM head (prm.LinearPRM): that it learns to rank promising steps over
failing ones, round-trips through plain JSON, is selectable via MAVERICK_PRM,
and fails OPEN to the heuristic on a missing/mismatched artifact. No torch.
"""
from __future__ import annotations

from maverick.prm import (
    HeuristicPRM,
    LinearPRM,
    StepContext,
    build_from_env,
    step_features,
)
from maverick.training import prm_linear


def _final_ctx():
    return StepContext(goal_id=0, step_index=1, role="orchestrator", is_final=True)


def _error_ctx():
    return StepContext(goal_id=0, step_index=2, role="coder", error="boom")


def _separating_examples(reps=25):
    """Final/no-error steps are good (+1); error steps are bad (-1)."""
    good = step_features(_final_ctx())
    bad = step_features(_error_ctx())
    return ([(good, [1.0, 0.5]) for _ in range(reps)]
            + [(bad, [-1.0, -0.5]) for _ in range(reps)])


# ---------- trainer ----------

def test_fit_learns_to_separate_good_from_bad():
    model = prm_linear.fit(_separating_examples(), epochs=600, lr=0.3)
    assert model["feature_names"] and model["input_dim"] == 12
    assert len(model["promise"]["w"]) == 12 and len(model["progress"]["w"]) == 12


def test_fit_is_deterministic():
    a = prm_linear.fit(_separating_examples(), epochs=200, lr=0.2)
    b = prm_linear.fit(_separating_examples(), epochs=200, lr=0.2)
    assert a == b  # zero-init + fixed pass order => reproducible artifact


def test_fit_empty_returns_zero_head():
    model = prm_linear.fit([], epochs=10)
    assert model["promise"]["w"] == [0.0] * 12 and model["promise"]["b"] == 0.0


def test_fit_from_klear_rows():
    rows = [{
        "messages": [
            {"type": "tool_call", "role": "coder", "name": "shell", "error": None},
            {"type": "final", "role": "orchestrator"},
        ],
        "rewards": [
            {"step": 0, "promise": 0.6, "progress": 0.1},
            {"step": 1, "promise": 1.0, "progress": 0.5},
        ],
    }]
    model = prm_linear.fit_from_klear(rows, epochs=50)
    assert model["kind"] == "linear" and len(model["promise"]["w"]) == 12


# ---------- LinearPRM inference (round-trip through JSON) ----------

def test_trained_linear_prm_ranks_good_over_bad(tmp_path):
    model = prm_linear.fit(_separating_examples(), epochs=600, lr=0.3)
    path = tmp_path / "prm_linear.json"
    prm_linear.save(model, path)

    prm = LinearPRM(str(path))
    good = prm.score(_final_ctx())
    bad = prm.score(_error_ctx())
    assert good.promise > bad.promise          # learned the ordering
    assert good.promise > 0 > bad.promise      # and the sign of the signal
    assert -1.0 <= good.promise <= 1.0         # tanh-bounded


def test_save_load_roundtrip_is_stable(tmp_path):
    model = prm_linear.fit(_separating_examples(), epochs=300, lr=0.2)
    path = tmp_path / "prm_linear.json"
    prm_linear.save(model, path)
    s1 = LinearPRM(str(path)).score(_final_ctx())
    s2 = LinearPRM(str(path)).score(_final_ctx())
    assert s1.promise == s2.promise and s1.progress == s2.progress


# ---------- fail-open contract ----------

def test_missing_artifact_falls_open_to_heuristic():
    prm = LinearPRM("/nonexistent/prm_linear.json")
    ctx = _error_ctx()
    assert prm.score(ctx).promise == HeuristicPRM().score(ctx).promise


def test_vocabulary_mismatch_falls_open(tmp_path):
    import json
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "feature_names": ["wrong"], "role_vocab": ["x"],
        "promise": {"w": [0.0], "b": 0.0}, "progress": {"w": [0.0], "b": 0.0},
    }))
    prm = LinearPRM(str(bad))
    ctx = _final_ctx()
    assert prm.score(ctx).promise == HeuristicPRM().score(ctx).promise


def test_malformed_weights_fall_open(tmp_path):
    import json

    from maverick.prm import FEATURE_NAMES, ROLE_VOCAB
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "feature_names": list(FEATURE_NAMES), "role_vocab": list(ROLE_VOCAB),
        "promise": {"w": [0.0, 0.0], "b": 0.0},  # wrong length
        "progress": {"w": [0.0] * 12, "b": 0.0},
    }))
    ctx = _final_ctx()
    assert LinearPRM(str(bad)).score(ctx).promise == HeuristicPRM().score(ctx).promise


def test_non_finite_weights_fall_open(tmp_path):
    import json

    from maverick.prm import FEATURE_NAMES, ROLE_VOCAB

    bad = tmp_path / "non-finite.json"
    weights = [0.0] * 12
    weights[0] = float("nan")
    bad.write_text(json.dumps({
        "kind": "linear",
        "feature_names": list(FEATURE_NAMES),
        "role_vocab": list(ROLE_VOCAB),
        "input_dim": 12,
        "promise": {"w": weights, "b": 0.0},
        "progress": {"w": [0.0] * 12, "b": 0.0},
    }), encoding="utf-8")
    ctx = _final_ctx()
    assert LinearPRM(str(bad)).score(ctx).promise == HeuristicPRM().score(ctx).promise


def test_oversized_artifact_falls_open_without_parsing(tmp_path):
    from maverick.prm import MAX_LINEAR_PRM_ARTIFACT_BYTES

    bad = tmp_path / "oversized.json"
    bad.write_bytes(b" " * (MAX_LINEAR_PRM_ARTIFACT_BYTES + 1))
    ctx = _final_ctx()
    assert LinearPRM(str(bad)).score(ctx).promise == HeuristicPRM().score(ctx).promise


# ---------- env selection ----------

def test_build_from_env_selects_linear(tmp_path, monkeypatch):
    import hashlib

    model = prm_linear.fit(_separating_examples(), epochs=50)
    path = tmp_path / "prm_linear.json"
    prm_linear.save(model, path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MAVERICK_PRM", "linear")
    monkeypatch.setenv("MAVERICK_PRM_PATH", path.name)
    monkeypatch.setenv(
        "MAVERICK_PRM_BOOTSTRAP_SHA256",
        hashlib.sha256(path.read_bytes()).hexdigest(),
    )
    prm = build_from_env()
    assert isinstance(prm, LinearPRM)
    assert prm.path == str(path)


def test_build_from_env_linear_requires_durable_recovery_authority(
    tmp_path, monkeypatch,
):
    from maverick.self_improvement import PromotionLedger, SelfImprovementController

    model = prm_linear.fit(_separating_examples(), epochs=50)
    path = tmp_path / "prm_linear.json"
    prm_linear.save(model, path)
    monkeypatch.setenv("MAVERICK_PRM", "linear")
    monkeypatch.setenv("MAVERICK_PRM_PATH", str(path))
    controller = SelfImprovementController(
        frozen_fn=lambda: False, audit_fn=lambda **_kwargs: None,
        ledger=PromotionLedger(),
    )

    assert isinstance(
        build_from_env(recovery_controller=controller), HeuristicPRM,
    )


def test_build_from_env_linear_without_path_falls_open(monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM", "linear")
    monkeypatch.delenv("MAVERICK_PRM_PATH", raising=False)
    assert isinstance(build_from_env(), HeuristicPRM)


# ---------- CLI / main ----------

def test_main_writes_loadable_artifact(tmp_path):
    import json
    data = tmp_path / "traj.jsonl"
    row = {
        "messages": [
            {"type": "tool_call", "role": "coder", "name": "shell", "error": "x"},
            {"type": "final", "role": "orchestrator"},
        ],
        "rewards": [
            {"step": 0, "promise": -1.0, "progress": -0.5},
            {"step": 1, "promise": 1.0, "progress": 0.5},
        ],
    }
    data.write_text(json.dumps(row) + "\n")
    out = tmp_path / "prm_linear.json"
    rc = prm_linear.main(["--data", str(data), "--out", str(out), "--epochs", "200"])
    assert rc == 0 and out.exists()
    # The artifact loads and scores without falling open.
    prm = LinearPRM(str(out))
    assert prm.score(_final_ctx()).promise > prm.score(_error_ctx()).promise


def test_main_no_examples_returns_nonzero(tmp_path):
    data = tmp_path / "empty.jsonl"
    data.write_text("")
    out = tmp_path / "prm_linear.json"
    assert prm_linear.main(["--data", str(data), "--out", str(out)]) == 1
    assert not out.exists()
