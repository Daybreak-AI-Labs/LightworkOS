"""LearnedPRM + prm_train: the SHARED feature spec, the fail-open path, and
the torch-free training helpers. These all run WITHOUT torch installed —
that is the point. The round-trip train/load test is skipped if torch is
absent.
"""
import json
import sys
import types

import pytest
from maverick.prm import (
    FEATURE_NAMES,
    MAX_LEARNED_PRM_HIDDEN_DIM,
    ROLE_VOCAB,
    HeuristicPRM,
    LearnedPRM,
    StepContext,
    StepReward,
    build_from_env,
    step_features,
)
from maverick.training import prm_train

# --- step_features ---------------------------------------------------------

def test_step_features_length_is_12():
    feats = step_features(StepContext(goal_id=0, step_index=0, role="coder"))
    assert len(feats) == 12 == len(FEATURE_NAMES)


def test_step_features_known_role_onehot():
    feats = step_features(StepContext(goal_id=0, step_index=0, role="coder"))
    onehot = feats[6:]
    assert onehot == [0.0, 0.0, 1.0, 0.0, 0.0, 0.0]
    assert sum(onehot) == 1.0
    assert ROLE_VOCAB[onehot.index(1.0)] == "coder"


def test_step_features_role_prefix_before_dash():
    feats = step_features(StepContext(goal_id=0, step_index=0, role="researcher-3"))
    onehot = feats[6:]
    assert onehot[ROLE_VOCAB.index("researcher")] == 1.0
    assert sum(onehot) == 1.0


def test_step_features_unknown_role_is_other():
    feats = step_features(StepContext(goal_id=0, step_index=0, role="gremlin"))
    onehot = feats[6:]
    assert onehot[ROLE_VOCAB.index("other")] == 1.0
    assert sum(onehot) == 1.0


def test_step_features_tool_succeeded_mapping():
    base = dict(goal_id=0, step_index=0, role="coder")
    assert step_features(StepContext(**base, tool_succeeded=None))[2] == 0.0
    assert step_features(StepContext(**base, tool_succeeded=True))[2] == 1.0
    assert step_features(StepContext(**base, tool_succeeded=False))[2] == -1.0


def test_step_features_flags_and_scalars():
    ctx = StepContext(
        goal_id=0,
        step_index=250,
        role="writer",
        tool_name="shell",
        is_final=True,
        error="boom",
        prior_step_score=0.42,
    )
    feats = step_features(ctx)
    assert feats[0] == 1.0          # is_final
    assert feats[1] == 1.0          # has_error
    assert feats[3] == 1.0          # has_tool
    assert feats[4] == pytest.approx(0.42)   # prior_step_score
    assert feats[5] == 1.0          # step_index_norm clamps at 1.0


def test_step_features_step_index_norm():
    feats = step_features(StepContext(goal_id=0, step_index=50, role="coder"))
    assert feats[5] == pytest.approx(0.5)


# --- LearnedPRM fail-open --------------------------------------------------

@pytest.mark.parametrize(
    "ctx",
    [
        StepContext(goal_id=0, step_index=0, role="coder", error="boom"),
        StepContext(goal_id=0, step_index=1, role="writer", is_final=True),
    ],
)
def test_learned_prm_bogus_path_falls_back_to_heuristic(ctx):
    learned = LearnedPRM(model_dir="/nonexistent/path/does/not/exist")
    heuristic = HeuristicPRM()
    got = learned.score(ctx)
    want = heuristic.score(ctx)
    assert isinstance(got, StepReward)
    assert got == want


def test_learned_prm_construction_does_not_import_torch():
    # Construction must not touch torch / the filesystem.
    learned = LearnedPRM(model_dir="/nope")
    assert learned._model is None


class _FakeTensor:
    def __init__(self, shape):
        self.shape = shape


class _FakeNet:
    def __init__(self, *layers):
        self.layers = layers
        self.loaded_state = None

    def load_state_dict(self, state):
        self.loaded_state = state

    def eval(self):
        return None


def _install_fake_torch(monkeypatch, state):
    calls = {}

    def load(path, *, map_location=None, weights_only=None):
        calls["path"] = path
        calls["map_location"] = map_location
        calls["weights_only"] = weights_only
        return state

    fake_torch = types.SimpleNamespace(
        load=load,
        is_tensor=lambda value: isinstance(value, _FakeTensor),
        nn=types.SimpleNamespace(
            Linear=lambda *args: ("linear", args),
            ReLU=lambda: ("relu",),
            Sequential=_FakeNet,
        ),
    )
    monkeypatch.setitem(sys.modules, "torch", fake_torch)
    return calls


def _valid_meta(hidden_dim=16):
    return {
        "version": 1,
        "input_dim": len(FEATURE_NAMES),
        "hidden_dim": hidden_dim,
        "feature_names": FEATURE_NAMES,
        "role_vocab": ROLE_VOCAB,
    }


def _valid_state(hidden_dim=16):
    return {
        "0.weight": _FakeTensor((hidden_dim, len(FEATURE_NAMES))),
        "0.bias": _FakeTensor((hidden_dim,)),
        "2.weight": _FakeTensor((2, hidden_dim)),
        "2.bias": _FakeTensor((2,)),
    }


def test_learned_prm_uses_weights_only_torch_load(monkeypatch, tmp_path):
    (tmp_path / "head.json").write_text(json.dumps(_valid_meta()), encoding="utf-8")
    (tmp_path / "head.pt").write_bytes(b"fake")
    calls = _install_fake_torch(monkeypatch, _valid_state())

    learned = LearnedPRM(model_dir=str(tmp_path))
    model = learned._load()

    assert model is not None
    assert calls["map_location"] == "cpu"
    assert calls["weights_only"] is True


def test_learned_prm_rejects_metadata_mismatch_before_loading(monkeypatch, tmp_path):
    bad_meta = _valid_meta()
    bad_meta["feature_names"] = [*FEATURE_NAMES, "unexpected"]
    (tmp_path / "head.json").write_text(json.dumps(bad_meta), encoding="utf-8")
    (tmp_path / "head.pt").write_bytes(b"fake")
    calls = _install_fake_torch(monkeypatch, _valid_state())

    learned = LearnedPRM(model_dir=str(tmp_path))

    assert learned._load() is None
    assert calls == {}


def test_learned_prm_rejects_invalid_state_dict(monkeypatch, tmp_path):
    (tmp_path / "head.json").write_text(json.dumps(_valid_meta()), encoding="utf-8")
    (tmp_path / "head.pt").write_bytes(b"fake")
    bad_state = _valid_state()
    bad_state["2.weight"] = _FakeTensor((3, 16))
    _install_fake_torch(monkeypatch, bad_state)

    learned = LearnedPRM(model_dir=str(tmp_path))

    assert learned._load() is None


def test_learned_prm_caps_hidden_dim(monkeypatch, tmp_path):
    too_large = MAX_LEARNED_PRM_HIDDEN_DIM + 1
    (tmp_path / "head.json").write_text(
        json.dumps(_valid_meta(hidden_dim=too_large)), encoding="utf-8"
    )
    (tmp_path / "head.pt").write_bytes(b"fake")
    calls = _install_fake_torch(monkeypatch, _valid_state(hidden_dim=too_large))

    learned = LearnedPRM(model_dir=str(tmp_path))

    assert learned._load() is None
    assert calls == {}


# --- build_from_env --------------------------------------------------------

def test_build_from_env_learned_no_path_falls_back_to_heuristic(monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM", "learned")
    monkeypatch.delenv("MAVERICK_PRM_PATH", raising=False)
    model = build_from_env()
    assert isinstance(model, HeuristicPRM)


def test_build_from_env_learned_with_path_returns_learned(monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM", "learned")
    monkeypatch.setenv("MAVERICK_PRM_PATH", "/some/dir")
    model = build_from_env()
    assert isinstance(model, LearnedPRM)
    assert model.model_dir == "/some/dir"


# --- prm_train pure helpers ------------------------------------------------

def _toy_klear_row():
    """A hand-built Klear row mirroring schema.to_klear_jsonl output."""
    return {
        "id": "toy-1",
        "task_family": None,
        "model": "test",
        "outcome": "success",
        "terminal_reward": 1.0,
        "messages": [
            {"role": "coder", "type": "tool_call", "name": "shell",
             "obs_hash": "abc", "error": None},
            {"role": "coder", "type": "tool_call", "name": "shell",
             "obs_hash": "def", "error": "boom"},
            {"role": "writer", "type": "final", "name": "",
             "obs_hash": "ghi", "error": None},
        ],
        "rewards": [
            {"step": 0, "promise": 0.6, "progress": 0.1},
            {"step": 1, "promise": 0.3, "progress": -0.05},
            {"step": 2, "promise": 1.0, "progress": 0.5},
        ],
    }


def test_load_klear_parses_jsonl(tmp_path):
    p = tmp_path / "traj.jsonl"
    rows_in = [_toy_klear_row(), _toy_klear_row()]
    p.write_text("\n".join(json.dumps(r) for r in rows_in) + "\n", encoding="utf-8")
    rows = prm_train.load_klear(p)
    assert len(rows) == 2
    assert rows[0]["id"] == "toy-1"


def test_load_klear_skips_blank_lines(tmp_path):
    p = tmp_path / "traj.jsonl"
    p.write_text(json.dumps(_toy_klear_row()) + "\n\n  \n", encoding="utf-8")
    assert len(prm_train.load_klear(p)) == 1


def test_rows_to_examples_shapes_and_values():
    examples = prm_train.rows_to_examples([_toy_klear_row()])
    assert len(examples) == 3
    for x, y in examples:
        assert len(x) == 12
        assert len(y) == 2
    # Y values come straight from the rewards array.
    ys = [y for _, y in examples]
    assert ys[0] == [0.6, 0.1]
    assert ys[2] == [1.0, 0.5]
    # The tool_call with an error -> tool_succeeded False -> feature index 2.
    assert examples[1][0][2] == -1.0
    assert examples[0][0][2] == 1.0
    # The final step sets is_final.
    assert examples[2][0][0] == 1.0


def test_rows_to_examples_skips_none_labels():
    row = _toy_klear_row()
    row["rewards"][1] = {"step": 1, "promise": None, "progress": None}
    examples = prm_train.rows_to_examples([row])
    assert len(examples) == 2  # the None-labeled step is dropped


# --- optional torch round-trip --------------------------------------------

def test_train_load_score_roundtrip(tmp_path):
    pytest.importorskip("torch")
    examples = [
        (step_features(StepContext(goal_id=0, step_index=0, role="coder",
                                   tool_name="shell", tool_succeeded=True)),
         [0.6, 0.1]),
        (step_features(StepContext(goal_id=0, step_index=1, role="coder",
                                   error="boom")),
         [-0.5, -0.1]),
        (step_features(StepContext(goal_id=0, step_index=2, role="writer",
                                   is_final=True)),
         [1.0, 0.5]),
    ]
    state = prm_train.train(examples, epochs=5, lr=1e-2)
    out = tmp_path / "prm_head"
    prm_train.save_head(out, state)
    assert (out / "head.pt").exists()
    meta = json.loads((out / "head.json").read_text(encoding="utf-8"))
    assert meta["input_dim"] == 12
    assert meta["feature_names"] == FEATURE_NAMES
    assert meta["role_vocab"] == ROLE_VOCAB

    learned = LearnedPRM(model_dir=str(out))
    reward = learned.score(StepContext(goal_id=0, step_index=0, role="coder"))
    import math
    assert math.isfinite(reward.promise) and -1.0 <= reward.promise <= 1.0
    assert math.isfinite(reward.progress) and -1.0 <= reward.progress <= 1.0
    assert reward.confidence == 0.7
