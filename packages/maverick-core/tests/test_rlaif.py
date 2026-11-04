"""Tests for the RLAIF/DPO pair-construction + plumbing.

Only the pure, torch-free parts are exercised here: loading Klear JSONL,
turning verifier rewards into DPO preference pairs, the structural-text
stand-in, and the "torch missing -> actionable message + return 1" path.

The DPO training loop itself (which needs a GPU + a real base model) is
deliberately NOT validated here.
"""
import builtins
import json

import pytest
from maverick.training import rlaif


def _row(rid, family, reward, conf=1.0, messages=None):
    return {
        "id": rid,
        "task_family": family,
        "model": "m",
        "outcome": "success",
        "terminal_reward": reward,
        "messages": messages or [
            {"role": "planner", "type": "think", "name": "",
             "obs_hash": "ab", "error": None},
        ],
        "rewards": [],
        "meta": {"verifier_confidence": conf},
    }


# --------------------------------------------------------------------------
# load_klear
# --------------------------------------------------------------------------


def test_load_klear_parses_jsonl(tmp_path):
    rows = [_row("a", "swe", 1.0), _row("b", "swe", 0.0)]
    p = tmp_path / "traj.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    loaded = rlaif.load_klear(p)
    assert len(loaded) == 2
    assert loaded[0]["id"] == "a"
    assert loaded[1]["terminal_reward"] == 0.0


def test_load_klear_skips_blank_and_bad_lines(tmp_path):
    p = tmp_path / "traj.jsonl"
    p.write_text(
        json.dumps(_row("a", "swe", 1.0)) + "\n"
        "\n"
        "{not valid json}\n"
        + json.dumps(_row("b", "swe", 0.0)) + "\n",
        encoding="utf-8",
    )
    loaded = rlaif.load_klear(p)
    assert [r["id"] for r in loaded] == ["a", "b"]


# --------------------------------------------------------------------------
# build_preference_pairs
# --------------------------------------------------------------------------


def test_pairs_only_within_family():
    rows = [
        _row("hi", "swe", 1.0),
        _row("lo", "swe", 0.0),
        _row("other_hi", "research", 1.0),
        _row("other_lo", "research", 0.0),
    ]
    pairs = rlaif.build_preference_pairs(rows, min_margin=0.5)
    # One pair per family; never cross-family.
    fams = sorted(p["task_family"] for p in pairs)
    assert fams == ["research", "swe"]
    for p in pairs:
        if p["task_family"] == "swe":
            assert {p["chosen_id"], p["rejected_id"]} == {"hi", "lo"}
        else:
            assert {p["chosen_id"], p["rejected_id"]} == {"other_hi", "other_lo"}


def test_pairs_respect_min_margin():
    rows = [
        _row("a", "swe", 1.0),
        _row("b", "swe", 0.9),   # margin 0.1 -> dropped
        _row("c", "swe", 0.2),   # margin vs a = 0.8 -> kept
    ]
    pairs = rlaif.build_preference_pairs(rows, min_margin=0.5)
    margins = sorted(round(p["margin"], 3) for p in pairs)
    # a-c (0.8) and b-c (0.7) qualify; a-b (0.1) does not.
    assert margins == [0.7, 0.8]
    assert all(p["margin"] >= 0.5 for p in pairs)


def test_chosen_reward_greater_than_rejected():
    rows = [_row("hi", "swe", 1.0), _row("lo", "swe", 0.0)]
    pairs = rlaif.build_preference_pairs(rows, min_margin=0.5)
    assert len(pairs) == 1
    p = pairs[0]
    assert p["chosen_id"] == "hi"
    assert p["rejected_id"] == "lo"
    assert p["chosen_reward"] > p["rejected_reward"]
    assert p["margin"] == pytest.approx(1.0)


def test_per_group_cap_respected():
    # 5 members all pairwise above margin -> 10 candidate pairs; cap to 3.
    rewards = [5.0, 4.0, 3.0, 2.0, 1.0]
    rows = [_row(f"r{i}", "swe", rw) for i, rw in enumerate(rewards)]
    pairs = rlaif.build_preference_pairs(
        rows, min_margin=0.5, max_pairs_per_group=3,
    )
    assert len(pairs) == 3
    # Cap keeps the widest-margin pairs first.
    assert pairs[0]["margin"] == pytest.approx(4.0)  # 5.0 vs 1.0
    assert all(pairs[i]["margin"] >= pairs[i + 1]["margin"]
               for i in range(len(pairs) - 1))


def test_per_group_cap_avoids_materializing_all_candidates(monkeypatch):
    rows = [_row(f"r{i}", "swe", float(i)) for i in range(100)]
    built = 0
    real_pair = rlaif._preference_pair

    def counted_pair(*args, **kwargs):
        nonlocal built
        built += 1
        return real_pair(*args, **kwargs)

    monkeypatch.setattr(rlaif, "_preference_pair", counted_pair)
    pairs = rlaif.build_preference_pairs(
        rows, min_margin=0.5, max_pairs_per_group=3,
    )

    assert len(pairs) == 3
    assert built == 3


def test_empty_or_missing_family_skipped():
    rows = [
        _row("a", "", 1.0),
        _row("b", "", 0.0),
        _row("c", None, 1.0),
        _row("d", None, 0.0),
        _row("e", "swe", 1.0),
        _row("f", "swe", 0.0),
    ]
    pairs = rlaif.build_preference_pairs(rows, min_margin=0.5)
    assert len(pairs) == 1
    assert pairs[0]["task_family"] == "swe"


def test_verifier_confidence_becomes_weight():
    rows = [_row("hi", "swe", 1.0, conf=0.8), _row("lo", "swe", 0.0, conf=0.6)]
    pairs = rlaif.build_preference_pairs(rows, min_margin=0.5)
    # weight = mean of the two confidences.
    assert pairs[0]["weight"] == pytest.approx(0.7)


def test_confidence_tiebreaks_cap():
    # Two pairs with equal margin; the higher-confidence one survives a cap=1.
    rows = [
        _row("hi1", "swe", 1.0, conf=0.2),
        _row("lo1", "swe", 0.0, conf=0.2),
        _row("hi2", "swe", 1.0, conf=0.9),
        _row("lo2", "swe", 0.0, conf=0.9),
    ]
    pairs = rlaif.build_preference_pairs(
        rows, min_margin=0.5, max_pairs_per_group=1,
    )
    assert len(pairs) == 1
    # The kept pair should be the high-confidence one (weight ~0.9).
    assert pairs[0]["weight"] == pytest.approx(0.9)


# --------------------------------------------------------------------------
# trajectory_to_text
# --------------------------------------------------------------------------


def test_trajectory_to_text_structural_stand_in():
    row = _row("a", "swe", 1.0, messages=[
        {"role": "planner", "type": "think", "name": "",
         "obs_hash": "x", "error": None},
        {"role": "observer", "type": "tool_call", "name": "grep",
         "obs_hash": "y", "error": None},
        {"role": "observer", "type": "tool_call", "name": "shell",
         "obs_hash": "z", "error": "boom"},
    ])
    text = rlaif.trajectory_to_text(row)
    assert text == "planner/think | observer/tool_call:grep | observer/tool_call:shell!err"


# --------------------------------------------------------------------------
# train: torch missing -> actionable message + return 1
# --------------------------------------------------------------------------


def test_train_returns_1_when_torch_missing(monkeypatch, capsys):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "torch" or name.startswith("torch.") or name == "transformers":
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = rlaif.train(
        [{"chosen_id": "a", "rejected_id": "b", "weight": 1.0}],
        base_model="dummy",
        out_dir="/tmp/does-not-matter",
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "packages/maverick-core[training]" in err
    assert "torch" in err


# --------------------------------------------------------------------------
# CLI arg parsing
# --------------------------------------------------------------------------


def test_arg_parser_requires_core_flags():
    parser = rlaif._build_parser()
    args = parser.parse_args([
        "--data", "t.jsonl", "--base-model", "hf/x", "--out", "./o",
    ])
    assert str(args.data) == "t.jsonl"
    assert args.base_model == "hf/x"
    assert args.beta == 0.1
    assert args.epochs == 1
    assert args.max_pairs == 32
    assert args.min_margin == 0.5


def test_arg_parser_missing_required_exits():
    parser = rlaif._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--data", "t.jsonl"])  # no --base-model/--out


def test_main_returns_1_without_torch(tmp_path, monkeypatch):
    # End-to-end CLI plumbing: build pairs from a file, hit the missing-dep
    # path, and bubble up return code 1.
    p = tmp_path / "traj.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(_row("hi", "swe", 1.0)) + "\n")
        fh.write(json.dumps(_row("lo", "swe", 0.0)) + "\n")

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "torch" or name.startswith("torch.") or name == "transformers":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = rlaif.main([
        "--data", str(p), "--base-model", "dummy", "--out", str(tmp_path / "o"),
    ])
    assert rc == 1


def test_main_reward_model_cross_check(tmp_path, capsys, monkeypatch):
    # --reward-model runs the learned-reward cross-check (and downweights
    # disagreements) before the torch-gated train step. Verify the agreement
    # line prints; train still no-ops without torch.
    import builtins

    from maverick.training.reward_model import PreferenceRewardModel
    p = tmp_path / "traj.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(_row("hi", "swe", 1.0)) + "\n")
        fh.write(json.dumps(_row("lo", "swe", 0.0)) + "\n")
    rm_path = tmp_path / "rm.json"
    PreferenceRewardModel({"n_errors": -2.0}).save(rm_path)

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "torch" or name.startswith("torch.") or name == "transformers":
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = rlaif.main([
        "--data", str(p), "--base-model", "dummy", "--out", str(tmp_path / "o"),
        "--reward-model", str(rm_path),
    ])
    assert rc == 1  # torch still missing
    assert "reward-model cross-check" in capsys.readouterr().err
