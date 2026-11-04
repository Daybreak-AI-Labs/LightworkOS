"""`maverick reward-model` CLI: train + score, with clean errors."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main


def _runner():
    return CliRunner()


def _rows():
    rows = []
    for f in range(5):
        rows.append({"id": f"{f}-g", "task_family": f"f{f}", "terminal_reward": 1.0,
                     "messages": [{"role": "w", "type": "tool_call", "name": "grep",
                                   "error": None}]})
        rows.append({"id": f"{f}-b", "task_family": f"f{f}", "terminal_reward": 0.0,
                     "messages": [{"role": "w", "type": "tool_call", "name": "grep",
                                   "error": "boom"}]})
    return rows


def _write_jsonl(path, rows):
    path.write_text("\n".join(json.dumps(r) for r in rows))


def test_train_writes_model(tmp_path):
    data = tmp_path / "traj.jsonl"
    _write_jsonl(data, _rows())
    out = tmp_path / "rm.json"
    r = _runner().invoke(main, ["reward-model", "train", str(data),
                                "--out", str(out), "--epochs", "200"])
    assert r.exit_code == 0, r.output
    assert "pairwise accuracy" in r.output
    model = json.loads(out.read_text())
    assert model["type"] == "bradley_terry_linear"


def test_train_no_pairs_is_clean_error(tmp_path):
    # One attempt per family -> no preference pairs -> ClickException, not a trace.
    data = tmp_path / "traj.jsonl"
    _write_jsonl(data, [{"id": "solo", "task_family": "f", "terminal_reward": 1.0,
                         "messages": []}])
    out = tmp_path / "rm.json"
    r = _runner().invoke(main, ["reward-model", "train", str(data), "--out", str(out)])
    assert r.exit_code != 0
    assert "no preference pairs" in r.output
    assert "Traceback" not in r.output


def test_score_ranks_high_to_low(tmp_path):
    data = tmp_path / "traj.jsonl"
    _write_jsonl(data, _rows())
    out = tmp_path / "rm.json"
    assert _runner().invoke(main, ["reward-model", "train", str(data),
                                   "--out", str(out)]).exit_code == 0
    r = _runner().invoke(main, ["reward-model", "score", str(out), str(data), "--top", "1"])
    assert r.exit_code == 0, r.output
    ranked = json.loads(r.output)
    assert len(ranked) == 1
    # The clean (error-free) trajectory ranks first.
    assert ranked[0]["id"].endswith("-g")


def test_score_bad_model_is_clean_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"weights": "notadict"}')
    data = tmp_path / "traj.jsonl"
    _write_jsonl(data, _rows())
    r = _runner().invoke(main, ["reward-model", "score", str(bad), str(data)])
    assert r.exit_code != 0
    assert "cannot load reward model" in r.output
    assert "Traceback" not in r.output
