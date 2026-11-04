"""Local question/answer authoring preserves source artifacts and uncertainty."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick import config
from maverick.cli import main
from maverick.flow.learned_operator import synthesize


def _json(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _invoke(tmp_path, *args):
    return CliRunner().invoke(main, ["--db", str(tmp_path / "world.db"),
                                    "flow", "operator", *map(str, args)])


def _artifact(tmp_path):
    return _json(tmp_path, "operator.json", synthesize({
        "inputs": {"x": {"type": "integer", "min": 0, "max": 10}},
        "output_type": "boolean", "constants": [5],
    }, [{"inputs": {"x": 0}, "output": False},
        {"inputs": {"x": 10}, "output": True}]))


@pytest.mark.parametrize("value, expected", [
    (True, True), (False, False), ("true", False), ("false", False),
    (1, False), (None, False), ([], False),
])
def test_questions_config_is_strict_opt_in(monkeypatch, value, expected):
    monkeypatch.setattr(config, "load_config", lambda: {
        "flows": {"learned_operator_questions": value},
    })
    assert config.get_flows()["learned_operator_questions"] is expected
    assert config.get_flows()["learned_operators"] is False


def test_questions_default_off(monkeypatch):
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_flows()["learned_operator_questions"] is False


def test_question_answer_cycle_no_overwrite_no_implied_identity(tmp_path):
    artifact = _artifact(tmp_path)
    before = artifact.read_bytes()
    question = tmp_path / "question.json"
    result = _invoke(tmp_path, "question", "--artifact", artifact, "--max-probes", 256,
                     "--output", question)
    assert result.exit_code == 0, result.output
    proposed = json.loads(question.read_text(encoding="utf-8"))
    assert proposed["status"] == "found"
    assert proposed["inputs"] == {"x": 5}
    assert len(proposed["predictions"]) > 1
    original_question = question.read_bytes()
    result = _invoke(tmp_path, "question", "--artifact", artifact, "--output", question)
    assert result.exit_code != 0 and "already exists" in result.output
    assert question.read_bytes() == original_question
    label = _json(tmp_path, "answer.json", False)
    refined = tmp_path / "refined.json"
    args = ("answer", "--artifact", artifact, "--question", question,
            "--answer", label, "--output", refined)
    result = _invoke(tmp_path, *args)
    assert result.exit_code != 0 and "--reviewed" in result.output
    assert not refined.exists()
    result = _invoke(tmp_path, *args, "--reviewed")
    assert result.exit_code == 0, result.output
    assert "No authenticated reviewer identity" in result.output
    after = json.loads(refined.read_text(encoding="utf-8"))
    assert after["example_count"] == 3
    assert len(after["candidates"]) < len(json.loads(before)["candidates"])
    assert artifact.read_bytes() == before and question.read_bytes() == original_question
    result = _invoke(tmp_path, *args, "--reviewed")
    assert result.exit_code != 0 and "already exists" in result.output


@pytest.mark.parametrize("value", [None, 1.5, {}, []])
def test_answer_requires_a_strict_scalar(tmp_path, value):
    artifact = _artifact(tmp_path)
    question = tmp_path / "question.json"
    result = _invoke(tmp_path, "question", "--artifact", artifact, "--output", question)
    assert result.exit_code == 0, result.output
    label = _json(tmp_path, "answer.json", value)
    output = tmp_path / "refined.json"
    result = _invoke(tmp_path, "answer", "--artifact", artifact, "--question", question,
                     "--answer", label, "--reviewed", "--output", output)
    assert result.exit_code != 0 and "one JSON" in result.output
    assert not output.exists()


def test_changed_question_is_rejected(tmp_path):
    artifact = _artifact(tmp_path)
    question = tmp_path / "question.json"
    result = _invoke(tmp_path, "question", "--artifact", artifact, "--output", question)
    assert result.exit_code == 0, result.output
    changed = json.loads(question.read_text(encoding="utf-8"))
    changed["inputs"] = {"x": 4}
    _json(tmp_path, "changed.json", changed)
    label = _json(tmp_path, "answer.json", False)
    output = tmp_path / "refined.json"
    result = _invoke(tmp_path, "answer", "--artifact", artifact,
                     "--question", tmp_path / "changed.json", "--answer", label,
                     "--reviewed", "--output", output)
    assert result.exit_code != 0 and not output.exists()


@pytest.mark.parametrize("budget", [0, 4097])
def test_question_probe_budget_is_bounded(tmp_path, budget):
    artifact = _artifact(tmp_path)
    result = _invoke(tmp_path, "question", "--artifact", artifact, "--max-probes", budget,
                     "--output", tmp_path / "question.json")
    assert result.exit_code == 2
    assert not (tmp_path / "question.json").exists()
