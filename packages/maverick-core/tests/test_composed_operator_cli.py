"""Composed learning is explicit file authoring and preserves strict ingress."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner
from maverick import config
from maverick.cli import main
from maverick.flow import composed_operator


def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _invoke(tmp_path, *args):
    return CliRunner().invoke(main, ["--db", str(tmp_path / "world.db"),
                                    "flow", "operator", *map(str, args)])


def _inputs(tmp_path):
    spec = _write(tmp_path, "spec.json", {
        "inputs": {"code": {"type": "string", "max_length": 30}}, "output_type": "string"})
    examples = _write(tmp_path, "examples.json", [
        {"inputs": {"code": " a "}, "output": "A"},
        {"inputs": {"code": " b "}, "output": "B"}])
    return spec, examples


@pytest.mark.parametrize("value,expected", [(True, True), (False, False), ("true", False),
                                           ("false", False), (1, False), (None, False)])
def test_composed_config_accepts_only_literal_boolean(monkeypatch, value, expected):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"composed_operators": value}})
    assert config.get_flows()["composed_operators"] is expected


def test_composed_config_defaults_off(monkeypatch):
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_flows()["composed_operators"] is False


def test_composed_learn_evaluate_refine_and_attach(tmp_path):
    spec, examples = _inputs(tmp_path)
    artifact = tmp_path / "packed.json"
    result = _invoke(tmp_path, "learn-composed", "--spec", spec, "--examples", examples,
                     "--max-operations", 2, "--operators", "strip,upper", "--reviewed", "--output", artifact)
    assert result.exit_code == 0, result.output
    assert "composed candidate expressions" in result.output
    original = artifact.read_bytes()
    body = json.loads(original)
    assert body["schema"] == composed_operator.SCHEMA and "candidates" not in body
    composed_operator.validate_artifact(body)
    data = _write(tmp_path, "input.json", {"code": " c "})
    result = _invoke(tmp_path, "evaluate", "--artifact", artifact, "--input", data)
    assert result.exit_code == 0, result.output
    decision = json.loads(result.output)
    assert decision["applied"] is True and decision["value"] == "C"
    additional = _write(tmp_path, "additional.json", [{"inputs": {"code": " d "}, "output": "D"}])
    refined = tmp_path / "refined.json"
    result = _invoke(tmp_path, "refine", "--artifact", artifact, "--examples", additional,
                     "--reviewed", "--output", refined)
    assert result.exit_code == 0, result.output
    assert artifact.read_bytes() == original
    assert json.loads(refined.read_text())["example_count"] == 3
    source = _write(tmp_path, "flow.json", {"id": "normalize", "name": "Normalize", "start": "code",
        "nodes": [{"id": "code", "kind": "agent", "brief": "Normalize code", "output": "answer"}]})
    before = source.read_bytes()
    draft = tmp_path / "draft.json"
    result = _invoke(tmp_path, "attach", source, "code", "--artifact", refined, "--output", draft)
    assert result.exit_code == 0, result.output
    assert source.read_bytes() == before
    assert json.loads(draft.read_text())["nodes"][0]["learned_operator"]["artifact"]["schema"] == composed_operator.SCHEMA


def test_composed_command_defaults_use_engine_defaults(tmp_path):
    spec, examples = _inputs(tmp_path)
    path = tmp_path / "defaults.json"
    result = _invoke(tmp_path, "learn-composed", "--spec", spec, "--examples", examples,
                     "--reviewed", "--output", path)
    assert result.exit_code == 0, result.output
    expected = composed_operator.synthesize(json.loads(spec.read_text()), json.loads(examples.read_text()))
    assert json.loads(path.read_text()) == expected


@pytest.mark.parametrize("option", [("--max-operations", "0"), ("--max-operations", "5"),
                                  ("--operators", "exec"), ("--operators", "strip,,upper"),
                                  ("--operators", "strip,strip")])
def test_composed_cli_rejects_invalid_grammar_without_artifact(tmp_path, option):
    spec, examples = _inputs(tmp_path)
    path = tmp_path / "invalid.json"
    result = _invoke(tmp_path, "learn-composed", "--spec", spec, "--examples", examples,
                     "--reviewed", "--output", path, *option)
    assert result.exit_code != 0 and not path.exists()


def test_composed_requires_review_and_refuses_overwrite(tmp_path):
    spec, examples = _inputs(tmp_path)
    path = tmp_path / "packed.json"
    args = ("learn-composed", "--spec", spec, "--examples", examples,
            "--max-operations", "2", "--operators", "strip,upper", "--output", path)
    result = _invoke(tmp_path, *args)
    assert result.exit_code != 0 and "--reviewed" in result.output and not path.exists()
    path.write_text("existing output", encoding="utf-8")
    result = _invoke(tmp_path, *args, "--reviewed")
    assert result.exit_code != 0 and "already exists" in result.output
    assert path.read_text() == "existing output"


def test_composed_question_answer_cli_preserves_source_files(tmp_path):
    artifact = composed_operator.synthesize(
        {"inputs": {"code": {"type": "string", "max_length": 30}}, "output_type": "string"},
        [{"inputs": {"code": "a"}, "output": "A"}, {"inputs": {"code": "b"}, "output": "B"}],
        max_operations=2, operators=["strip", "upper"])
    path = _write(tmp_path, "ambiguous.json", artifact)
    original = path.read_bytes()
    proposal = tmp_path / "question.json"
    result = _invoke(tmp_path, "question", "--artifact", path, "--max-probes", 32, "--output", proposal)
    assert result.exit_code == 0, result.output
    original_question = proposal.read_bytes()
    question = json.loads(original_question)
    assert question["status"] == "found"
    answer = _write(tmp_path, "answer.json", question["inputs"]["code"].strip().upper())
    refined = tmp_path / "answer-artifact.json"
    result = _invoke(tmp_path, "answer", "--artifact", path, "--question", proposal,
                     "--answer", answer, "--reviewed", "--output", refined)
    assert result.exit_code == 0, result.output
    assert path.read_bytes() == original and proposal.read_bytes() == original_question
    assert json.loads(refined.read_text())["schema"] == composed_operator.SCHEMA


def test_composed_duplicate_json_keys_are_refused(tmp_path):
    spec, examples = _inputs(tmp_path)
    spec.write_text('{"inputs":{},"inputs":{}}', encoding="utf-8")
    path = tmp_path / "invalid.json"
    result = _invoke(tmp_path, "learn-composed", "--spec", spec, "--examples", examples,
                     "--reviewed", "--output", path)
    assert result.exit_code != 0 and "duplicate JSON key" in result.output
    assert not path.exists()
