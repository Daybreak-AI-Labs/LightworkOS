"""Real file-only operator authoring; strict ingress and no implicit publication."""
from __future__ import annotations

import json

import click
import pytest
from click.testing import CliRunner
from maverick import config
from maverick.cli import _flow_operator_groups as commands
from maverick.cli import main


@pytest.mark.parametrize("raw, expected", [
    ({}, False), ({"learned_operators": True}, True),
    ({"learned_operators": False}, False), ({"learned_operators": "true"}, False),
    ({"learned_operators": "false"}, False), ({"learned_operators": 1}, False),
    ({"learned_operators": None}, False), (None, False), ([], False),
])
def test_config_requires_literal_bool(monkeypatch, raw, expected):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": raw})
    assert config.get_flows()["learned_operators"] is expected


def _json(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _invoke(tmp_path, *args):
    return CliRunner().invoke(main, ["--db", str(tmp_path / "world.db"),
                                    "flow", "operator", *map(str, args)])


def _learn(tmp_path):
    spec = _json(tmp_path, "spec.json", {
        "inputs": {"x": {"type": "integer", "min": 0, "max": 100}},
        "output_type": "integer", "constants": [1],
    })
    examples = _json(tmp_path, "examples.json", [
        {"inputs": {"x": 2}, "output": 3},
        {"inputs": {"x": 7}, "output": 8},
    ])
    artifact = tmp_path / "operator.json"
    result = _invoke(tmp_path, "learn", "--spec", spec, "--examples", examples,
                     "--reviewed", "--output", artifact)
    assert result.exit_code == 0, result.output
    return artifact, spec, examples


def test_registered_help(tmp_path):
    result = _invoke(tmp_path, "--help")
    assert result.exit_code == 0
    for command in ("learn", "evaluate", "refine", "attach", "remove"):
        assert command in result.output


def test_learn_evaluate_and_outside_domain(tmp_path):
    artifact, _, _ = _learn(tmp_path)
    body = json.loads(artifact.read_text(encoding="utf-8"))
    assert body["example_count"] == 2
    assert len(body["artifact_sha256"]) == 64
    data = _json(tmp_path, "input.json", {"x": 12})
    result = _invoke(tmp_path, "evaluate", "--artifact", artifact, "--input", data)
    assert result.exit_code == 0, result.output
    decision = json.loads(result.output)
    assert decision["applied"] is True and decision["value"] == 13
    data = _json(tmp_path, "outside.json", {"x": 101})
    result = _invoke(tmp_path, "evaluate", "--artifact", artifact, "--input", data)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["applied"] is False


def test_review_required_and_no_output_overwrite(tmp_path):
    artifact, spec, examples = _learn(tmp_path)
    original = artifact.read_bytes()
    result = _invoke(tmp_path, "learn", "--spec", spec, "--examples", examples,
                     "--output", tmp_path / "unreviewed.json")
    assert result.exit_code != 0 and "--reviewed" in result.output
    assert not (tmp_path / "unreviewed.json").exists()
    result = _invoke(tmp_path, "learn", "--spec", spec, "--examples", examples,
                     "--reviewed", "--output", artifact)
    assert result.exit_code != 0 and "already exists" in result.output
    assert artifact.read_bytes() == original


@pytest.mark.parametrize("raw, error", [
    ('{"x":1,"x":2}', "duplicate JSON key"),
    ('{"x":NaN}', "non-finite"),
    ('{"x":Infinity}', "non-finite"),
    ('{"x":1e999}', "non-finite"),
    ("[" * 42 + "0" + "]" * 42, "nesting"),
    (" " * 262145, "exceeds"),
], ids=["duplicate", "nan", "infinity", "overflow", "depth", "bytes"])
def test_strict_bounded_json(tmp_path, raw, error):
    path = tmp_path / "bad.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(click.ClickException, match=error):
        commands._read_json(path)


def test_attach_remove_are_new_drafts_preserving_original(tmp_path, monkeypatch):
    from maverick.flow import store

    def no_publish(*args, **kwargs):
        raise AssertionError("file authoring must not publish")

    monkeypatch.setattr(store, "save_flow", no_publish)
    artifact, _, _ = _learn(tmp_path)
    source = _json(tmp_path, "flow.json", {
        "id": "draft", "name": "Increment", "start": "step", "owner": "alice",
        "nodes": [{"id": "step", "kind": "agent", "brief": "Compute x plus one",
                   "output": "answer"}],
    })
    original = source.read_bytes()
    attached = tmp_path / "attached.json"
    result = _invoke(tmp_path, "attach", source, "step", "--artifact", artifact,
                     "--output", attached)
    assert result.exit_code == 0, result.output
    assert source.read_bytes() == original
    draft = json.loads(attached.read_text(encoding="utf-8"))
    assert draft["owner"] == "alice"
    assert draft["nodes"][0]["learned_operator"]
    assert draft["nodes"][0]["kind"] == "agent"
    assert draft["nodes"][0]["brief"] == "Compute x plus one"
    result = _invoke(tmp_path, "attach", source, "step", "--artifact", artifact,
                     "--output", source)
    assert result.exit_code != 0 and "already exists" in result.output
    assert source.read_bytes() == original
    removed = tmp_path / "removed.json"
    result = _invoke(tmp_path, "remove", attached, "step", "--output", removed)
    assert result.exit_code == 0, result.output
    node = json.loads(removed.read_text(encoding="utf-8"))["nodes"][0]
    assert not node.get("learned_operator")
    assert node["kind"] == "agent" and node["brief"] == "Compute x plus one"


def test_duplicate_node_ids_rejected_before_draft_write(tmp_path):
    artifact, _, _ = _learn(tmp_path)
    source = _json(tmp_path, "flow.json", {"nodes": [
        {"id": "same", "kind": "agent", "brief": "one", "output": "x"},
        {"id": "same", "kind": "agent", "brief": "two", "output": "x"},
    ]})
    result = _invoke(tmp_path, "attach", source, "same", "--artifact", artifact,
                     "--output", tmp_path / "invalid.json")
    assert result.exit_code != 0 and "unique" in result.output
    assert not (tmp_path / "invalid.json").exists()


def test_refine_resolves_boundary_without_mutating_old_artifact(tmp_path):
    from maverick.flow.learned_operator import synthesize

    old = synthesize({
        "inputs": {"x": {"type": "integer", "min": 0, "max": 10}},
        "output_type": "boolean", "constants": [5],
    }, [{"inputs": {"x": 0}, "output": False},
        {"inputs": {"x": 10}, "output": True}])
    artifact = _json(tmp_path, "threshold.json", old)
    original = artifact.read_bytes()
    data = _json(tmp_path, "boundary.json", {"x": 5})
    result = _invoke(tmp_path, "evaluate", "--artifact", artifact, "--input", data)
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["applied"] is False
    examples = _json(tmp_path, "additional.json", [{"inputs": {"x": 5}, "output": False}])
    refined = tmp_path / "refined.json"
    result = _invoke(tmp_path, "refine", "--artifact", artifact, "--examples", examples,
                     "--output", refined)
    assert result.exit_code != 0 and "--reviewed" in result.output
    assert not refined.exists()
    result = _invoke(tmp_path, "refine", "--artifact", artifact, "--examples", examples,
                     "--reviewed", "--output", refined)
    assert result.exit_code == 0, result.output
    assert artifact.read_bytes() == original
    new = json.loads(refined.read_text(encoding="utf-8"))
    assert new["example_count"] == 3
    assert len(new["candidates"]) < len(old["candidates"])
    result = _invoke(tmp_path, "evaluate", "--artifact", refined, "--input", data)
    assert result.exit_code == 0, result.output
    decision = json.loads(result.output)
    assert decision["applied"] is True and decision["value"] is False
    contradictory = _json(tmp_path, "contradictory.json", [
        {"inputs": {"x": 5}, "output": True},
    ])
    result = _invoke(tmp_path, "refine", "--artifact", refined,
                     "--examples", contradictory, "--reviewed",
                     "--output", tmp_path / "bad-refinement.json")
    assert result.exit_code != 0
    assert not (tmp_path / "bad-refinement.json").exists()
