"""Writer/routing regressions; synthetic payloads do not qualify learned artifacts.

The command's package validation and Flow construction are stubbed only to
isolate the former 256 KiB writer mismatch. Native byte/structure validation and
exclusive file creation remain real. Actual signed learning is tested elsewhere.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import click
import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.cli._flow_recipe_groups import _write_memory_flow_json
from maverick.flow import Flow, action_recipe, recipe_flow, recipe_lineage, workflow_memory


def test_memory_writer_allows_native_bounded_payload_above_legacy_limit(tmp_path):
    payload = {"writer_fixture": "x" * 270_000}
    target = tmp_path / "large-inspection.json"
    _write_memory_flow_json(target, payload)
    assert 262_144 < target.stat().st_size < 1_000_000
    assert json.loads(target.read_bytes()) == payload
    original = target.read_bytes()
    with pytest.raises(click.ClickException, match="already exists"):
        _write_memory_flow_json(target, {"different": "value"})
    assert target.read_bytes() == original


def test_memory_writer_enforces_actual_native_bound_before_creating_file(tmp_path):
    target = tmp_path / "too-large.json"
    with pytest.raises(click.ClickException, match="1000000-byte"):
        _write_memory_flow_json(target, {"writer_fixture": "x" * 1_000_000})
    assert not target.exists()


def test_actual_large_pure_memory_artifact_roundtrips_through_native_draft_writer(tmp_path):
    # Complete pure examples, explicitly not signed/authenticated business
    # evidence. This verifies an actual generated artifact and native graph.
    def obj(properties):
        return {"type": "object", "properties": properties, "required": sorted(properties),
                "additionalProperties": False}

    integer = {"type": "integer", "minimum": 0, "maximum": 100}
    domain = {"inputs": obj({f"value{index}": integer for index in range(7)}), "tools": {
        tool: {"arguments": obj({"amount": integer}), "result": obj({"quantity": integer})}
        for tool in ("inspect", "record")}}
    examples = [{"id": f"complete-{index}", "inputs": {f"value{leaf}": index + leaf for leaf in range(7)},
        "steps": [{"tool": tool, "arguments": {"amount": index}, "result": {"quantity": index + 1}}
                  for tool in ("inspect", "record")]} for index in (1, 2)]
    artifact = workflow_memory.synthesize(examples, allowed_tools=["inspect", "record"],
        domain=domain, max_operations=1)
    assert artifact["model_count"] == artifact["enumerated_model_count"] == 89
    assert len(workflow_memory._canonical(artifact).encode("utf-8")) > 262_144
    flow = recipe_flow.make_flow(artifact, flow_id="large-pure-memory", name="Large pure memory inspection")
    target = tmp_path / "actual-large-draft.json"
    _write_memory_flow_json(target, flow.to_dict())
    assert 262_144 < target.stat().st_size <= 1_000_000
    recovered = Flow.from_dict(json.loads(target.read_bytes()))
    recipe_flow.validate_flow(recovered)
    assert recovered.to_dict() == flow.to_dict()


@pytest.mark.parametrize("schema,success", [(action_recipe.MEMORY_SCHEMA, True),
                                            (action_recipe.WORKFLOW_SCHEMA, False)])
def test_verified_command_uses_larger_writer_only_for_memory(monkeypatch, tmp_path, schema, success):
    package, trust, output = (tmp_path / name for name in ("package.json", "trust.json", "draft.json"))
    package.write_text(json.dumps({"artifact": {"schema": schema}}), encoding="utf-8")
    trust.write_text("{}", encoding="utf-8")
    payload = {"writer_fixture": "x" * 270_000}
    monkeypatch.setattr(recipe_lineage, "validate_package", lambda *a, **kw: None)
    monkeypatch.setattr(recipe_flow, "make_flow", lambda *a, **kw: SimpleNamespace(to_dict=lambda: payload))
    result = CliRunner().invoke(main, ["flow", "recipe", "draft-verified", "--package", str(package),
        "--trust", str(trust), "--tenant", "writer-tenant", "--flow-id", "writer-inspection",
        "--name", "Writer inspection", "--output", str(output)])
    assert (result.exit_code == 0) is success, result.output
    assert output.exists() is success
    if success:
        assert json.loads(output.read_bytes()) == payload
