"""Real learner artifacts cross the browser form/wire helper back to native validation.

No provider, tool dispatch, authentication bypass, or browser acceptance claim.
The JS suite covers actual designer/dialog control paths; these cases catch
strict Python number types and evidence digests that JS-only assertions miss.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from maverick.flow import action_recipe, recipe_flow
from maverick.flow.action_recipe_transforms import synthesize_transformed

HELPER = Path(__file__).resolve().parents[1] / "maverick_dashboard/templates/flow_designer_inputs.js"
SCRIPT = """
const fs = require('node:fs');
const helper = require(process.argv[1]);
const source = fs.readFileSync(0, 'utf8');
const request = JSON.parse(source);
const flow = helper.parseText(request.flow_text);
const plan = helper.plan(flow.learned_recipe);
const raw = Object.fromEntries(plan.fields.filter(field => field.type !== 'null').map(field => {
  const value = field.path.reduce((part, key) => part[key], request.inputs);
  return [field.id, String(value)];
}));
const data = helper.read(plan, raw);
// Native numeric literals must survive a clone/undo-like editor round trip.
const copy = JSON.parse(JSON.stringify(flow));
copy.nodes[0].label = 'Reviewed step';
process.stdout.write(helper.payloadText(plan, {flow: copy, data, dry_run: true}));
"""


def _object(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def _inputs(index):
    return {"customer_name": f"customer-{index}", "quantity": index, "amount": float(index),
            "confirmed": index % 2 == 0, "note": None, "items": [{"sku": f"sku-{index}"}]}


def _domain():
    text = {"type": "string", "maxLength": 32}
    inputs = _object({"customer_name": text, "quantity": {"type": "integer", "minimum": 0, "maximum": 10},
                      "amount": {"type": "number", "minimum": 0, "maximum": 10},
                      "confirmed": {"type": "boolean"}, "note": {"type": "null"},
                      "items": {"type": "array", "items": _object({"sku": text}), "minItems": 1, "maxItems": 1}})
    return {"inputs": inputs, "steps": [{"arguments": inputs, "result": _object({})},
                                       {"arguments": _object({}), "result": _object({})}]}


@pytest.mark.parametrize("transformed", [False, True])
def test_actual_artifact_and_typed_inputs_survive_form_draft_roundtrip(transformed):
    node = shutil.which("node")
    assert node, "The qualified local JS runtime is required for this UI transport test"
    episodes = [{"id": f"episode-{index}", "inputs": _inputs(index), "steps": [
        {"tool": "record_case", "arguments": _inputs(index), "result": {}},
        {"tool": "finish_case", "arguments": {}, "result": {}},
    ]} for index in (1, 2)]
    artifact = (synthesize_transformed(episodes, allowed_tools=["record_case", "finish_case"],
                domain=_domain(), max_operations=1, operators=["lower"])
                if transformed else action_recipe.synthesize(episodes, allowed_tools=["record_case", "finish_case"]))
    original = json.dumps(artifact, sort_keys=True)
    flow = recipe_flow.make_flow(artifact, flow_id="form-roundtrip", name="Form round trip")
    entered = _inputs(3)
    result = subprocess.run(
        [node, "-e", SCRIPT, str(HELPER)],
        input=json.dumps({"flow_text": json.dumps(flow.to_dict()), "inputs": entered}),
        capture_output=True, text=True, check=False, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    retained = payload["flow"]["learned_recipe"]
    action_recipe.validate_artifact(retained)
    assert retained["artifact_sha256"] == artifact["artifact_sha256"]
    assert type(retained["episodes"][0]["inputs"]["amount"]) is float
    assert type(payload["data"]["input"]["amount"]) is float
    assert type(payload["data"]["input"]["quantity"]) is int
    assert type(payload["data"]["input"]["confirmed"]) is bool
    decision = action_recipe.resolve_step(retained, 0, payload["data"]["input"], [])
    assert decision.applied, decision.reason
    assert decision.arguments == entered
    assert json.dumps(artifact, sort_keys=True) == original
    assert not payload["flow"].get("inputs")
    from maverick.flow.ir import Flow
    recipe_flow.validate_flow(Flow.from_dict(payload["flow"]))


def test_actual_legacy_recipe_with_65_inputs_survives_form_transport():
    node = shutil.which("node")
    assert node, "The qualified local JS runtime is required for this UI transport test"
    def inputs(index):
        return {f"field_{position:02d}": index + position for position in range(65)}

    episodes = [{"id": f"episode-{index}", "inputs": inputs(index), "steps": [
        {"tool": "record_case", "arguments": {"number": inputs(index)["field_00"]}, "result": {}},
        {"tool": "finish_case", "arguments": {}, "result": {}},
    ]} for index in (1, 2)]
    artifact = action_recipe.synthesize(episodes, allowed_tools=["record_case", "finish_case"])
    flow = recipe_flow.make_flow(artifact, flow_id="many-inputs", name="Many inputs")
    entered = inputs(3)
    result = subprocess.run(
        [node, "-e", SCRIPT, str(HELPER)],
        input=json.dumps({"flow_text": json.dumps(flow.to_dict()), "inputs": entered}),
        capture_output=True, text=True, check=False, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["data"] == {"input": entered}
    retained = payload["flow"]["learned_recipe"]
    action_recipe.validate_artifact(retained)
    assert retained["artifact_sha256"] == artifact["artifact_sha256"]
    decision = action_recipe.resolve_step(retained, 0, payload["data"]["input"], [])
    assert decision.applied, decision.reason
    assert decision.arguments == {"number": entered["field_00"]}
