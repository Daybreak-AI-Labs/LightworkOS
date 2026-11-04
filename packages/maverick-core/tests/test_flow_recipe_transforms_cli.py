"""Explicit transformed file authoring uses the real learner and keeps v1 defaults."""
from __future__ import annotations

import json
import subprocess
import sys

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.flow import action_recipe


def _object(**fields):
    return {"type": "object", "properties": fields,
            "required": list(fields), "additionalProperties": False}


def _integer(low=0, high=20):
    return {"type": "integer", "minimum": low, "maximum": high}


def _episode(index, quantity, discount, price):
    return {"id": f"reviewed-{index}", "inputs": {"quantity": quantity, "discount": discount}, "steps": [
        {"tool": "price_lookup", "arguments": {"quantity": quantity}, "result": {"unit_price": price}},
        {"tool": "invoice_create", "arguments": {"amount": quantity * price - discount},
         "result": {"invoice_id": f"invoice-{index}"}},
    ]}


def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _inputs(tmp_path):
    episodes = _write(tmp_path, "episodes.json", [_episode(0, 2, 1, 3), _episode(1, 3, 2, 4)])
    domain = _write(tmp_path, "domain.json", {
        "inputs": _object(quantity=_integer(1, 5), discount=_integer(0, 5)),
        "steps": [
            {"arguments": _object(quantity=_integer(1, 5)), "result": _object(unit_price=_integer(1, 5))},
            {"arguments": _object(amount=_integer(-5, 25)),
             "result": _object(invoice_id={"type": "string", "maxLength": 64})},
        ],
    })
    return episodes, domain


def _args(tmp_path, episodes, output, *options):
    return ["--db", str(tmp_path / "world.db"), "flow", "recipe", "learn",
            "--episodes", str(episodes), "--allow-tool", "price_lookup", "--allow-tool", "invoice_create",
            "--output", str(output), *map(str, options)]


def test_transformed_cli_learn_refine_draft_keeps_complete_artifact_and_sources(tmp_path):
    episodes, domain = _inputs(tmp_path)
    constants = _write(tmp_path, "constants.json", [0, 1])
    artifact, refined, draft = [tmp_path / name for name in ("recipe.json", "refined.json", "flow.json")]
    runner = CliRunner()
    result = runner.invoke(main, _args(tmp_path, episodes, artifact, "--reviewed", "--transforms",
                           "--domain", domain, "--operators", "add,sub,mul", "--constants", constants))
    assert result.exit_code == 0, result.output
    before, domain_before, episodes_before = artifact.read_bytes(), domain.read_bytes(), episodes.read_bytes()
    learned = json.loads(before)
    assert learned["schema"] == "lightwork.action-recipe.v2"
    action_recipe.validate_artifact(learned)
    assert "summed across leaves" in result.output
    assert "does not authenticate" in result.output
    extra = _write(tmp_path, "extra.json", [_episode(2, 4, 0, 2)])
    result = runner.invoke(main, ["flow", "recipe", "refine", "--artifact", str(artifact),
                                 "--episodes", str(extra), "--reviewed", "--output", str(refined)])
    assert result.exit_code == 0, result.output
    updated = json.loads(refined.read_bytes())
    assert updated["schema"] == learned["schema"] and updated["episode_count"] == 3
    assert updated["artifact_sha256"] != learned["artifact_sha256"]
    action_recipe.validate_artifact(updated)
    result = runner.invoke(main, ["flow", "recipe", "draft", "--artifact", str(refined),
                                 "--flow-id", "invoice-draft", "--name", "Invoice draft", "--output", str(draft)])
    assert result.exit_code == 0, result.output
    flow = json.loads(draft.read_bytes())
    assert flow["learned_recipe"] == updated
    assert [node["kind"] for node in flow["nodes"]] == ["approval", "action", "approval", "action"]
    assert "Not saved, published or executed" in result.output
    assert artifact.read_bytes() == before
    assert domain.read_bytes() == domain_before and episodes.read_bytes() == episodes_before


def test_transformed_cli_defaults_match_engine_and_never_overwrite(tmp_path):
    from maverick.flow.action_recipe_transforms import synthesize_transformed

    episodes, domain = _inputs(tmp_path)
    path = tmp_path / "defaults.json"
    args = _args(tmp_path, episodes, path, "--reviewed", "--transforms", "--domain", domain)
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    before = path.read_bytes()
    expected = synthesize_transformed(json.loads(episodes.read_bytes()), allowed_tools=["price_lookup", "invoice_create"],
                                     domain=json.loads(domain.read_bytes()))
    assert json.loads(before) == expected
    exists = CliRunner().invoke(main, args)
    assert exists.exit_code != 0 and "already exists" in exists.output and path.read_bytes() == before


@pytest.mark.parametrize("options", [[], ["--transforms"]])
def test_transform_options_require_review_and_domain_without_output(tmp_path, options):
    episodes, _domain = _inputs(tmp_path)
    output = tmp_path / "missing.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, output, *options))
    assert result.exit_code != 0 and "--reviewed" in result.output and not output.exists()
    if options:
        result = CliRunner().invoke(main, _args(tmp_path, episodes, output, *options, "--reviewed"))
        assert result.exit_code != 0 and "requires --domain" in result.output and not output.exists()


@pytest.mark.parametrize("option", ["--domain", "--max-operations", "--operators", "--constants"])
def test_v1_does_not_silently_ignore_transform_grammar_options(tmp_path, option):
    episodes, domain = _inputs(tmp_path)
    constants = _write(tmp_path, "constants.json", [1])
    values = {"--domain": domain, "--max-operations": "2", "--operators": "add", "--constants": constants}
    output = tmp_path / "wrong-mode.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, output, "--reviewed", option, values[option]))
    assert result.exit_code != 0 and "require --transforms" in result.output and not output.exists()


@pytest.mark.parametrize("options", [["--max-operations", "0"], ["--max-operations", "5"],
                                     ["--operators", "eval"], ["--operators", "mul,,sub"],
                                     ["--operators", "mul,mul"], ["--operators", ""]])
def test_invalid_transform_grammar_leaves_no_artifact(tmp_path, options):
    episodes, domain = _inputs(tmp_path)
    output = tmp_path / "invalid.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, output, "--reviewed", "--transforms",
                                          "--domain", domain, *options))
    assert result.exit_code != 0 and not output.exists()


@pytest.mark.parametrize("contents", ['{"inputs":{},"inputs":{}}', '{"steps":NaN}', '{"inputs":'])
def test_malformed_domain_uses_strict_json_ingress(tmp_path, contents):
    episodes, domain = _inputs(tmp_path)
    domain.write_text(contents, encoding="utf-8")
    output = tmp_path / "invalid-domain.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, output, "--reviewed", "--transforms", "--domain", domain))
    assert result.exit_code != 0 and "cannot read" in result.output and not output.exists()


@pytest.mark.parametrize("constants", [[True, 1.0], {"formula": "quantity * unit_price"}, list(range(9))])
def test_invalid_constants_cannot_smuggle_a_formula_or_expand_the_grammar(tmp_path, constants):
    episodes, domain = _inputs(tmp_path)
    values = _write(tmp_path, "constants.json", constants)
    output = tmp_path / "invalid-constants.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, output, "--reviewed", "--transforms",
                                          "--domain", domain, "--constants", values))
    assert result.exit_code != 0 and not output.exists()


def test_no_consistent_program_never_creates_a_partial_cli_artifact(tmp_path):
    episodes, domain = _inputs(tmp_path)
    output = tmp_path / "no-program.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, output, "--reviewed", "--transforms",
                                          "--domain", domain, "--max-operations", 1, "--operators", "mul"))
    assert result.exit_code != 0 and not output.exists()
    assert "Error:" in result.output and "Traceback" not in result.output


def test_transformed_cli_launches_in_a_fresh_interpreter(tmp_path):
    episodes, domain = _inputs(tmp_path)
    output = tmp_path / "subprocess.json"
    result = subprocess.run([sys.executable, "-m", "maverick.cli", *_args(
        tmp_path, episodes, output, "--reviewed", "--transforms", "--domain", domain,
        "--operators", "add,sub,mul")], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(output.read_bytes())["schema"] == "lightwork.action-recipe.v2"


def test_cli_refinement_keeps_initial_literal_grammar_when_target_stops_being_constant(tmp_path):
    def episode(index, value, output):
        return {"id": f"floor-{index}", "inputs": {"x": value}, "steps": [
            {"tool": "price_lookup", "arguments": {"x": value}, "result": {"id": f"row-{index}"}},
            {"tool": "invoice_create", "arguments": {"y": output}, "result": {"id": f"invoice-{index}"}},
        ]}

    domain = _write(tmp_path, "floor-domain.json", {
        "inputs": _object(x=_integer(-3, 3)), "steps": [
            {"arguments": _object(x=_integer(-3, 3)),
             "result": _object(id={"type": "string", "maxLength": 32})},
            {"arguments": _object(y=_integer(1, 3)),
             "result": _object(id={"type": "string", "maxLength": 32})},
        ],
    })
    episodes = _write(tmp_path, "floor-episodes.json", [episode(0, -2, 1), episode(1, -1, 1)])
    original, refined = tmp_path / "floor.json", tmp_path / "floor-refined.json"
    result = CliRunner().invoke(main, _args(tmp_path, episodes, original, "--reviewed", "--transforms",
                                            "--domain", domain, "--max-operations", 1, "--operators", "max"))
    assert result.exit_code == 0, result.output
    before = original.read_bytes()
    extra = _write(tmp_path, "floor-extra.json", [episode(2, 2, 2)])
    result = CliRunner().invoke(main, ["flow", "recipe", "refine", "--artifact", str(original),
                                     "--episodes", str(extra), "--reviewed", "--output", str(refined)])
    assert result.exit_code == 0, result.output
    body = json.loads(refined.read_bytes())
    action_recipe.validate_artifact(body)
    decision = action_recipe.resolve_step(body, 1, {"x": 0}, [{"id": "new-row"}])
    assert decision.applied is True and decision.arguments == {"y": 1}
    assert original.read_bytes() == before
