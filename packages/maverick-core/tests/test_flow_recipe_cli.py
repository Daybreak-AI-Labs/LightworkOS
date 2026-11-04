"""File authoring keeps recipe learning, review assertions and publication apart."""
from __future__ import annotations

import json

from click.testing import CliRunner
from maverick.cli import main


def _examples():
    return [{"id": f"run{n}", "inputs": {"code": f"sku{n}"}, "steps": [
        {"tool": "crm_lookup", "arguments": {"code": f"sku{n}"}, "result": {"id": f"item{n}"}},
        {"tool": "crm_create", "arguments": {"id": f"item{n}"}, "result": {"id": f"order{n}"}},
    ]} for n in range(2)]


def test_recipe_cli_review_learn_refine_draft_no_overwrite(tmp_path):
    runner = CliRunner()
    episodes, artifact, refined, draft = [tmp_path / name for name in
                                          ("episodes.json", "recipe.json", "revised.json", "flow.json")]
    episodes.write_text(json.dumps(_examples()), encoding="utf-8")
    args = ["flow", "recipe", "learn", "--episodes", str(episodes), "--allow-tool", "crm_lookup",
            "--allow-tool", "crm_create", "--output", str(artifact)]
    refused = runner.invoke(main, args)
    assert refused.exit_code != 0 and not artifact.exists()
    learned = runner.invoke(main, [*args, "--reviewed"])
    assert learned.exit_code == 0, learned.output
    before = artifact.read_bytes()
    exists = runner.invoke(main, [*args, "--reviewed"])
    assert exists.exit_code != 0 and artifact.read_bytes() == before
    extra = _examples()[:1]
    extra[0]["id"] = "reviewed-extra"
    episodes.write_text(json.dumps(extra), encoding="utf-8")
    result = runner.invoke(main, ["flow", "recipe", "refine", "--artifact", str(artifact),
        "--episodes", str(episodes), "--reviewed", "--output", str(refined)])
    assert result.exit_code == 0, result.output
    assert json.loads(refined.read_text(encoding="utf-8"))["episode_count"] == 3
    result = runner.invoke(main, ["flow", "recipe", "draft", "--artifact", str(refined),
        "--flow-id", "reviewable-recipe", "--name", "Reviewable", "--output", str(draft)])
    assert result.exit_code == 0, result.output
    flow = json.loads(draft.read_text(encoding="utf-8"))
    assert [n["kind"] for n in flow["nodes"]] == ["approval", "action", "approval", "action"]
    assert flow["learned_recipe"] == json.loads(refined.read_text(encoding="utf-8"))
    assert "Not saved, published or executed" in result.output
    assert artifact.read_bytes() == before


def test_recipe_cli_duplicate_keys_rejected_without_output(tmp_path):
    episodes, artifact = tmp_path / "episodes.json", tmp_path / "recipe.json"
    episodes.write_text('{"id":1,"id":2}', encoding="utf-8")
    result = CliRunner().invoke(main, ["flow", "recipe", "learn", "--episodes", str(episodes),
        "--allow-tool", "crm_lookup", "--reviewed", "--output", str(artifact)])
    assert result.exit_code != 0 and "duplicate" in result.output
    assert not artifact.exists()
