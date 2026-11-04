"""Integer history learning is a separate, strict default-off installer option."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_installer import wizard


@pytest.mark.parametrize("advanced", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
def test_memory_question_preserves_explicit_dependency_choices(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "bounded integer history accumulator learning" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **kw: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **kw: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: [])
    chosen = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_workflow_memory_learning" if advanced else "action_workflow_memory_learning"
    found = [prompt for prompt, default in prompts
             if "bounded integer history accumulator learning" in prompt and default is False]
    if not enabled:
        assert key not in chosen and not found
        return
    assert chosen[key] is True and len(found) == 1
    for text in ("workflow learning", "transformed arguments", "governed lineage",
                 "fixed update program", "all consistent models", "resource exhaustion",
                 "Signed execution receipts are mandatory",
                 "execution refuses if signing or persistence is unavailable",
                 "does not enable audit signing or other dependencies"):
        assert text in found[0]
    lines = wizard._cfg_advanced(chosen, []) if advanced else wizard._cfg_flows(chosen)
    document = tomllib.loads("\n".join(lines))
    assert "audit" not in document
    assert chosen.get("audit_sign", False) is False
    monkeypatch.setattr(config, "load_config", lambda: document)
    flags = config.get_flows()
    assert flags["action_workflow_memory_learning"] is True
    for dependency in ("action_workflow_learning", "action_recipes", "action_recipe_transforms", "action_recipe_lineage"):
        assert flags[dependency] is False


@pytest.mark.parametrize("dedicated,advanced,expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_workflow_memory_learning": False}, True, False),
    ({"enable": True, "action_workflow_memory_learning": True}, False, True),
])
def test_memory_config_merge_preserves_dedicated_choice(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_workflow_memory_learning": advanced}, flows=dedicated)
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_workflow_memory_learning"] is expected


@pytest.mark.parametrize("value", [None, False, "true", "false", 0, 1, [], {}])
def test_memory_flag_refuses_truthy_coercions(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_workflow_memory_learning": value}})
    assert config.get_flows()["action_workflow_memory_learning"] is False


def test_memory_flag_defaults_off_independent_of_prior_workflow_opt_in(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {
        "enable": True, "action_workflow_learning": True, "action_recipes": True,
        "action_recipe_transforms": True, "action_recipe_lineage": True,
    }})
    assert config.get_flows()["action_workflow_memory_learning"] is False
