"""Transformed arguments need a separate strict, default-off execution option."""
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
def test_transforms_prompt_with_flows_preserves_other_explicit_choices(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "learned transformations in action arguments" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    picked = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_recipe_transforms" if advanced else "action_recipe_transforms"
    asked = [(p, d) for p, d in prompts if "learned transformations in action arguments" in p]
    if not enabled:
        assert key not in picked and not asked
        return
    assert picked[key] is True and len(asked) == 1 and asked[0][1] is False
    for phrase in ("requires action recipes", "explicit data bounds", "every retained expression", "Approvals"):
        assert phrase in asked[0][0]
    lines = wizard._cfg_advanced(picked, []) if advanced else wizard._cfg_flows(picked)
    parsed = tomllib.loads("\n".join(lines))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    settings = config.get_flows()
    assert settings["action_recipe_transforms"] is True
    assert settings["action_recipes"] is False
    assert settings["action_episode_capture"] is False
    assert settings["composed_operators"] is False


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_recipe_transforms": False}, True, False),
    ({"enable": True, "action_recipe_transforms": True}, False, True),
])
def test_transform_merge_keeps_explicit_dedicated_answer(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_recipe_transforms": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_recipe_transforms"] is expected


@pytest.mark.parametrize("setting", [None, False, "true", "false", 1, 0, [], {}])
def test_transform_setting_does_not_accept_truthy_coercion(monkeypatch, setting):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_recipe_transforms": setting}})
    assert config.get_flows()["action_recipe_transforms"] is False


def test_transform_execution_defaults_off_when_other_learning_is_enabled(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {
        "enable": True, "action_recipes": True, "composed_operators": True,
    }})
    assert config.get_flows()["action_recipe_transforms"] is False
