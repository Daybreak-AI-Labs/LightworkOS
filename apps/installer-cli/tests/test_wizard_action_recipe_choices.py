"""Action-choice learning has a separate strict opt-in in both wizard paths."""
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
def test_choice_prompt_preserves_separate_recipe_and_transform_choices(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "learned binary action choices" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    result = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_recipe_choices" if advanced else "action_recipe_choices"
    chosen = [prompt for prompt, default in prompts if "learned binary action choices" in prompt and default is False]
    if not enabled:
        assert key not in result and not chosen
        return
    assert result[key] is True and len(chosen) == 1
    for text in ("requires action recipes and transformed arguments", "Every retained guard", "approval",
                 "never repeats the shared action"):
        assert text in chosen[0]
    lines = wizard._cfg_advanced(result, []) if advanced else wizard._cfg_flows(result)
    document = tomllib.loads("\n".join(lines))
    monkeypatch.setattr(config, "load_config", lambda: document)
    settings = config.get_flows()
    assert settings["action_recipe_choices"] is True
    assert settings["action_recipes"] is False and settings["action_recipe_transforms"] is False
    assert settings["action_episode_capture"] is False


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_recipe_choices": False}, True, False),
    ({"enable": True, "action_recipe_choices": True}, False, True),
])
def test_choice_merge_keeps_explicit_dedicated_setting(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_recipe_choices": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_recipe_choices"] is expected


@pytest.mark.parametrize("value", [None, False, "true", "false", 1, 0, [], {}])
def test_choice_runtime_setting_is_strict_boolean(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_recipe_choices": value}})
    assert config.get_flows()["action_recipe_choices"] is False


def test_action_choices_default_off_when_other_recipe_modes_are_on(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {
        "enable": True, "action_recipes": True, "action_recipe_transforms": True,
    }})
    assert config.get_flows()["action_recipe_choices"] is False
