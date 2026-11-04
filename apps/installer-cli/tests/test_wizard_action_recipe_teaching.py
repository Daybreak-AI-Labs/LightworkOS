"""Native choice teaching is an explicit independent opt-in in both wizard paths."""
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
def test_teaching_prompt_preserves_independent_dependencies(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "human teaching at a real completed action prefix" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    value = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_recipe_teaching" if advanced else "action_recipe_teaching"
    chosen = [prompt for prompt, default in prompts
              if "human teaching at a real completed action prefix" in prompt and default is False]
    if not enabled:
        assert key not in value and not chosen
        return
    assert value[key] is True and len(chosen) == 1
    for text in ("governed lineage", "Both continuation arguments must agree", "separate action approval",
                 "never repeats the shared action"):
        assert text in chosen[0]
    lines = wizard._cfg_advanced(value, []) if advanced else wizard._cfg_flows(value)
    document = tomllib.loads("\n".join(lines))
    monkeypatch.setattr(config, "load_config", lambda: document)
    settings = config.get_flows()
    assert settings["action_recipe_teaching"] is True
    for other in ("action_recipes", "action_recipe_transforms", "action_recipe_choices",
                  "action_recipe_lineage", "action_episode_capture"):
        assert settings[other] is False


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_recipe_teaching": False}, True, False),
    ({"enable": True, "action_recipe_teaching": True}, False, True),
])
def test_teaching_merge_keeps_explicit_dedicated_setting(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_recipe_teaching": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_recipe_teaching"] is expected


@pytest.mark.parametrize("value", [None, False, "true", "false", 1, 0, [], {}])
def test_teaching_runtime_setting_is_strict_boolean(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_recipe_teaching": value}})
    assert config.get_flows()["action_recipe_teaching"] is False


def test_teaching_defaults_off_when_all_other_recipe_modes_are_on(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {
        "enable": True, "action_recipes": True, "action_recipe_transforms": True,
        "action_recipe_choices": True, "action_recipe_lineage": True,
    }})
    assert config.get_flows()["action_recipe_teaching"] is False
