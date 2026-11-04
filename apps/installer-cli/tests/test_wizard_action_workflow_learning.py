"""Bounded workflow learning stays an independent default-off installer opt-in."""
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
def test_workflow_prompt_preserves_independent_dependencies(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "bounded workflow learning from signed reviewed executions" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    value = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_workflow_learning" if advanced else "action_workflow_learning"
    chosen = [prompt for prompt, default in prompts
              if "bounded workflow learning from signed reviewed executions" in prompt and default is False]
    if not enabled:
        assert key not in value and not chosen
        return
    assert value[key] is True and len(chosen) == 1
    for text in ("governed lineage", "next actions and completion", "approvals remain required",
                 "ambiguity stops further work", "Signed execution receipts are mandatory",
                 "execution refuses if signing or persistence is unavailable",
                 "does not enable audit signing or other dependencies"):
        assert text in chosen[0]
    lines = wizard._cfg_advanced(value, []) if advanced else wizard._cfg_flows(value)
    document = tomllib.loads("\n".join(lines))
    assert "audit" not in document
    assert value.get("audit_sign", False) is False
    monkeypatch.setattr(config, "load_config", lambda: document)
    settings = config.get_flows()
    assert settings["action_workflow_learning"] is True
    for other in ("action_recipes", "action_recipe_transforms", "action_recipe_choices",
                  "action_recipe_lineage", "action_episode_capture"):
        assert settings[other] is False


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_workflow_learning": False}, True, False),
    ({"enable": True, "action_workflow_learning": True}, False, True),
])
def test_workflow_merge_keeps_explicit_dedicated_setting(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_workflow_learning": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_workflow_learning"] is expected


@pytest.mark.parametrize("value", [None, False, "true", "false", 1, 0, [], {}])
def test_workflow_runtime_setting_is_strict_boolean(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_workflow_learning": value}})
    assert config.get_flows()["action_workflow_learning"] is False


def test_workflow_defaults_off_when_all_other_recipe_modes_are_on(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {
        "enable": True, "action_recipes": True, "action_recipe_transforms": True,
        "action_recipe_choices": True, "action_recipe_lineage": True,
    }})
    assert config.get_flows()["action_workflow_learning"] is False
