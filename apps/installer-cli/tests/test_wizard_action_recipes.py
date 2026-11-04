"""Action recipe execution needs a separate explicit opt-in in both flow setup paths."""
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
def test_action_recipes_prompt_only_when_flows_enabled(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "learning action sequences" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    picked = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_recipes" if advanced else "action_recipes"
    asked = [(p, d) for p, d in prompts if "learning action sequences" in p]
    if enabled:
        assert picked[key] is True and len(asked) == 1 and asked[0][1] is False
        lines = wizard._cfg_advanced(picked, []) if advanced else wizard._cfg_flows(picked)
        parsed = tomllib.loads("\n".join(lines))
        monkeypatch.setattr(config, "load_config", lambda: parsed)
        assert config.get_flows()["action_recipes"] is True
        assert config.get_flows()["learned_operators"] is False
    else:
        assert key not in picked and not asked


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_recipes": False}, True, False),
])
def test_action_recipes_merge_retains_explicit_dedicated_answer(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_recipes": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_recipes"] is expected
