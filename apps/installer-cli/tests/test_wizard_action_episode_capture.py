"""Retention consent stays distinct from execution and survives config merging."""
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
def test_retention_consent_only_asked_for_enabled_flows(monkeypatch, advanced, enabled):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "retaining workflow examples" in prompt:
            return True
        return enabled and ("Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"))

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    picked = wizard.pick_advanced() if advanced else wizard.pick_flows()
    key = "flows_action_episode_capture" if advanced else "action_episode_capture"
    asked = [(p, d) for p, d in prompts if "retaining workflow examples" in p]
    if not enabled:
        assert key not in picked and not asked
        return
    assert picked[key] is True and len(asked) == 1 and asked[0][1] is False
    for phrase in ("enrollment", "encrypted storage", "expiry", "human review"):
        assert phrase in asked[0][0]
    lines = wizard._cfg_advanced(picked, []) if advanced else wizard._cfg_flows(picked)
    parsed = tomllib.loads("\n".join(lines))
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    settings = config.get_flows()
    assert settings["action_episode_capture"] is True
    assert settings["action_recipes"] is False
    assert settings["learned_operators"] is False


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True), (None, False, False),
    ({"enable": True, "action_episode_capture": False}, True, False),
])
def test_retention_merge_keeps_explicit_dedicated_consent(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_action_episode_capture": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    assert tomllib.loads(text)["flows"]["action_episode_capture"] is expected


@pytest.mark.parametrize("setting", [None, False, "true", "false", 1, 0, [], {}])
def test_retention_requires_literal_boolean_consent(monkeypatch, setting):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_episode_capture": setting}})
    assert config.get_flows()["action_episode_capture"] is False


def test_retention_defaults_off_with_flow_execution_enabled(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"enable": True, "action_recipes": True}})
    assert config.get_flows()["action_episode_capture"] is False
