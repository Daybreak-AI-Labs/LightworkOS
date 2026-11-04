"""Flow-operator opt-in reaches the strict runtime knob through either wizard path."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_installer import wizard


def _questions(monkeypatch, *, enabled, operators):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        if "bounded learned pure operators" in prompt:
            return operators
        if "Enable the flow engine?" in prompt or prompt.startswith("Flow engine?"):
            return enabled
        return False

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **k: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **k: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **k: [])
    return prompts


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("operators", [False, True])
def test_dedicated_flow_prompt(monkeypatch, enabled, operators):
    prompts = _questions(monkeypatch, enabled=enabled, operators=operators)
    chosen = wizard.pick_flows()
    asked = [(p, d) for p, d in prompts if "bounded learned pure operators" in p]
    if enabled:
        assert chosen["learned_operators"] is operators
        assert len(asked) == 1 and asked[0][1] is False
        parsed = tomllib.loads("\n".join(wizard._cfg_flows(chosen)))
        monkeypatch.setattr(config, "load_config", lambda: parsed)
        assert config.get_flows()["learned_operators"] is operators
    else:
        assert chosen == {"enable": False}
        assert not asked


@pytest.mark.parametrize("enabled", [False, True])
def test_advanced_flow_prompt(monkeypatch, enabled):
    prompts = _questions(monkeypatch, enabled=enabled, operators=True)
    chosen = wizard.pick_advanced()
    asked = [(p, d) for p, d in prompts if "bounded learned pure operators" in p]
    assert chosen["flows"] is enabled
    if enabled:
        assert chosen["flows_learned_operators"] is True
        assert len(asked) == 1 and asked[0][1] is False
        parsed = tomllib.loads("\n".join(wizard._cfg_advanced(chosen, [])))
        assert parsed["flows"]["learned_operators"] is True
    else:
        assert "flows_learned_operators" not in chosen
        assert not asked


@pytest.mark.parametrize("dedicated, advanced, expected", [
    (None, True, True),
    (None, False, False),
    ({"enable": True, "learned_operators": False}, True, False),
    ({"enable": True, "learned_operators": True}, False, True),
])
def test_merged_config_is_single_table(tmp_path, monkeypatch, dedicated, advanced, expected):
    monkeypatch.setattr(wizard, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(wizard, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(wizard, "CONFIG_FILE", tmp_path / "config.toml")
    wizard.write_config(
        providers=[], role_models={}, channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"}, keys={}, capabilities={},
        advanced={"flows": True, "flows_learned_operators": advanced}, flows=dedicated,
    )
    text = (tmp_path / "config.toml").read_text(encoding="utf-8")
    assert text.count("[flows]") == 1
    parsed = tomllib.loads(text)
    assert parsed["flows"]["learned_operators"] is expected
    monkeypatch.setattr(config, "load_config", lambda: parsed)
    assert config.get_flows()["learned_operators"] is expected
