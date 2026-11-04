"""Bounded Copilot actions require a deliberate strict feature opt-in."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_dashboard import settings_store
from maverick_installer import wizard


@pytest.mark.parametrize("value", [None, False, 0, 1, "true", "false", [], {}])
def test_copilot_actions_require_literal_true(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"copilot_operations": value}})
    monkeypatch.setattr(config, "config_source_errors", lambda **kw: {})
    assert config.get_features()["copilot_operations"] is False


def test_copilot_actions_fail_closed_for_unreadable_configuration(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"copilot_operations": True}})
    monkeypatch.setattr(config, "config_source_errors", lambda **kw: {"config": "invalid"})
    assert config.get_features()["copilot_operations"] is False


def test_installer_prompt_and_serialization_are_explicit_default_off(monkeypatch):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        return "Let Copilot open" in prompt

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **kw: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **kw: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: [])
    result = wizard.pick_advanced()
    assert result["allow_copilot_operations"] is True
    chosen = [default for prompt, default in prompts if "Let Copilot open" in prompt]
    assert chosen == [False]
    document = tomllib.loads("\n".join(wizard._cfg_advanced(result, [])))
    assert document["features"]["copilot_operations"] is True
    assert "copilot_operations" not in tomllib.loads("\n".join(wizard._cfg_advanced({}, []))).get("features", {})
    assert "allow_copilot_operations" not in wizard._EXPRESS_ADVANCED


def test_feature_setting_reports_when_higher_priority_source_still_controls_it(monkeypatch):
    monkeypatch.setattr(config, "get_features", lambda: {"copilot_operations": False})
    with pytest.raises(settings_store.FeatureSettingNotEffective, match="not active"):
        settings_store.assert_effective_copilot_operations(True)
    settings_store.assert_effective_copilot_operations(False)


def test_installer_action_families_and_employee_guidance_roundtrip():
    values = {"allow_copilot_operations": True, "copilot_operation_families": ["preferences", "budget", "commitments"],
              "allow_runtime_configuration_status": False, "allow_employee_task_diagnostics": False,
              "allow_employee_activation": False}
    document = tomllib.loads("\n".join(wizard._cfg_advanced(values, [])))
    assert document["copilot"]["operation_families"] == ["preferences", "budget", "commitments"]
    assert document["settings"]["runtime_status"] is False
    assert document["features"]["employee_task_diagnostics"] is False
    assert document["features"]["employee_activation"] is False


def test_installer_offers_promise_reviews_with_a_plain_label(monkeypatch):
    offered = []

    def choose(prompt, choices, default=None):
        if "action families may Copilot open" in prompt:
            offered.extend(choices)
            return ["Promise reviews"]
        return default or []

    monkeypatch.setattr(wizard, "_q_checkbox", choose)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, default=False, **kw: default)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **kw: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **kw: default)
    result = wizard.pick_advanced()
    assert "Promise reviews" in offered and "commitments" not in offered
    assert result["copilot_operation_families"] == ["commitments"]
