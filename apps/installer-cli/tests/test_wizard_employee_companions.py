"""Employee companions need an explicit opt-in and scoped discovery."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_dashboard import copilot_context, plain_labels, settings_store, ui_visibility
from maverick_installer import wizard


@pytest.mark.parametrize("value", [None, False, 0, 1, "true", "false", [], {}])
def test_employee_companions_require_literal_true(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"employee_companions": value}})
    monkeypatch.setattr(config, "config_source_errors", lambda **kw: {})
    assert config.get_features()["employee_companions"] is False


def test_employee_companions_default_off_and_explicitly_enabled(monkeypatch):
    monkeypatch.setattr(config, "config_source_errors", lambda **kw: {})
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_features()["employee_companions"] is False
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"employee_companions": True}})
    assert config.get_features()["employee_companions"] is True


def test_employee_companions_fail_closed_for_unreadable_configuration(monkeypatch):
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"employee_companions": True}})
    monkeypatch.setattr(config, "config_source_errors", lambda **kw: {"config": "invalid"})
    assert config.get_features()["employee_companions"] is False


def test_installer_prompt_and_serialization_are_explicit_default_off(monkeypatch):
    prompts = []

    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        return "Enable personal companions" in prompt

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **kw: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **kw: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: [])
    result = wizard.pick_advanced()
    assert result["allow_employee_companions"] is True
    chosen = [default for prompt, default in prompts if "Enable personal companions" in prompt]
    assert chosen == [False]
    companion_prompt = next(prompt for prompt, _ in prompts if "Enable personal companions" in prompt)
    assert "must permit drafts for each employee" in companion_prompt
    assert "configured AI service receives" in companion_prompt
    document = tomllib.loads("\n".join(wizard._cfg_advanced(result, [])))
    assert document["features"]["employee_companions"] is True
    assert "allow_employee_companions" not in wizard._EXPRESS_ADVANCED


@pytest.mark.parametrize("value", [None, False, 0, 1, "true", "false"])
def test_installer_does_not_enable_companions_for_non_boolean_opt_ins(value):
    document = tomllib.loads("\n".join(wizard._cfg_advanced({"allow_employee_companions": value}, [])))
    assert "employee_companions" not in document.get("features", {})


def test_settings_discoverability_and_effective_policy_readback(monkeypatch):
    assert settings_store.FEATURE_DEFAULTS["employee_companions"] is False
    assert plain_labels.FEATURE_LABELS["employee_companions"] == "Employee companions"
    monkeypatch.setattr(config, "get_features", lambda: {"employee_companions": False})
    with pytest.raises(settings_store.FeatureSettingNotEffective, match="not active"):
        settings_store.assert_effective_employee_companions(True)
    settings_store.assert_effective_employee_companions(False)


def test_companion_navigation_has_separate_employee_and_workspace_admin_floors():
    employee = ui_visibility.page_for("/companion")
    admin = ui_visibility.page_for("/companion/admin")
    assert employee["label"] == "My companion"
    # One "Work" group: the raw group is Operate, shown as "Work".
    assert ui_visibility.group_title(employee["group"]) == "Work"
    assert employee["floor"] == "view"
    assert admin["label"] == "Employee companions"
    assert admin["floor"] == "admin"
    assert admin["scope"] == "workspace"
    assert not ui_visibility.eligible(admin, "viewer")
    assert not ui_visibility.eligible(admin, "operator")


def test_companion_copilot_guidance_distinguishes_ai_drafts_from_actions():
    employee = copilot_context.context_for_page("/companion")
    admin = copilot_context.context_for_page("/companion/admin")
    assert employee.title == "My companion"
    assert admin.title == "Employee companions"
    assert any(
        "clear it after you review" in boundary
        and "does not read or share your conversation text" in boundary
        for boundary in employee.boundaries
    )
    assert any("cannot enroll" in boundary for boundary in admin.boundaries)
    assert any("private companion history" in boundary for boundary in admin.boundaries)
    assert any("configured AI service" in boundary for boundary in employee.boundaries)
    assert any("current message only" in boundary for boundary in employee.boundaries)
    assert any("cannot execute tools or task actions" in boundary for boundary in employee.boundaries)
    assert any("administrator has enabled" in capability for capability in employee.capabilities)
