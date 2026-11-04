"""Project planning opt-in is deliberate, typed and exposed by the installer."""
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

import pytest
from maverick import config
from maverick_dashboard import settings_store
from maverick_installer import wizard


@pytest.mark.parametrize("value", [None, False, 0, 1, "true", "false", [], {}])
def test_feature_requires_literal_true(monkeypatch, value):
    monkeypatch.setattr(config, "load_config", lambda: {"features": {"project_workspaces": value}})
    assert config.get_features()["project_workspaces"] is False
    assert settings_store.FEATURE_DEFAULTS["project_workspaces"] is False


def test_installer_project_workspace_prompt_and_serialization(monkeypatch):
    prompts = []
    def confirm(prompt, *, default=False):
        prompts.append((prompt, default))
        return "Enable project workspaces" in prompt
    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_select", lambda *a, default=None, **kw: default)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, default="", **kw: default)
    monkeypatch.setattr(wizard, "_q_checkbox", lambda *a, **kw: [])
    result = wizard.pick_advanced()
    assert result["allow_project_workspaces"] is True
    assert [default for prompt, default in prompts if "Enable project workspaces" in prompt] == [False]
    document = tomllib.loads("\n".join(wizard._cfg_advanced(result, [])))
    assert document["features"]["project_workspaces"] is True
    assert "allow_project_workspaces" not in wizard._EXPRESS_ADVANCED
