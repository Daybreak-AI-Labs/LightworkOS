"""Installer coverage for the governed Knowledge feature gate."""

from __future__ import annotations


def test_knowledge_access_picker_is_recommended_and_explicit(monkeypatch):
    from maverick_installer import wizard

    observed = []

    def confirm(prompt, *, default):
        observed.append({"prompt": prompt, "default": default})
        return True

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    assert wizard.pick_knowledge_access() == {"enable": True, "task_context": True}
    assert observed[0]["default"] is True
    assert observed[1]["default"] is False
    assert "governed Knowledge" in observed[0]["prompt"]


def test_knowledge_access_config_is_closed_boolean_toml():
    from maverick_installer import wizard

    assert wizard._cfg_knowledge_access({"enable": True}) == [
        "",
        "[knowledge_access]",
        "enable = true",
        "task_context = false",
    ]
    assert wizard._cfg_knowledge_access({"enable": False})[-2] == "enable = false"


def test_knowledge_access_config_rejects_ambiguous_enable_values():
    import pytest
    from maverick_installer import wizard

    with pytest.raises(ValueError, match="must be boolean"):
        wizard._cfg_knowledge_access({"enable": "true"})
