"""Installer coverage for the saved company folder and space limits."""

from __future__ import annotations

import pytest


def test_saved_source_limits_are_kept_at_their_defaults_unless_changed(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, *, default: False)
    assert wizard.pick_knowledge_sources() == {}


def test_saved_source_limits_reask_until_each_value_is_a_whole_number_in_range(monkeypatch):
    from maverick_installer import wizard

    answers = iter(["lots", "5000", "100", "16", "8", "512", "0", "30"])
    prompts = []

    def text(prompt, default=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, *, default: True)
    monkeypatch.setattr(wizard, "_q_text", text)
    assert wizard.pick_knowledge_sources() == {"max_items": 100, "max_pages": 16, "max_download_mib": 8,
                                               "max_text_kib": 512, "max_refresh_minutes": 30}
    # Each refused answer asks its own question again, before the accepted one.
    assert len(prompts) == 8
    assert prompts[0] == prompts[1] == prompts[2]
    assert prompts[-1] == prompts[-2]
    assert "(1-1000" in prompts[0] and "(1-60" in prompts[-1]


def test_saved_source_limits_config_is_closed_integer_toml():
    from maverick_installer import wizard

    values = {"max_items": 100, "max_pages": 16, "max_download_mib": 8, "max_text_kib": 512, "max_refresh_minutes": 30}
    assert wizard._cfg_knowledge_sources(values) == [
        "",
        "[knowledge_sources]",
        "max_items = 100",
        "max_pages = 16",
        "max_download_mib = 8",
        "max_text_kib = 512",
        "max_refresh_minutes = 30",
    ]
    assert wizard._cfg_knowledge_sources({}) == []
    assert wizard._cfg_knowledge_sources(None) == []


@pytest.mark.parametrize("value", [0, 1001, True, "64"])
def test_saved_source_limits_config_rejects_values_outside_the_runtime_range(value):
    from maverick_installer import wizard

    values = {"max_items": value, "max_pages": 16, "max_download_mib": 4, "max_text_kib": 256}
    with pytest.raises(ValueError, match=r"knowledge_sources\.max_items must be a whole number from 1 to 1000"):
        wizard._cfg_knowledge_sources(values)


@pytest.mark.parametrize("value", [0, 61, True, "5"])
def test_saved_source_refresh_minutes_config_rejects_values_outside_the_runtime_range(value):
    from maverick_installer import wizard

    values = {"max_items": 64, "max_pages": 16, "max_download_mib": 4, "max_text_kib": 256, "max_refresh_minutes": value}
    with pytest.raises(ValueError, match=r"knowledge_sources\.max_refresh_minutes must be a whole number from 1 to 60"):
        wizard._cfg_knowledge_sources(values)


def test_the_permission_question_keeps_the_connection_rule_unless_email_matching_is_chosen(monkeypatch):
    from maverick_installer import wizard

    printed = []
    monkeypatch.setattr(wizard.console, "print", lambda *args, **kwargs: printed.append(" ".join(map(str, args))))
    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, *, default: False)
    assert wizard.pick_knowledge_source_permissions() == {}
    assert any("only with a group are left out" in text for text in printed)  # the group rule is stated before the choice
    # Everyone who cannot be matched to a verified address is told before the choice, not after.
    assert any("sign in with SAML" in text and "see no saved company files" in text for text in printed)


def test_choosing_email_matching_writes_only_the_permission_filter(monkeypatch):
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda prompt, *, default: True)
    assert wizard.pick_knowledge_source_permissions() == {"permission_filter": "by_email"}
