"""Installer opt-in preserves a disabled native callback unless explicitly chosen."""
import pytest
from maverick_installer import wizard


@pytest.mark.parametrize("answers,expected", [([False], False), ([True, False], False), ([True, True], True)])
def test_native_return_has_separate_default_off_consent(monkeypatch, answers, expected):
    prompts = []
    values = iter(answers)

    def confirm(message, **options):
        prompts.append((message, options))
        return next(values)

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    selected = wizard.pick_oauth_vault()
    assert selected == {"vault": answers[0], "desktop_return": expected}
    assert len(prompts) == len(answers)
    assert all(options["default"] is False for _, options in prompts)
    if len(prompts) == 2:
        assert "http://127.0.0.1:8766/connections" in prompts[1][0]
    rendered = "\n".join(wizard._cfg_oauth(selected))
    assert ("desktop_return = true" in rendered) is expected
    if answers[0] and not expected:
        assert "desktop_return = false" in rendered


def test_old_vault_configuration_does_not_implicitly_enable_native_return():
    assert "desktop_return = false" in wizard._cfg_oauth({"vault": True})
