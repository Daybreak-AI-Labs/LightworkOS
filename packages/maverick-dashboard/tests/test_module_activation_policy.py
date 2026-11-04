"""The shared module policy is independent of the API router."""
from __future__ import annotations

from maverick import config
from maverick_dashboard import module_activation


def test_child_requires_exact_boolean_parent_and_target():
    section = "consent_preferences.global_opt_out"
    allowed = {"consent_preferences": {"enable": True, "global_opt_out": {"enable": True}}}
    assert module_activation._module_switch_enabled(allowed, section)
    assert module_activation._module_activation_state(allowed, section)["enabled"] is True

    for parent_value in (False, "true", 1, None):
        settings = {"consent_preferences": {"enable": parent_value, "global_opt_out": {"enable": True}}}
        assert not module_activation._module_switch_enabled(settings, section)
        assert module_activation._module_activation_state(settings, section)["enabled"] is False


def test_module_banners_fail_closed_for_unavailable_or_unknown_configuration(monkeypatch):
    section = "consent_preferences.global_opt_out"
    loaded = {"consent_preferences": {"enable": True, "global_opt_out": {"enable": True}}}
    monkeypatch.setattr(config, "load_config", lambda: loaded)
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: {})
    assert module_activation.module_activation_enabled(section) is True
    assert module_activation.module_activation_enabled("unknown") is False
    monkeypatch.setattr(config, "config_source_errors", lambda **kwargs: {"tenant": "unreadable"})
    assert module_activation.module_activation_enabled(section) is False


def test_fingerprints_are_stable_and_bind_the_effective_module_roots():
    section = "consent_preferences.global_opt_out"
    loaded = {"consent_preferences": {"enable": True, "global_opt_out": {"enable": True}}}
    first = module_activation._module_activation_state(loaded, section)["fingerprint"]
    assert first == module_activation._module_config_fingerprint(loaded, section)
    changed = {"consent_preferences": {"enable": True, "global_opt_out": {"enable": False}}}
    assert first != module_activation._module_config_fingerprint(changed, section)
