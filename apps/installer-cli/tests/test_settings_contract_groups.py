"""Installer, settings page and kernel share defaults without sharing authority."""
from __future__ import annotations

import pytest
from maverick.config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS

_AGENT_NUMBERS = ("agent_tests.max_cases_per_specialist", "agent_tests.canary_percent")
_AGENT_SWITCHES = (
    "agent_tests.require_for_new_specialists",
    "agent_tests.bypass_requires_second_person",
    "agent_tests.tool_checks",
    "agent_tests.canary_auto_rollback",
)


def test_answer_check_contracts_match_installer_and_dashboard(monkeypatch):
    from maverick_dashboard.settings_catalog import BY_ID
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_text", lambda *_args, **kwargs: kwargs["default"])
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **kwargs: kwargs["default"])
    selected = wizard.pick_agent_test_rules()

    for path in _AGENT_NUMBERS:
        contract, row = INTEGER_SETTINGS[path], BY_ID[path]
        assert (row.default, row.minimum, row.maximum) == (contract.default, contract.minimum, contract.maximum)
        assert selected[path.split(".", 1)[1]] == contract.default
    for path in _AGENT_SWITCHES:
        contract, row = BOOLEAN_SETTINGS[path], BY_ID[path]
        assert row.default is contract.default
        assert selected[path.split(".", 1)[1]] is contract.default
    assert wizard._cfg_agent_tests(selected) == []


def test_answer_check_contract_values_survive_wizard_serialization(monkeypatch):
    from maverick import agent_tests_policy, config
    from maverick_installer import wizard

    limit = INTEGER_SETTINGS["agent_tests.max_cases_per_specialist"].maximum
    share = INTEGER_SETTINGS["agent_tests.canary_percent"].maximum
    selected = {"max_cases_per_specialist": limit, "canary_percent": share,
                **{path.split(".", 1)[1]: True for path in _AGENT_SWITCHES}}
    lines = wizard._cfg_agent_tests(selected)
    config_text = "\n".join(lines)
    document = wizard.tomllib.loads(config_text)
    monkeypatch.setattr(config, "load_config", lambda: document)
    monkeypatch.setattr(config, "config_source_errors", list)
    assert agent_tests_policy.max_cases_per_specialist() == limit
    assert agent_tests_policy.canary_percent() == share
    assert agent_tests_policy.require_for_new_specialists() is True
    assert agent_tests_policy.bypass_requires_second_person() is True
    assert agent_tests_policy.tool_checks_enabled() is True
    assert agent_tests_policy.canary_auto_rollback() is True


def test_automation_and_durable_defaults_are_shared(monkeypatch):
    from maverick import config
    from maverick_dashboard.settings_catalog import BY_ID
    from maverick_installer import wizard

    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **kwargs: kwargs["default"])
    monkeypatch.setattr(config, "load_config", dict)
    for path in ("automation_import.enable", "automation_import.create_schedules", "durable.enabled"):
        contract, row = BOOLEAN_SETTINGS[path], BY_ID[path]
        assert row.default is contract.default
        assert row.env == contract.dashboard_env
    contract, row = INTEGER_SETTINGS["durable.keep_last"], BY_ID["durable.keep_last"]
    assert (row.default, row.minimum, row.maximum) == (contract.default, contract.minimum, contract.maximum)
    assert wizard.pick_automation_import() == {"enable": BOOLEAN_SETTINGS["automation_import.enable"].default}
    assert wizard.pick_durable() == {"enabled": BOOLEAN_SETTINGS["durable.enabled"].default}
    assert config.get_automation_import() == {
        "enable": BOOLEAN_SETTINGS["automation_import.enable"].default,
        "create_schedules": BOOLEAN_SETTINGS["automation_import.create_schedules"].default,
    }
    assert config.get_durable() == {"enabled": BOOLEAN_SETTINGS["durable.enabled"].default,
                                    "keep_last": contract.default}


@pytest.mark.parametrize("value, expected", [(0, 1), (101, 101), ("broken", 5)])
def test_durable_retention_keeps_runtime_bounds_distinct_from_the_form(monkeypatch, value, expected):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"durable": {"keep_last": value}})
    assert config.get_durable()["keep_last"] == expected


def test_automation_approval_switches_do_not_accept_string_truthiness(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"automation_import": {
        "enable": "true", "create_schedules": "true"}})
    assert config.get_automation_import() == {"enable": False, "create_schedules": False}


def test_selected_automation_and_durable_settings_survive_wizard_serialization(monkeypatch):
    from maverick import config
    from maverick_installer import wizard

    answers = iter((True, True, True))
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **_kwargs: next(answers))
    automation = wizard.pick_automation_import()
    durable = wizard.pick_durable()
    document = wizard.tomllib.loads("\n".join(
        wizard._cfg_automation_import(automation) + wizard._cfg_durable(durable)
    ))
    monkeypatch.setattr(config, "load_config", lambda: document)
    assert config.get_automation_import() == {"enable": True, "create_schedules": True}
    assert config.get_durable() == {"enabled": True, "keep_last": INTEGER_SETTINGS["durable.keep_last"].default}
