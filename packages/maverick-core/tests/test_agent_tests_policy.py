"""The [agent_tests] switches that size and gate saved answer checks."""
from __future__ import annotations

import pytest


@pytest.fixture
def settings(monkeypatch, tmp_path):
    from maverick import config

    path = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))

    def write(text: str) -> None:
        path.write_text(text, encoding="utf-8")
        config.reset_config_cache()

    write("")
    yield write
    config.reset_config_cache()


def test_defaults_are_twenty_checks_and_both_switches_off(settings):
    from maverick import agent_tests_policy as policy

    assert policy.max_cases_per_specialist() == 20
    assert policy.require_for_new_specialists() is False
    assert policy.bypass_requires_second_person() is False


def test_the_check_limit_follows_the_setting_between_one_and_two_hundred(settings):
    from maverick import agent_tests_policy as policy

    settings("[agent_tests]\nmax_cases_per_specialist = 35\n")
    assert policy.max_cases_per_specialist() == 35
    settings("[agent_tests]\nmax_cases_per_specialist = 200\n")
    assert policy.max_cases_per_specialist() == 200
    settings("[agent_tests]\nmax_cases_per_specialist = 1\n")
    assert policy.max_cases_per_specialist() == 1


@pytest.mark.parametrize("value", ["0", "201", "-5", "\"25\"", "2.5", "true"])
def test_a_check_limit_outside_the_range_reads_as_the_default(settings, value):
    from maverick import agent_tests_policy as policy

    settings(f"[agent_tests]\nmax_cases_per_specialist = {value}\n")
    assert policy.max_cases_per_specialist() == 20


def test_the_switches_read_only_true_as_on(settings):
    from maverick import agent_tests_policy as policy

    settings("[agent_tests]\nrequire_for_new_specialists = true\nbypass_requires_second_person = true\n")
    assert policy.require_for_new_specialists() is True
    assert policy.bypass_requires_second_person() is True


def test_unreadable_settings_keep_the_stricter_reading(settings):
    from maverick import agent_tests_policy as policy

    # A switch that is not a true/false value is read as on, never as off.
    settings("[agent_tests]\nrequire_for_new_specialists = \"no\"\nbypass_requires_second_person = 0\n")
    assert policy.require_for_new_specialists() is True
    assert policy.bypass_requires_second_person() is True
    # A broken settings file keeps both switches on and the check limit at its default.
    settings("[agent_tests\nmax_cases_per_specialist = 50\n")
    assert policy.require_for_new_specialists() is True
    assert policy.bypass_requires_second_person() is True
    assert policy.max_cases_per_specialist() == 20


def test_the_canary_share_is_off_by_default_and_follows_a_whole_share_from_one_to_fifty(settings):
    from maverick import agent_tests_policy as policy

    assert policy.canary_percent() == 0
    assert policy.canary_auto_rollback() is False
    settings("[agent_tests]\ncanary_percent = 1\n")
    assert policy.canary_percent() == 1
    settings("[agent_tests]\ncanary_percent = 50\ncanary_auto_rollback = true\n")
    assert policy.canary_percent() == 50
    assert policy.canary_auto_rollback() is True


@pytest.mark.parametrize("value", ["51", "-1", "\"10\"", "2.5", "true"])
def test_a_canary_share_that_is_not_a_whole_number_in_range_reads_as_off(settings, value):
    from maverick import agent_tests_policy as policy

    settings(f"[agent_tests]\ncanary_percent = {value}\n")
    assert policy.canary_percent() == 0


def test_unreadable_settings_turn_the_canary_off(settings):
    from maverick import agent_tests_policy as policy

    settings("[agent_tests\ncanary_percent = 20\n")
    assert policy.canary_percent() == 0


def test_the_config_checker_knows_the_section_and_its_limits():
    from maverick.config_lint import lint_config

    findings = lint_config({"agent_tests": {
        "max_cases_per_specialist": 500, "require_for_new_specialists": "yes",
        "bypass_requires_second_person": True, "canary_percent": 75,
        "canary_auto_rollback": "yes", "mystery": 1}})
    flagged = {(f.section, f.key) for f in findings}
    assert ("agent_tests", "max_cases_per_specialist") in flagged
    assert ("agent_tests", "require_for_new_specialists") in flagged
    assert ("agent_tests", "mystery") in flagged
    assert ("agent_tests", "canary_percent") in flagged
    assert ("agent_tests", "canary_auto_rollback") in flagged
    assert ("agent_tests", "bypass_requires_second_person") not in flagged
    assert lint_config({"agent_tests": {"max_cases_per_specialist": 200,
                                        "require_for_new_specialists": True}}) == []


def test_tool_checks_default_to_off_and_are_on_only_for_exactly_true(settings):
    from maverick import agent_tests_policy as policy

    assert policy.tool_checks_enabled() is False
    settings("[agent_tests]\ntool_checks = true\n")
    assert policy.tool_checks_enabled() is True
    # Anything that is not the boolean true keeps tool checks off.
    for value in ["\"yes\"", "1", "\"true\""]:
        settings(f"[agent_tests]\ntool_checks = {value}\n")
        assert policy.tool_checks_enabled() is False, value


def test_a_broken_settings_file_keeps_tool_checks_off(settings):
    from maverick import agent_tests_policy as policy

    settings("[agent_tests\ntool_checks = true\n")
    assert policy.tool_checks_enabled() is False


def test_the_config_checker_knows_the_tool_checks_switch():
    from maverick.config_lint import lint_config

    findings = lint_config({"agent_tests": {"tool_checks": "yes", "mystery": 1}})
    flagged = {(f.section, f.key) for f in findings}
    assert ("agent_tests", "tool_checks") in flagged
    assert ("agent_tests", "mystery") in flagged
    clean = lint_config({"agent_tests": {"tool_checks": True}})
    assert not [f for f in clean if f.key == "tool_checks"]


@pytest.mark.parametrize("text", ["[agent_tests\ncanary_auto_rollback = true\n", "[agent_tests]\ncanary_auto_rollback = \"yes\"\n",
                                  "[agent_tests]\ncanary_auto_rollback = 1\n"])
def test_unreadable_or_non_boolean_settings_leave_automatic_roll_back_off(settings, text):
    from maverick import agent_tests_policy as policy

    # Automatic roll back is the one switch that acts without a person, so only a true value turns it on.
    settings(text)
    assert policy.canary_auto_rollback() is False
