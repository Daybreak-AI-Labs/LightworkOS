"""The wizard's saved-answer-check questions (rule-6 loop): the defaults keep
today's behaviour and write nothing; a changed answer writes [agent_tests]
and the kernel reads it back."""
from __future__ import annotations


def _write(cfg_dir, monkeypatch, capabilities):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={}, capabilities=capabilities,
    )
    return (cfg_dir / "config.toml").read_text()


def test_the_check_questions_default_to_todays_behaviour(monkeypatch):
    from maverick_installer import wizard

    asked = []

    def fake_confirm(message, default=True):
        asked.append(message)
        return default

    def fake_text(message, default=""):
        asked.append(message)
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    monkeypatch.setattr(wizard, "_q_text", fake_text)
    assert wizard.pick_agent_test_rules() == {
        "max_cases_per_specialist": 20, "require_for_new_specialists": False,
        "bypass_requires_second_person": False, "tool_checks": False, "canary_percent": 0,
        "canary_auto_rollback": False}
    assert any("saved answer checks" in message for message in asked)


def test_defaults_write_no_agent_tests_table(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"jd_hiring": True, "max_cases_per_specialist": 20,
                                        "require_for_new_specialists": False,
                                        "bypass_requires_second_person": False})
    assert "[agent_tests]" not in cfg and "max_cases_per_specialist" not in cfg


def test_changed_answers_write_the_table_and_the_kernel_reads_them(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"max_cases_per_specialist": 40,
                                        "require_for_new_specialists": True,
                                        "bypass_requires_second_person": True})
    assert cfg.count("[agent_tests]") == 1
    assert "max_cases_per_specialist = 40" in cfg
    assert "require_for_new_specialists = true" in cfg and "bypass_requires_second_person = true" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import agent_tests_policy, config
    config.reset_config_cache()
    try:
        assert agent_tests_policy.max_cases_per_specialist() == 40
        assert agent_tests_policy.require_for_new_specialists() is True
        assert agent_tests_policy.bypass_requires_second_person() is True
    finally:
        config.reset_config_cache()


def test_a_canary_share_is_written_only_when_on_and_the_kernel_reads_it(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"max_cases_per_specialist": 20, "require_for_new_specialists": False,
                                        "bypass_requires_second_person": False, "canary_percent": 25,
                                        "canary_auto_rollback": True})
    assert "canary_percent = 25" in cfg and "canary_auto_rollback = true" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import agent_tests_policy, config
    config.reset_config_cache()
    try:
        assert agent_tests_policy.canary_percent() == 25
        assert agent_tests_policy.canary_auto_rollback() is True
    finally:
        config.reset_config_cache()


def test_the_tool_checks_question_writes_the_switch_only_when_yes(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"tool_checks": False})
    assert "[agent_tests]" not in cfg
    cfg = _write(cfg_dir, monkeypatch, {"tool_checks": True})
    assert cfg.count("[agent_tests]") == 1 and "\ntool_checks = true\n" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import agent_tests_policy, config
    config.reset_config_cache()
    try:
        assert agent_tests_policy.tool_checks_enabled() is True
    finally:
        config.reset_config_cache()


def test_auto_rollback_without_a_canary_is_not_written(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"max_cases_per_specialist": 20, "require_for_new_specialists": False,
                                        "bypass_requires_second_person": False, "canary_percent": 0,
                                        "canary_auto_rollback": True})
    assert "canary_percent" not in cfg and "canary_auto_rollback" not in cfg


def test_the_check_limit_question_accepts_only_one_to_two_hundred(monkeypatch):
    from maverick_installer import wizard

    answers = iter(["0", "lots", "201", "150"])
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": next(answers))
    monkeypatch.setattr(wizard, "console", type("C", (), {"print": staticmethod(lambda *a, **k: None)})())
    assert wizard._prompt_check_limit() == 150
