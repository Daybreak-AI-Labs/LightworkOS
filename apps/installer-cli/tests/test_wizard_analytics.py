"""The wizard's Analytics consent step (rule-6 loop): declining writes no
[analytics] section and the kernel keeps the tally off; granting writes
[analytics] mcp_client_language = true and maverick.mcp_analytics reads it
back. Consent is opt-in -- the default answer is No."""
from __future__ import annotations


def _write(cfg_dir, monkeypatch, analytics):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    from maverick_installer.wizard import write_config
    write_config(
        providers=["anthropic"], role_models={},
        channels={}, safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={}, capabilities={},
        analytics=analytics,
    )
    return (cfg_dir / "config.toml").read_text()


def test_pick_analytics_default_is_decline(monkeypatch):
    """Consent must be opt-in: the prompt's default answer is No."""
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_analytics() == {}
    assert captured["default"] is False


def test_pick_analytics_grant_returns_knob(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    assert wizard.pick_analytics() == {"mcp_client_language": True}


def test_analytics_grant_writes_and_kernel_reads_it(tmp_path, monkeypatch):
    """Rule-6 loop: granting consent writes [analytics] mcp_client_language,
    and the kernel's analytics_enabled() reads it back."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_MCP_ANALYTICS", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"mcp_client_language": True})
    assert "[analytics]" in cfg
    assert "mcp_client_language = true" in cfg

    from maverick.mcp_analytics import analytics_enabled
    assert analytics_enabled() is True


def test_analytics_declined_writes_no_section_and_stays_off(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_MCP_ANALYTICS", raising=False)
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {})
    assert "[analytics]" not in cfg

    from maverick.mcp_analytics import analytics_enabled
    assert analytics_enabled() is False


def test_usability_survey_question_defaults_to_no(monkeypatch):
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_usability_survey() == {}
    assert captured["default"] is False


def test_usability_survey_yes_writes_the_knob_and_the_kernel_reads_it(tmp_path, monkeypatch):
    """Rule-6 loop for [analytics] usability_survey."""
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    answer = wizard.pick_usability_survey()
    assert answer == {"usability_survey": True}
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, answer)
    assert "usability_survey = true" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import config, usability_survey
    config.reset_config_cache()
    try:
        assert usability_survey.enabled() is True
    finally:
        config.reset_config_cache()


def test_web_vitals_question_defaults_to_no(monkeypatch):
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_web_vitals() == {}
    assert captured["default"] is False


def test_web_vitals_yes_writes_the_knob_and_the_kernel_reads_it(tmp_path, monkeypatch):
    """Rule-6 loop for [analytics] web_vitals."""
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": default)
    answer = wizard.pick_web_vitals()
    assert answer == {"web_vitals": True, "web_vitals_sample_rate": 0.5}
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, answer)
    assert "web_vitals = true" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import config, web_vitals
    config.reset_config_cache()
    try:
        assert web_vitals.enabled() is True
    finally:
        config.reset_config_cache()


def test_the_analytics_step_asks_about_page_speed():
    import inspect

    from maverick_installer import wizard
    assert "pick_web_vitals()" in inspect.getsource(wizard)


def test_web_vitals_asks_how_many_visits_to_measure(monkeypatch):
    from maverick_installer import wizard
    answers = iter(["2", "abc", "0.25"])   # out of range and not a number are asked again
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    assert wizard.pick_web_vitals() == {"web_vitals": True, "web_vitals_sample_rate": 0.25}


def test_web_vitals_sample_rate_default_is_written_when_kept(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": default)
    assert wizard.pick_web_vitals() == {"web_vitals": True, "web_vitals_sample_rate": 0.5}


def test_usage_measures_question_defaults_to_no_and_yes_writes_the_knob(tmp_path, monkeypatch):
    """Rule-6 loop for [analytics] usage_measures (the usage research measures)."""
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_usage_measures() == {} and captured["default"] is False
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    answer = wizard.pick_usage_measures()
    assert answer == {"usage_measures": True}
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, answer)
    assert "usage_measures = true" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import config, usage_measures
    config.reset_config_cache()
    try:
        assert usage_measures.enabled() is True
    finally:
        config.reset_config_cache()
