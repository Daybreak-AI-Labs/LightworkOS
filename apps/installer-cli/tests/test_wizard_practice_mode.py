"""The wizard's practice-mode question (rule-6 loop): the default
offers practice and writes nothing; turning it off writes [practice]
enable = false and the kernel reads it back."""
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


def test_practice_mode_question_defaults_to_on_and_off_writes_the_knob(tmp_path, monkeypatch):
    """Rule-6 loop for [practice] enable."""
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["default"] = default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_practice_mode() is True and captured["default"] is True
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    assert "[practice]" not in _write(cfg_dir, monkeypatch, {"practice_mode": True})
    cfg = _write(cfg_dir, monkeypatch, {"practice_mode": False})
    assert "[practice]" in cfg and "enable = false" in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import config, practice
    config.reset_config_cache()
    try:
        assert practice.enabled() is False
        assert practice.unavailable_reason() == "Practice mode is turned off in Settings."
    finally:
        config.reset_config_cache()


def test_practice_spending_cap_question_writes_only_a_changed_cap(tmp_path, monkeypatch):
    """Rule-6 loop for [practice] daily_spend_cap: asked only when practice is offered."""
    from maverick_installer import wizard
    asked = []
    monkeypatch.setattr(wizard, "_q_text", lambda message, default="": asked.append((message, default)) or "2.50")
    assert wizard.pick_practice_spend_cap() == 2.5
    assert asked[0][1] == "1.00" and "real money" in asked[0][0]
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    assert "[practice]" not in _write(cfg_dir, monkeypatch, {"practice_mode": True, "practice_daily_spend_cap": 1.0})
    cfg = _write(cfg_dir, monkeypatch, {"practice_mode": True, "practice_daily_spend_cap": 2.5})
    assert "[practice]" in cfg and "daily_spend_cap = 2.5" in cfg and "enable" not in cfg.split("[practice]")[1]
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import config, practice
    config.reset_config_cache()
    try:
        assert practice.spend_cap() == 2.5 and practice.enabled() is True
    finally:
        config.reset_config_cache()
