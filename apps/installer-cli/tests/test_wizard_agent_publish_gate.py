"""The wizard's Agent Factory publish-gate question (rule-6 loop): the default
keeps the gate on and writes nothing; turning it off writes
[agent_factory] require_passing_tests = false and the kernel reads it back."""
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


def test_publish_gate_question_defaults_to_on(monkeypatch):
    from maverick_installer import wizard
    captured = {}

    def fake_confirm(message, default=True):
        captured["message"], captured["default"] = message, default
        return default

    monkeypatch.setattr(wizard, "_q_confirm", fake_confirm)
    assert wizard.pick_agent_publish_gate() is True
    assert captured["default"] is True and "passing tests" in captured["message"]


def test_publish_gate_off_writes_the_knob_and_the_kernel_reads_it(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    kept = _write(cfg_dir, monkeypatch, {"jd_hiring": True, "require_passing_tests": True})
    assert "require_passing_tests" not in kept and "[agent_factory]" not in kept
    cfg = _write(cfg_dir, monkeypatch, {"jd_hiring": True, "require_passing_tests": False})
    assert "[agent_factory]" in cfg and "require_passing_tests = false" in cfg
    assert "jd_hiring" not in cfg
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg_dir / "config.toml"))
    from maverick import agent_publish_policy, config
    config.reset_config_cache()
    try:
        assert agent_publish_policy.require_passing_tests() is False
    finally:
        config.reset_config_cache()


def test_both_agent_factory_choices_share_one_table(tmp_path, monkeypatch):
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, {"jd_hiring": False, "require_passing_tests": False})
    assert cfg.count("[agent_factory]") == 1
    assert "jd_hiring = false" in cfg and "require_passing_tests = false" in cfg
