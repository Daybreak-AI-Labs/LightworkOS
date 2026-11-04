"""The wizard's savings-assumptions step (rule-6 loop): setting the client's
human-cost numbers writes [value], and the kernel's get_value() reads them
back; declining writes no section and the conservative defaults hold."""
from __future__ import annotations


def _write(cfg_dir, monkeypatch, value):
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
        value=value,
    )
    return (cfg_dir / "config.toml").read_text()


def test_pick_value_returns_assumptions(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: True)
    answers = iter(["150", "0.75"])
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **kw: next(answers))
    assert wizard.pick_value() == {"hourly_rate": 150.0, "hours_per_task": 0.75}


def test_pick_value_declined_is_empty(monkeypatch):
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    assert wizard.pick_value() == {}


def test_value_writes_and_kernel_reads_it(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_VALUE_HOURLY_RATE", raising=False)
    monkeypatch.delenv("MAVERICK_VALUE_HOURS", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch,
                 {"hourly_rate": 150.0, "hours_per_task": 0.75})
    assert "[value]" in cfg
    assert "hourly_rate = 150.0" in cfg

    from maverick.config import get_value, reset_config_cache
    reset_config_cache()
    v = get_value()
    assert v["hourly_rate"] == 150.0
    assert v["hours_per_task"] == 0.75
    reset_config_cache()


def test_value_declined_writes_no_section(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = _write(cfg_dir, monkeypatch, None)
    assert "[value]" not in cfg


def test_intent_value_pick_and_writer_default_confirmation_off(monkeypatch):
    from maverick.config_install import (
        blocking_config_findings,
        config_findings,
        parse_config_bytes,
    )
    from maverick_installer import wizard
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: kw["default"])
    picked = wizard.pick_intent_value()
    assert picked == {"enabled": True, "recommendations": True, "completion_confirmation": False}
    text = "\n".join(wizard._cfg_intent_value(picked))
    assert "[intent_value]" in text and "completion_confirmation = false" in text
    assert not blocking_config_findings(config_findings(parse_config_bytes(text.encode())))
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **kw: False)
    assert wizard.pick_intent_value()["enabled"] is False


def test_intent_value_configuration_rejects_invalid_flags_and_unknown_controls():
    from maverick.config_install import blocking_config_findings, config_findings
    invalid = {"intent_value": {"enabled": "yes", "recommendations": "false",
                                "completion_confirmation": 1, "activate_automatically": True}}
    findings = blocking_config_findings(config_findings(invalid))
    assert {finding.key for finding in findings} == {
        "enabled", "recommendations", "completion_confirmation", "activate_automatically"}
