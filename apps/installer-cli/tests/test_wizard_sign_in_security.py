"""The wizard's Sign-in security step writes [auth.mfa] and
[auth.ip_allowlist], and the kernel reads them back (rule-6 loop)."""
from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore

from maverick_installer import wizard


def _write(cfg_dir, monkeypatch, advanced):
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_DIR", cfg_dir)
    monkeypatch.setattr("maverick_installer.wizard.ENV_FILE", cfg_dir / ".env")
    monkeypatch.setattr("maverick_installer.wizard.CONFIG_FILE", cfg_dir / "config.toml")
    wizard.write_config(
        providers=["anthropic"], role_models={}, channels={},
        safety={"profile": "balanced"},
        budget={"max_dollars": 5.0, "max_wall_seconds": 600, "max_tool_calls": 30},
        sandbox={"backend": "local", "workdir": "~/ws"},
        keys={"ANTHROPIC_API_KEY": "x"}, capabilities={}, advanced=advanced,
    )
    return (cfg_dir / "config.toml").read_text()


def _answers(monkeypatch, confirms, texts, selects=()):
    confirms, texts, selects = list(confirms), list(texts), list(selects)
    monkeypatch.setattr(wizard, "_q_confirm", lambda *a, **k: confirms.pop(0))
    monkeypatch.setattr(wizard, "_q_text", lambda *a, **k: texts.pop(0))
    monkeypatch.setattr(wizard, "_q_select", lambda *a, **k: selects.pop(0) if selects else k.get("default"))


def test_step_declined_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    # Browser time limits declined, then second factor declined.
    _answers(monkeypatch, [False, False], [""])
    assert wizard.pick_sign_in_security(True) == {}
    # Without company sign-in the second-factor question is not even asked; the
    # owner's authenticator choice is, and optional writes nothing.
    _answers(monkeypatch, [False], [""], ["optional"])
    assert wizard.pick_sign_in_security(False) == {}
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True)
    cfg = _write(cfg_dir, monkeypatch, {"sign_in_security": {}})
    assert "[auth.mfa]" not in cfg and "[auth.ip_allowlist]" not in cfg
    assert "[auth.sessions]" not in cfg
    from maverick import config

    config.reset_config_cache()
    assert config.get_auth_mfa()["require"] is False
    assert config.get_ip_allowlist()["cidrs"] == []


def test_step_answers_write_and_are_read(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    for env in ("MAVERICK_MFA_REQUIRE", "MAVERICK_MFA_STEP_UP_MINUTES",
                "MAVERICK_IP_ALLOWLIST"):
        monkeypatch.delenv(env, raising=False)
    _answers(monkeypatch, [True, True], ["45", "12", "20", "10.0.0.0/8, 203.0.113.7"])
    chosen = wizard.pick_sign_in_security(True)
    assert chosen == {"idle_minutes": 45, "company_hours": 12, "require": True, "step_up_minutes": 20,
                      "cidrs": ["10.0.0.0/8", "203.0.113.7"]}
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True)
    cfg = _write(cfg_dir, monkeypatch, {"sign_in_security": chosen})
    parsed = tomllib.loads(cfg)
    assert parsed["auth"]["mfa"] == {"require": True, "step_up_minutes": 20}
    assert parsed["auth"]["ip_allowlist"] == {"cidrs": ["10.0.0.0/8", "203.0.113.7"]}
    assert parsed["auth"]["sessions"] == {"company_hours": 12, "idle_minutes": 45}
    from maverick import config

    config.reset_config_cache()
    assert config.get_auth_mfa()["require"] is True
    assert config.get_auth_mfa()["step_up_minutes"] == 20
    assert config.get_ip_allowlist()["cidrs"] == ["10.0.0.0/8", "203.0.113.7"]
    sessions = config.get_auth_sessions()
    assert (sessions["company_hours"], sessions["idle_minutes"]) == (12, 45)


def test_owner_authenticator_choice_is_written_and_read(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _answers(monkeypatch, [False, False], ["10.0.0.0/8"], ["required"])
    chosen = wizard.pick_sign_in_security(False)
    assert chosen == {"local_owner_totp": "required", "cidrs": ["10.0.0.0/8"]}
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir(parents=True)
    cfg = _write(cfg_dir, monkeypatch, {"sign_in_security": chosen})
    parsed = tomllib.loads(cfg)
    assert parsed["auth"]["local_owner"] == {"totp": "required"}
    assert "mfa" not in parsed["auth"]
    from maverick import config

    config.reset_config_cache()
    assert config.get_auth_local_owner_totp() == "required"


def test_bad_address_is_asked_again(tmp_path, monkeypatch):
    printed: list[str] = []
    monkeypatch.setattr(wizard.console, "print", lambda *a, **k: printed.append(str(a[0])))
    _answers(monkeypatch, [False, False], ["office, 10.0.0.0/8", "10.0.0.0/8"])
    assert wizard.pick_sign_in_security(True) == {"cidrs": ["10.0.0.0/8"]}
    assert any("office" in line for line in printed)
